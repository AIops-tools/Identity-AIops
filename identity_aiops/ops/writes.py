"""Governed identity writes — the only state-changing operations in the tool.

Identity writes are high-consequence — they grant, revoke, or re-key access,
which is why they carry the higher risk-tier labels on the audit row. Every
reversible write reads the IdP's current state **before** it changes anything,
so the harness records a faithful undo / audit trail (the before-state is
fetched via a real GET, never guessed):

  * ``disable_user`` / ``enable_user`` — read the user's current enabled flag
    first; undo restores it (a symmetric pair).
  * ``require_password_reset`` — reads the user's current required actions;
    undo clears the flag only if it wasn't already set (``clear=True`` replays
    through the same tool).
  * ``update_client_redirect_uris`` — reads the client's current URI list;
    undo replays the prior list.

Two writes are irreversible and record ``priorState`` only:

  * ``revoke_user_sessions`` — sessions cannot be resurrected; the prior
    session count is recorded.
  * ``rotate_client_secret`` — the old secret is gone; a **masked** fingerprint
    of it is recorded (never the value).

Two writes additionally refuse to act on **this connection's own identity**
(:class:`SelfLockout`), because doing so would destroy the tool's ability to
reverse — or even to continue — its own work:

  * ``disable_user`` — disabling the account whose token is in flight makes the
    undo (``enable_user``) fail 403.
  * ``rotate_client_secret`` — re-keying the client this tool authenticates as
    invalidates the stored secret instantly, and this write has no undo at all.

Both guards are exact (only the tool's own identity is refused) and **fail
open**: when the identity cannot be determined the call proceeds, because an
unknown identity must never be treated as "it is me".

Each function returns a plain descriptor; the MCP layer adds dry-run + the
governance harness (risk tier + audit + undo).
"""

from __future__ import annotations

from typing import Any

from identity_aiops.ops import clients as client_ops
from identity_aiops.ops import users as user_ops
from identity_aiops.ops._util import as_obj, s
from identity_aiops.platform import KEYCLOAK

REQUIRED_ACTION_UPDATE_PASSWORD = "UPDATE_PASSWORD"  # nosec B105 — action name
_MAX_SESSION_DELETES = 500


def _is_keycloak(conn: Any) -> bool:
    return conn.target.platform == KEYCLOAK


def _require_keycloak(conn: Any, action: str, alternative: str) -> None:
    if not _is_keycloak(conn):
        raise ValueError(
            f"{action} is a Keycloak-only operation — "
            f"{conn.platform.label} has no equivalent API. {alternative}"
        )


# ── user enable/disable (reversible pair) ────────────────────────────────────


def _set_user_enabled(conn: Any, user_id: str, enable: bool) -> dict:
    prior = user_ops.user_detail(conn, user_id)
    was_enabled = bool(prior.get("enabled", True)) if "error" not in prior else None
    if _is_keycloak(conn):
        conn.put(conn.path("user_update", user_id=user_id), json={"enabled": enable})
    else:
        conn.patch(conn.path("user_update", user_id=user_id), json={"is_active": enable})
    return {
        "action": "enable_user" if enable else "disable_user",
        "userId": s(user_id),
        "username": s(prior.get("username", "")),
        "enabled": bool(enable),
        "priorState": {"enabled": was_enabled},
    }


class SelfLockout(ValueError):  # noqa: N818 — teaching error, reads as a statement
    """Refused: the operation would disable the identity this tool authenticates as."""


def guard_disable_user(conn: Any, user_id: str) -> None:
    """Raise the :class:`SelfLockout` ``disable_user`` would raise, without writing.

    Called by ``disable_user`` itself *and* by the MCP wrapper ahead of its
    ``dry_run`` early return, so a preview of a self-disable reports the refusal
    instead of a green ``wouldDisable``. Both paths run this one function, so
    the preview and the real call can never disagree.
    """
    self_id = conn.self_user_id() if hasattr(conn, "self_user_id") else None
    if self_id is None or str(user_id) != str(self_id):
        return
    raise SelfLockout(
        f"Refusing to disable user '{user_id}': that is the account this tool "
        f"authenticates as. Disabling it revokes the credential immediately, so "
        f"the undo (enable_user) would fail with 403 and you would be locked out. "
        f"Use a different administrative credential if you really must disable it."
    )


def disable_user(conn: Any, user_id: str) -> dict:
    """[WRITE][med] Disable a user (blocks sign-in), capturing prior state.

    The containment move for a compromised or stale account. Reads the user
    first so ``priorState.enabled`` reflects what it *was* (drives a faithful
    undo via enable_user). Does not revoke live sessions — pair it with
    ``revoke_user_sessions``.

    **Refuses to disable the account this connection authenticates as.** Doing so
    revokes the credential mid-flight: the disable succeeds, and the undo that
    would re-enable it then fails 403 — an operation that destroys its own
    reversibility. Found exactly that way against a live authentik. If the
    identity cannot be determined, the call proceeds (unknown is never treated
    as "not me" in the other direction either — it simply cannot guard).
    """
    guard_disable_user(conn, user_id)
    return _set_user_enabled(conn, user_id, enable=False)


def enable_user(conn: Any, user_id: str) -> dict:
    """[WRITE][high] Re-enable a user (restores sign-in), capturing prior state.

    Re-granting access reverses a containment action, so this side of the pair
    carries the high risk tier (a descriptive audit label, not a gate).
    """
    return _set_user_enabled(conn, user_id, enable=True)


# ── session revocation (irreversible — priorState only) ─────────────────────


def revoke_user_sessions(conn: Any, user_id: str) -> dict:
    """[WRITE][med] Revoke all of a user's sessions. IRREVERSIBLE — no undo;
    the prior session count is recorded so the audit shows the blast radius.
    """
    prior = user_ops.user_sessions(conn, user_id)
    prior_count = prior.get("returned") if "error" not in prior else None
    if _is_keycloak(conn):
        conn.post(conn.path("user_logout", user_id=user_id))
        revoked: Any = prior_count if prior_count is not None else True
    else:
        revoked = 0
        for sess in prior.get("sessions", [])[:_MAX_SESSION_DELETES]:
            sid = sess.get("id")
            if sid:
                conn.delete(conn.path("session_delete", session_id=sid))
                revoked += 1
    return {
        "action": "revoke_user_sessions",
        "userId": s(user_id),
        "revoked": revoked,
        "priorState": {"sessionCount": prior_count},
        "note": "Sessions cannot be restored; the user must sign in again.",
    }


# ── required password reset (reversible via clear=True) ─────────────────────


def require_password_reset(conn: Any, user_id: str, clear: bool = False) -> dict:
    """[WRITE][med] Require (or with ``clear=True`` un-require) a password
    reset at the user's next sign-in (Keycloak required actions).

    Captures the prior required-action list; the undo replays this same tool
    with ``clear=True`` only when the flag wasn't already set. authentik has
    no required-actions concept — use its recovery-link flow instead.
    """
    _require_keycloak(
        conn, "require_password_reset",
        "For authentik, issue a recovery link from the admin UI instead.",
    )
    raw = as_obj(conn.platform.normalise(conn.get(conn.path("user_get", user_id=user_id))))
    prior_actions = [str(a) for a in raw.get("requiredActions") or []]
    already = REQUIRED_ACTION_UPDATE_PASSWORD in prior_actions
    if clear:
        new_actions = [a for a in prior_actions if a != REQUIRED_ACTION_UPDATE_PASSWORD]
    elif already:
        new_actions = prior_actions
    else:
        new_actions = [*prior_actions, REQUIRED_ACTION_UPDATE_PASSWORD]
    conn.put(conn.path("user_update", user_id=user_id), json={"requiredActions": new_actions})
    return {
        "action": "require_password_reset",
        "userId": s(user_id),
        "cleared": bool(clear),
        "requiredActions": [s(a, 64) for a in new_actions],
        "priorState": {
            "requiredActions": [s(a, 64) for a in prior_actions],
            "alreadyRequired": already,
        },
    }


# ── client redirect URIs (reversible — undo replays the prior list) ─────────


def update_client_redirect_uris(conn: Any, client_id: str, uris: list[str]) -> dict:
    """[WRITE][high] Replace a client's redirect-URI list, capturing the prior
    list (the undo replays it through this same tool).

    Redirect URIs are the security boundary of the OAuth flow — this is a
    replace operation and sits in the high tier.
    """
    if (
        not isinstance(uris, list)
        or not uris
        or not all(isinstance(u, str) and u.strip() for u in uris)
    ):
        raise ValueError(
            "redirect_uris must be a non-empty list of non-blank URI strings "
            "(pass the FULL desired list — this replaces, not appends)."
        )
    prior = client_ops.client_detail(conn, client_id)
    prior_uris = prior.get("redirectUris", []) if "error" not in prior else []
    cleaned = [u.strip() for u in uris]
    if _is_keycloak(conn):
        conn.put(conn.path("client_update", client_id=client_id),
                 json={"redirectUris": cleaned})
    else:
        conn.patch(conn.path("client_update", client_id=client_id),
                   json={"redirect_uris": "\n".join(cleaned)})
    return {
        "action": "update_client_redirect_uris",
        "clientId": s(client_id),
        "redirectUris": [s(u, 200) for u in cleaned],
        "priorState": {"redirectUris": prior_uris},
    }


# ── client secret rotation (irreversible — masked priorState only) ──────────


def _mask_secret(secret: str) -> str:
    """A non-reversible fingerprint of a secret for the audit trail."""
    if not secret:
        return "(none)"
    if len(secret) <= 8:
        return "****"
    return f"{secret[:4]}…{secret[-2:]} ({len(secret)} chars)"


def guard_rotate_client_secret(conn: Any, client_id: str) -> None:
    """Refuse to re-key the client this connection authenticates as.

    Called by ``rotate_client_secret`` itself *and* by the MCP wrapper ahead of
    its ``dry_run`` early return, so a preview of a self-rotation reports the
    refusal instead of a green ``wouldRotateSecret``. Both paths run this one
    function, so the preview and the real call can never disagree — the dry-run
    path pays one extra GET (``client_detail``) for that guarantee.

    Keycloak auth is ``client_credentials`` using the target's ``username``
    (which holds the client_id) plus the stored secret. Rotating that client's
    secret invalidates the stored credential the instant it succeeds, and
    ``rotate_client_secret`` records **no undo at all** — so every later token
    fetch fails until an operator re-keys the tool by hand. That is strictly
    worse than the ``disable_user`` lockout, which at least had an undo to fail.

    Exact and fail-open: only a confirmed match on the tool's own client_id is
    refused. If the client cannot be read (``{"error": ...}``) or carries no
    ``clientId``, the identity is *unknown* and the call proceeds — a false
    positive here would block legitimate rotation of every other client.
    """
    own_client_id = str(getattr(conn.target, "username", "") or "")
    if not own_client_id:
        return  # no client_id configured — nothing to compare against
    detail = client_ops.client_detail(conn, client_id)
    if "error" in detail:
        return  # could not read the client — unknown, never assumed to be self
    target_client_id = detail.get("clientId")
    if not target_client_id:
        return  # client carries no clientId — unknown, same reasoning
    if str(target_client_id) != own_client_id:
        return
    # Kept under the MCP layer's _safe_error truncation (300 chars) so the route
    # back — the part an agent acts on — is never the part that gets cut off.
    raise SelfLockout(
        f"Refusing to rotate client '{target_client_id}': that is the client this tool "
        f"authenticates as. Rotation invalidates the stored secret at once and this "
        f"write has no undo, so every later call fails until it is re-keyed by hand. "
        f"Rotate it in the Keycloak admin console, then 'identity-aiops secret set "
        f"{getattr(conn.target, 'name', '')}'."
    )


def rotate_client_secret(conn: Any, client_id: str) -> dict:
    """[WRITE][high] Rotate a client's secret. IRREVERSIBLE — the old secret
    is invalidated; only a **masked** fingerprint of it is recorded, never the
    value. The new secret is likewise returned masked — retrieve it from the
    Keycloak admin console (or client-secret endpoint) over a trusted channel
    and update every deployment that uses this client.

    **Refuses to rotate the secret of the client this connection authenticates
    as.** That credential is what every subsequent call depends on, and this
    write has no undo — the lockout would be permanent until a human re-keys the
    tool. If the client's identity cannot be determined, the call proceeds
    (unknown is never treated as "it is me").

    authentik has no rotation endpoint — edit the OAuth2 provider instead.
    """
    _require_keycloak(
        conn, "rotate_client_secret",
        "For authentik, set a new client secret on the OAuth2 provider.",
    )
    guard_rotate_client_secret(conn, client_id)
    prior_raw = as_obj(conn.get(conn.path("client_secret", client_id=client_id)))
    prior_masked = _mask_secret(str(prior_raw.get("value") or ""))
    new_raw = as_obj(conn.post(conn.path("client_secret", client_id=client_id)))
    return {
        "action": "rotate_client_secret",
        "clientId": s(client_id),
        "rotated": True,
        "newSecretMasked": _mask_secret(str(new_raw.get("value") or "")),
        "priorState": {"secretMasked": prior_masked},
        "note": "Old secret invalidated. Fetch the new value from the admin "
        "console and update every deployment before sessions expire.",
    }
