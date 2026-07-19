"""Authentication / admin event reads (read-only).

Keycloak exposes two feeds (``/events`` for login events, ``/admin-events``
for admin operations); authentik exposes one feed (``/api/v3/events/events/``)
filtered by ``action``. Both are reconciled to one normalized event row:
``{time, type, user, ip, client, error}``. Event types are normalized to
UPPER_SNAKE (Keycloak ``LOGIN_ERROR`` and authentik ``login_failed`` →
``LOGIN_FAILED``-family constants below).
"""

from __future__ import annotations

from typing import Any

from identity_aiops.ops._util import as_obj, opt_s, pick, s
from identity_aiops.platform import KEYCLOAK

# Normalized event types the analyses key on.
LOGIN_OK_TYPES = frozenset({"LOGIN", "LOGIN_SUCCESS"})
LOGIN_FAIL_TYPES = frozenset({"LOGIN_ERROR", "LOGIN_FAILED"})

# authentik event actions that read as admin/config operations.
_AUTHENTIK_ADMIN_ACTIONS = frozenset(
    {"model_created", "model_updated", "model_deleted", "policy_exception",
     "configuration_error", "update_available"}
)

MAX_EVENTS = 500


def _is_keycloak(conn: Any) -> bool:
    return conn.target.platform == KEYCLOAK


def norm_event(r: dict) -> dict:
    """Normalise one event row across Keycloak / authentik field names.

    Optional fields the feed did not carry come back as ``None`` (JSON
    ``null``), never as ``""`` — an event with no client is a different fact
    from an event whose client is the empty string, and a consumer cannot
    recover that difference once the two are folded together. The keys are
    always present; only their values may be null.
    """
    user = as_obj(r.get("user"))
    details = as_obj(r.get("details"))
    context = as_obj(r.get("context"))
    etype = opt_s(pick(r, "type", "action"))
    return {
        "time": opt_s(pick(r, "time", "created")),
        "type": etype.upper() if etype is not None else None,
        "user": opt_s(
            pick(details, "username")
            or pick(user, "username")
            or pick(r, "userId")
        ),
        "ip": opt_s(pick(r, "ipAddress", "client_ip")),
        "client": opt_s(pick(r, "clientId") or pick(context, "application", "client_id")),
        "error": opt_s(pick(r, "error") or pick(context, "message"), 200),
    }


def login_events(
    conn: Any,
    event_type: str | None = None,
    user: str | None = None,
    max_results: int = 200,
) -> dict:
    """[READ] Recent authentication events, normalized (optionally filtered).

    ``event_type`` uses the platform's vocabulary (Keycloak ``LOGIN`` /
    ``LOGIN_ERROR``; authentik ``login`` / ``login_failed``) — pass it
    case-insensitively, the op adapts it per platform.

    Returns a truncation envelope rather than a bare count + list::

        {"events": [...], "returned": 200, "limit": 200, "truncated": true}

    An event feed is exactly where a partial read gets misread as "nothing is
    happening": a bare list cannot say "there is more", so the consumer has to
    infer it from the length happening to equal the limit. One extra event is
    requested from the IdP so ``truncated`` is *measured*, not guessed.
    """
    try:
        requested = max(1, min(int(max_results), MAX_EVENTS))
        probe = requested + 1
        if _is_keycloak(conn):
            params: dict[str, Any] = {"max": probe}
            if event_type:
                params["type"] = event_type.upper()
            if user:
                params["user"] = user
        else:
            params = {"page_size": probe}
            if event_type:
                params["action"] = event_type.lower()
            if user:
                params["username"] = user
        rows = conn.platform.rows(conn.get(conn.path("events"), params=params))
        truncated = len(rows) > requested
        events = [norm_event(r) for r in rows[:requested]]
        return {
            "events": events,
            "returned": len(events),
            "limit": requested,
            "truncated": truncated,
        }
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def failed_login_events(conn: Any, max_results: int = MAX_EVENTS) -> dict:
    """[READ] Recent failed-login events (the login-failure RCA feed).

    Returns the same truncation envelope as :func:`login_events` — the RCA and
    the overview both need to know whether the feed they analysed was complete,
    since every conclusion they draw is bounded by it. A failure degrades to an
    empty, non-truncated envelope so callers never have to branch on ``error``.
    """
    fail_type = "LOGIN_ERROR" if _is_keycloak(conn) else "login_failed"
    out = login_events(conn, event_type=fail_type, max_results=max_results)
    if "error" in out:
        return {"events": [], "returned": 0, "limit": int(max_results),
                "truncated": False, "error": out["error"]}
    return out


def admin_events(conn: Any, max_results: int = 200) -> dict:
    """[READ] Recent admin/config-change events, normalized.

    Keycloak has a dedicated admin-events feed; authentik's single feed is
    post-filtered to admin-flavoured actions (model_created/updated/deleted...).

    Returns the same truncation envelope as :func:`login_events`. On authentik
    the envelope reports truncation of the *underlying feed* as well as of the
    filtered result — rows past the probe were never even examined for
    admin-flavoured actions, so more admin events may exist either way.
    """
    try:
        requested = max(1, min(int(max_results), MAX_EVENTS))
        probe = requested + 1
        if _is_keycloak(conn):
            rows = conn.platform.rows(
                conn.get(conn.path("admin_events"), params={"max": probe})
            )
            matched = [
                {
                    "time": opt_s(pick(r, "time")),
                    "operation": opt_s(pick(r, "operationType")),
                    "resourceType": opt_s(pick(r, "resourceType")),
                    "resourcePath": opt_s(pick(r, "resourcePath")),
                    "actor": opt_s(pick(as_obj(r.get("authDetails")), "userId")),
                    "ip": opt_s(pick(as_obj(r.get("authDetails")), "ipAddress")),
                }
                for r in rows
            ]
        else:
            rows = conn.platform.rows(
                conn.get(conn.path("admin_events"), params={"page_size": probe})
            )
            matched = [
                {
                    "time": opt_s(pick(r, "created")),
                    "operation": opt_s(pick(r, "action")),
                    "resourceType": opt_s(
                        pick(as_obj(as_obj(r.get("context")).get("model")), "model_name")
                    ),
                    "resourcePath": opt_s(
                        pick(as_obj(as_obj(r.get("context")).get("model")), "name")
                    ),
                    "actor": opt_s(pick(as_obj(r.get("user")), "username")),
                    "ip": opt_s(pick(r, "client_ip")),
                }
                for r in rows
                if str(pick(r, "action", default="")).lower() in _AUTHENTIK_ADMIN_ACTIONS
            ]
        truncated = len(rows) > requested or len(matched) > requested
        events = matched[:requested]
        return {
            "events": events,
            "returned": len(events),
            "limit": requested,
            "truncated": truncated,
        }
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}
