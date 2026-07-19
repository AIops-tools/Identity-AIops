"""User reads — list, detail, count, sessions, credentials, groups (read-only).

The day-to-day "who is in this realm and what can they do?" surface,
platform-neutral: each op asks the connection for the right path and unwraps
the payload through the shared helpers, so the same function serves Keycloak
and authentik. Every call is resilient — a transport/parse failure surfaces as
``{"error": ...}`` instead of raising, and all IdP text is sanitised via ``s``.
Nothing here mutates a user — enable/disable/reset live in
:mod:`identity_aiops.ops.writes`.
"""

from __future__ import annotations

from typing import Any

from identity_aiops.ops._util import (
    as_obj,
    is_service_account,
    num,
    opt_s,
    pick,
    s,
    to_bool,
    user_enabled,
)
from identity_aiops.platform import KEYCLOAK


def _is_keycloak(conn: Any) -> bool:
    return conn.target.platform == KEYCLOAK


def norm_user(r: dict) -> dict:
    """Normalise one user row across Keycloak / authentik field names.

    Fields the IdP did not return come back as ``None`` (JSON ``null``), never
    as ``""``. This matters most for ``lastLogin`` and ``email``: "never signed
    in" and "signed in at an unrecorded time" are different facts, and folding
    both to an empty string invites a consumer to guess which one it is. The
    keys are always present; only their values may be null.
    """
    return {
        "id": opt_s(pick(r, "id", "pk")),
        "username": opt_s(pick(r, "username", "name")),
        "email": opt_s(pick(r, "email")),
        "enabled": user_enabled(r),
        "created": opt_s(pick(r, "createdTimestamp", "date_joined")),
        "lastLogin": opt_s(pick(r, "last_login", "lastLogin")),
        "serviceAccount": is_service_account(r),
    }


def list_users(conn: Any, search: str | None = None, max_results: int = 200) -> dict:
    """[READ] Users in the realm (optionally matching ``search``), normalized.

    Returns a truncation envelope::

        {"users": [...], "returned": 200, "limit": 200, "truncated": true}

    One extra user is requested from the IdP so ``truncated`` is *measured*
    rather than guessed from the row count happening to equal the limit. A
    realm larger than the limit is the normal case, not an edge case — an
    audit drawn from a silently clipped user list is simply wrong.
    """
    try:
        requested = max(1, int(max_results))
        probe = requested + 1
        if _is_keycloak(conn):
            params: dict[str, Any] = {"max": probe}
            if search:
                params["search"] = search
        else:
            params = {"page_size": probe}
            if search:
                params["search"] = search
        rows = conn.platform.rows(conn.get(conn.path("users"), params=params))
        truncated = len(rows) > requested
        users = [norm_user(r) for r in rows[:requested]]
        return {
            "users": users,
            "returned": len(users),
            "limit": requested,
            "truncated": truncated,
        }
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def user_detail(conn: Any, user_id: str) -> dict:
    """[READ] One user's full detail by id, normalized (+ platform extras)."""
    try:
        raw = as_obj(conn.platform.normalise(conn.get(conn.path("user_get", user_id=user_id))))
        detail = norm_user(raw)
        detail["id"] = detail["id"] or s(user_id)
        detail["requiredActions"] = [s(a, 64) for a in raw.get("requiredActions") or []]
        detail["attributes"] = as_obj(raw.get("attributes"))
        return detail
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200), "id": s(user_id)}


def user_count(conn: Any) -> dict:
    """[READ] Total user count in the realm (the cheap doctor probe)."""
    try:
        if _is_keycloak(conn):
            raw = conn.get(conn.path("user_count"))
            count = int(raw) if isinstance(raw, (int, float, str)) else 0
        else:
            raw = conn.get(conn.path("user_count"), params={"page_size": 1})
            pagination = as_obj(as_obj(raw).get("pagination"))
            count = int(pick(pagination, "count", default=len(conn.platform.rows(raw))))
        return {"count": count}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def user_sessions(conn: Any, user_id: str) -> dict:
    """[READ] A user's active sessions (id, IP, start/last-access, client).

    The IdP returns a user's whole session set, so nothing is ever dropped
    here — but the envelope still carries ``returned`` and
    ``truncated: false``. Stating "this list is complete" explicitly is what
    lets a caller act on it (revoke, or conclude the user is not signed in
    anywhere) instead of wondering whether it was clipped.
    """
    try:
        rows = conn.platform.rows(conn.get(conn.path("user_sessions", user_id=user_id)))
        sessions = [
            {
                "id": opt_s(pick(r, "id", "uuid")),
                "ip": opt_s(pick(r, "ipAddress", "last_ip")),
                "started": opt_s(pick(r, "start", "expires")),
                "lastAccess": opt_s(pick(r, "lastAccess", "last_used")),
                "clients": pick(r, "clients", default={}),
            }
            for r in rows
        ]
        return {
            "userId": s(user_id),
            "sessions": sessions,
            "returned": len(sessions),
            "truncated": False,
        }
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200), "userId": s(user_id)}


# Credential/device types that count as a second factor (Keycloak credential
# ``type`` values and authentik device verbose names/types). ``password`` is
# the first factor; recovery codes are backup, not a second factor.
SECOND_FACTOR_TYPES = frozenset(
    {"otp", "totp", "hotp", "webauthn", "webauthn-passwordless", "duo", "sms"}
)


def _norm_credential(r: dict) -> dict:
    raw_type = opt_s(pick(r, "type", "verbose_name"))
    ctype = raw_type.lower().replace(" device", "") if raw_type is not None else None
    return {
        "id": opt_s(pick(r, "id", "pk")),
        "type": ctype,
        "label": opt_s(pick(r, "userLabel", "name")),
        "created": opt_s(pick(r, "createdDate", "created")),
        "confirmed": to_bool(pick(r, "confirmed", default=True)),
        # A credential whose type the IdP did not name cannot be counted as a
        # second factor — `None not in SECOND_FACTOR_TYPES` is False, which is
        # the safe answer for an MFA-coverage claim.
        "secondFactor": ctype in SECOND_FACTOR_TYPES,
    }


def user_credentials(conn: Any, user_id: str) -> dict:
    """[READ] A user's configured credentials/authenticators (MFA surface)."""
    try:
        rows = conn.platform.rows(conn.get(conn.path("user_credentials", user_id=user_id)))
        creds = [_norm_credential(r) for r in rows]
        return {
            "userId": s(user_id),
            "credentials": creds,
            "returned": len(creds),
            "truncated": False,
            "secondFactors": sum(1 for c in creds if c["secondFactor"] and c["confirmed"]),
        }
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200), "userId": s(user_id)}


def list_groups(conn: Any, max_results: int = 200) -> dict:
    """[READ] Groups in the realm.

    Returns a truncation envelope; one extra group is requested so
    ``truncated`` is measured rather than guessed.
    """
    try:
        requested = max(1, int(max_results))
        probe = requested + 1
        params = {"max": probe} if _is_keycloak(conn) else {"page_size": probe}
        rows = conn.platform.rows(conn.get(conn.path("groups"), params=params))
        truncated = len(rows) > requested
        groups = [
            {
                "id": opt_s(pick(r, "id", "pk")),
                "name": opt_s(pick(r, "name")),
                "path": opt_s(pick(r, "path")),
                "members": pick(r, "num_pk", default=None),
            }
            for r in rows[:requested]
        ]
        return {
            "groups": groups,
            "returned": len(groups),
            "limit": requested,
            "truncated": truncated,
        }
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def group_members(conn: Any, group_id: str, max_results: int = 200) -> dict:
    """[READ] Members of one group, normalized user rows.

    Returns a truncation envelope. On Keycloak one extra member is requested
    from the API; on authentik the whole member list arrives embedded in the
    group detail (``users_obj``), so truncation is measured against the full
    embedded length before slicing. Either way it is measured, never guessed.
    """
    try:
        requested = max(1, int(max_results))
        if _is_keycloak(conn):
            rows = conn.platform.rows(
                conn.get(conn.path("group_members", group_id=group_id),
                         params={"max": requested + 1})
            )
        else:
            # authentik: the group detail embeds member objects under users_obj.
            raw = as_obj(conn.platform.normalise(conn.get(conn.path("group_members",
                                                                    group_id=group_id))))
            rows = [r for r in raw.get("users_obj") or [] if isinstance(r, dict)]
        truncated = len(rows) > requested
        members = [norm_user(r) for r in rows[:requested]]
        return {
            "groupId": s(group_id),
            "members": members,
            "returned": len(members),
            "limit": requested,
            "truncated": truncated,
        }
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200), "groupId": s(group_id)}


def user_lockout_status(conn: Any, user_id: str) -> dict:
    """[READ] Brute-force lockout status for one user (Keycloak attack-detection).

    authentik has no per-user lockout register; the platform map raises a
    teaching error that surfaces here as ``{"error": ...}``.
    """
    try:
        raw = as_obj(conn.platform.normalise(conn.get(conn.path("user_lockout",
                                                                user_id=user_id))))
        return {
            "userId": s(user_id),
            "numFailures": int(num(pick(raw, "numFailures", default=0))),
            "disabled": to_bool(pick(raw, "disabled", default=False)),
            "lastFailure": opt_s(pick(raw, "lastFailure")),
            "lastIPFailure": opt_s(pick(raw, "lastIPFailure")),
        }
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200), "userId": s(user_id)}
