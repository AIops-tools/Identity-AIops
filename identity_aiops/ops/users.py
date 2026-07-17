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
    pick,
    s,
    to_bool,
    user_enabled,
)
from identity_aiops.platform import KEYCLOAK


def _is_keycloak(conn: Any) -> bool:
    return conn.target.platform == KEYCLOAK


def norm_user(r: dict) -> dict:
    """Normalise one user row across Keycloak / authentik field names."""
    return {
        "id": s(pick(r, "id", "pk")),
        "username": s(pick(r, "username", "name")),
        "email": s(pick(r, "email")),
        "enabled": user_enabled(r),
        "created": s(pick(r, "createdTimestamp", "date_joined", default="")),
        "lastLogin": s(pick(r, "last_login", "lastLogin", default="")),
        "serviceAccount": is_service_account(r),
    }


def list_users(conn: Any, search: str | None = None, max_results: int = 200) -> dict:
    """[READ] Users in the realm (optionally matching ``search``), normalized."""
    try:
        limit = max(1, int(max_results))
        if _is_keycloak(conn):
            params: dict[str, Any] = {"max": limit}
            if search:
                params["search"] = search
        else:
            params = {"page_size": limit}
            if search:
                params["search"] = search
        rows = conn.platform.rows(conn.get(conn.path("users"), params=params))
        users = [norm_user(r) for r in rows]
        return {"total": len(users), "users": users}
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
    """[READ] A user's active sessions (id, IP, start/last-access, client)."""
    try:
        rows = conn.platform.rows(conn.get(conn.path("user_sessions", user_id=user_id)))
        sessions = [
            {
                "id": s(pick(r, "id", "uuid")),
                "ip": s(pick(r, "ipAddress", "last_ip", default="")),
                "started": s(pick(r, "start", "expires", default="")),
                "lastAccess": s(pick(r, "lastAccess", "last_used", default="")),
                "clients": pick(r, "clients", default={}),
            }
            for r in rows
        ]
        return {"userId": s(user_id), "total": len(sessions), "sessions": sessions}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200), "userId": s(user_id)}


# Credential/device types that count as a second factor (Keycloak credential
# ``type`` values and authentik device verbose names/types). ``password`` is
# the first factor; recovery codes are backup, not a second factor.
SECOND_FACTOR_TYPES = frozenset(
    {"otp", "totp", "hotp", "webauthn", "webauthn-passwordless", "duo", "sms"}
)


def _norm_credential(r: dict) -> dict:
    ctype = s(pick(r, "type", "verbose_name", default="")).lower().replace(" device", "")
    return {
        "id": s(pick(r, "id", "pk")),
        "type": ctype,
        "label": s(pick(r, "userLabel", "name", default="")),
        "created": s(pick(r, "createdDate", "created", default="")),
        "confirmed": to_bool(pick(r, "confirmed", default=True)),
        "secondFactor": ctype in SECOND_FACTOR_TYPES,
    }


def user_credentials(conn: Any, user_id: str) -> dict:
    """[READ] A user's configured credentials/authenticators (MFA surface)."""
    try:
        rows = conn.platform.rows(conn.get(conn.path("user_credentials", user_id=user_id)))
        creds = [_norm_credential(r) for r in rows]
        return {
            "userId": s(user_id),
            "total": len(creds),
            "secondFactors": sum(1 for c in creds if c["secondFactor"] and c["confirmed"]),
            "credentials": creds,
        }
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200), "userId": s(user_id)}


def list_groups(conn: Any, max_results: int = 200) -> dict:
    """[READ] Groups in the realm."""
    try:
        limit = max(1, int(max_results))
        params = {"max": limit} if _is_keycloak(conn) else {"page_size": limit}
        rows = conn.platform.rows(conn.get(conn.path("groups"), params=params))
        groups = [
            {
                "id": s(pick(r, "id", "pk")),
                "name": s(pick(r, "name")),
                "path": s(pick(r, "path", default="")),
                "members": pick(r, "num_pk", default=None),
            }
            for r in rows
        ]
        return {"total": len(groups), "groups": groups}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def group_members(conn: Any, group_id: str, max_results: int = 200) -> dict:
    """[READ] Members of one group, normalized user rows."""
    try:
        limit = max(1, int(max_results))
        if _is_keycloak(conn):
            rows = conn.platform.rows(
                conn.get(conn.path("group_members", group_id=group_id), params={"max": limit})
            )
        else:
            # authentik: the group detail embeds member objects under users_obj.
            raw = as_obj(conn.platform.normalise(conn.get(conn.path("group_members",
                                                                    group_id=group_id))))
            rows = [r for r in raw.get("users_obj") or [] if isinstance(r, dict)][:limit]
        members = [norm_user(r) for r in rows]
        return {"groupId": s(group_id), "total": len(members), "members": members}
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
            "lastFailure": s(pick(raw, "lastFailure", default="")),
            "lastIPFailure": s(pick(raw, "lastIPFailure", default="")),
        }
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200), "userId": s(user_id)}
