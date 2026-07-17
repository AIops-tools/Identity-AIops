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

from identity_aiops.ops._util import as_obj, pick, s
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
    """Normalise one event row across Keycloak / authentik field names."""
    user = as_obj(r.get("user"))
    details = as_obj(r.get("details"))
    context = as_obj(r.get("context"))
    return {
        "time": s(pick(r, "time", "created", default="")),
        "type": s(pick(r, "type", "action", default="")).upper(),
        "user": s(
            pick(details, "username")
            or pick(user, "username")
            or pick(r, "userId", default="")
        ),
        "ip": s(pick(r, "ipAddress", "client_ip", default="")),
        "client": s(pick(r, "clientId") or pick(context, "application", "client_id",
                                                default="")),
        "error": s(pick(r, "error") or pick(context, "message", default=""), 200),
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
    """
    try:
        limit = max(1, min(int(max_results), MAX_EVENTS))
        if _is_keycloak(conn):
            params: dict[str, Any] = {"max": limit}
            if event_type:
                params["type"] = event_type.upper()
            if user:
                params["user"] = user
        else:
            params = {"page_size": limit}
            if event_type:
                params["action"] = event_type.lower()
            if user:
                params["username"] = user
        rows = conn.platform.rows(conn.get(conn.path("events"), params=params))
        events = [norm_event(r) for r in rows]
        return {"total": len(events), "events": events}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def failed_login_events(conn: Any, max_results: int = MAX_EVENTS) -> list[dict]:
    """[READ] Recent failed-login events (the login-failure RCA feed)."""
    fail_type = "LOGIN_ERROR" if _is_keycloak(conn) else "login_failed"
    out = login_events(conn, event_type=fail_type, max_results=max_results)
    return out.get("events", []) if "error" not in out else []


def admin_events(conn: Any, max_results: int = 200) -> dict:
    """[READ] Recent admin/config-change events, normalized.

    Keycloak has a dedicated admin-events feed; authentik's single feed is
    post-filtered to admin-flavoured actions (model_created/updated/deleted...).
    """
    try:
        limit = max(1, min(int(max_results), MAX_EVENTS))
        if _is_keycloak(conn):
            rows = conn.platform.rows(
                conn.get(conn.path("admin_events"), params={"max": limit})
            )
            events = [
                {
                    "time": s(pick(r, "time", default="")),
                    "operation": s(pick(r, "operationType", default="")),
                    "resourceType": s(pick(r, "resourceType", default="")),
                    "resourcePath": s(pick(r, "resourcePath", default="")),
                    "actor": s(pick(as_obj(r.get("authDetails")), "userId", default="")),
                    "ip": s(pick(as_obj(r.get("authDetails")), "ipAddress", default="")),
                }
                for r in rows
            ]
        else:
            rows = conn.platform.rows(
                conn.get(conn.path("admin_events"), params={"page_size": limit})
            )
            events = [
                {
                    "time": s(pick(r, "created", default="")),
                    "operation": s(pick(r, "action", default="")),
                    "resourceType": s(
                        pick(as_obj(as_obj(r.get("context")).get("model")), "model_name",
                             default="")
                    ),
                    "resourcePath": s(
                        pick(as_obj(as_obj(r.get("context")).get("model")), "name",
                             default="")
                    ),
                    "actor": s(pick(as_obj(r.get("user")), "username", default="")),
                    "ip": s(pick(r, "client_ip", default="")),
                }
                for r in rows
                if str(pick(r, "action", default="")).lower() in _AUTHENTIK_ADMIN_ACTIONS
            ]
        return {"total": len(events), "events": events}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}
