"""OAuth/OIDC client (application) reads (read-only).

Keycloak's ``clients`` and authentik's ``providers/oauth2`` carry the same
security-relevant client configuration — redirect URIs, public/confidential
type, enabled grant flows — under different names; both are reconciled to one
normalized client row the misconfiguration audit consumes. Nothing here
mutates a client — redirect-URI updates and secret rotation live in
:mod:`identity_aiops.ops.writes`.
"""

from __future__ import annotations

from typing import Any

from identity_aiops.ops._util import as_obj, num, pick, s, to_bool
from identity_aiops.platform import KEYCLOAK


def _is_keycloak(conn: Any) -> bool:
    return conn.target.platform == KEYCLOAK


def redirect_uris(r: dict) -> list[str]:
    """Extract a client's redirect URIs across all platform shapes.

    Keycloak: ``redirectUris`` (list of strings). authentik: ``redirect_uris``
    — historically a newline-joined string, since 2024.2 a list of
    ``{matching_mode, url}`` objects. All three shapes fold to a list of
    bounded, sanitised strings.
    """
    raw = pick(r, "redirectUris", "redirect_uris", default=[])
    uris: list[str] = []
    if isinstance(raw, str):
        uris = [line.strip() for line in raw.splitlines() if line.strip()]
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                uris.append(str(pick(item, "url", default="")))
            else:
                uris.append(str(item))
    return [s(u, 200) for u in uris if u]


def norm_client(r: dict) -> dict:
    """Normalise one client/provider row across Keycloak / authentik."""
    attrs = as_obj(r.get("attributes"))
    public = (
        to_bool(r.get("publicClient"))
        if "publicClient" in r
        else str(r.get("client_type") or "").lower() == "public"
    )
    return {
        "id": s(pick(r, "id", "pk")),
        "clientId": s(pick(r, "clientId", "client_id", default="")),
        "name": s(pick(r, "name", default="")),
        "enabled": to_bool(pick(r, "enabled", default=True)),
        "protocol": s(pick(r, "protocol", default="openid-connect")),
        "publicClient": public,
        "redirectUris": redirect_uris(r),
        "implicitFlow": to_bool(pick(r, "implicitFlowEnabled", default=False)),
        "directAccessGrants": to_bool(pick(r, "directAccessGrantsEnabled", default=False)),
        "serviceAccounts": to_bool(pick(r, "serviceAccountsEnabled", default=False)),
        "secretConfigured": bool(pick(r, "secret", "client_secret", default="")),
        "pkceMethod": s(pick(attrs, "pkce.code.challenge.method", default="")),
    }


def list_clients(conn: Any, max_results: int = 200) -> dict:
    """[READ] OAuth/OIDC clients in the realm, normalized.

    Keycloak lists realm clients; authentik lists OAuth2 providers (where the
    client configuration lives).
    """
    try:
        limit = max(1, int(max_results))
        params = {"max": limit} if _is_keycloak(conn) else {"page_size": limit}
        rows = conn.platform.rows(conn.get(conn.path("clients"), params=params))
        clients = [norm_client(r) for r in rows]
        return {"total": len(clients), "clients": clients}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def client_detail(conn: Any, client_id: str) -> dict:
    """[READ] One client's full normalized detail by internal id/pk."""
    try:
        raw = as_obj(conn.platform.normalise(conn.get(conn.path("client_get",
                                                                client_id=client_id))))
        detail = norm_client(raw)
        detail["id"] = detail["id"] or s(client_id)
        return detail
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200), "id": s(client_id)}


def client_sessions(conn: Any, client_id: str, max_results: int = 200) -> dict:
    """[READ] Active user sessions on one client (Keycloak).

    authentik has no per-provider session listing; the platform map raises a
    teaching error that surfaces here as ``{"error": ...}``.
    """
    try:
        limit = max(1, int(max_results))
        rows = conn.platform.rows(
            conn.get(conn.path("client_sessions", client_id=client_id),
                     params={"max": limit})
        )
        sessions = [
            {
                "id": s(pick(r, "id", "uuid")),
                "username": s(pick(r, "username", default="")),
                "ip": s(pick(r, "ipAddress", default="")),
                "started": s(pick(r, "start", default="")),
                "lastAccess": s(pick(r, "lastAccess", default="")),
            }
            for r in rows
        ]
        return {"clientId": s(client_id), "total": len(sessions), "sessions": sessions}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200), "clientId": s(client_id)}


def client_session_stats(conn: Any) -> dict:
    """[READ] Active-session counts per client (Keycloak client-session-stats).

    authentik has no per-client session rollup; the platform map raises a
    teaching error that surfaces here as ``{"error": ...}``.
    """
    try:
        rows = conn.platform.rows(conn.get(conn.path("client_session_stats")))
        stats = [
            {
                "clientId": s(pick(r, "clientId", "id", default="")),
                "activeSessions": int(num(pick(r, "active", default=0))),
                "offlineSessions": int(num(pick(r, "offline", default=0))),
            }
            for r in rows
        ]
        stats.sort(key=lambda x: x["activeSessions"], reverse=True)
        return {"total": len(stats), "clients": stats}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}
