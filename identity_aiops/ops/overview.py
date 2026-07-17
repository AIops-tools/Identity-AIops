"""One-shot identity-estate overview (read-only).

A single call an operator can lead with: platform + realm, user / client /
identity-provider counts, and the size of the recent failed-login feed.
Resilient — a failing sub-call degrades to a partial summary with an
``errors`` list.
"""

from __future__ import annotations

from typing import Any

from identity_aiops.ops import clients as client_ops
from identity_aiops.ops import events as event_ops
from identity_aiops.ops import realm as realm_ops
from identity_aiops.ops import users as user_ops


def identity_overview(conn: Any) -> dict:
    """[READ] Summary: platform/realm + user/client/IdP counts + failed logins."""
    errors: list[str] = []

    info = realm_ops.realm_info(conn)
    if "error" in info:
        errors.append(f"realm: {info['error']}")
        info = {}

    uc = user_ops.user_count(conn)
    count = uc.get("count") if "error" not in uc else None
    if "error" in uc:
        errors.append(f"users: {uc['error']}")

    cl = client_ops.list_clients(conn)
    client_total = cl.get("total") if "error" not in cl else None
    public_clients = (
        sum(1 for c in cl.get("clients", []) if c.get("publicClient"))
        if "error" not in cl
        else None
    )
    if "error" in cl:
        errors.append(f"clients: {cl['error']}")

    idps = realm_ops.list_identity_providers(conn)
    idp_total = idps.get("total") if "error" not in idps else None
    if "error" in idps:
        errors.append(f"identityProviders: {idps['error']}")

    failed = event_ops.failed_login_events(conn, max_results=200)

    return {
        "platform": conn.target.platform,
        "target": conn.target.name,
        "realm": conn.target.realm,
        "bruteForceProtected": info.get("bruteForceProtected"),
        "passwordPolicy": info.get("passwordPolicy"),
        "userCount": count,
        "clientCount": client_total,
        "publicClients": public_clients,
        "identityProviderCount": idp_total,
        "recentFailedLogins": len(failed),
        "errors": errors,
    }
