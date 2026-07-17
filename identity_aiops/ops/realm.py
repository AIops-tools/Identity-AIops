"""Realm / system reads — realm settings and identity providers (read-only).

The "how is this IdP configured?" surface. Keycloak returns the realm
representation (password policy, brute-force protection); authentik has no
realms, so its admin/system endpoint stands in — the normalized row keeps the
shared keys and degrades gracefully where a concept does not exist.
"""

from __future__ import annotations

from typing import Any

from identity_aiops.ops._util import as_obj, pick, s, to_bool
from identity_aiops.platform import KEYCLOAK


def _is_keycloak(conn: Any) -> bool:
    return conn.target.platform == KEYCLOAK


def realm_info(conn: Any) -> dict:
    """[READ] Realm / instance settings relevant to identity hygiene."""
    try:
        raw = as_obj(conn.platform.normalise(conn.get(conn.path("realm_info"))))
        if _is_keycloak(conn):
            return {
                "platform": conn.target.platform,
                "realm": s(pick(raw, "realm", default=conn.target.realm)),
                "enabled": to_bool(pick(raw, "enabled", default=True)),
                "bruteForceProtected": to_bool(pick(raw, "bruteForceProtected",
                                                    default=False)),
                "passwordPolicy": s(pick(raw, "passwordPolicy", default="")),
                "otpPolicyType": s(pick(raw, "otpPolicyType", default="")),
                "sslRequired": s(pick(raw, "sslRequired", default="")),
                "registrationAllowed": to_bool(pick(raw, "registrationAllowed",
                                                    default=False)),
            }
        runtime = as_obj(raw.get("runtime"))
        return {
            "platform": conn.target.platform,
            "realm": s(conn.target.realm),
            "enabled": True,
            "version": s(pick(runtime, "authentik_version") or pick(raw, "version",
                                                                    default="")),
            "environment": s(pick(runtime, "environment", default="")),
            "httpIsSecure": to_bool(pick(raw, "http_is_secure", default=True)),
        }
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}


def list_identity_providers(conn: Any) -> dict:
    """[READ] Federated identity providers / sources configured on the IdP."""
    try:
        rows = conn.platform.rows(conn.get(conn.path("identity_providers")))
        idps = [
            {
                "id": s(pick(r, "internalId", "pk", "alias", default="")),
                "name": s(pick(r, "alias", "slug", "name", default="")),
                "type": s(pick(r, "providerId", "verbose_name", default="")),
                "enabled": to_bool(pick(r, "enabled", default=True)),
            }
            for r in rows
        ]
        return {"total": len(idps), "identityProviders": idps}
    except Exception as exc:  # noqa: BLE001 — report as partial
        return {"error": s(exc, 200)}
