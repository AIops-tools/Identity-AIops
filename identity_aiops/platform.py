"""Platform descriptors — the identity providers identity-aiops speaks to.

identity-aiops is multi-platform by construction. A registry maps a *platform
name* to a :class:`Platform` descriptor that captures everything the connection
and ops layers need to talk to that identity provider: how it authenticates,
the concrete REST path for each *logical resource*, and how a raw response is
normalised (injection-safe). Because Keycloak and authentik expose the same
identity concepts behind very different URLs and auth schemes, the ops modules
ask the platform for a path (``conn.path("users")``) and for the row list of a
payload (``conn.platform.rows(payload)``) instead of hard-coding either — so
the same tool works on both.

v0.1 registers two platforms:

  * **keycloak** — Keycloak admin REST API (``/admin/realms/{realm}/...``).
    Auth is an OAuth2 *client-credentials* grant against the realm token
    endpoint (``/realms/{realm}/protocol/openid-connect/token``); the
    short-lived access token is attached per request as a Bearer header and
    refreshed once on a 401.
  * **authentik** — authentik API v3 (``/api/v3/...``) with a long-lived API
    token presented as a static Bearer header.

Additional identity providers can ``register`` their own descriptor later
without touching the ops / CLI / MCP layers — a registry keyed by ``platform``
name.

The concrete REST paths below are modelled from each project's public API and
are exercised against mocked HTTP responses only; see the README's preview note.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from identity_aiops.governance import sanitize


def _seg(value: Any) -> str:
    """URL-encode one path/query value so agent-supplied identifiers (user ids,
    client ids, realm names) cannot smuggle ``/``, ``../`` or query
    metacharacters into the request URL."""
    return quote(str(value), safe="")

# ─── registered platform names ──────────────────────────────────────────────
KEYCLOAK = "keycloak"
AUTHENTIK = "authentik"
PLATFORMS = (KEYCLOAK, AUTHENTIK)

# Auth flows.
AUTH_FLOW_CLIENT_CREDENTIALS = "client-credentials"  # nosec B105 — flow name, not a secret
AUTH_FLOW_STATIC = "static-bearer"  # long-lived API token as Bearer header

# Bounds for the response normaliser (defensive against a hostile IdP).
_MAX_STR = 512
_MAX_DEPTH = 8

# Keys under which each platform wraps a list payload, tried in order before
# falling back to a bare JSON array (Keycloak lists are bare arrays; authentik
# wraps under ``results``).
_LIST_KEYS = ("results", "rows", "data", "items")


def _sanitize_obj(obj: Any, depth: int = 0) -> Any:
    """Recursively fold IdP-returned JSON into injection-safe values.

    Every string leaf passes through ``sanitize`` (bounded length); numbers,
    booleans and ``None`` pass through unchanged. Depth is capped so a
    pathological nesting cannot exhaust the stack.
    """
    if depth > _MAX_DEPTH:
        return None
    if isinstance(obj, dict):
        return {str(k): _sanitize_obj(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize_obj(v, depth + 1) for v in obj]
    if isinstance(obj, str):
        return sanitize(obj, _MAX_STR)
    return obj


@dataclass(frozen=True)
class Platform:
    """An IdP's API shape: auth flow + logical-resource path map + normaliser."""

    name: str
    label: str
    auth_flow: str
    paths: dict[str, str] = field(default_factory=dict)
    token_path: str = ""  # nosec B105 — path template, not a secret
    default_page_size: int = 200

    @property
    def uses_client_credentials(self) -> bool:
        return self.auth_flow == AUTH_FLOW_CLIENT_CREDENTIALS

    def path(self, resource: str, **fmt: Any) -> str:
        """Return the concrete REST path for a logical ``resource``.

        Raises a teaching ``KeyError`` when the resource is not mapped for this
        platform (so a caller asking for an unsupported surface fails fast with
        the list of what *is* available, rather than hitting a confusing 404).

        Every substituted value is URL-encoded (``quote(..., safe="")``) so an
        agent-supplied identifier can never rewrite the path (e.g. via ``../``).
        Unused format keys are ignored, which lets callers always pass
        ``realm=...`` even for platforms whose templates don't use it.
        """
        try:
            template = self.paths[resource]
        except KeyError as exc:
            available = ", ".join(sorted(self.paths)) or "(none)"
            raise KeyError(
                f"Resource '{resource}' is not mapped for platform '{self.name}'. "
                f"Mapped resources: {available}."
            ) from exc
        if not fmt:
            return template
        return template.format(**{k: _seg(v) for k, v in fmt.items()})

    def token_url(self, realm: str) -> str:
        """The token-endpoint path for the client-credentials flow (realm-scoped)."""
        return self.token_path.format(realm=_seg(realm))

    def supports(self, resource: str) -> bool:
        return resource in self.paths

    def rows(self, payload: Any) -> list[dict]:
        """Normalise a list payload to a sanitised list of dict rows.

        A bare JSON array passes through (Keycloak); a dict is unwrapped via
        the first of ``results``/``rows``/``data``/``items`` that is present
        (authentik envelopes under ``results``). Every row is run through the
        injection-safe normaliser.
        """
        if isinstance(payload, dict):
            items: Any = []
            for key in _LIST_KEYS:
                value = payload.get(key)
                if isinstance(value, list):
                    items = value
                    break
        else:
            items = payload
        return [_sanitize_obj(r) for r in (items or []) if isinstance(r, dict)]

    def normalise(self, payload: Any) -> Any:
        """Return an injection-safe copy of a raw response payload."""
        return _sanitize_obj(payload)


# ─── registry ───────────────────────────────────────────────────────────────
_REGISTRY: dict[str, Platform] = {}


def register(platform: Platform) -> None:
    """Register a platform descriptor under its name (idempotent overwrite)."""
    _REGISTRY[platform.name] = platform


def get_platform(name: str) -> Platform:
    """Return the descriptor for ``name`` or raise with the registered names."""
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        available = ", ".join(sorted(_REGISTRY)) or "(none)"
        raise ValueError(
            f"Unknown platform '{name}'. Registered platforms: {available}."
        ) from exc


def platform_names() -> tuple[str, ...]:
    """All registered platform names (sorted)."""
    return tuple(sorted(_REGISTRY))


# ─── Keycloak (admin REST /admin/realms/{realm}/..., client-credentials) ─────
_KEYCLOAK_PATHS = {
    # realm / system
    "realm_info": "/admin/realms/{realm}",
    "identity_providers": "/admin/realms/{realm}/identity-provider/instances",
    # users
    "users": "/admin/realms/{realm}/users",
    "user_get": "/admin/realms/{realm}/users/{user_id}",
    "user_count": "/admin/realms/{realm}/users/count",
    "user_sessions": "/admin/realms/{realm}/users/{user_id}/sessions",
    "user_credentials": "/admin/realms/{realm}/users/{user_id}/credentials",
    "user_groups": "/admin/realms/{realm}/users/{user_id}/groups",
    "user_update": "/admin/realms/{realm}/users/{user_id}",
    "user_logout": "/admin/realms/{realm}/users/{user_id}/logout",
    "user_lockout": "/admin/realms/{realm}/attack-detection/brute-force/users/{user_id}",
    # groups
    "groups": "/admin/realms/{realm}/groups",
    "group_members": "/admin/realms/{realm}/groups/{group_id}/members",
    # events
    "events": "/admin/realms/{realm}/events",
    "admin_events": "/admin/realms/{realm}/admin-events",
    # clients
    "clients": "/admin/realms/{realm}/clients",
    "client_get": "/admin/realms/{realm}/clients/{client_id}",
    "client_update": "/admin/realms/{realm}/clients/{client_id}",
    "client_sessions": "/admin/realms/{realm}/clients/{client_id}/user-sessions",
    "client_session_stats": "/admin/realms/{realm}/client-session-stats",
    "client_secret": "/admin/realms/{realm}/clients/{client_id}/client-secret",  # nosec B105
}

# ─── authentik (API v3 /api/v3/..., static Bearer token) ─────────────────────
_AUTHENTIK_PATHS = {
    # system (authentik has no realms; the admin/system surface stands in)
    "realm_info": "/api/v3/admin/system/",
    "identity_providers": "/api/v3/sources/all/",
    # users
    "users": "/api/v3/core/users/",
    "user_get": "/api/v3/core/users/{user_id}/",
    "user_count": "/api/v3/core/users/",
    "user_sessions": "/api/v3/core/authenticated_sessions/?user={user_id}",
    "sessions": "/api/v3/core/authenticated_sessions/",
    "user_credentials": "/api/v3/authenticators/admin/all/?user={user_id}",
    "user_update": "/api/v3/core/users/{user_id}/",
    "session_delete": "/api/v3/core/authenticated_sessions/{session_id}/",
    # groups
    "groups": "/api/v3/core/groups/",
    "group_members": "/api/v3/core/groups/{group_id}/",
    # events (single feed; ops filter by action)
    "events": "/api/v3/events/events/",
    "admin_events": "/api/v3/events/events/",
    # clients: the OAuth2 provider carries the client config (redirect URIs,
    # client type); applications are the launcher shells around providers.
    "clients": "/api/v3/providers/oauth2/",
    "client_get": "/api/v3/providers/oauth2/{client_id}/",
    "client_update": "/api/v3/providers/oauth2/{client_id}/",
    "applications": "/api/v3/core/applications/",
}


register(
    Platform(
        name=KEYCLOAK,
        label="Keycloak admin REST API",
        auth_flow=AUTH_FLOW_CLIENT_CREDENTIALS,
        paths=_KEYCLOAK_PATHS,
        token_path="/realms/{realm}/protocol/openid-connect/token",  # nosec B106
        default_page_size=200,
    )
)
register(
    Platform(
        name=AUTHENTIK,
        label="authentik API v3",
        auth_flow=AUTH_FLOW_STATIC,
        paths=_AUTHENTIK_PATHS,
        default_page_size=200,
    )
)


__all__ = [
    "KEYCLOAK",
    "AUTHENTIK",
    "PLATFORMS",
    "AUTH_FLOW_CLIENT_CREDENTIALS",
    "AUTH_FLOW_STATIC",
    "Platform",
    "register",
    "get_platform",
    "platform_names",
]
