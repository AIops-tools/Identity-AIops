"""Connection management for identity providers (Keycloak + authentik).

Thin httpx wrapper with per-target session reuse and two auth flows, selected
by the target's :class:`~identity_aiops.platform.Platform` descriptor:

  * **client-credentials** (Keycloak) — the stored *client secret* (paired with
    the target's ``client_id``) is exchanged lazily at the realm token endpoint
    (``/realms/{realm}/protocol/openid-connect/token``,
    ``grant_type=client_credentials``) for a short-lived access token attached
    per request as ``Authorization: Bearer``. Access tokens expire (~1 min–1 h
    depending on realm settings); a 401 mid-session is treated as expiry — the
    token is dropped, re-fetched once, and the request retried.
  * **static-bearer** (authentik) — the stored long-lived API token is carried
    on every request as ``Authorization: Bearer``.

Ops modules never hard-code a path or a payload key: they ask
``conn.path("users")`` for the concrete URL (the target's realm is injected
automatically) and ``conn.platform.rows()`` to unwrap a list payload, so the
same op works on both identity providers.

All non-2xx responses are translated centrally into ``IdentityApiError`` with a
teaching message — HTTP errors are translated at the connection layer rather
than leaking raw tracebacks. The httpx client is injectable for tests: pass
``client=`` a mock implementing ``request`` / ``close``.
"""

from __future__ import annotations

import atexit
import base64
import json
import logging
import weakref
from typing import Any

import httpx

from identity_aiops.config import AppConfig, TargetConfig, load_config

_log = logging.getLogger("identity-aiops.connection")

_TIMEOUT = 30.0

# Every live ConnectionManager registers here (weakly) so the atexit hook can
# close any cached httpx clients when the interpreter shuts down.
_MANAGERS: weakref.WeakSet = weakref.WeakSet()


def _close_all_managers() -> None:
    """atexit hook: close every cached httpx client. Idempotent and error-safe —
    close failures are logged, never raised (raising at interpreter exit only
    obscures the real shutdown path)."""
    for mgr in list(_MANAGERS):
        try:
            mgr.disconnect_all()
        except Exception:  # noqa: BLE001 — never raise at interpreter exit
            _log.debug("Error closing cached connections at exit", exc_info=True)


atexit.register(_close_all_managers)


class IdentityApiError(Exception):
    """An IdP REST API call failed; carries a teaching message + status."""

    def __init__(self, message: str, *, status_code: int | None = None, path: str = "") -> None:
        self.status_code = status_code
        self.path = path
        super().__init__(message)


def _teaching_message(status: int, path: str, body: str, label: str) -> str:
    """Map a non-2xx status to an actionable, teaching error message."""
    snippet = body[:200].strip()
    if status in (401, 403):
        return (
            f"Authentication/authorization failed ({status}) on {label} {path}. "
            f"Check the stored credential ('identity-aiops secret set <target>') "
            f"and that it has admin API access (Keycloak: a confidential client "
            f"with service account + realm-admin roles; authentik: an API token "
            f"for a user with admin permissions). {snippet}"
        )
    if status == 404:
        return (
            f"Resource not found (404) on {label} {path}. The id may be stale — "
            f"list the parent collection first to get a current id, and check "
            f"the configured realm name. {snippet}"
        )
    if status == 429:
        return (
            f"Rate limited (429) on {label} {path}. Back off and retry after "
            f"the Retry-After delay. {snippet}"
        )
    if status in (400, 409, 422):
        return (
            f"Validation error ({status}) on {label} {path}. The IdP rejected "
            f"the request body — check required fields and value formats. {snippet}"
        )
    if status in (500, 502, 503, 504):
        return (
            f"{label} server error ({status}) on {path}. The identity provider "
            f"may be busy; retry shortly. {snippet}"
        )
    return f"{label} API error ({status}) on {path}. {snippet}"


class IdentityConnection:
    """A single authenticated session against one Keycloak or authentik target."""

    def __init__(self, target: TargetConfig, client: Any | None = None) -> None:
        self._target = target
        self._access_token: str | None = None
        headers = {"Accept": "application/json"}
        if not target.platform_obj.uses_client_credentials:
            # Static bearer (authentik): the long-lived token rides every call.
            headers["Authorization"] = f"Bearer {target.secret}"
        self._client = client or httpx.Client(
            base_url=target.base_url,
            verify=target.verify_ssl,
            timeout=_TIMEOUT,
            headers=headers,
        )

    @property
    def target(self) -> TargetConfig:
        return self._target

    @property
    def platform(self) -> Any:
        return self._target.platform_obj

    def path(self, resource: str, **fmt: Any) -> str:
        """Concrete REST path for ``resource`` with the target's realm injected.

        Every substituted value (realm included) is URL-encoded centrally in
        ``Platform.path``.
        """
        return self.platform.path(resource, realm=self._target.realm, **fmt)

    # ── client-credentials flow (Keycloak) ───────────────────────────────────
    def _fetch_access_token(self) -> str:
        """Exchange client_id + client secret for a short-lived access token."""
        platform = self._target.platform_obj
        token_path = platform.token_url(self._target.realm)
        if not self._target.username:
            raise IdentityApiError(
                f"Target '{self._target.name}' has no client_id configured — the "
                f"{platform.label} client-credentials grant needs one. Re-run "
                f"'identity-aiops init' or add 'username: <client_id>' in config.yaml.",
                path=token_path,
            )
        try:
            resp = self._client.request(
                "POST",
                token_path,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._target.username,
                    "client_secret": self._target.secret,
                },
            )
        except httpx.HTTPError as exc:
            raise IdentityApiError(
                f"Could not reach {platform.label} at {self._target.base_url} for "
                f"a token (POST {token_path}): {exc}. Check the base URL, the "
                f"realm name, and that the IdP is reachable.",
                path=token_path,
            ) from exc
        if not (200 <= resp.status_code < 300):
            raise IdentityApiError(
                f"Token request failed ({resp.status_code}) on {platform.label} "
                f"{token_path}. Check the client_id / client secret "
                f"('identity-aiops secret set {self._target.name}'), that the "
                f"client is confidential with service accounts enabled, and that "
                f"its service account holds realm-admin roles. "
                f"{resp.text[:200].strip()}",
                status_code=resp.status_code,
                path=token_path,
            )
        body = self._parse(resp)
        token = body.get("access_token") if isinstance(body, dict) else None
        if not token:
            raise IdentityApiError(
                f"{platform.label} token response carried no 'access_token' field "
                f"(POST {token_path}) — is the base URL pointing at the IdP, not "
                f"a proxy login page?",
                path=token_path,
            )
        return str(token)

    def self_user_id(self) -> str | None:
        """Return the user id this connection's own credential belongs to.

        Used to refuse operations that would lock the tool out of its own undo —
        disabling the account whose token you are holding revokes your ability to
        re-enable it. Verified the hard way against a live authentik: the disable
        succeeded, and the undo then failed 403.

        Keycloak authenticates as a service account via client_credentials, so the
        identity is the access token's ``sub`` claim — no extra request. authentik
        exposes ``/core/users/me/``. Returns ``None`` when it cannot be determined;
        callers must treat that as "unknown", never as "not me".
        """
        platform = self._target.platform_obj
        try:
            if platform.name == "authentik":
                body = self.get(platform.path("self_user"))
                if isinstance(body, dict):
                    user = body.get("user") if isinstance(body.get("user"), dict) else body
                    pk = user.get("pk") if isinstance(user, dict) else None
                    return str(pk) if pk is not None else None
                return None
            token = self._ensure_access_token()
            payload = token.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
            sub = claims.get("sub")
            return str(sub) if sub else None
        except Exception:  # noqa: BLE001 — unknown identity, never a false "not me"
            return None

    def _ensure_access_token(self) -> str:
        if self._access_token is None:
            self._access_token = self._fetch_access_token()
        return self._access_token

    def _token_request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Issue a token-authenticated request, refreshing once on a 401.

        Access tokens are short-lived; a 401 mid-session is treated as expiry —
        the token is dropped, re-fetched once, and the request retried. A
        second 401 surfaces via the normal error path.
        """
        headers = dict(kwargs.pop("headers", None) or {})
        headers["Authorization"] = f"Bearer {self._ensure_access_token()}"
        resp = self._client.request(method, path, headers=headers, **kwargs)
        if getattr(resp, "status_code", None) == 401:
            self._access_token = None
            headers["Authorization"] = f"Bearer {self._ensure_access_token()}"
            resp = self._client.request(method, path, headers=headers, **kwargs)
        return resp

    # ── request core ─────────────────────────────────────────────────────────
    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        platform = self._target.platform_obj
        try:
            if platform.uses_client_credentials:
                resp = self._token_request(method, path, **kwargs)
            else:
                resp = self._client.request(method, path, **kwargs)
        except IdentityApiError:
            raise
        except httpx.HTTPError as exc:
            raise IdentityApiError(
                f"Could not reach {platform.label} at {self._target.base_url} "
                f"({method} {path}): {exc}. Check the base URL and reachability.",
                path=path,
            ) from exc
        if not (200 <= resp.status_code < 300):
            raise IdentityApiError(
                _teaching_message(resp.status_code, path, resp.text, platform.label),
                status_code=resp.status_code,
                path=path,
            )
        return self._parse(resp)

    @staticmethod
    def _parse(resp: Any) -> Any:
        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            return {}

    def get(self, path: str, **kwargs: Any) -> Any:
        return self._request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Any:
        return self._request("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> Any:
        return self._request("PUT", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> Any:
        return self._request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Any:
        return self._request("DELETE", path, **kwargs)

    def close(self) -> None:
        self._client.close()


class ConnectionManager:
    """Manages connections to multiple IdP targets with session reuse."""

    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._connections: dict[str, IdentityConnection] = {}
        _MANAGERS.add(self)

    @classmethod
    def from_config(cls, config: AppConfig | None = None) -> ConnectionManager:
        cfg = config or load_config()
        return cls(cfg)

    def connect(self, target_name: str | None = None) -> IdentityConnection:
        target = (
            self._config.get_target(target_name)
            if target_name
            else self._config.default_target
        )
        cached = self._connections.get(target.name)
        if cached is not None:
            return cached
        conn = IdentityConnection(target)
        self._connections[target.name] = conn
        return conn

    def disconnect(self, target_name: str) -> None:
        conn = self._connections.pop(target_name, None)
        if conn is not None:
            conn.close()

    def disconnect_all(self) -> None:
        for name in list(self._connections):
            self.disconnect(name)

    def list_targets(self) -> list[str]:
        return [t.name for t in self._config.targets]

    def list_connected(self) -> list[str]:
        return list(self._connections.keys())
