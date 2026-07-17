"""Platform registry + connection wiring (Keycloak + authentik), config dispatch.

No real IdP is needed — the httpx client is injected. Proves the registry maps
each platform name to its API shape, path templates format (realm injected,
segments URL-encoded), list payloads unwrap across both response conventions,
and the connection runs the right auth flow: Keycloak exchanges the client
secret for a token via client-credentials and refreshes once on a 401;
authentik sends a static Bearer header.
"""

import pytest

from identity_aiops.config import TargetConfig
from identity_aiops.connection import IdentityApiError, IdentityConnection
from identity_aiops.platform import (
    AUTHENTIK,
    KEYCLOAK,
    get_platform,
    platform_names,
)


@pytest.mark.unit
def test_both_platforms_registered():
    assert set(platform_names()) == {KEYCLOAK, AUTHENTIK}
    assert get_platform(KEYCLOAK).uses_client_credentials
    assert not get_platform(AUTHENTIK).uses_client_credentials


@pytest.mark.unit
def test_unknown_platform_raises_with_registered_names():
    with pytest.raises(ValueError, match="keycloak"):
        get_platform("okta")


@pytest.mark.unit
def test_path_templates_differ_per_platform():
    kc = get_platform(KEYCLOAK)
    ak = get_platform(AUTHENTIK)
    assert kc.path("users", realm="master") == "/admin/realms/master/users"
    assert ak.path("users", realm="master") == "/api/v3/core/users/"
    assert kc.path("user_get", realm="r1", user_id="u1").endswith("/r1/users/u1")
    assert ak.path("user_get", realm="r1", user_id="42") == "/api/v3/core/users/42/"


@pytest.mark.unit
def test_keycloak_token_url_is_realm_scoped():
    kc = get_platform(KEYCLOAK)
    assert kc.token_url("prod") == "/realms/prod/protocol/openid-connect/token"
    # realm names are URL-encoded too
    assert "%2F" in kc.token_url("a/b")


@pytest.mark.unit
def test_unmapped_resource_raises_teaching_keyerror():
    with pytest.raises(KeyError, match="not mapped"):
        get_platform(AUTHENTIK).path("client_secret", client_id="c1")


@pytest.mark.unit
def test_rows_unwraps_both_conventions_and_bare_array():
    kc = get_platform(KEYCLOAK)
    assert kc.rows([{"a": 1}, {"a": 2}]) == [{"a": 1}, {"a": 2}]  # bare (Keycloak)
    assert kc.rows({"results": [{"b": 3}]}) == [{"b": 3}]  # authentik envelope
    assert kc.rows({"data": [{"c": 4}]}) == [{"c": 4}]
    assert kc.rows({"nope": 1}) == []


@pytest.mark.unit
def test_rows_sanitizes_strings():
    out = get_platform(AUTHENTIK).rows({"results": [{"x": "ok", "n": 5}]})
    assert out[0]["x"] == "ok" and out[0]["n"] == 5


class _Resp:
    def __init__(self, status, payload=None, content=b"{}", text="body"):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.content = content
        self.text = text

    def json(self):
        return self._payload


class _Client:
    """Scripted fake httpx client recording every request."""

    def __init__(self, script):
        # script: callable(method, path, kwargs) -> _Resp
        self._script = script
        self.calls = []

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        return self._script(method, path, kwargs)

    def close(self):
        pass


def _kc_target(monkeypatch, name="sso1"):
    monkeypatch.setenv(f"IDENTITY_{name.upper()}_SECRET", "kc-client-secret")
    return TargetConfig(name=name, platform=KEYCLOAK, base_url="https://kc.local",
                        realm="master", username="agent-client")


@pytest.mark.unit
def test_keycloak_client_credentials_token_flow(monkeypatch):
    """First call exchanges the secret for a token, then the API call carries
    the Bearer header."""
    target = _kc_target(monkeypatch)

    def script(method, path, kwargs):
        if path.endswith("/protocol/openid-connect/token"):
            assert method == "POST"
            assert kwargs["data"]["grant_type"] == "client_credentials"
            assert kwargs["data"]["client_id"] == "agent-client"
            assert kwargs["data"]["client_secret"] == "kc-client-secret"
            return _Resp(200, {"access_token": "tok-1"})
        assert kwargs["headers"]["Authorization"] == "Bearer tok-1"
        return _Resp(200, [{"id": "u1"}])

    client = _Client(script)
    conn = IdentityConnection(target, client=client)
    out = conn.get(conn.path("users"))
    assert out[0]["id"] == "u1"
    assert client.calls[0][1].endswith("/realms/master/protocol/openid-connect/token")


@pytest.mark.unit
def test_keycloak_refreshes_token_once_on_401(monkeypatch):
    """A mid-session 401 drops the token, re-fetches once, and retries."""
    target = _kc_target(monkeypatch)
    state = {"tokens": 0}

    def script(method, path, kwargs):
        if path.endswith("/token"):
            state["tokens"] += 1
            return _Resp(200, {"access_token": f"tok-{state['tokens']}"})
        if kwargs["headers"]["Authorization"] == "Bearer tok-1":
            return _Resp(401, text="expired")
        return _Resp(200, [{"id": "u1"}])

    conn = IdentityConnection(target, client=_Client(script))
    out = conn.get(conn.path("users"))
    assert out[0]["id"] == "u1"
    assert state["tokens"] == 2  # initial fetch + one refresh


@pytest.mark.unit
def test_keycloak_token_failure_is_teaching(monkeypatch):
    target = _kc_target(monkeypatch)
    conn = IdentityConnection(
        target, client=_Client(lambda m, p, k: _Resp(401, text="invalid_client"))
    )
    with pytest.raises(IdentityApiError, match="client_id / client secret"):
        conn.get(conn.path("users"))


@pytest.mark.unit
def test_keycloak_missing_client_id_is_teaching(monkeypatch):
    monkeypatch.setenv("IDENTITY_SSO2_SECRET", "s")
    target = TargetConfig(name="sso2", platform=KEYCLOAK, base_url="https://kc.local")
    conn = IdentityConnection(target, client=_Client(lambda m, p, k: _Resp(200)))
    with pytest.raises(IdentityApiError, match="no client_id"):
        conn.get(conn.path("users"))


@pytest.mark.unit
def test_authentik_uses_static_bearer_header(monkeypatch):
    monkeypatch.setenv("IDENTITY_AK1_SECRET", "ak-token-xyz")
    target = TargetConfig(name="ak1", platform=AUTHENTIK, base_url="https://ak.local/")
    calls = []

    class _Probe:
        def request(self, method, path, **kwargs):
            calls.append(path)
            return _Resp(200, {"results": []})

        def close(self):
            pass

    conn = IdentityConnection(target, client=_Probe())
    conn.get(conn.path("users"))
    # No token endpoint was hit — the Bearer token is static (client headers).
    assert calls == ["/api/v3/core/users/"]
    # And a REAL client construction would carry the Authorization header:
    real = IdentityConnection(target)
    try:
        assert real._client.headers["Authorization"] == "Bearer ak-token-xyz"
    finally:
        real.close()


@pytest.mark.unit
def test_connection_translates_non_2xx(monkeypatch):
    monkeypatch.setenv("IDENTITY_AK1_SECRET", "t")
    target = TargetConfig(name="ak1", platform=AUTHENTIK, base_url="https://h")
    conn = IdentityConnection(target, client=_Client(lambda m, p, k: _Resp(404, content=b"x")))
    with pytest.raises(IdentityApiError) as ei:
        conn.get("/api/v3/core/users/zzz/")
    assert ei.value.status_code == 404
    assert "not found" in str(ei.value).lower()


@pytest.mark.unit
def test_config_rejects_bad_platform_and_requires_base_url():
    with pytest.raises(ValueError):
        TargetConfig(name="x", platform="okta", base_url="https://h")
    with pytest.raises(ValueError, match="base_url"):
        TargetConfig(name="x", platform=KEYCLOAK)
    t = TargetConfig(name="k", platform=KEYCLOAK, base_url="https://h/")
    assert t.base_url == "https://h"  # trailing slash stripped
    assert t.realm == "master"  # default realm
    assert t.verify_ssl is True  # TLS verify default ON


# ── URL-encoding of agent-supplied path segments ─────────────────────────────


@pytest.mark.unit
def test_path_traversal_ids_are_url_encoded():
    """An id carrying ``../`` must not reach the HTTP client as a raw path
    traversal — every substituted value is URL-encoded in Platform.path()."""
    kc = get_platform(KEYCLOAK)
    path = kc.path("user_get", realm="master", user_id="../../clients/x/client-secret")
    assert "../" not in path
    assert path.startswith("/admin/realms/master/users/")

    ak = get_platform(AUTHENTIK)
    path = ak.path("user_sessions", realm="r", user_id="1&superuser=1?x=../y")
    assert "../" not in path and "&superuser" not in path


@pytest.mark.unit
def test_realm_itself_is_url_encoded():
    kc = get_platform(KEYCLOAK)
    path = kc.path("users", realm="master/../other")
    assert "/../" not in path
