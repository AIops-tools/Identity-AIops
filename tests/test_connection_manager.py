"""Connection-layer coverage the platform tests don't reach: the teaching
error map for every non-2xx family, the JSON body parser's empty/garbage
paths, the HTTP verb helpers, and the ``ConnectionManager`` session cache +
the atexit close hook.

The httpx client is injected as a fake (``request``/``close``) so no socket is
ever opened. authentik targets are used for the status-map cases because their
static-bearer flow sends the request straight through (no token pre-flight),
so a single injected response drives ``_teaching_message`` directly.
"""

from __future__ import annotations

import httpx
import pytest

import identity_aiops.connection as conn_mod
from identity_aiops.config import AppConfig, TargetConfig
from identity_aiops.connection import (
    ConnectionManager,
    IdentityApiError,
    IdentityConnection,
    _teaching_message,
)
from identity_aiops.platform import AUTHENTIK, KEYCLOAK


class _Resp:
    def __init__(self, status_code=200, json_body=None, content=b"{}", text=""):
        self.status_code = status_code
        self._json = json_body
        self.content = content
        self.text = text

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class _FakeClient:
    """Records requests; returns a queued response (or raises a queued error)."""

    def __init__(self, responses=None, raise_exc=None):
        self._responses = list(responses or [])
        self._raise = raise_exc
        self.calls = []
        self.closed = False

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        if self._raise is not None:
            raise self._raise
        return self._responses.pop(0) if self._responses else _Resp()

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def _ak_secret(monkeypatch):
    # authentik target secret resolved from the legacy env fallback (no store).
    monkeypatch.setenv("IDENTITY_AK_SECRET", "static-token-abc")


def _ak_conn(client):
    target = TargetConfig(name="ak", platform=AUTHENTIK, base_url="https://h")
    return IdentityConnection(target, client=client)


# ── teaching-message map (all families) ──────────────────────────────────────


@pytest.mark.unit
@pytest.mark.parametrize(
    "status, needle",
    [
        (401, "Authentication/authorization failed"),
        (403, "Authentication/authorization failed"),
        (404, "Resource not found"),
        (429, "Rate limited"),
        (400, "Validation error"),
        (409, "Validation error"),
        (422, "Validation error"),
        (500, "server error"),
        (503, "server error"),
        (418, "API error"),  # the catch-all branch
    ],
)
def test_teaching_message_covers_every_status_family(status, needle):
    msg = _teaching_message(status, "/api/v3/core/users/", "detail-body", "authentik")
    assert needle in msg
    assert "detail-body" in msg  # the response snippet is appended


@pytest.mark.unit
def test_non_2xx_status_raises_teaching_identity_api_error():
    client = _FakeClient([_Resp(status_code=404, content=b"missing", text="missing")])
    conn = _ak_conn(client)
    with pytest.raises(IdentityApiError) as ei:
        conn.get("/api/v3/core/users/x/")
    assert ei.value.status_code == 404
    assert "Resource not found" in str(ei.value)


@pytest.mark.unit
def test_transport_error_is_translated_to_identity_api_error():
    client = _FakeClient(raise_exc=httpx.ConnectError("refused"))
    conn = _ak_conn(client)
    with pytest.raises(IdentityApiError, match="Could not reach"):
        conn.get("/api/v3/core/users/")


# ── body parser ──────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_parse_empty_content_returns_empty_dict():
    client = _FakeClient([_Resp(status_code=204, content=b"")])
    assert _ak_conn(client).get("/api/v3/core/users/") == {}


@pytest.mark.unit
def test_parse_invalid_json_returns_empty_dict():
    client = _FakeClient([_Resp(status_code=200, content=b"<html>", json_body=None)])
    assert _ak_conn(client).get("/api/v3/core/users/") == {}


# ── verb helpers all route through _request ──────────────────────────────────


@pytest.mark.unit
def test_all_http_verbs_dispatch_and_parse():
    client = _FakeClient([
        _Resp(json_body={"m": "get"}),
        _Resp(json_body={"m": "post"}),
        _Resp(json_body={"m": "put"}),
        _Resp(json_body={"m": "patch"}),
        _Resp(json_body={"m": "delete"}),
    ])
    conn = _ak_conn(client)
    assert conn.get("/x")["m"] == "get"
    assert conn.post("/x")["m"] == "post"
    assert conn.put("/x")["m"] == "put"
    assert conn.patch("/x")["m"] == "patch"
    assert conn.delete("/x")["m"] == "delete"
    assert [c[0] for c in client.calls] == ["GET", "POST", "PUT", "PATCH", "DELETE"]


@pytest.mark.unit
def test_authentik_static_bearer_header_is_attached_to_real_client():
    # No injected client → the connection builds an httpx.Client and bakes the
    # long-lived token into the default Authorization header (no token pre-flight).
    target = TargetConfig(name="ak", platform=AUTHENTIK, base_url="https://h")
    conn = IdentityConnection(target)
    assert conn._client.headers["Authorization"] == "Bearer static-token-abc"
    conn.close()


@pytest.mark.unit
def test_close_delegates_to_injected_client():
    client = _FakeClient([_Resp(json_body={})])
    conn = _ak_conn(client)
    conn.close()
    assert client.closed is True


# ── ConnectionManager: cache, disconnect, listing, atexit hook ───────────────


def _kc_cfg():
    return AppConfig(targets=(
        TargetConfig(name="kc1", platform=KEYCLOAK, base_url="https://a"),
        TargetConfig(name="kc2", platform=KEYCLOAK, base_url="https://b"),
    ))


@pytest.mark.unit
def test_manager_connect_caches_and_lists(monkeypatch):
    made = []

    class _StubConn:
        def __init__(self, target, client=None):
            self.target = target
            made.append(target.name)

        def close(self):
            made.append(f"close:{self.target.name}")

    monkeypatch.setattr(conn_mod, "IdentityConnection", _StubConn)
    mgr = ConnectionManager(_kc_cfg())

    c1 = mgr.connect("kc1")
    c1_again = mgr.connect("kc1")
    assert c1 is c1_again  # cached, only built once
    assert made == ["kc1"]

    default = mgr.connect()  # no name → default target (first)
    assert default is c1  # kc1 is the default (targets[0]) and already cached

    assert set(mgr.list_targets()) == {"kc1", "kc2"}
    assert mgr.list_connected() == ["kc1"]

    mgr.disconnect("kc1")
    assert "close:kc1" in made
    assert mgr.list_connected() == []
    mgr.disconnect("nonexistent")  # no-op, no raise


@pytest.mark.unit
def test_manager_disconnect_all_and_from_config(monkeypatch):
    closed = []

    class _StubConn:
        def __init__(self, target, client=None):
            self.target = target

        def close(self):
            closed.append(self.target.name)

    monkeypatch.setattr(conn_mod, "IdentityConnection", _StubConn)
    cfg = _kc_cfg()
    mgr = ConnectionManager.from_config(cfg)
    mgr.connect("kc1")
    mgr.connect("kc2")
    mgr.disconnect_all()
    assert set(closed) == {"kc1", "kc2"}


@pytest.mark.unit
def test_atexit_hook_closes_managers_and_swallows_errors(monkeypatch):
    class _Boom(ConnectionManager):
        def disconnect_all(self):  # noqa: D401
            raise RuntimeError("shutdown race")

    # A raising manager must not propagate out of the atexit hook.
    _Boom(_kc_cfg())
    conn_mod._close_all_managers()  # must not raise
