"""End-to-end MCP analysis-tool coverage: each governed tool pulls live
telemetry through the read ops (fake connection, canned JSON) and feeds the
pure analysis, so the pull wiring AND the classification are exercised through
the real tool signature. Also covers the MCP ``_shared`` error sanitiser and
the lazy connection helper.
"""

from __future__ import annotations

import pytest

from identity_aiops.config import TargetConfig
from identity_aiops.platform import AUTHENTIK, KEYCLOAK, get_platform


class _Conn:
    def __init__(self, responses, platform=KEYCLOAK):
        self.target = TargetConfig(name="t", platform=platform,
                                   base_url="https://h", realm="master", username="cid")
        self.platform = get_platform(platform)
        self._responses = responses

    def path(self, resource, **fmt):
        return self.platform.path(resource, realm="master", **fmt)

    def get(self, path, **kw):
        return self._responses.get(path, [])


def _kp(resource, **fmt):
    return get_platform(KEYCLOAK).path(resource, realm="master", **fmt)


@pytest.fixture
def wire_conn(monkeypatch):
    def _install(responses, platform=KEYCLOAK):
        conn = _Conn(responses, platform=platform)
        from mcp_server.tools import analysis as tools
        monkeypatch.setattr(tools, "_get_connection", lambda target=None: conn)
        return conn
    return _install


@pytest.mark.unit
def test_login_failure_rca_tool_flags_password_spray(wire_conn):
    from mcp_server.tools import analysis as tools

    # 25 failures from one IP against 6 distinct users → password spray.
    events = [
        {"time": 1_752_000_000_000, "type": "LOGIN_ERROR", "ipAddress": "9.9.9.9",
         "clientId": "web", "error": "invalid_user_credentials",
         "details": {"username": f"user{i % 6}"}}
        for i in range(25)
    ]
    wire_conn({_kp("events"): events})
    out = tools.login_failure_rca(window_minutes=120)
    assert "error" not in out
    kinds = {f["kind"] for f in out["findings"]}
    assert "password-spray" in kinds


@pytest.mark.unit
def test_client_misconfig_audit_tool_ranks_findings(wire_conn):
    from mcp_server.tools import analysis as tools

    wire_conn({_kp("clients"): [
        {"id": "c1", "clientId": "spa", "enabled": True, "publicClient": True,
         "redirectUris": ["https://app/*"], "implicitFlowEnabled": True},
    ]})
    out = tools.client_misconfig_audit()
    assert out["clientsFlagged"] == 1
    issues = {f["issue"] for f in out["ranked"][0]["findings"]}
    assert "wildcard-redirect-uri" in issues
    assert "implicit-flow-enabled" in issues


@pytest.mark.unit
def test_stale_access_audit_tool_flags_idle_user(wire_conn):
    from mcp_server.tools import analysis as tools

    # An enabled user last seen long ago (authentik lastLogin on the row).
    wire_conn(
        {
            get_platform(AUTHENTIK).path("users", realm="master"): {"results": [
                {"pk": 1, "username": "dormant", "is_active": True,
                 "last_login": "2000-01-01T00:00:00Z"},
            ]},
            get_platform(AUTHENTIK).path("events", realm="master"): {"results": []},
            get_platform(AUTHENTIK).path("sessions", realm="master"): {"results": []},
        },
        platform=AUTHENTIK,
    )
    out = tools.stale_access_audit(stale_days=90)
    assert "error" not in out
    assert out["staleCount"] >= 1
    assert any(u["username"] == "dormant" for u in out["staleUsers"])


@pytest.mark.unit
def test_mfa_coverage_analysis_tool_reports_gap(wire_conn):
    from mcp_server.tools import analysis as tools

    wire_conn({
        _kp("users"): [
            {"id": "u1", "username": "alice", "enabled": True},
            {"id": "u2", "username": "bob", "enabled": True},
        ],
        _kp("user_credentials", user_id="u1"): [
            {"id": "c1", "type": "otp", "confirmed": True}],
        _kp("user_credentials", user_id="u2"): [
            {"id": "c2", "type": "password"}],
    })
    out = tools.mfa_coverage_analysis()
    assert out["usersEvaluated"] == 2
    assert out["withMfa"] == 1 and out["withoutMfa"] == 1
    assert "bob" in out["usersWithoutMfa"]


# ── mcp_server/_shared internals ─────────────────────────────────────────────


@pytest.mark.unit
def test_tool_errors_sanitizes_generic_and_passes_known(monkeypatch):
    from mcp_server import _shared

    @_shared.tool_errors("dict")
    def _generic():
        raise RuntimeError("secret internal detail")

    @_shared.tool_errors("list")
    def _known_list():
        raise ValueError("teaching message")

    @_shared.tool_errors("str")
    def _known_str():
        raise ValueError("teach")

    generic = _generic()
    assert "secret internal detail" not in generic["error"]
    assert generic["error"] == "RuntimeError: operation failed."

    listed = _known_list()
    assert listed[0]["error"] == "teaching message"  # known type passes through

    assert _known_str().startswith("Error: teach")


@pytest.mark.unit
def test_shared_get_connection_lazily_builds_manager(monkeypatch, tmp_path):
    from identity_aiops import config as config_mod
    from mcp_server import _shared

    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        "targets:\n  - name: kc1\n    platform: keycloak\n"
        "    base_url: https://sso\n    username: cid\n"
    )
    monkeypatch.setattr(config_mod, "CONFIG_FILE", cfg_file)
    monkeypatch.setattr(_shared, "_conn_mgr", None)
    conn = _shared._get_connection("kc1")
    assert conn.target.name == "kc1"
