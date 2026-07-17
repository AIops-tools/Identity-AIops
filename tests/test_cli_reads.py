"""CLI read-command coverage + the shared CLI plumbing.

Each read command is driven through the real Typer app with ``get_connection``
patched to a fake connection (canned JSON per path), so the command's JSON
rendering and the lazy ops import both execute without a live IdP. Also covers
``cli_errors`` (known exceptions → one red line + exit 1) and ``get_connection``
building a manager from a temp config file.
"""

from __future__ import annotations

import pytest
import typer
import yaml
from typer.testing import CliRunner

from identity_aiops.cli import _common
from identity_aiops.config import TargetConfig
from identity_aiops.platform import KEYCLOAK, get_platform

runner = CliRunner()


class _Conn:
    def __init__(self, responses):
        self.target = TargetConfig(name="t", platform=KEYCLOAK,
                                   base_url="https://h", realm="master", username="cid")
        self.platform = get_platform(KEYCLOAK)
        self._responses = responses

    def path(self, resource, **fmt):
        return self.platform.path(resource, realm="master", **fmt)

    def get(self, path, **kw):
        return self._responses.get(path, {})


def _kp(resource, **fmt):
    return get_platform(KEYCLOAK).path(resource, realm="master", **fmt)


@pytest.fixture
def patched_conn(monkeypatch):
    """Patch get_connection in every CLI sub-module to a shared fake conn."""
    responses = {}
    conn = _Conn(responses)

    from identity_aiops.cli import clients as clients_cli
    from identity_aiops.cli import events as events_cli
    from identity_aiops.cli import overview as overview_cli
    from identity_aiops.cli import users as users_cli

    for mod in (users_cli, clients_cli, events_cli, overview_cli):
        monkeypatch.setattr(mod, "get_connection", lambda target=None: (conn, None))
    return responses


@pytest.mark.unit
def test_users_list_and_show_render_json(patched_conn):
    from identity_aiops.cli import app

    patched_conn[_kp("users")] = [
        {"id": "u1", "username": "alice", "enabled": True},
    ]
    patched_conn[_kp("user_get", user_id="u1")] = {
        "id": "u1", "username": "alice", "enabled": True}

    r = runner.invoke(app, ["users", "list"])
    assert r.exit_code == 0 and "alice" in r.output
    r = runner.invoke(app, ["users", "show", "u1"])
    assert r.exit_code == 0 and "u1" in r.output


@pytest.mark.unit
def test_users_sessions_and_credentials(patched_conn):
    from identity_aiops.cli import app

    patched_conn[_kp("user_sessions", user_id="u1")] = [
        {"id": "s1", "ipAddress": "1.2.3.4"}]
    patched_conn[_kp("user_credentials", user_id="u1")] = [
        {"id": "c1", "type": "otp"}]

    assert runner.invoke(app, ["users", "sessions", "u1"]).exit_code == 0
    r = runner.invoke(app, ["users", "credentials", "u1"])
    assert r.exit_code == 0 and "secondFactors" in r.output


@pytest.mark.unit
def test_clients_list_and_show(patched_conn):
    from identity_aiops.cli import app

    patched_conn[_kp("clients")] = [
        {"id": "c1", "clientId": "spa", "publicClient": True, "enabled": True}]
    patched_conn[_kp("client_get", client_id="c1")] = {
        "id": "c1", "clientId": "spa", "enabled": True}

    assert runner.invoke(app, ["clients", "list"]).exit_code == 0
    r = runner.invoke(app, ["clients", "show", "c1"])
    assert r.exit_code == 0 and "spa" in r.output


@pytest.mark.unit
def test_events_and_overview_commands(patched_conn):
    from identity_aiops.cli import app

    patched_conn[_kp("events")] = [
        {"time": 1, "type": "LOGIN_ERROR", "error": "invalid_user_credentials"}]
    patched_conn[_kp("realm_info")] = {"realm": "master", "bruteForceProtected": True}
    patched_conn[_kp("user_count")] = 5
    patched_conn[_kp("identity_providers")] = []

    r = runner.invoke(app, ["events", "--type", "LOGIN_ERROR"])
    assert r.exit_code == 0 and "LOGIN_ERROR" in r.output
    r = runner.invoke(app, ["overview"])
    assert r.exit_code == 0 and "keycloak" in r.output


# ── shared plumbing: cli_errors + get_connection ─────────────────────────────


@pytest.mark.unit
def test_cli_errors_translates_known_exceptions_to_exit_1():
    from identity_aiops.connection import IdentityApiError

    @_common.cli_errors
    def _keyerr():
        raise KeyError("MISSING_VAR")

    @_common.cli_errors
    def _apierr():
        raise IdentityApiError("bad auth", status_code=401)

    for fn in (_keyerr, _apierr):
        with pytest.raises(typer.Exit) as ei:
            fn()
        assert ei.value.exit_code == 1


@pytest.mark.unit
def test_cli_errors_passes_through_typer_exit():
    @_common.cli_errors
    def _boom():
        raise typer.Exit(3)

    with pytest.raises(typer.Exit) as ei:
        _boom()
    assert ei.value.exit_code == 3


@pytest.mark.unit
def test_get_connection_builds_manager_from_temp_config(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(yaml.safe_dump({"targets": [
        {"name": "kc1", "platform": "keycloak", "base_url": "https://sso",
         "username": "cid"},
    ]}))
    conn, cfg = _common.get_connection("kc1", config_path=cfg_file)
    assert conn.target.name == "kc1"
    assert [t.name for t in cfg.targets] == ["kc1"]
