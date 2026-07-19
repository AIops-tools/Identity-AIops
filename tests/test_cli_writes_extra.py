"""CLI governed-write coverage for the commands beyond ``users disable``:
enable / revoke-sessions / require-reset and clients set-redirect-uris, each
driven past dry-run and the double-confirm prompts so the governed twin fires
and lands an audit row. Dry-run branches are asserted to make no API call.
"""

from __future__ import annotations

import sqlite3
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

import identity_aiops.governance.audit as audit_mod
import identity_aiops.governance.policy as policy_mod
import identity_aiops.governance.undo as undo_mod
from identity_aiops.platform import KEYCLOAK, get_platform

runner = CliRunner()


@pytest.fixture
def gov_home(tmp_path, monkeypatch):
    monkeypatch.setenv("IDENTITY_AIOPS_HOME", str(tmp_path))
    audit_mod.reset_engine()
    policy_mod.reset_policy_engine()
    undo_mod.reset_undo_store()
    yield tmp_path
    audit_mod.reset_engine()
    policy_mod.reset_policy_engine()
    undo_mod.reset_undo_store()


@pytest.fixture
def idp_conn(monkeypatch):
    from identity_aiops.ops import clients as client_ops
    from identity_aiops.ops import users as user_ops
    from mcp_server.tools import writes as gov

    conn = MagicMock(name="conn")
    conn.target.platform = KEYCLOAK
    conn.target.realm = "master"
    conn.platform = get_platform(KEYCLOAK)
    conn.path = lambda resource, **fmt: conn.platform.path(resource, realm="master", **fmt)
    conn.get.return_value = {"id": "u1", "requiredActions": []}
    monkeypatch.setattr(user_ops, "user_detail",
                        lambda c, u: {"id": u, "username": "bob", "enabled": False})
    monkeypatch.setattr(user_ops, "user_sessions",
                        lambda c, u: {"returned": 2, "sessions": [{"id": "s1"}, {"id": "s2"}]})
    monkeypatch.setattr(client_ops, "client_detail",
                        lambda c, cid: {"id": cid, "redirectUris": ["https://old/cb"]})
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)
    return conn


def _audit_tools(db_path):
    conn = sqlite3.connect(db_path)
    try:
        return [r[0] for r in conn.execute("SELECT tool FROM audit_log ORDER BY id")]
    finally:
        conn.close()


@pytest.mark.unit
def test_cli_users_enable_confirmed_is_audited(gov_home, idp_conn):
    from identity_aiops.cli import app

    r = runner.invoke(app, ["users", "enable", "u1"], input="y\ny\n")
    assert r.exit_code == 0, r.output
    idp_conn.put.assert_called_once()
    assert _audit_tools(gov_home / "audit.db") == ["enable_user"]


@pytest.mark.unit
def test_cli_users_revoke_sessions_confirmed_is_audited(gov_home, idp_conn):
    from identity_aiops.cli import app

    r = runner.invoke(app, ["users", "revoke-sessions", "u1"], input="y\ny\n")
    assert r.exit_code == 0, r.output
    idp_conn.post.assert_called_once()
    assert _audit_tools(gov_home / "audit.db") == ["revoke_user_sessions"]


@pytest.mark.unit
def test_cli_users_require_reset_confirmed_is_audited(gov_home, idp_conn):
    from identity_aiops.cli import app

    r = runner.invoke(app, ["users", "require-reset", "u1"], input="y\ny\n")
    assert r.exit_code == 0, r.output
    idp_conn.put.assert_called_once()
    assert _audit_tools(gov_home / "audit.db") == ["require_password_reset"]


@pytest.mark.unit
def test_cli_clients_set_redirect_uris_confirmed_is_audited(gov_home, idp_conn):
    from identity_aiops.cli import app

    r = runner.invoke(
        app,
        ["clients", "set-redirect-uris", "c1", "--uri", "https://new/cb"],
        input="y\ny\n",
    )
    assert r.exit_code == 0, r.output
    idp_conn.put.assert_called_once()
    assert _audit_tools(gov_home / "audit.db") == ["update_client_redirect_uris"]


@pytest.mark.unit
def test_cli_write_dry_runs_make_no_call_and_no_audit(gov_home, idp_conn):
    from identity_aiops.cli import app

    for argv in (
        ["users", "enable", "u1", "--dry-run"],
        ["users", "revoke-sessions", "u1", "--dry-run"],
        ["users", "require-reset", "u1", "--dry-run"],
        ["clients", "set-redirect-uris", "c1", "--uri", "https://a/cb", "--dry-run"],
        ["clients", "rotate-secret", "c1", "--dry-run"],
    ):
        r = runner.invoke(app, argv)
        assert r.exit_code == 0, r.output
        assert "DRY-RUN" in r.output
    idp_conn.put.assert_not_called()
    idp_conn.post.assert_not_called()
    assert not (gov_home / "audit.db").exists()
