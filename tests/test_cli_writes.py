"""CLI confirmed-write path — past dry-run, through governance, onto disk.

The CLI write commands delegate real execution to the ``@governed_tool``
functions in ``mcp_server.tools``. These tests drive ``users disable`` PAST
the dry-run branch and the double-confirm prompts and assert the call really
went through the governed path (audit row on disk) — the regression test for
the "CLI writes were unaudited" line-wide fix.
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
    """A fake Keycloak connection wired into the governed write module."""
    from identity_aiops.ops import users as user_ops
    from mcp_server.tools import writes as gov

    conn = MagicMock(name="conn")
    conn.target.platform = KEYCLOAK
    conn.target.realm = "master"
    conn.platform = get_platform(KEYCLOAK)
    conn.path = lambda resource, **fmt: conn.platform.path(resource, realm="master", **fmt)
    monkeypatch.setattr(user_ops, "user_detail",
                        lambda c, u: {"id": u, "username": "alice", "enabled": True})
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)
    return conn


def _audit_tools(db_path) -> list[str]:
    conn = sqlite3.connect(db_path)
    try:
        return [r[0] for r in conn.execute("SELECT tool FROM audit_log ORDER BY id")]
    finally:
        conn.close()


@pytest.mark.unit
def test_cli_users_disable_dry_run_mutates_nothing_but_is_audited(gov_home, idp_conn):
    """The invariant is: a dry_run MAY read, it must never WRITE.

    disable_user is self-lockout guarded, so its preview routes through the
    governed twin to find out whether the real call would be refused. That also
    lands an audit row — which is not new behaviour but the removal of an
    inconsistency: MCP dry-runs have always audited, the CLI was the outlier.
    """
    from identity_aiops.cli import app

    result = CliRunner().invoke(app, ["users", "disable", "u1", "--dry-run"])
    assert result.exit_code == 0
    assert "DRY-RUN" in result.output
    idp_conn.put.assert_not_called()
    idp_conn.patch.assert_not_called()
    idp_conn.post.assert_not_called()
    idp_conn.delete.assert_not_called()
    assert _audit_tools(gov_home / "audit.db") == ["disable_user"]


@pytest.mark.unit
def test_cli_users_disable_confirmed_goes_through_governance(gov_home, idp_conn):
    """Confirmed CLI write must execute via the governed twin: the API call
    fires AND an audit row lands in audit.db (this is what the reroute fix
    bought)."""
    from identity_aiops.cli import app

    result = CliRunner().invoke(app, ["users", "disable", "u1"], input="y\ny\n")
    assert result.exit_code == 0, result.output
    idp_conn.put.assert_called_once()
    assert _audit_tools(gov_home / "audit.db") == ["disable_user"]


@pytest.mark.unit
def test_cli_users_disable_aborts_without_double_confirm(gov_home, idp_conn):
    from identity_aiops.cli import app

    result = CliRunner().invoke(app, ["users", "disable", "u1"], input="y\nn\n")
    assert result.exit_code != 0
    idp_conn.put.assert_not_called()
    assert not (gov_home / "audit.db").exists()


@pytest.mark.unit
def test_cli_rotate_secret_confirmed_is_audited_high_risk(gov_home, idp_conn):
    from identity_aiops.cli import app

    idp_conn.get.return_value = {"value": "old-secret"}
    idp_conn.post.return_value = {"value": "new-secret"}
    result = CliRunner().invoke(app, ["clients", "rotate-secret", "c1"], input="y\ny\n")
    assert result.exit_code == 0, result.output
    assert "new-secret" not in result.output  # masked in the CLI too
    assert _audit_tools(gov_home / "audit.db") == ["rotate_client_secret"]
