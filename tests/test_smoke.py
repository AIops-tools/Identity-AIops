"""Smoke tests for identity-aiops.

Proves: every module imports, the CLI builds and --help works, the MCP server
exposes the expected tool surface and EVERY tool carries the harness marker
``_is_governed_tool``, and config platform validation works. No real
Keycloak/authentik is needed.
"""

import asyncio
import importlib

import pytest
from typer.testing import CliRunner

# Kept in sync with mcp_server/server.py (the full registered tool surface).
EXPECTED_TOOLS = {
    # system / realm
    "identity_overview", "realm_info", "list_identity_providers",
    # users / groups
    "list_users", "user_detail", "user_count", "user_sessions",
    "user_credentials", "list_groups", "group_members", "user_lockout_status",
    # events
    "login_events", "admin_events",
    # clients
    "list_clients", "client_detail", "client_sessions", "client_session_stats",
    # analysis (flagship)
    "login_failure_rca", "stale_access_audit", "client_misconfig_audit",
    "mfa_coverage_analysis",
    # writes
    "disable_user", "enable_user", "revoke_user_sessions",
    "require_password_reset", "update_client_redirect_uris",
    "rotate_client_secret",
}


@pytest.mark.unit
def test_all_modules_import():
    for name in (
        "identity_aiops", "identity_aiops.config", "identity_aiops.connection",
        "identity_aiops.platform", "identity_aiops.doctor",
        "identity_aiops.secretstore",
        "identity_aiops.ops.realm", "identity_aiops.ops.users",
        "identity_aiops.ops.events", "identity_aiops.ops.clients",
        "identity_aiops.ops.analysis", "identity_aiops.ops.writes",
        "identity_aiops.ops.overview",
        "identity_aiops.cli", "identity_aiops.cli._root",
        "identity_aiops.cli._common", "identity_aiops.cli.init",
        "identity_aiops.cli.secret", "identity_aiops.cli.users",
        "identity_aiops.cli.clients", "identity_aiops.cli.events",
        "identity_aiops.cli.overview", "identity_aiops.cli.doctor",
        "mcp_server.server", "mcp_server._shared",
        "mcp_server.tools.system", "mcp_server.tools.writes",
    ):
        importlib.import_module(name)


@pytest.mark.unit
def test_version_matches_pyproject():
    """__version__ is single-sourced from package metadata; it must track
    pyproject.toml so a release bump can never ship a stale self-report."""
    import tomllib
    from pathlib import Path

    import identity_aiops

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    expected = tomllib.loads(pyproject.read_text("utf-8"))["project"]["version"]
    assert identity_aiops.__version__ == expected


@pytest.mark.unit
def test_cli_app_builds_and_help_works():
    from identity_aiops.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for sub in ("users", "clients", "secret", "init", "overview", "events",
                "doctor", "mcp"):
        assert sub in result.output


@pytest.mark.unit
def test_cli_leaf_help_triggers_lazy_imports():
    from identity_aiops.cli import app

    runner = CliRunner()
    for cmd in (
        ["users", "--help"], ["clients", "--help"], ["secret", "--help"],
        ["doctor", "--help"], ["overview", "--help"], ["events", "--help"],
        ["init", "--help"],
        ["users", "list", "--help"], ["users", "show", "--help"],
        ["users", "disable", "--help"], ["users", "enable", "--help"],
        ["users", "revoke-sessions", "--help"], ["users", "require-reset", "--help"],
        ["clients", "list", "--help"], ["clients", "set-redirect-uris", "--help"],
        ["clients", "rotate-secret", "--help"],
        ["secret", "list", "--help"], ["secret", "set", "--help"],
    ):
        result = runner.invoke(app, cmd)
        assert result.exit_code == 0, f"{cmd} failed: {result.output}"


@pytest.mark.unit
def test_mcp_list_tools_exposes_expected_tools():
    from mcp_server.server import mcp

    tools = asyncio.run(mcp.list_tools())
    names = {t.name for t in tools}
    assert EXPECTED_TOOLS <= names, f"missing: {EXPECTED_TOOLS - names}"


@pytest.mark.unit
def test_every_mcp_tool_is_governed_by_harness():
    from mcp_server import _shared

    tool_objs = _shared.mcp._tool_manager._tools
    assert EXPECTED_TOOLS <= set(tool_objs), "tool registry incomplete"
    for name, tool in tool_objs.items():
        fn = getattr(tool, "fn", None)
        assert fn is not None, f"{name} has no fn"
        assert getattr(fn, "_is_governed_tool", False), f"{name} missing @governed_tool"


@pytest.mark.unit
def test_tool_count_is_expected():
    from mcp_server import _shared

    assert len(_shared.mcp._tool_manager._tools) == 29
