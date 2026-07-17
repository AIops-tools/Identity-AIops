"""Flagship analysis MCP tools — the tool's reason to exist.

Each tool pulls live telemetry through the read ops and feeds the pure
analysis functions in :mod:`identity_aiops.ops.analysis`; the heuristics are
transparent (thresholds included in the output) and read-only.
"""

from typing import Optional

from identity_aiops.governance import governed_tool
from identity_aiops.ops import analysis as ops
from mcp_server._shared import _get_connection, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def login_failure_rca(
    window_minutes: int = 60,
    max_events: int = 500,
    target: Optional[str] = None,
) -> dict:
    """[READ] RCA over the failed-auth feed: separates brute-force (spray or
    targeted) from a misconfigured client from an expired-credential storm and
    a lockout storm — each finding carries its numbers, cause, and action.

    Args:
        window_minutes: Trailing analysis window (default 60).
        max_events: Failed-login events to pull (default 500).
        target: IdP target name from config; omit for the default.
    """
    conn = _get_connection(target)
    events = ops.pull_failed_logins(conn, limit=max_events)
    return ops.login_failure_rca(events, window_minutes=window_minutes)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def stale_access_audit(
    stale_days: int = 90,
    max_users: int = 500,
    target: Optional[str] = None,
) -> dict:
    """[READ] Dormant-access audit: enabled users idle > N days, accounts that
    never signed in, service accounts with interactive logins, and sessions
    orphaned by disabled/unknown users.

    Args:
        stale_days: Idle threshold in days (default 90).
        max_users: Users to pull (default 500).
        target: IdP target name from config; omit for the default.
    """
    conn = _get_connection(target)
    users, logins, sessions = ops.pull_stale_inputs(conn, max_users=max_users)
    return ops.stale_access_audit(users, logins, sessions, stale_days=stale_days)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def client_misconfig_audit(
    max_clients: int = 200,
    target: Optional[str] = None,
) -> dict:
    """[READ] Ranked OAuth/OIDC client risk: wildcard/http redirect URIs,
    public clients with secrets, implicit flow, missing PKCE, password grant —
    per-client riskScore with evidence and actions.

    Args:
        max_clients: Clients to pull (default 200).
        target: IdP target name from config; omit for the default.
    """
    conn = _get_connection(target)
    clients = ops.pull_clients(conn, max_results=max_clients)
    return ops.client_misconfig_audit(clients)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def mfa_coverage_analysis(
    max_users: int = 200,
    target: Optional[str] = None,
) -> dict:
    """[READ] Second-factor coverage: overall %, the users without MFA, and the
    factor types counted. Pulls one credential list per user (bounded).

    Args:
        max_users: Users to sample (default 200 — one API call each).
        target: IdP target name from config; omit for the default.
    """
    conn = _get_connection(target)
    users, creds = ops.pull_mfa_inputs(conn, max_users=max_users)
    return ops.mfa_coverage_analysis(users, creds)
