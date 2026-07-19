"""Authentication / admin event read MCP tools."""

from typing import Optional

from identity_aiops.governance import governed_tool
from identity_aiops.ops import events as ops
from mcp_server._shared import _get_connection, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def login_events(
    event_type: Optional[str] = None,
    user: Optional[str] = None,
    max_results: int = 200,
    target: Optional[str] = None,
) -> dict:
    """[READ] Recent authentication events, normalized (time/type/user/ip/client/error).

    Args:
        event_type: Platform vocabulary — Keycloak LOGIN / LOGIN_ERROR,
            authentik login / login_failed (case-insensitive).
        user: Optional username / user-id filter.
        max_results: Page bound (default 200, max 500).
        target: IdP target name from config; omit for the default.

    Returns {"events": [...], "returned": N, "limit": L, "truncated": bool}.
    truncated is measured (one extra event is fetched), not guessed — when it
    is true, more events exist; re-run with a higher max_results rather than
    treating the partial feed as the whole picture. Optional fields an event
    did not carry are null, never "".
    """
    return ops.login_events(_get_connection(target), event_type, user, max_results)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def admin_events(max_results: int = 200, target: Optional[str] = None) -> dict:
    """[READ] Recent admin/config-change events (who changed what, from where).

    Args:
        max_results: Page bound (default 200, max 500).
        target: IdP target name from config; omit for the default.

    Returns {"events": [...], "returned": N, "limit": L, "truncated": bool},
    with truncated measured rather than guessed. On authentik the single event
    feed is post-filtered to admin actions, so truncated also reports feed rows
    that were never examined.
    """
    return ops.admin_events(_get_connection(target), max_results)
