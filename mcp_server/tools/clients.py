"""OAuth/OIDC client read MCP tools."""

from typing import Optional

from identity_aiops.governance import governed_tool
from identity_aiops.ops import clients as ops
from mcp_server._shared import _get_connection, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def list_clients(max_results: int = 200, target: Optional[str] = None) -> dict:
    """[READ] OAuth/OIDC clients in the realm, normalized (redirect URIs,
    public/confidential, grant flags, PKCE method).

    Args:
        max_results: Page bound (default 200).
        target: IdP target name from config; omit for the default.
    """
    return ops.list_clients(_get_connection(target), max_results)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def client_detail(client_id: str, target: Optional[str] = None) -> dict:
    """[READ] One client's normalized detail by internal id.

    Args:
        client_id: Internal id (Keycloak UUID / authentik provider pk), from list_clients.
        target: IdP target name from config; omit for the default.
    """
    return ops.client_detail(_get_connection(target), client_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def client_sessions(
    client_id: str,
    max_results: int = 200,
    target: Optional[str] = None,
) -> dict:
    """[READ] Active user sessions on one client (Keycloak).

    Args:
        client_id: Internal id, from list_clients.
        max_results: Page bound (default 200).
        target: IdP target name from config; omit for the default.
    """
    return ops.client_sessions(_get_connection(target), client_id, max_results)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def client_session_stats(target: Optional[str] = None) -> dict:
    """[READ] Active-session counts per client, busiest first (Keycloak).

    Args:
        target: IdP target name from config; omit for the default.
    """
    return ops.client_session_stats(_get_connection(target))
