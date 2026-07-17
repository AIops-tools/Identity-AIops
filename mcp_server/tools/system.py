"""Realm / system read MCP tools (overview, realm info, identity providers)."""

from typing import Optional

from identity_aiops.governance import governed_tool
from identity_aiops.ops import overview as overview_ops
from identity_aiops.ops import realm as realm_ops
from mcp_server._shared import _get_connection, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def identity_overview(target: Optional[str] = None) -> dict:
    """[READ] One-shot summary: platform/realm, user/client/IdP counts, and the
    size of the recent failed-login feed. Lead with this.

    Args:
        target: IdP target name from config; omit for the default.
    """
    return overview_ops.identity_overview(_get_connection(target))


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def realm_info(target: Optional[str] = None) -> dict:
    """[READ] Realm / instance settings relevant to identity hygiene
    (brute-force protection, password policy, OTP policy, registration).

    Args:
        target: IdP target name from config; omit for the default.
    """
    return realm_ops.realm_info(_get_connection(target))


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def list_identity_providers(target: Optional[str] = None) -> dict:
    """[READ] Federated identity providers / sources configured on the IdP.

    Args:
        target: IdP target name from config; omit for the default.
    """
    return realm_ops.list_identity_providers(_get_connection(target))
