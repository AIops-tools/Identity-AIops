"""User / group read MCP tools."""

from typing import Optional

from identity_aiops.governance import governed_tool
from identity_aiops.ops import users as ops
from mcp_server._shared import _get_connection, mcp, tool_errors


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def list_users(
    search: Optional[str] = None,
    max_results: int = 200,
    target: Optional[str] = None,
) -> dict:
    """[READ] Users in the realm, normalized across Keycloak/authentik.

    Args:
        search: Optional username/email search string.
        max_results: Page bound (default 200).
        target: IdP target name from config; omit for the default.

    Returns {"users": [...], "returned": N, "limit": L, "truncated": bool}.
    truncated is measured (one extra user is fetched); when true, more users
    exist — re-run with a higher max_results before drawing a realm-wide
    conclusion. Fields the IdP did not return are null, never "".
    """
    return ops.list_users(_get_connection(target), search, max_results)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def user_detail(user_id: str, target: Optional[str] = None) -> dict:
    """[READ] One user's full detail (enabled state, required actions, attributes).

    Args:
        user_id: User id (Keycloak UUID / authentik pk), from list_users.
        target: IdP target name from config; omit for the default.
    """
    return ops.user_detail(_get_connection(target), user_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def user_count(target: Optional[str] = None) -> dict:
    """[READ] Total user count in the realm (the cheap health probe).

    Args:
        target: IdP target name from config; omit for the default.
    """
    return ops.user_count(_get_connection(target))


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def user_sessions(user_id: str, target: Optional[str] = None) -> dict:
    """[READ] A user's active sessions (id, IP, start/last access, clients).

    Args:
        user_id: User id, from list_users.
        target: IdP target name from config; omit for the default.

    Returns {"sessions": [...], "returned": N, "truncated": false} — the IdP
    returns the user's whole session set, so this listing is always complete.
    """
    return ops.user_sessions(_get_connection(target), user_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def user_credentials(user_id: str, target: Optional[str] = None) -> dict:
    """[READ] A user's configured credentials/authenticators — the MFA surface.

    Args:
        user_id: User id, from list_users.
        target: IdP target name from config; omit for the default.

    Returns {"credentials": [...], "returned": N, "truncated": false,
    "secondFactors": N} — always the user's complete credential set.
    """
    return ops.user_credentials(_get_connection(target), user_id)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def list_groups(max_results: int = 200, target: Optional[str] = None) -> dict:
    """[READ] Groups in the realm.

    Args:
        max_results: Page bound (default 200).
        target: IdP target name from config; omit for the default.

    Returns {"groups": [...], "returned": N, "limit": L, "truncated": bool},
    with truncated measured rather than guessed.
    """
    return ops.list_groups(_get_connection(target), max_results)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def group_members(
    group_id: str,
    max_results: int = 200,
    target: Optional[str] = None,
) -> dict:
    """[READ] Members of one group, normalized user rows.

    Args:
        group_id: Group id, from list_groups.
        max_results: Page bound (default 200).
        target: IdP target name from config; omit for the default.

    Returns {"members": [...], "returned": N, "limit": L, "truncated": bool},
    with truncated measured rather than guessed.
    """
    return ops.group_members(_get_connection(target), group_id, max_results)


@mcp.tool()
@governed_tool(risk_level="low")
@tool_errors("dict")
def user_lockout_status(user_id: str, target: Optional[str] = None) -> dict:
    """[READ] Brute-force lockout status for one user (Keycloak attack-detection).

    KEYCLOAK ONLY. authentik keeps no per-user lockout register, so on an
    authentik target this returns {"error": "Resource \'user_lockout\' is not
    mapped for platform \'authentik\'..."}. That is a definitive answer about
    the platform, not a fault: do not retry it and do not report the tool as
    broken — use login_failure_rca on the failed-auth feed instead.

    Args:
        user_id: User id, from list_users.
        target: IdP target name from config; omit for the default.
    """
    return ops.user_lockout_status(_get_connection(target), user_id)
