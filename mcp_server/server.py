"""MCP server wrapping identity-aiops operations (stdio transport).

Thin adapter layer: each ``@mcp.tool()`` function (in ``mcp_server/tools/``)
delegates to the ``identity_aiops`` ops package and is wrapped with the
identity-aiops ``@governed_tool`` harness (audit / budget / undo / risk-tier).

Standalone, self-governed identity-provider operations (preview) over Keycloak
and authentik: realm/users/sessions/credentials/groups/events/clients reads,
four flagship analyses (login-failure RCA, stale-access audit, client
misconfiguration audit, MFA coverage), and governed writes (user
disable/enable, session revocation, required password reset, redirect-URI
update, client-secret rotation).

Source: https://github.com/AIops-tools/Identity-AIops
License: MIT
"""

import logging

from mcp_server._shared import _safe_error, mcp, tool_errors

# Importing the tool modules registers every @mcp.tool() onto the shared
# `mcp` instance. Order does not matter; each module is self-contained.
from mcp_server.tools import (  # noqa: F401 — side effects
    analysis,
    clients,
    events,
    system,
    undo,
    users,
    writes,
)

__all__ = ["mcp", "main", "_safe_error", "tool_errors"]


def main() -> None:
    """Run the MCP server over stdio."""
    logging.basicConfig(level=logging.INFO)
    mcp.run(transport="stdio")
