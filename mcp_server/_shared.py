"""Shared MCP server primitives: the FastMCP instance, connection helper,
error sanitisation, and the ``@tool_errors`` decorator.

Tool modules under ``mcp_server/tools/`` import ``mcp`` from here and register
their ``@mcp.tool()`` functions onto it. ``mcp_server/server.py`` then imports
those modules and runs the server.

Keep ``Optional[X]`` (never PEP 604 ``X | None``) in any FastMCP-reflected
tool signature — on older mcp/pydantic the union eval'd to ``types.UnionType``
crashes FastMCP's ``issubclass`` check.
"""

import functools
import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any, Optional

import httpx
from mcp.server.fastmcp import FastMCP

from identity_aiops.config import load_config
from identity_aiops.connection import ConnectionManager, IdentityApiError
from identity_aiops.governance import mark_unknown, sanitize

logger = logging.getLogger(__name__)

_DOCTOR_HINT = "Run 'identity-aiops doctor' to verify connectivity and credentials."


# Failures that leave the request's fate genuinely undetermined: the bytes
# went out and either the response or the rest of the connection was lost. A
# write that hits one of these MAY have taken effect on the server.
#
# Deliberately narrow. Connect errors and pool timeouts mean the request never
# left this process, and an API error carrying a status means the server
# answered — all are ordinary failures where nothing, or a known something,
# happened. Marking them 'unknown' would cry wolf on every unreachable host.
_UNDETERMINED_ERRORS = (
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.ReadError,
    httpx.WriteError,
    httpx.RemoteProtocolError,
)


# Long enough to carry the remediation sentence. These messages teach the
# caller what to do instead, and that clause comes last — a 300-char cap cut
# it off silently on every refusal long enough to need one.
_ERROR_MAX = 800


def _safe_error(exc: Exception, tool: str) -> str:
    """Return an agent-safe error string; log full detail server-side only."""
    logger.error("Tool %s failed", tool, exc_info=True)
    _passthrough = (
        ValueError,
        FileNotFoundError,
        KeyError,
        PermissionError,
        TimeoutError,
        ConnectionError,
        IdentityApiError,
    )
    if isinstance(exc, _passthrough):
        return sanitize(str(exc), _ERROR_MAX)
    return f"{type(exc).__name__}: operation failed."


def tool_errors(shape: str = "dict") -> Callable:
    """Wrap a tool body in the canonical try/except → ``_safe_error`` pattern.

    Place this *between* ``@governed_tool`` and the function so the audit
    decorator and FastMCP still see the original signature.
    """

    def decorator(func: Callable) -> Callable:
        name = func.__name__

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as e:  # noqa: BLE001 — sanitised below
                msg = _safe_error(e, name)
                if shape == "list":
                    return [{"error": msg, "hint": _DOCTOR_HINT}]
                if shape == "str":
                    return f"Error: {msg} {_DOCTOR_HINT}"
                payload = {"error": msg, "hint": _DOCTOR_HINT}
                # Flatten the exception into a dict and its type is gone
                # for good — so classify here, while it is still known,
                # whether the operation may nonetheless have taken effect.
                if isinstance(e, _UNDETERMINED_ERRORS):
                    return mark_unknown(payload)
                return payload

        return wrapper

    return decorator


mcp = FastMCP(
    "identity-aiops",
    instructions=(
        "Identity-provider operations over Keycloak and authentik: "
        "realm settings and identity providers; users with sessions, "
        "credentials, groups, and lockout status; authentication + admin "
        "events; OAuth/OIDC clients. Flagship analyses: login_failure_rca "
        "(brute-force vs misconfigured client vs expired-credential storm), "
        "stale_access_audit, client_misconfig_audit, and "
        "mfa_coverage_analysis — transparent heuristics that show their "
        "numbers. Governed writes — disable_user/enable_user and "
        "require_password_reset (reversible, undo-recorded), "
        "revoke_user_sessions (priorState session count), "
        "update_client_redirect_uris (undo replays the prior list), and "
        "rotate_client_secret (masked priorState) at risk=high with a dry_run "
        "preview. Every tool runs through the identity-aiops "
        "governance harness (audit / budget / risk-tier / undo). The same "
        "tools work on both IdPs: a per-target 'platform' field selects the "
        "API shape."
    ),
)

_conn_mgr: Optional[ConnectionManager] = None


def _get_connection(target: Optional[str] = None) -> Any:
    """Return an identity connection, lazily initialising the manager."""
    global _conn_mgr  # noqa: PLW0603
    if _conn_mgr is None:
        config_path_str = os.environ.get("IDENTITY_AIOPS_CONFIG")
        config_path = Path(config_path_str) if config_path_str else None
        _conn_mgr = ConnectionManager(load_config(config_path))
    return _conn_mgr.connect(target)
