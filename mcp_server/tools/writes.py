"""Governed identity-write MCP tools (the only state-changing tools).

Every tool is wrapped with the governance harness (audit + graduated approval
tier) and takes a ``dry_run`` preview. Reversible writes pass an ``undo=``
callback that turns the fetched before-state into an inverse descriptor the
harness records; irreversible ones (revoke_user_sessions,
rotate_client_secret) record priorState only.

Risk tiers — identity writes are prime dual-approval material:
enable_user (reverses containment), update_client_redirect_uris (replaces the
OAuth security boundary) and rotate_client_secret (irreversible re-key) = high;
disable_user / revoke_user_sessions / require_password_reset (containment and
hygiene actions an operator needs promptly) = medium.
"""

from typing import Any, List, Optional  # noqa: UP035 — FastMCP reflects List

from identity_aiops.governance import governed_tool
from identity_aiops.ops import writes as ops
from mcp_server._shared import _get_connection, mcp, tool_errors

# ── undo descriptors (built from the fetched before-state) ──────────────────


def _disable_undo(params: dict[str, Any], result: Any) -> Optional[dict]:
    """Inverse of disable_user: re-enable only if the user WAS enabled before."""
    if not isinstance(result, dict):
        return None
    prior = (result.get("priorState") or {}).get("enabled")
    if prior is not True:
        return None  # was already disabled (or unknown) — nothing to restore
    return {
        "tool": "enable_user",
        "params": {"user_id": params.get("user_id")},
        "skill": "identity-aiops",
        "note": "Inverse of disable_user: restore the user's prior enabled state.",
    }


def _enable_undo(params: dict[str, Any], result: Any) -> Optional[dict]:
    """Inverse of enable_user: re-disable only if the user WAS disabled before."""
    if not isinstance(result, dict):
        return None
    prior = (result.get("priorState") or {}).get("enabled")
    if prior is not False:
        return None  # was already enabled (or unknown) — nothing to restore
    return {
        "tool": "disable_user",
        "params": {"user_id": params.get("user_id")},
        "skill": "identity-aiops",
        "note": "Inverse of enable_user: restore the user's prior disabled state.",
    }


def _require_reset_undo(params: dict[str, Any], result: Any) -> Optional[dict]:
    """Inverse of require_password_reset: clear the flag only if this call set it."""
    if not isinstance(result, dict) or params.get("clear"):
        return None
    prior = result.get("priorState") or {}
    if prior.get("alreadyRequired"):
        return None  # the flag predates this call — clearing would overreach
    return {
        "tool": "require_password_reset",
        "params": {"user_id": params.get("user_id"), "clear": True},
        "skill": "identity-aiops",
        "note": "Inverse of require_password_reset: clear the flag this call set.",
    }


def _redirect_uris_undo(params: dict[str, Any], result: Any) -> Optional[dict]:
    """Inverse of update_client_redirect_uris: replay the prior URI list."""
    if not isinstance(result, dict):
        return None
    prior = (result.get("priorState") or {}).get("redirectUris")
    if not prior:
        return None  # no faithful before-state — do not fabricate an undo
    return {
        "tool": "update_client_redirect_uris",
        "params": {"client_id": params.get("client_id"), "redirect_uris": list(prior)},
        "skill": "identity-aiops",
        "note": "Inverse of update_client_redirect_uris: replay the prior list.",
    }


# ── user enable/disable ──────────────────────────────────────────────────────


@mcp.tool()
@governed_tool(risk_level="medium", undo=_disable_undo)
@tool_errors("dict")
def disable_user(
    user_id: str,
    dry_run: bool = False,
    target: Optional[str] = None,
) -> dict:
    """[WRITE][risk=medium] Disable a user (blocks sign-in); reversible.

    The containment move for a compromised/stale account. Reads the user first
    so the harness records an undo that restores the prior enabled state. Live
    sessions survive — pair with revoke_user_sessions. Pass dry_run=True to
    preview.

    Refuses to disable the account this tool authenticates as — including under
    dry_run, which must report a refusal rather than preview a call that will be
    refused.

    Args:
        user_id: User id (Keycloak UUID / authentik pk), from list_users.
        dry_run: If True, preview without changing.
        target: IdP target name from config; omit for the default.
    """
    conn = _get_connection(target)
    # Ahead of the dry_run return: a preview whose real call would be refused
    # must say so, or the caller reads the refusal as transient and retries.
    ops.guard_disable_user(conn, user_id)
    if dry_run:
        return {"dryRun": True, "wouldDisable": {"userId": user_id}}
    return ops.disable_user(conn, user_id)


@mcp.tool()
@governed_tool(risk_level="high", undo=_enable_undo)
@tool_errors("dict")
def enable_user(
    user_id: str,
    dry_run: bool = False,
    target: Optional[str] = None,
) -> dict:
    """[WRITE][risk=high] Re-enable a user (restores sign-in); reversible.

    Re-granting access reverses a containment action, so it requires an
    approver (IDENTITY_AUDIT_APPROVED_BY) under the graduated-autonomy policy.
    Pass dry_run=True to preview.

    Args:
        user_id: User id, from list_users.
        dry_run: If True, preview without changing.
        target: IdP target name from config; omit for the default.
    """
    conn = _get_connection(target)
    if dry_run:
        return {"dryRun": True, "wouldEnable": {"userId": user_id}}
    return ops.enable_user(conn, user_id)


# ── session revocation ───────────────────────────────────────────────────────


@mcp.tool()
@governed_tool(risk_level="medium")
@tool_errors("dict")
def revoke_user_sessions(
    user_id: str,
    dry_run: bool = False,
    target: Optional[str] = None,
) -> dict:
    """[WRITE][risk=medium] Revoke ALL of a user's sessions. IRREVERSIBLE — no
    undo; the prior session count is recorded (audit shows the blast radius).

    Args:
        user_id: User id whose sessions to revoke, from list_users.
        dry_run: If True, preview without revoking.
        target: IdP target name from config; omit for the default.
    """
    conn = _get_connection(target)
    if dry_run:
        return {"dryRun": True, "wouldRevokeSessions": {"userId": user_id}}
    return ops.revoke_user_sessions(conn, user_id)


# ── required password reset ──────────────────────────────────────────────────


@mcp.tool()
@governed_tool(risk_level="medium", undo=_require_reset_undo)
@tool_errors("dict")
def require_password_reset(
    user_id: str,
    clear: bool = False,
    dry_run: bool = False,
    target: Optional[str] = None,
) -> dict:
    """[WRITE][risk=medium] Require a password reset at next sign-in (Keycloak
    required actions); reversible — the undo clears the flag only if this call
    set it. Pass clear=True to remove a pending requirement instead.

    Args:
        user_id: User id, from list_users.
        clear: If True, REMOVE the pending reset requirement (the undo path).
        dry_run: If True, preview without changing.
        target: IdP target name from config; omit for the default.
    """
    conn = _get_connection(target)
    if dry_run:
        return {"dryRun": True,
                "wouldRequireReset": {"userId": user_id, "clear": clear}}
    return ops.require_password_reset(conn, user_id, clear=clear)


# ── client writes ────────────────────────────────────────────────────────────


@mcp.tool()
@governed_tool(risk_level="high", undo=_redirect_uris_undo)
@tool_errors("dict")
def update_client_redirect_uris(
    client_id: str,
    redirect_uris: List[str],  # noqa: UP006 — FastMCP-reflected signature
    dry_run: bool = False,
    target: Optional[str] = None,
) -> dict:
    """[WRITE][risk=high] REPLACE a client's redirect-URI list; reversible —
    the prior list is captured and the undo replays it.

    Redirect URIs are the OAuth flow's security boundary, so this requires an
    approver (IDENTITY_AUDIT_APPROVED_BY). Pass the FULL desired list (this
    replaces, not appends) and dry_run=True to preview.

    Args:
        client_id: Client internal id, from list_clients.
        redirect_uris: The complete new redirect-URI list.
        dry_run: If True, preview without changing.
        target: IdP target name from config; omit for the default.
    """
    conn = _get_connection(target)
    if dry_run:
        return {"dryRun": True,
                "wouldSetRedirectUris": {"clientId": client_id,
                                         "redirectUris": list(redirect_uris)}}
    return ops.update_client_redirect_uris(conn, client_id, list(redirect_uris))


@mcp.tool()
@governed_tool(risk_level="high")
@tool_errors("dict")
def rotate_client_secret(
    client_id: str,
    dry_run: bool = False,
    target: Optional[str] = None,
) -> dict:
    """[WRITE][risk=high] Rotate a client's secret. IRREVERSIBLE — the old
    secret is invalidated; only masked fingerprints are recorded/returned,
    never the value. Requires an approver (IDENTITY_AUDIT_APPROVED_BY).

    Refuses to rotate the client this tool authenticates as: that would revoke
    its own credential with no undo to fall back on — including under dry_run,
    which must report a refusal rather than preview a call that will be refused.
    Rotate that one from the admin console and re-store it with
    'identity-aiops secret set'.

    Every deployment using this client must be updated with the new secret
    (fetch it from the admin console over a trusted channel). Pass
    dry_run=True to preview.

    Args:
        client_id: Client internal id, from list_clients.
        dry_run: If True, preview without rotating.
        target: IdP target name from config; omit for the default.
    """
    conn = _get_connection(target)
    # Ahead of the dry_run return: costs one client_detail GET on the preview
    # path, and in exchange the preview can never contradict the real call.
    ops.guard_rotate_client_secret(conn, client_id)
    if dry_run:
        return {"dryRun": True, "wouldRotateSecret": {"clientId": client_id}}
    return ops.rotate_client_secret(conn, client_id)
