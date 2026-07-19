"""``identity-aiops users`` — list / inspect users and governed user writes.

Read commands print normalized JSON; write commands preview with ``--dry-run``
and, once double-confirmed, delegate real execution to the governed MCP twins
so every CLI write lands in the audit log with undo where applicable.
"""

from __future__ import annotations

import json
from typing import Annotated

import typer

from identity_aiops.cli._common import (
    DryRunOption,
    TargetOption,
    cli_errors,
    console,
    double_confirm,
    dry_run_print,
    get_connection,
    print_result,
)

users_app = typer.Typer(
    name="users",
    help="Users: list, detail, sessions, credentials, and governed writes "
    "(disable/enable, revoke sessions, require password reset).",
    no_args_is_help=True,
)


@users_app.command("list")
@cli_errors
def users_list(
    search: Annotated[
        str | None, typer.Option("--search", "-s", help="Search by username/email")
    ] = None,
    limit: Annotated[int, typer.Option("--limit", "-n", help="Max users")] = 200,
    target: TargetOption = None,
) -> None:
    """List users in the realm (optionally matching a search string)."""
    from identity_aiops.ops import users as ops

    conn, _ = get_connection(target)
    print_result(ops.list_users(conn, search, limit))


@users_app.command("show")
@cli_errors
def users_show(
    user_id: Annotated[str, typer.Argument(help="User id (from 'users list')")],
    target: TargetOption = None,
) -> None:
    """Show one user's full detail."""
    from identity_aiops.ops import users as ops

    conn, _ = get_connection(target)
    console.print_json(json.dumps(ops.user_detail(conn, user_id)))


@users_app.command("sessions")
@cli_errors
def users_sessions(
    user_id: Annotated[str, typer.Argument(help="User id (from 'users list')")],
    target: TargetOption = None,
) -> None:
    """List a user's active sessions."""
    from identity_aiops.ops import users as ops

    conn, _ = get_connection(target)
    print_result(ops.user_sessions(conn, user_id))


@users_app.command("credentials")
@cli_errors
def users_credentials(
    user_id: Annotated[str, typer.Argument(help="User id (from 'users list')")],
    target: TargetOption = None,
) -> None:
    """List a user's configured credentials / second factors."""
    from identity_aiops.ops import users as ops

    conn, _ = get_connection(target)
    print_result(ops.user_credentials(conn, user_id))


@users_app.command("disable")
@cli_errors
def users_disable(
    user_id: Annotated[str, typer.Argument(help="User id to disable")],
    target: TargetOption = None,
    dry_run: DryRunOption = False,
) -> None:
    """Disable a user (blocks sign-in; sessions stay — revoke separately)."""
    from mcp_server.tools import writes as gov

    if dry_run:
        dry_run_print(operation="disable_user", api_call="set user enabled=false",
                      parameters={"user_id": user_id})
        return
    double_confirm("disable user", user_id)
    console.print_json(json.dumps(gov.disable_user(user_id=user_id, target=target)))


@users_app.command("enable")
@cli_errors
def users_enable(
    user_id: Annotated[str, typer.Argument(help="User id to enable")],
    target: TargetOption = None,
    dry_run: DryRunOption = False,
) -> None:
    """Re-enable a user (high risk: reverses containment; needs an approver)."""
    from mcp_server.tools import writes as gov

    if dry_run:
        dry_run_print(operation="enable_user", api_call="set user enabled=true",
                      parameters={"user_id": user_id})
        return
    double_confirm("enable user", user_id)
    console.print_json(json.dumps(gov.enable_user(user_id=user_id, target=target)))


@users_app.command("revoke-sessions")
@cli_errors
def users_revoke_sessions(
    user_id: Annotated[str, typer.Argument(help="User id whose sessions to revoke")],
    target: TargetOption = None,
    dry_run: DryRunOption = False,
) -> None:
    """Revoke all of a user's sessions (irreversible)."""
    from mcp_server.tools import writes as gov

    if dry_run:
        dry_run_print(operation="revoke_user_sessions", api_call="logout all sessions",
                      parameters={"user_id": user_id})
        return
    double_confirm("revoke all sessions for user", user_id)
    console.print_json(json.dumps(gov.revoke_user_sessions(user_id=user_id, target=target)))


@users_app.command("require-reset")
@cli_errors
def users_require_reset(
    user_id: Annotated[str, typer.Argument(help="User id to require a reset for")],
    clear: Annotated[
        bool, typer.Option("--clear", help="Remove the pending reset requirement instead")
    ] = False,
    target: TargetOption = None,
    dry_run: DryRunOption = False,
) -> None:
    """Require a password reset at next sign-in (Keycloak required actions)."""
    from mcp_server.tools import writes as gov

    verb = "clear password-reset requirement" if clear else "require password reset"
    if dry_run:
        dry_run_print(operation="require_password_reset", api_call=verb,
                      parameters={"user_id": user_id, "clear": clear})
        return
    double_confirm(verb, user_id)
    console.print_json(
        json.dumps(gov.require_password_reset(user_id=user_id, clear=clear, target=target))
    )
