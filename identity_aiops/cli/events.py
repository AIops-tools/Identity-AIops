"""``identity-aiops events`` — recent authentication events."""

from __future__ import annotations

import json
from typing import Annotated

import typer

from identity_aiops.cli._common import TargetOption, cli_errors, console, get_connection


@cli_errors
def events_cmd(
    event_type: Annotated[
        str | None,
        typer.Option("--type", "-T", help="Event type (Keycloak: LOGIN/LOGIN_ERROR; "
                                          "authentik: login/login_failed)"),
    ] = None,
    user: Annotated[
        str | None, typer.Option("--user", "-u", help="Filter by username/user id")
    ] = None,
    limit: Annotated[int, typer.Option("--limit", "-n", help="Max events")] = 100,
    target: TargetOption = None,
) -> None:
    """Show recent authentication events (optionally filtered)."""
    from identity_aiops.ops import events as ops

    conn, _ = get_connection(target)
    console.print_json(json.dumps(ops.login_events(conn, event_type, user, limit)))
