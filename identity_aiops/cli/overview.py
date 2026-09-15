"""``identity-aiops overview`` — one-shot identity-estate health."""

from __future__ import annotations

import json

from identity_aiops.cli._common import TargetOption, audited, cli_errors, console, get_connection


@cli_errors
@audited
def overview_cmd(target: TargetOption = None) -> None:
    """One-shot summary: platform/realm + user/client/IdP counts + failed logins."""
    from identity_aiops.ops import overview as ops

    conn, _ = get_connection(target)
    console.print_json(json.dumps(ops.identity_overview(conn)))
