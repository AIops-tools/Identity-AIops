"""Truncation announces itself, and it is measured rather than guessed.

A bare list cannot say "there is more". The consumer has to infer it from the
length happening to equal the limit — and a smaller local model faced with a
long, clipped feed tends to report that nothing came back at all, or to treat
the fragment it got as the complete picture. Every limit-bounded read therefore
returns ``{"<items>": [...], "returned": N, "limit": L, "truncated": bool}``.

``truncated`` is *measured*: one extra row is requested from the IdP (or, where
the whole list already arrived, compared against its real length), never
inferred from a length coincidence — ``len(rows) == limit`` is ambiguous
exactly when it matters.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from identity_aiops.cli import app
from identity_aiops.ops import analysis, clients, events, overview, realm, users
from identity_aiops.platform import AUTHENTIK, KEYCLOAK

# _Conn records the params it was called with, so the "one extra row is
# actually requested" assertions can look at the real query.
from tests.test_ops_reads_extra import _Conn, _Raising
from tests.test_reads import _p

runner = CliRunner()


def _rows(n: int, **extra) -> list[dict]:
    return [{"id": f"r{i}", "username": f"u{i}", **extra} for i in range(n)]


# ── the measurement itself ──────────────────────────────────────────────────


@pytest.mark.unit
def test_exactly_at_the_limit_is_not_truncated():
    """The ambiguous case: a full page that happens to be the whole set.

    A guessing implementation (`len(rows) == limit`) reports truncation here
    and is wrong. Over-fetching resolves it: the IdP had nothing more to give.
    """
    conn = _Conn({_p(KEYCLOAK, "users"): _rows(5)})
    out = users.list_users(conn, max_results=5)
    assert out["returned"] == 5
    assert out["truncated"] is False, "a full page is not evidence of more"


@pytest.mark.unit
def test_one_row_past_the_limit_is_truncated_and_not_returned():
    """The probe row proves there is more — and is not itself handed back."""
    conn = _Conn({_p(KEYCLOAK, "users"): _rows(6)})
    out = users.list_users(conn, max_results=5)
    assert out["truncated"] is True
    assert out["returned"] == 5 and out["limit"] == 5
    assert len(out["users"]) == 5, "the probe row must not leak into the payload"


@pytest.mark.unit
def test_the_probe_row_is_actually_requested():
    """limit+1 goes to the IdP, so truncation is measured at the source."""
    conn = _Conn({_p(KEYCLOAK, "users"): []})
    users.list_users(conn, max_results=50)
    assert conn.last_params == {"max": 51}


# ── event feeds — the highest-value case ────────────────────────────────────


@pytest.mark.unit
def test_login_events_announce_truncation():
    conn = _Conn({_p(KEYCLOAK, "events"): [
        {"type": "LOGIN_ERROR", "time": i} for i in range(11)
    ]})
    out = events.login_events(conn, max_results=10)
    assert out["truncated"] is True
    assert out["returned"] == 10 and out["limit"] == 10
    assert "total" not in out, "'total' was a lie once the feed could be clipped"


@pytest.mark.unit
def test_login_events_over_fetch_respects_the_platform_page_param():
    ak = _Conn({_p(AUTHENTIK, "events"): {"results": []}}, platform=AUTHENTIK)
    events.login_events(ak, max_results=30)
    assert ak.last_params == {"page_size": 31}


@pytest.mark.unit
def test_login_events_limit_reports_the_effective_cap():
    """max_results above MAX_EVENTS is clamped — the envelope says so."""
    conn = _Conn({_p(KEYCLOAK, "events"): []})
    out = events.login_events(conn, max_results=10_000)
    assert out["limit"] == events.MAX_EVENTS


@pytest.mark.unit
def test_admin_events_announce_truncation():
    conn = _Conn({_p(KEYCLOAK, "admin_events"): [
        {"operationType": "UPDATE", "time": i} for i in range(4)
    ]})
    out = events.admin_events(conn, max_results=3)
    assert out["truncated"] is True and out["returned"] == 3


@pytest.mark.unit
def test_admin_events_authentik_reports_unexamined_feed_rows():
    """The filter runs over a clipped feed — rows past the probe were never
    even examined for admin actions, so more admin events may well exist."""
    conn = _Conn(
        {_p(AUTHENTIK, "admin_events"): {"results": [
            {"action": "login", "created": str(i)} for i in range(5)
        ]}},
        platform=AUTHENTIK,
    )
    out = events.admin_events(conn, max_results=2)
    assert out["returned"] == 0, "none of these are admin actions"
    assert out["truncated"] is True, "but the feed itself was clipped — say so"


@pytest.mark.unit
def test_failed_login_events_carry_the_envelope_to_the_rca():
    conn = _Conn({_p(KEYCLOAK, "events"): [
        {"type": "LOGIN_ERROR", "time": i} for i in range(4)
    ]})
    out = events.failed_login_events(conn, max_results=3)
    assert out["truncated"] is True and out["returned"] == 3


@pytest.mark.unit
def test_failed_login_events_degrade_to_an_empty_envelope_on_error():
    """Callers must never have to branch on shape as well as on error."""
    out = events.failed_login_events(_Raising())
    assert out["events"] == []
    assert out["truncated"] is False and out["returned"] == 0
    assert "error" in out


# ── user / group / client / session listings ────────────────────────────────


@pytest.mark.unit
def test_list_groups_announces_truncation():
    conn = _Conn({_p(KEYCLOAK, "groups"): [{"id": f"g{i}"} for i in range(3)]})
    out = users.list_groups(conn, max_results=2)
    assert out["truncated"] is True and out["returned"] == 2


@pytest.mark.unit
def test_group_members_measure_against_the_embedded_list_on_authentik():
    """authentik ships the whole member list inside the group detail, so there
    is nothing to over-fetch — truncation is measured against its real length
    before slicing. Still measured, never guessed."""
    conn = _Conn(
        {_p(AUTHENTIK, "group_members", group_id="7"): {
            "pk": 7, "users_obj": [{"pk": i, "username": f"u{i}"} for i in range(5)],
        }},
        platform=AUTHENTIK,
    )
    out = users.group_members(conn, "7", max_results=2)
    assert out["truncated"] is True
    assert out["returned"] == 2 and out["limit"] == 2

    full = users.group_members(conn, "7", max_results=5)
    assert full["truncated"] is False and full["returned"] == 5


@pytest.mark.unit
def test_list_clients_announces_truncation():
    conn = _Conn({_p(KEYCLOAK, "clients"): [{"id": f"c{i}"} for i in range(3)]})
    out = clients.list_clients(conn, max_results=2)
    assert out["truncated"] is True and out["returned"] == 2


@pytest.mark.unit
def test_client_sessions_announce_truncation():
    conn = _Conn({_p(KEYCLOAK, "client_sessions", client_id="c1"): [
        {"id": f"s{i}"} for i in range(3)
    ]})
    out = clients.client_sessions(conn, "c1", max_results=2)
    assert out["truncated"] is True and out["returned"] == 2


@pytest.mark.unit
@pytest.mark.parametrize(
    "call",
    [
        lambda c: users.user_sessions(c, "u1"),
        lambda c: users.user_credentials(c, "u1"),
        lambda c: clients.client_session_stats(c),
        lambda c: realm.list_identity_providers(c),
    ],
)
def test_unbounded_listings_state_completeness_explicitly(call):
    """These reads have no limit — nothing is ever dropped.

    They still say ``truncated: false`` rather than leaving it out. "This list
    is complete" is what lets a caller act on it (revoke, or conclude the user
    is signed in nowhere) instead of wondering whether it was clipped.
    """
    out = call(_Conn({}))
    assert out["truncated"] is False
    assert out["returned"] == 0


# ── analyses: capped finding lists and clipped inputs ───────────────────────


@pytest.mark.unit
def test_rca_echoes_a_clipped_feed():
    """Every count is a lower bound when the feed was clipped — say so."""
    out = analysis.login_failure_rca([], feed_truncated=True)
    assert out["feedTruncated"] is True

    assert analysis.login_failure_rca([])["feedTruncated"] is False


@pytest.mark.unit
def test_client_misconfig_audit_echoes_clipped_inputs():
    """A clean result over a clipped client list is not a clean estate."""
    out = analysis.client_misconfig_audit([], inputs_truncated=True)
    assert out["inputsTruncated"] is True and out["truncated"] is False


@pytest.mark.unit
def test_stale_audit_reports_capped_finding_lists():
    """The *Count fields stay the full totals; `truncated` says a list was cut."""
    many = [
        {"username": f"u{i}", "enabled": True, "serviceAccount": False,
         "created": 1_000_000, "lastLogin": 1_000_000}
        for i in range(analysis.MAX_ROWS + 5)
    ]
    out = analysis.stale_access_audit(many, [], [], stale_days=1, now=2_000_000_000)
    assert out["staleCount"] == analysis.MAX_ROWS + 5
    assert len(out["staleUsers"]) == analysis.MAX_ROWS
    assert out["truncated"] is True and out["maxRows"] == analysis.MAX_ROWS


@pytest.mark.unit
def test_mfa_analysis_echoes_a_sampled_realm():
    out = analysis.mfa_coverage_analysis([], {}, inputs_truncated=True)
    assert out["inputsTruncated"] is True


@pytest.mark.unit
def test_pull_helpers_hand_the_truncation_flag_to_the_analyses():
    """The pulls are where truncation is known; they must not swallow it."""
    conn = _Conn({_p(KEYCLOAK, "clients"): [{"id": f"c{i}"} for i in range(3)]})
    rows, truncated = analysis.pull_clients(conn, max_results=2)
    assert len(rows) == 2 and truncated is True

    conn = _Conn({_p(KEYCLOAK, "users"): _rows(3)})
    _users, _creds, clipped = analysis.pull_mfa_inputs(conn, max_users=2)
    assert clipped is True


# ── the overview and the CLI both surface it ────────────────────────────────


@pytest.mark.unit
def test_overview_flags_a_clipped_failed_login_feed():
    """'42 recent failures' and 'at least 42' call for different next steps."""
    conn = _Conn({_p(KEYCLOAK, "events"): [
        {"type": "LOGIN_ERROR", "time": i} for i in range(300)
    ]})
    out = overview.identity_overview(conn)
    assert out["recentFailedLogins"] == 200
    assert out["recentFailedLoginsTruncated"] is True


@pytest.mark.unit
def test_cli_prints_a_truncation_notice(monkeypatch):
    """The flag at the bottom of a long JSON blob is easy to skim past."""
    import identity_aiops.cli.users as users_cli

    conn = _Conn({_p(KEYCLOAK, "users"): _rows(4)})
    # The command module binds get_connection at import time, so patch it there.
    monkeypatch.setattr(users_cli, "get_connection", lambda target=None, **_k: (conn, object()))

    result = runner.invoke(app, ["users", "list", "--limit", "3"])
    assert result.exit_code == 0, result.output
    assert "truncated" in result.output
    assert "--limit" in result.output, "the notice must name the flag to raise"


@pytest.mark.unit
def test_cli_stays_quiet_when_nothing_was_clipped(monkeypatch):
    import identity_aiops.cli.users as users_cli

    conn = _Conn({_p(KEYCLOAK, "users"): _rows(2)})
    # The command module binds get_connection at import time, so patch it there.
    monkeypatch.setattr(users_cli, "get_connection", lambda target=None, **_k: (conn, object()))

    result = runner.invoke(app, ["users", "list", "--limit", "3"])
    assert result.exit_code == 0, result.output
    assert "re-run with a higher" not in result.output
