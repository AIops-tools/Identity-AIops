"""Absent fields come back as null, not as an empty string.

An empty string reads as "this field exists and is empty"; a missing field is a
different fact. Collapsing the two hides information from any consumer, and a
smaller local model will confidently invent the difference. These tests pin the
contract end-to-end: helper, ops layer, and the CLI rendering that has to cope
with a null.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from identity_aiops.cli import app
from identity_aiops.governance import opt_str
from identity_aiops.ops import clients, events, realm, users
from identity_aiops.ops._util import opt_s
from identity_aiops.platform import AUTHENTIK, KEYCLOAK
from tests.test_reads import _Conn, _p

runner = CliRunner()


@pytest.mark.unit
def test_opt_str_distinguishes_absent_from_empty():
    assert opt_str(None) is None, "absent must stay absent"
    assert opt_str("") == "", "a genuinely empty value is not the same as absent"
    assert opt_str("master", 64) == "master"


@pytest.mark.unit
def test_opt_str_still_sanitizes_and_truncates():
    assert opt_str("a\x00b") == "ab"  # control character stripped
    assert opt_str("abcdef", 3) == "abc"


@pytest.mark.unit
def test_opt_str_accepts_non_string_values():
    assert opt_str(42) == "42"


@pytest.mark.unit
def test_opt_s_is_the_ops_layer_companion_to_s():
    """``opt_s`` keeps ``s``'s 256-char bound but preserves absence."""
    assert opt_s(None) is None
    assert opt_s("") == ""
    assert len(opt_s("x" * 400)) == 256


@pytest.mark.unit
def test_user_row_reports_absent_fields_as_none():
    """A user with no email and no last sign-in reports null, not ''."""
    conn = _Conn({_p(KEYCLOAK, "users"): [{"id": "u1", "username": "alice"}]})
    row = users.list_users(conn)["users"][0]
    assert row["username"] == "alice"
    assert row["email"] is None
    assert row["lastLogin"] is None, "never-signed-in must not read as ''"
    assert row["created"] is None


@pytest.mark.unit
def test_user_row_keeps_empty_string_when_source_is_empty():
    """An explicitly empty upstream value is preserved — not turned into null."""
    conn = _Conn({_p(KEYCLOAK, "users"): [{"id": "u1", "username": "a", "email": ""}]})
    assert users.list_users(conn)["users"][0]["email"] == ""


@pytest.mark.unit
def test_user_row_never_drops_the_key_itself():
    """Keys are always present; only their value may be null.

    Omitting a key entirely is worse than a null — the consumer cannot tell the
    field was even considered.
    """
    conn = _Conn({_p(KEYCLOAK, "users"): [{}]})
    row = users.list_users(conn)["users"][0]
    for key in ("id", "username", "email", "enabled", "created", "lastLogin",
                "serviceAccount"):
        assert key in row, f"{key} must be present even when the IdP omitted it"


@pytest.mark.unit
def test_event_row_reports_absent_fields_as_none():
    """An event with no client and no error reports null for both."""
    conn = _Conn({_p(KEYCLOAK, "events"): [{"type": "LOGIN", "time": 1720000000000}]})
    e = events.login_events(conn)["events"][0]
    assert e["type"] == "LOGIN"
    assert e["client"] is None and e["error"] is None and e["ip"] is None
    assert e["user"] is None


@pytest.mark.unit
def test_event_type_is_none_rather_than_the_string_none():
    """A typeless event must not stringify to 'NONE' and match nothing loudly."""
    conn = _Conn({_p(KEYCLOAK, "events"): [{"ipAddress": "1.1.1.1"}]})
    assert events.login_events(conn)["events"][0]["type"] is None


@pytest.mark.unit
def test_credential_row_survives_an_unnamed_type():
    """A credential with no type is not a second factor — and does not crash."""
    conn = _Conn({_p(KEYCLOAK, "user_credentials", user_id="u1"): [{"id": "c1"}]})
    cred = users.user_credentials(conn, "u1")["credentials"][0]
    assert cred["type"] is None
    assert cred["secondFactor"] is False


@pytest.mark.unit
def test_client_row_reports_absent_pkce_as_none():
    """null pkceMethod means 'no method pinned' — a real audit finding."""
    conn = _Conn({_p(KEYCLOAK, "clients"): [{"id": "c1", "clientId": "spa"}]})
    row = clients.list_clients(conn)["clients"][0]
    assert row["pkceMethod"] is None
    assert row["name"] is None


@pytest.mark.unit
def test_realm_info_reports_absent_password_policy_as_none():
    """null passwordPolicy != 'no policy is set' — it must not be guessed."""
    conn = _Conn({_p(KEYCLOAK, "realm_info"): {"realm": "master", "enabled": True}})
    info = realm.realm_info(conn)
    assert info["passwordPolicy"] is None
    assert info["otpPolicyType"] is None


@pytest.mark.unit
def test_session_row_reports_absent_last_access_as_none():
    conn = _Conn(
        {_p(AUTHENTIK, "user_sessions", user_id="9"): {"results": [{"uuid": "aa"}]}},
        platform=AUTHENTIK,
    )
    sess = users.user_sessions(conn, "9")["sessions"][0]
    assert sess["id"] == "aa"
    assert sess["lastAccess"] is None and sess["ip"] is None


@pytest.mark.unit
def test_analysis_tolerates_null_event_fields():
    """The RCA buckets null user/ip/client without crashing on a string method."""
    from identity_aiops.ops import analysis

    out = analysis.login_failure_rca(
        [{"time": 1720000000, "type": "LOGIN_ERROR", "user": None, "ip": None,
          "client": None, "error": None}],
        now=1720000000,
    )
    assert out["failuresEvaluated"] == 1


@pytest.mark.unit
def test_stale_audit_tolerates_null_user_fields():
    """A user row full of nulls is evaluated, not crashed on."""
    from identity_aiops.ops import analysis

    out = analysis.stale_access_audit(
        [{"id": None, "username": None, "email": None, "enabled": True,
          "created": None, "lastLogin": None, "serviceAccount": False}],
        [{"time": None, "type": None, "user": None}],
        now=1720000000,
    )
    assert out["usersEvaluated"] == 1


@pytest.mark.unit
def test_cli_renders_rows_with_null_fields(monkeypatch):
    """The CLI must survive a null field rather than crashing on render."""
    import identity_aiops.cli.users as users_cli

    conn = _Conn({_p(KEYCLOAK, "users"): [{"id": "u1"}]})
    # The command module binds get_connection at import time, so patch it there.
    monkeypatch.setattr(users_cli, "get_connection", lambda target=None, **_k: (conn, object()))

    result = runner.invoke(app, ["users", "list"])
    assert result.exit_code == 0, result.output
    assert "u1" in result.output
    assert "null" in result.output, "an absent field must render as JSON null"


@pytest.mark.unit
def test_undo_list_envelope_measures_truncation(monkeypatch):
    from mcp_server.tools import undo as undo_tools

    rows = [
        {
            "undo_id": f"u{i}",
            "ts": "2026-07-18T00:00:00Z",
            "tool": "some_tool",
            "undo_tool": "some_inverse_tool",
            "note": "",
        }
        for i in range(4)
    ]
    captured = {}

    class _Store:
        def list(self, *, status=None, limit=50):
            captured["limit"] = limit
            return rows[:limit]

    monkeypatch.setattr(undo_tools, "get_undo_store", lambda: _Store())
    result = undo_tools.undo_list(limit=3)
    assert captured["limit"] == 4, "one extra row is fetched to measure truncation"
    assert result["returned"] == 3
    assert result["limit"] == 3
    assert result["truncated"] is True
    assert len(result["undos"]) == 3
