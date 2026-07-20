"""Refuse operations that destroy their own reversibility.

Found live against authentik: disabling the account whose token the tool holds
succeeded, and the undo (enable_user) then failed 403 — the tool had revoked its
own credential mid-flight and could not roll back. A governed, reversible tool
must not offer an action that removes the ability to reverse it.

``rotate_client_secret`` is the same class one notch worse: Keycloak auth is
client_credentials on the target's own client_id, so rotating that client's
secret invalidates the stored credential instantly — and unlike disable_user
there is no undo to fail, the tool is simply locked out until re-keyed by hand.

Both guards must be EXACT (no other target blocked) and FAIL OPEN (an identity
that cannot be determined is "unknown", never "it is me").
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from identity_aiops.ops import clients as client_ops
from identity_aiops.ops import writes as ops
from identity_aiops.ops.writes import SelfLockout, disable_user
from identity_aiops.platform import KEYCLOAK, get_platform


def _conn(self_id, *, platform="authentik"):
    c = MagicMock(name="conn")
    c.self_user_id.return_value = self_id
    c.get.return_value = {"pk": "other", "is_active": True, "enabled": True}
    return c


@pytest.mark.unit
def test_disabling_own_account_is_refused():
    with pytest.raises(SelfLockout, match="account this tool authenticates as"):
        disable_user(_conn("3"), "3")


@pytest.mark.unit
def test_the_refusal_says_why_and_what_to_do_instead():
    with pytest.raises(SelfLockout) as ei:
        disable_user(_conn("3"), "3")
    msg = str(ei.value)
    assert "403" in msg, "must name the concrete failure the operator would hit"
    assert "different administrative credential" in msg, "must offer a way forward"


@pytest.mark.unit
def test_other_accounts_are_not_blocked():
    """The guard must be exact — over-blocking would break normal containment."""
    conn = _conn("3")
    disable_user(conn, "4")  # must not raise
    conn.self_user_id.assert_called()


@pytest.mark.unit
def test_unknown_identity_does_not_block():
    """If self-identity can't be determined, proceed — unknown is not 'it is me'."""
    disable_user(_conn(None), "4")  # must not raise


@pytest.mark.unit
def test_id_comparison_is_type_insensitive():
    """authentik pks are ints in some payloads, strings in others."""
    with pytest.raises(SelfLockout):
        disable_user(_conn(3), "3")


# ── rotate_client_secret: the client this tool authenticates as ──────────────


def _kc_conn(own_client_id="aiops-svc", name="prod"):
    """A Keycloak connection whose client_credentials identity is own_client_id.

    ``target.username`` is where the Keycloak client_id lives (config.py) — the
    secret paired with it is what every request depends on.
    """
    conn = MagicMock(name="conn")
    conn.target.platform = KEYCLOAK
    conn.target.username = own_client_id
    conn.target.name = name
    conn.target.realm = "master"
    conn.platform = get_platform(KEYCLOAK)
    conn.path = lambda resource, **fmt: conn.platform.path(resource, realm="master", **fmt)
    conn.get.return_value = {"type": "secret", "value": "old-secret-value"}
    conn.post.return_value = {"type": "secret", "value": "new-secret-value"}
    return conn


@pytest.mark.unit
def test_rotating_own_client_secret_is_refused(monkeypatch):
    monkeypatch.setattr(client_ops, "client_detail",
                        lambda c, cid: {"id": cid, "clientId": "aiops-svc"})
    with pytest.raises(SelfLockout, match="client this tool authenticates as"):
        ops.rotate_client_secret(_kc_conn("aiops-svc"), "internal-uuid-1")


@pytest.mark.unit
def test_rotate_refusal_happens_before_the_secret_is_touched(monkeypatch):
    """Refuse first: no GET of the old secret, and certainly no POST."""
    monkeypatch.setattr(client_ops, "client_detail",
                        lambda c, cid: {"id": cid, "clientId": "aiops-svc"})
    conn = _kc_conn("aiops-svc")
    with pytest.raises(SelfLockout):
        ops.rotate_client_secret(conn, "internal-uuid-1")
    conn.get.assert_not_called()
    conn.post.assert_not_called()


@pytest.mark.unit
def test_rotate_refusal_says_why_and_what_to_do_instead(monkeypatch):
    monkeypatch.setattr(client_ops, "client_detail",
                        lambda c, cid: {"id": cid, "clientId": "aiops-svc"})
    with pytest.raises(SelfLockout) as ei:
        ops.rotate_client_secret(_kc_conn("aiops-svc", name="prod"), "internal-uuid-1")
    msg = str(ei.value)
    assert "no undo" in msg, "must say this one cannot be rolled back at all"
    assert "admin console" in msg, "must offer the safe route"
    assert "secret set prod" in msg, "must name the concrete re-key command"


@pytest.mark.unit
def test_rotating_another_client_still_works(monkeypatch):
    """The guard must be exact — rotating any other client is normal hygiene."""
    monkeypatch.setattr(client_ops, "client_detail",
                        lambda c, cid: {"id": cid, "clientId": "web-frontend"})
    conn = _kc_conn("aiops-svc")
    out = ops.rotate_client_secret(conn, "internal-uuid-2")
    assert out["rotated"] is True
    conn.post.assert_called_once()


@pytest.mark.unit
def test_unreadable_client_does_not_block_rotation(monkeypatch):
    """Fail open: an errored client_detail is 'unknown', never assumed to be self."""
    monkeypatch.setattr(client_ops, "client_detail",
                        lambda c, cid: {"error": "404 not found", "id": cid})
    conn = _kc_conn("aiops-svc")
    ops.rotate_client_secret(conn, "internal-uuid-3")  # must not raise
    conn.post.assert_called_once()


@pytest.mark.unit
def test_client_without_a_client_id_does_not_block_rotation(monkeypatch):
    """Fail open: a client row carrying no clientId cannot be compared."""
    monkeypatch.setattr(client_ops, "client_detail",
                        lambda c, cid: {"id": cid, "clientId": None})
    conn = _kc_conn("aiops-svc")
    ops.rotate_client_secret(conn, "internal-uuid-4")  # must not raise
    conn.post.assert_called_once()


# ── dry_run must report the refusal, not preview a call that will be refused ─
#
# A green preview followed by a refusal is the weak-model trap this line designs
# against: the model reads the refusal as transient and retries. dry_run's whole
# job is to say what would happen, so "it would be refused" IS the right answer.


@pytest.mark.unit
def test_dry_run_of_a_self_disable_is_refused(monkeypatch):
    from mcp_server.tools import writes as t

    conn = _conn("3")
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    result = t.disable_user(user_id="3", dry_run=True)

    assert "error" in result, "the preview must report the refusal"
    assert "authenticates as" in result["error"]
    assert "wouldDisable" not in result, "must not also hand back a green preview"


@pytest.mark.unit
def test_dry_run_of_a_normal_disable_still_previews(monkeypatch):
    """The dry-run guard must be exact, not a blanket refusal of every preview."""
    from mcp_server.tools import writes as t

    conn = _conn("3")
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    result = t.disable_user(user_id="4", dry_run=True)

    assert result["dryRun"] is True
    assert result["wouldDisable"] == {"userId": "4"}
    conn.put.assert_not_called()
    conn.patch.assert_not_called()


@pytest.mark.unit
def test_dry_run_of_a_self_rotation_is_refused(monkeypatch):
    from mcp_server.tools import writes as t

    monkeypatch.setattr(client_ops, "client_detail",
                        lambda c, cid: {"id": cid, "clientId": "aiops-svc"})
    conn = _kc_conn("aiops-svc", name="prod")
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    result = t.rotate_client_secret(client_id="internal-uuid-1", dry_run=True)

    assert "error" in result, "the preview must report the refusal"
    assert "wouldRotateSecret" not in result
    conn.post.assert_not_called()


@pytest.mark.unit
def test_dry_run_of_another_clients_rotation_still_previews(monkeypatch):
    """Exactness: the extra client_detail GET must not turn into a blanket refusal."""
    from mcp_server.tools import writes as t

    monkeypatch.setattr(client_ops, "client_detail",
                        lambda c, cid: {"id": cid, "clientId": "web-frontend"})
    conn = _kc_conn("aiops-svc")
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    result = t.rotate_client_secret(client_id="internal-uuid-2", dry_run=True)

    assert result["dryRun"] is True
    assert result["wouldRotateSecret"] == {"clientId": "internal-uuid-2"}
    conn.post.assert_not_called()


@pytest.mark.unit
def test_dry_run_fails_open_exactly_like_the_real_call(monkeypatch):
    """A dry_run must never refuse something the real call would allow."""
    from mcp_server.tools import writes as t

    monkeypatch.setattr(client_ops, "client_detail",
                        lambda c, cid: {"error": "404 not found", "id": cid})
    conn = _kc_conn("aiops-svc")
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    result = t.rotate_client_secret(client_id="internal-uuid-3", dry_run=True)

    assert result["dryRun"] is True, "unreadable identity is unknown, never 'it is me'"


# ── the CLI preview path must refuse too, and exit non-zero ─────────────────


def _flat(text: str) -> str:
    """Collapse whitespace: rich wraps console output at the terminal width, so a
    phrase can arrive split across two lines. Assert on meaning, not on layout."""
    return " ".join(text.split())


def _cli_dry_run(monkeypatch, tmp_path, argv, conn):
    """Drive a CLI --dry-run with the governed write module pointed at ``conn``."""
    from typer.testing import CliRunner

    import identity_aiops.governance.audit as audit_mod
    import identity_aiops.governance.policy as policy_mod
    import identity_aiops.governance.undo as undo_mod
    from identity_aiops.cli import app
    from mcp_server.tools import writes as gov

    monkeypatch.setenv("IDENTITY_AIOPS_HOME", str(tmp_path))
    audit_mod.reset_engine()
    policy_mod.reset_policy_engine()
    undo_mod.reset_undo_store()
    monkeypatch.setattr(gov, "_get_connection", lambda target=None: conn)
    try:
        return CliRunner().invoke(app, argv)
    finally:
        audit_mod.reset_engine()
        policy_mod.reset_policy_engine()
        undo_mod.reset_undo_store()


@pytest.mark.unit
def test_cli_dry_run_of_a_self_disable_is_refused(monkeypatch, tmp_path):
    """A refused preview must look like a refusal: teaching message, exit 1."""
    result = _cli_dry_run(monkeypatch, tmp_path,
                          ["users", "disable", "3", "--dry-run"], _conn("3"))

    assert result.exit_code == 1, result.output
    assert "DRY-RUN" not in _flat(result.output), "must not print a green banner"
    assert "authenticates as" in _flat(result.output), "must carry the teaching message"


@pytest.mark.unit
def test_cli_dry_run_of_a_normal_disable_still_previews(monkeypatch, tmp_path):
    """Exactness: the CLI guard must not turn into a blanket refusal."""
    conn = _conn("3")
    result = _cli_dry_run(monkeypatch, tmp_path,
                          ["users", "disable", "4", "--dry-run"], conn)

    assert result.exit_code == 0, result.output
    assert "DRY-RUN" in _flat(result.output)
    conn.put.assert_not_called()
    conn.patch.assert_not_called()


@pytest.mark.unit
def test_cli_dry_run_of_a_self_rotation_is_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(client_ops, "client_detail",
                        lambda c, cid: {"id": cid, "clientId": "aiops-svc"})
    result = _cli_dry_run(monkeypatch, tmp_path,
                          ["clients", "rotate-secret", "c1", "--dry-run"],
                          _kc_conn("aiops-svc", name="prod"))

    assert result.exit_code == 1, result.output
    assert "DRY-RUN" not in _flat(result.output)
    assert "admin console" in _flat(result.output), "must carry the route back"


@pytest.mark.unit
def test_cli_dry_run_of_another_clients_rotation_still_previews(monkeypatch, tmp_path):
    monkeypatch.setattr(client_ops, "client_detail",
                        lambda c, cid: {"id": cid, "clientId": "web-frontend"})
    conn = _kc_conn("aiops-svc")
    result = _cli_dry_run(monkeypatch, tmp_path,
                          ["clients", "rotate-secret", "c1", "--dry-run"], conn)

    assert result.exit_code == 0, result.output
    assert "DRY-RUN" in _flat(result.output)
    conn.post.assert_not_called()


@pytest.mark.unit
def test_the_refusal_reaches_the_agent_intact_through_the_mcp_layer(monkeypatch):
    """The teaching tail must survive _safe_error's length cap.

    ValueError is on the passthrough list, so the message is forwarded rather
    than replaced — but it is truncated. The route back sits at the END of the
    message, so an over-long refusal loses exactly the part the caller acts on.
    """
    from mcp_server.tools import writes as t

    monkeypatch.setattr(client_ops, "client_detail",
                        lambda c, cid: {"id": cid, "clientId": "aiops-svc"})
    conn = _kc_conn("aiops-svc", name="prod")
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    result = t.rotate_client_secret(client_id="internal-uuid-1")

    assert "error" in result, "the refusal must surface as an error, not a success"
    assert "secret set prod" in result["error"], "the route back must not be truncated away"
    conn.post.assert_not_called()


@pytest.mark.unit
def test_unconfigured_own_client_id_does_not_block_rotation(monkeypatch):
    """Fail open: with no client_id configured there is no self to protect."""
    called: list = []

    def _detail(c, cid):
        called.append(cid)
        return {"id": cid, "clientId": "anything"}

    monkeypatch.setattr(client_ops, "client_detail", _detail)
    conn = _kc_conn(own_client_id="")
    ops.rotate_client_secret(conn, "internal-uuid-5")  # must not raise
    assert called == [], "with no self identity the client need not even be fetched"
    conn.post.assert_called_once()
