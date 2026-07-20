"""Unit tests for the governed identity writes (ops + MCP tools).

Proves: every reversible write reads the IdP and captures its prior state
BEFORE mutating (and the governed tool records a real undo token); undo
descriptors invert correctly AND replay through the real tool signatures;
irreversible writes record priorState only (rotate masks the secret); risk
tiers are correct; and dry_run previews never mutate. No real IdP — the
connection is a MagicMock carrying a real Platform descriptor.
"""

from unittest.mock import MagicMock

import pytest

from identity_aiops.platform import AUTHENTIK, KEYCLOAK, get_platform


def _conn(platform=KEYCLOAK, realm="master"):
    conn = MagicMock(name="conn")
    conn.target.platform = platform
    conn.target.realm = realm
    conn.platform = get_platform(platform)
    conn.path = lambda resource, **fmt: conn.platform.path(resource, realm=realm, **fmt)
    return conn


# ── disable/enable prior-state capture ───────────────────────────────────────


@pytest.mark.unit
def test_disable_user_captures_prior_enabled_before_mutating(monkeypatch):
    from identity_aiops.ops import users as user_ops
    from identity_aiops.ops import writes as ops

    conn = _conn(KEYCLOAK)
    monkeypatch.setattr(user_ops, "user_detail",
                        lambda c, u: {"id": u, "username": "alice", "enabled": True})
    out = ops.disable_user(conn, "u1")

    assert out["action"] == "disable_user"
    assert out["enabled"] is False
    assert out["priorState"] == {"enabled": True}
    conn.put.assert_called_once()
    path, kwargs = conn.put.call_args
    assert path[0].endswith("/users/u1")
    assert kwargs["json"] == {"enabled": False}


@pytest.mark.unit
def test_enable_user_authentik_patches_is_active(monkeypatch):
    from identity_aiops.ops import users as user_ops
    from identity_aiops.ops import writes as ops

    conn = _conn(AUTHENTIK)
    monkeypatch.setattr(user_ops, "user_detail",
                        lambda c, u: {"id": u, "username": "bob", "enabled": False})
    out = ops.enable_user(conn, "9")

    assert out["priorState"] == {"enabled": False}
    conn.patch.assert_called_once()
    path, kwargs = conn.patch.call_args
    assert path[0] == "/api/v3/core/users/9/"
    assert kwargs["json"] == {"is_active": True}


# ── revoke sessions: priorState count, platform dispatch ────────────────────


@pytest.mark.unit
def test_revoke_sessions_keycloak_logout_with_prior_count(monkeypatch):
    from identity_aiops.ops import users as user_ops
    from identity_aiops.ops import writes as ops

    conn = _conn(KEYCLOAK)
    monkeypatch.setattr(user_ops, "user_sessions",
                        lambda c, u: {"returned": 3, "sessions": [{}, {}, {}]})
    out = ops.revoke_user_sessions(conn, "u1")

    assert out["priorState"] == {"sessionCount": 3}
    conn.post.assert_called_once()
    assert conn.post.call_args[0][0].endswith("/users/u1/logout")


@pytest.mark.unit
def test_revoke_sessions_authentik_deletes_each_session(monkeypatch):
    from identity_aiops.ops import users as user_ops
    from identity_aiops.ops import writes as ops

    conn = _conn(AUTHENTIK)
    monkeypatch.setattr(
        user_ops, "user_sessions",
        lambda c, u: {"returned": 2, "sessions": [{"id": "s1"}, {"id": "s2"}]},
    )
    out = ops.revoke_user_sessions(conn, "9")

    assert out["revoked"] == 2 and out["priorState"] == {"sessionCount": 2}
    deleted = [c.args[0] for c in conn.delete.call_args_list]
    assert deleted == [
        "/api/v3/core/authenticated_sessions/s1/",
        "/api/v3/core/authenticated_sessions/s2/",
    ]


# ── require_password_reset: prior actions + clear + platform gate ────────────


@pytest.mark.unit
def test_require_reset_appends_action_and_captures_prior():
    from identity_aiops.ops import writes as ops

    conn = _conn(KEYCLOAK)
    conn.get.return_value = {"id": "u1", "requiredActions": ["VERIFY_EMAIL"]}
    out = ops.require_password_reset(conn, "u1")

    assert out["priorState"]["requiredActions"] == ["VERIFY_EMAIL"]
    assert out["priorState"]["alreadyRequired"] is False
    _, kwargs = conn.put.call_args
    assert kwargs["json"] == {"requiredActions": ["VERIFY_EMAIL", "UPDATE_PASSWORD"]}


@pytest.mark.unit
def test_require_reset_already_set_is_idempotent_and_flagged():
    from identity_aiops.ops import writes as ops

    conn = _conn(KEYCLOAK)
    conn.get.return_value = {"id": "u1", "requiredActions": ["UPDATE_PASSWORD"]}
    out = ops.require_password_reset(conn, "u1")
    assert out["priorState"]["alreadyRequired"] is True
    _, kwargs = conn.put.call_args
    assert kwargs["json"] == {"requiredActions": ["UPDATE_PASSWORD"]}


@pytest.mark.unit
def test_require_reset_clear_removes_only_the_flag():
    from identity_aiops.ops import writes as ops

    conn = _conn(KEYCLOAK)
    conn.get.return_value = {"id": "u1",
                             "requiredActions": ["VERIFY_EMAIL", "UPDATE_PASSWORD"]}
    out = ops.require_password_reset(conn, "u1", clear=True)
    assert out["cleared"] is True
    _, kwargs = conn.put.call_args
    assert kwargs["json"] == {"requiredActions": ["VERIFY_EMAIL"]}


@pytest.mark.unit
def test_require_reset_and_rotate_secret_teach_on_authentik():
    from identity_aiops.ops import writes as ops

    conn = _conn(AUTHENTIK)
    with pytest.raises(ValueError, match="Keycloak-only"):
        ops.require_password_reset(conn, "9")
    with pytest.raises(ValueError, match="Keycloak-only"):
        ops.rotate_client_secret(conn, "9")
    conn.put.assert_not_called()
    conn.post.assert_not_called()


# ── redirect URIs: prior list capture, validation, platform payloads ────────


@pytest.mark.unit
def test_update_redirect_uris_captures_prior_list(monkeypatch):
    from identity_aiops.ops import clients as client_ops
    from identity_aiops.ops import writes as ops

    conn = _conn(KEYCLOAK)
    monkeypatch.setattr(client_ops, "client_detail",
                        lambda c, cid: {"id": cid,
                                        "redirectUris": ["https://old.example.com/cb"]})
    out = ops.update_client_redirect_uris(conn, "c1", ["https://new.example.com/cb"])

    assert out["priorState"] == {"redirectUris": ["https://old.example.com/cb"]}
    _, kwargs = conn.put.call_args
    assert kwargs["json"] == {"redirectUris": ["https://new.example.com/cb"]}


@pytest.mark.unit
def test_update_redirect_uris_authentik_joins_with_newlines(monkeypatch):
    from identity_aiops.ops import clients as client_ops
    from identity_aiops.ops import writes as ops

    conn = _conn(AUTHENTIK)
    monkeypatch.setattr(client_ops, "client_detail",
                        lambda c, cid: {"id": cid, "redirectUris": []})
    ops.update_client_redirect_uris(conn, "5", ["https://a/cb", "https://b/cb"])
    _, kwargs = conn.patch.call_args
    assert kwargs["json"] == {"redirect_uris": "https://a/cb\nhttps://b/cb"}


@pytest.mark.unit
def test_update_redirect_uris_validates_input():
    from identity_aiops.ops import writes as ops

    conn = _conn(KEYCLOAK)
    with pytest.raises(ValueError, match="non-empty list"):
        ops.update_client_redirect_uris(conn, "c1", [])
    with pytest.raises(ValueError, match="non-empty list"):
        ops.update_client_redirect_uris(conn, "c1", ["ok", "  "])
    conn.put.assert_not_called()


# ── rotate secret: masked priorState, never the raw value ────────────────────


@pytest.mark.unit
def test_rotate_client_secret_masks_old_and_new_values():
    import json

    from identity_aiops.ops import writes as ops

    conn = _conn(KEYCLOAK)
    conn.get.return_value = {"type": "secret", "value": "old-secret-value-123456"}
    conn.post.return_value = {"type": "secret", "value": "new-secret-value-654321"}
    out = ops.rotate_client_secret(conn, "c1")

    blob = json.dumps(out)
    assert "old-secret-value-123456" not in blob
    assert "new-secret-value-654321" not in blob
    assert out["priorState"]["secretMasked"].startswith("old-")
    assert "(23 chars)" in out["priorState"]["secretMasked"]
    conn.post.assert_called_once()
    assert conn.post.call_args[0][0].endswith("/clients/c1/client-secret")


# ── governed tools record real undo tokens ───────────────────────────────────


@pytest.mark.unit
def test_governed_disable_user_records_undo_token(monkeypatch):
    """End-to-end: the governed disable_user records an inverse in the undo store."""
    from identity_aiops.governance.undo import get_undo_store
    from identity_aiops.ops import users as user_ops
    from mcp_server.tools import writes as t

    conn = _conn(KEYCLOAK)
    monkeypatch.setattr(user_ops, "user_detail",
                        lambda c, u: {"id": u, "username": "alice", "enabled": True})
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    result = t.disable_user(user_id="u1")

    assert "_undo_id" in result
    recorded = get_undo_store().list()
    assert any(u.get("undo_tool") == "enable_user" for u in recorded)


@pytest.mark.unit
def test_governed_redirect_uris_undo_replays_prior_list(monkeypatch):
    import json

    from identity_aiops.governance.undo import get_undo_store
    from identity_aiops.ops import clients as client_ops
    from mcp_server.tools import writes as t

    conn = _conn(KEYCLOAK)
    monkeypatch.setattr(client_ops, "client_detail",
                        lambda c, cid: {"id": cid, "redirectUris": ["https://old/cb"]})
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    result = t.update_client_redirect_uris(client_id="c1",
                                           redirect_uris=["https://new/cb"])
    assert "_undo_id" in result
    undo = next(u for u in get_undo_store().list()
                if u.get("tool") == "update_client_redirect_uris")
    assert undo["undo_tool"] == "update_client_redirect_uris"
    assert json.loads(undo["undo_params"]) == {
        "client_id": "c1", "redirect_uris": ["https://old/cb"],
    }


@pytest.mark.unit
def test_irreversible_writes_record_no_undo(monkeypatch):
    from identity_aiops.governance.undo import get_undo_store
    from identity_aiops.ops import users as user_ops
    from mcp_server.tools import writes as t

    conn = _conn(KEYCLOAK)
    conn.get.return_value = {"value": "sec"}
    conn.post.return_value = {"value": "new"}
    monkeypatch.setattr(user_ops, "user_sessions",
                        lambda c, u: {"returned": 1, "sessions": [{"id": "s1"}]})
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    r1 = t.revoke_user_sessions(user_id="u1")
    r2 = t.rotate_client_secret(client_id="c1")
    assert "_undo_id" not in r1 and "_undo_id" not in r2
    assert get_undo_store().list() == []


# ── undo descriptors invert correctly AND replay ─────────────────────────────


@pytest.mark.unit
def test_undo_descriptors_invert_correctly():
    from mcp_server.tools import writes as t

    d = t._disable_undo({"user_id": "u1"}, {"priorState": {"enabled": True}})
    assert d["tool"] == "enable_user" and d["params"] == {"user_id": "u1"}
    # no-op disable (already disabled) → no undo
    assert t._disable_undo({"user_id": "u1"}, {"priorState": {"enabled": False}}) is None

    e = t._enable_undo({"user_id": "u2"}, {"priorState": {"enabled": False}})
    assert e["tool"] == "disable_user" and e["params"] == {"user_id": "u2"}
    assert t._enable_undo({"user_id": "u2"}, {"priorState": {"enabled": True}}) is None

    r = t._require_reset_undo({"user_id": "u3"},
                              {"priorState": {"alreadyRequired": False}})
    assert r["tool"] == "require_password_reset"
    assert r["params"] == {"user_id": "u3", "clear": True}
    # flag predates the call → clearing would overreach
    assert t._require_reset_undo({"user_id": "u3"},
                                 {"priorState": {"alreadyRequired": True}}) is None
    # the clear direction records no undo
    assert t._require_reset_undo({"user_id": "u3", "clear": True},
                                 {"priorState": {"alreadyRequired": False}}) is None

    u = t._redirect_uris_undo({"client_id": "c1"},
                              {"priorState": {"redirectUris": ["https://old/cb"]}})
    assert u["params"] == {"client_id": "c1", "redirect_uris": ["https://old/cb"]}


@pytest.mark.unit
def test_undo_descriptors_replay_through_real_tool_signatures(monkeypatch):
    """The recorded undo params must invoke the target tools without a
    TypeError — replayability is a contract, so actually call them."""
    from identity_aiops.ops import clients as client_ops
    from identity_aiops.ops import users as user_ops
    from mcp_server.tools import writes as t

    conn = _conn(KEYCLOAK)
    conn.get.return_value = {"id": "u1", "requiredActions": ["UPDATE_PASSWORD"]}
    monkeypatch.setattr(user_ops, "user_detail",
                        lambda c, u: {"id": u, "username": "x", "enabled": False})
    monkeypatch.setattr(client_ops, "client_detail",
                        lambda c, cid: {"id": cid, "redirectUris": ["https://n/cb"]})
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    disable_undo = t._disable_undo({"user_id": "u1"}, {"priorState": {"enabled": True}})
    out = getattr(t, disable_undo["tool"])(**disable_undo["params"])
    assert out["action"] == "enable_user"

    reset_undo = t._require_reset_undo({"user_id": "u1"},
                                       {"priorState": {"alreadyRequired": False}})
    out = getattr(t, reset_undo["tool"])(**reset_undo["params"])
    assert out["cleared"] is True

    uris_undo = t._redirect_uris_undo({"client_id": "c1"},
                                      {"priorState": {"redirectUris": ["https://o/cb"]}})
    out = getattr(t, uris_undo["tool"])(**uris_undo["params"])
    assert out["action"] == "update_client_redirect_uris"


# ── risk tiers ──────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_write_risk_tiers():
    from mcp_server.tools import writes as t

    for fn in (t.enable_user, t.update_client_redirect_uris, t.rotate_client_secret):
        assert fn._risk_level == "high"
    for fn in (t.disable_user, t.revoke_user_sessions, t.require_password_reset):
        assert fn._risk_level == "medium"


# ── dry-run previews never mutate ───────────────────────────────────────────


@pytest.mark.unit
def test_dry_run_previews_do_not_mutate(monkeypatch):
    from mcp_server.tools import writes as t

    conn = _conn(KEYCLOAK)
    monkeypatch.setattr(t, "_get_connection", lambda target=None: conn)

    assert t.disable_user(user_id="u1", dry_run=True)["dryRun"] is True
    assert t.enable_user(user_id="u1", dry_run=True)["dryRun"] is True
    assert t.revoke_user_sessions(user_id="u1", dry_run=True)["dryRun"] is True
    assert t.require_password_reset(user_id="u1", dry_run=True)["dryRun"] is True
    assert t.update_client_redirect_uris(
        client_id="c1", redirect_uris=["https://a/cb"], dry_run=True)["dryRun"] is True
    # Previews with no self-lockout guard to evaluate touch nothing at all.
    conn.get.assert_not_called()

    # rotate_client_secret IS guarded, so its preview pays one client_detail GET
    # to find out whether the real call would be refused. A preview that costs a
    # read and tells the truth beats a free one that reports a green
    # 'wouldRotateSecret' for a call that is about to be refused.
    assert t.rotate_client_secret(client_id="c1", dry_run=True)["dryRun"] is True

    # No preview, guarded or not, may ever mutate.
    conn.put.assert_not_called()
    conn.post.assert_not_called()
    conn.patch.assert_not_called()
    conn.delete.assert_not_called()
