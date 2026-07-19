"""Extra read-path coverage: user_detail / list_groups, client detail & session
reads, the resilient ``{"error": ...}`` branches, and the cross-platform field
coercion helpers in ``ops/_util``.

Uses the same fake-connection style as ``test_reads`` (canned JSON per path, a
real Platform descriptor) plus a ``_Raising`` connection that makes every read
op fall into its except branch — proving reads degrade to a partial error dict
rather than raising. No live Keycloak/authentik is ever contacted.
"""

from __future__ import annotations

import pytest

from identity_aiops.config import TargetConfig
from identity_aiops.ops import _util, clients, users
from identity_aiops.platform import AUTHENTIK, KEYCLOAK, get_platform


class _Conn:
    def __init__(self, responses, platform=KEYCLOAK, realm="master"):
        self.target = TargetConfig(
            name="t", platform=platform, base_url="https://h", realm=realm,
            username="cid",
        )
        self.platform = self.target.platform_obj
        self._responses = responses
        self.last_params = None

    def path(self, resource, **fmt):
        return self.platform.path(resource, realm=self.target.realm, **fmt)

    def get(self, path, **kw):
        self.last_params = kw.get("params")
        return self._responses.get(path, {})


class _Raising:
    """A connection whose every GET raises — drives the except branches."""

    def __init__(self, platform=KEYCLOAK):
        self.target = TargetConfig(name="t", platform=platform, base_url="https://h")
        self.platform = self.target.platform_obj

    def path(self, resource, **fmt):
        return self.platform.path(resource, realm="master", **fmt)

    def get(self, path, **kw):
        raise RuntimeError("boom-connection-down")


def _p(platform, resource, realm="master", **fmt):
    return get_platform(platform).path(resource, realm=realm, **fmt)


# ── ops/_util coercers ───────────────────────────────────────────────────────


@pytest.mark.unit
def test_to_bool_covers_bool_numeric_and_text_paths():
    assert _util.to_bool(True) is True
    assert _util.to_bool(1) is True and _util.to_bool(0) is False
    assert _util.to_bool(2.5) is True
    assert _util.to_bool("yes") is True and _util.to_bool("disabled") is False
    # unknown non-empty text falls through to bool(text)
    assert _util.to_bool("weird") is True
    assert _util.to_bool("") is False


@pytest.mark.unit
def test_user_enabled_prefers_enabled_then_is_active():
    assert _util.user_enabled({"enabled": False, "is_active": True}) is False
    assert _util.user_enabled({"is_active": False}) is False
    assert _util.user_enabled({}) is True  # absent both → assumed enabled


@pytest.mark.unit
def test_is_service_account_type_and_prefix():
    assert _util.is_service_account({"type": "internal_service_account"}) is True
    assert _util.is_service_account({"username": "service-account-ci"}) is True
    assert _util.is_service_account({"serviceAccountClientId": "ci"}) is True
    assert _util.is_service_account({"username": "alice"}) is False


@pytest.mark.unit
def test_num_and_epoch_seconds_shapes():
    assert _util.num("abc") == 0.0 and _util.num(None) == 0.0
    assert _util.num("3.5") == 3.5
    # int epoch-millis folds to seconds
    assert _util.epoch_seconds(1_720_000_000_000) == 1_720_000_000.0
    # numeric string epoch-millis
    assert _util.epoch_seconds("1720000000000") == 1_720_000_000.0
    # plain epoch seconds pass through
    assert _util.epoch_seconds(1_720_000_000) == 1_720_000_000.0
    # ISO-8601 parses to a positive timestamp
    assert _util.epoch_seconds("2026-07-01T00:00:00Z") > 0
    # unparseable / empty → 0.0
    assert _util.epoch_seconds("not-a-date") == 0.0
    assert _util.epoch_seconds("") == 0.0


# ── ops/users: detail, groups, search params, error branches ─────────────────


@pytest.mark.unit
def test_user_detail_keycloak_carries_required_actions_and_attributes():
    conn = _Conn({
        _p(KEYCLOAK, "user_get", user_id="u1"): {
            "id": "u1", "username": "alice", "enabled": True,
            "requiredActions": ["UPDATE_PASSWORD"],
            "attributes": {"dept": ["eng"]},
        }
    })
    out = users.user_detail(conn, "u1")
    assert out["id"] == "u1" and out["username"] == "alice"
    assert out["requiredActions"] == ["UPDATE_PASSWORD"]
    assert out["attributes"] == {"dept": ["eng"]}


@pytest.mark.unit
def test_user_detail_falls_back_to_passed_id_when_missing():
    conn = _Conn({_p(KEYCLOAK, "user_get", user_id="u9"): {"username": "x"}})
    out = users.user_detail(conn, "u9")
    assert out["id"] == "u9"  # normalized row had no id → fall back to arg


@pytest.mark.unit
def test_list_users_search_param_per_platform():
    kc = _Conn({_p(KEYCLOAK, "users"): []})
    users.list_users(kc, search="alice", max_results=50)
    # 51, not 50: one extra row is fetched so `truncated` can be measured.
    assert kc.last_params == {"max": 51, "search": "alice"}

    ak = _Conn({_p(AUTHENTIK, "users"): {"results": []}}, platform=AUTHENTIK)
    users.list_users(ak, search="bob", max_results=25)
    assert ak.last_params == {"page_size": 26, "search": "bob"}


@pytest.mark.unit
def test_list_groups_normalizes_both_platforms():
    kc = _Conn({_p(KEYCLOAK, "groups"): [
        {"id": "g1", "name": "admins", "path": "/admins"},
    ]})
    out = users.list_groups(kc)
    assert out["returned"] == 1 and out["truncated"] is False
    assert out["groups"][0] == {"id": "g1", "name": "admins", "path": "/admins",
                                "members": None}

    ak = _Conn({_p(AUTHENTIK, "groups"): {"results": [
        {"pk": 7, "name": "eng", "num_pk": 12},
    ]}}, platform=AUTHENTIK)
    out = users.list_groups(ak)
    assert out["groups"][0]["id"] == "7" and out["groups"][0]["members"] == 12


@pytest.mark.unit
def test_user_reads_degrade_to_error_dict_when_connection_raises():
    conn = _Raising()
    assert "error" in users.list_users(conn)
    assert users.user_detail(conn, "u1")["id"] == "u1" and "error" in users.user_detail(conn, "u1")
    assert users.user_sessions(conn, "u1")["userId"] == "u1"
    assert "error" in users.user_sessions(conn, "u1")
    assert "error" in users.user_credentials(conn, "u1")
    assert "error" in users.list_groups(conn)
    assert users.group_members(conn, "g1")["groupId"] == "g1"
    assert "error" in users.group_members(conn, "g1")
    assert "error" in users.user_count(conn)
    assert "error" in users.user_lockout_status(conn, "u1")


# ── ops/clients: detail, sessions, session-stats, error branches ─────────────


@pytest.mark.unit
def test_client_detail_keycloak_normalizes_and_backfills_id():
    conn = _Conn({_p(KEYCLOAK, "client_get", client_id="c1"): {
        "clientId": "spa", "publicClient": True, "enabled": True,
        "redirectUris": ["https://app/cb"],
    }})
    out = clients.client_detail(conn, "c1")
    assert out["id"] == "c1"  # backfilled from arg
    assert out["clientId"] == "spa" and out["publicClient"] is True


@pytest.mark.unit
def test_client_sessions_keycloak_normalizes_rows():
    conn = _Conn({_p(KEYCLOAK, "client_sessions", client_id="c1"): [
        {"id": "s1", "username": "alice", "ipAddress": "1.2.3.4",
         "start": 1, "lastAccess": 2},
    ]})
    out = clients.client_sessions(conn, "c1")
    assert out["clientId"] == "c1" and out["returned"] == 1
    assert out["sessions"][0]["username"] == "alice"
    assert out["sessions"][0]["ip"] == "1.2.3.4"


@pytest.mark.unit
def test_client_reads_degrade_to_error_dict_when_connection_raises():
    conn = _Raising()
    assert "error" in clients.list_clients(conn)
    assert clients.client_detail(conn, "c1")["id"] == "c1"
    assert "error" in clients.client_detail(conn, "c1")
    assert clients.client_sessions(conn, "c1")["clientId"] == "c1"
    assert "error" in clients.client_sessions(conn, "c1")
    assert "error" in clients.client_session_stats(conn)


@pytest.mark.unit
def test_client_session_stats_authentik_teaching_error_surfaces():
    # authentik has no client-session-stats path → KeyError caught as error dict.
    ak = _Conn({}, platform=AUTHENTIK)
    out = clients.client_session_stats(ak)
    assert "error" in out and "not mapped" in out["error"]
