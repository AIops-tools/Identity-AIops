"""Read-path ops tests (realm / users / events / clients / overview).

Uses a fake connection that returns canned JSON per path, so the cross-platform
normalisation is exercised without a live Keycloak/authentik. The fake carries
a real Platform descriptor so ops resolve the same paths they would in
production.
"""

import pytest

from identity_aiops.config import TargetConfig
from identity_aiops.ops import clients, events, overview, realm, users
from identity_aiops.platform import AUTHENTIK, KEYCLOAK, get_platform


class _Conn:
    """Fake connection: get() looks up canned responses by path."""

    def __init__(self, responses, platform=KEYCLOAK, realm="master"):
        self.target = TargetConfig(
            name="t", platform=platform, base_url="https://h", realm=realm,
            username="cid",
        )
        self.platform = self.target.platform_obj
        self._responses = responses

    def path(self, resource, **fmt):
        return self.platform.path(resource, realm=self.target.realm, **fmt)

    def get(self, path, **_kw):
        return self._responses.get(path, {})


def _p(platform, resource, realm="master", **fmt):
    return get_platform(platform).path(resource, realm=realm, **fmt)


# ── users ───────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_list_users_keycloak_normalizes():
    conn = _Conn({
        _p(KEYCLOAK, "users"): [
            {"id": "u1", "username": "alice", "enabled": True, "email": "a@x.io",
             "createdTimestamp": 1720000000000},
            {"id": "u2", "username": "service-account-ci", "enabled": True,
             "serviceAccountClientId": "ci"},
        ]
    })
    out = users.list_users(conn)
    assert out["returned"] == 2 and out["truncated"] is False
    assert out["users"][0] == {
        "id": "u1", "username": "alice", "email": "a@x.io", "enabled": True,
        # lastLogin is null, not "" — the IdP did not report a last sign-in,
        # which is a different fact from an empty one.
        "created": "1720000000000", "lastLogin": None, "serviceAccount": False,
    }
    assert out["users"][1]["serviceAccount"] is True


@pytest.mark.unit
def test_list_users_authentik_results_envelope_and_is_active():
    conn = _Conn(
        {_p(AUTHENTIK, "users"): {"results": [
            {"pk": 1, "username": "bob", "is_active": False,
             "last_login": "2026-01-02T03:04:05Z", "type": "internal"},
        ]}},
        platform=AUTHENTIK,
    )
    out = users.list_users(conn)
    assert out["returned"] == 1 and out["truncated"] is False
    u = out["users"][0]
    assert u["id"] == "1" and u["enabled"] is False
    assert u["lastLogin"].startswith("2026-01-02")


@pytest.mark.unit
def test_user_count_keycloak_bare_int_and_authentik_pagination():
    kc = _Conn({_p(KEYCLOAK, "user_count"): 42})
    assert users.user_count(kc) == {"count": 42}
    ak = _Conn(
        {_p(AUTHENTIK, "user_count"): {"pagination": {"count": 7}, "results": [{}]}},
        platform=AUTHENTIK,
    )
    assert users.user_count(ak) == {"count": 7}


@pytest.mark.unit
def test_user_sessions_normalize_both_platforms():
    kc = _Conn({
        _p(KEYCLOAK, "user_sessions", user_id="u1"): [
            {"id": "s1", "ipAddress": "1.2.3.4", "start": 1720000000000,
             "lastAccess": 1720000360000, "clients": {"c1": "web"}},
        ]
    })
    out = users.user_sessions(kc, "u1")
    assert out["returned"] == 1 and out["truncated"] is False
    assert out["sessions"][0]["ip"] == "1.2.3.4"

    ak = _Conn(
        {_p(AUTHENTIK, "user_sessions", user_id="9"): {"results": [
            {"uuid": "aa-bb", "last_ip": "5.6.7.8", "last_used": "2026-07-01T00:00:00Z"},
        ]}},
        platform=AUTHENTIK,
    )
    out = users.user_sessions(ak, "9")
    assert out["sessions"][0]["id"] == "aa-bb"
    assert out["sessions"][0]["ip"] == "5.6.7.8"


@pytest.mark.unit
def test_user_credentials_flags_second_factors():
    kc = _Conn({
        _p(KEYCLOAK, "user_credentials", user_id="u1"): [
            {"id": "c1", "type": "password", "createdDate": 1},
            {"id": "c2", "type": "otp", "userLabel": "phone", "createdDate": 2},
        ]
    })
    out = users.user_credentials(kc, "u1")
    assert out["secondFactors"] == 1
    assert out["credentials"][0]["secondFactor"] is False
    assert out["credentials"][1]["secondFactor"] is True

    ak = _Conn(
        {_p(AUTHENTIK, "user_credentials", user_id="9"): {"results": [
            {"pk": 5, "name": "yubikey", "verbose_name": "WebAuthn Device",
             "confirmed": True},
        ]}},
        platform=AUTHENTIK,
    )
    out = users.user_credentials(ak, "9")
    assert out["secondFactors"] == 1
    assert out["credentials"][0]["type"] == "webauthn"


@pytest.mark.unit
def test_group_members_keycloak_list_and_authentik_users_obj():
    kc = _Conn({
        _p(KEYCLOAK, "group_members", group_id="g1"): [
            {"id": "u1", "username": "alice", "enabled": True},
        ]
    })
    out = users.group_members(kc, "g1")
    assert out["returned"] == 1 and out["members"][0]["username"] == "alice"

    ak = _Conn(
        {_p(AUTHENTIK, "group_members", group_id="7"): {
            "pk": 7, "name": "admins",
            "users_obj": [{"pk": 2, "username": "carol", "is_active": True}],
        }},
        platform=AUTHENTIK,
    )
    out = users.group_members(ak, "7")
    assert out["returned"] == 1 and out["members"][0]["username"] == "carol"


@pytest.mark.unit
def test_user_lockout_status_keycloak_and_authentik_teaching_error():
    kc = _Conn({
        _p(KEYCLOAK, "user_lockout", user_id="u1"): {
            "numFailures": 7, "disabled": True, "lastIPFailure": "9.9.9.9"},
    })
    out = users.user_lockout_status(kc, "u1")
    assert out["numFailures"] == 7 and out["disabled"] is True

    ak = _Conn({}, platform=AUTHENTIK)
    out = users.user_lockout_status(ak, "9")
    assert "error" in out and "not mapped" in out["error"]


# ── events ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_login_events_keycloak_normalizes():
    conn = _Conn({
        _p(KEYCLOAK, "events"): [
            {"time": 1720000000000, "type": "LOGIN_ERROR", "clientId": "web",
             "ipAddress": "1.1.1.1", "error": "invalid_user_credentials",
             "details": {"username": "alice"}},
        ]
    })
    out = events.login_events(conn, event_type="login_error")
    e = out["events"][0]
    assert e["type"] == "LOGIN_ERROR" and e["user"] == "alice"
    assert e["ip"] == "1.1.1.1" and e["client"] == "web"
    assert e["error"] == "invalid_user_credentials"


@pytest.mark.unit
def test_login_events_authentik_normalizes():
    conn = _Conn(
        {_p(AUTHENTIK, "events"): {"results": [
            {"action": "login_failed", "created": "2026-07-01T10:00:00Z",
             "client_ip": "2.2.2.2", "user": {"username": "bob"},
             "context": {"application": "wiki", "message": "denied"}},
        ]}},
        platform=AUTHENTIK,
    )
    out = events.login_events(conn)
    e = out["events"][0]
    assert e["type"] == "LOGIN_FAILED" and e["user"] == "bob"
    assert e["client"] == "wiki" and e["error"] == "denied"


@pytest.mark.unit
def test_admin_events_authentik_filters_admin_actions():
    conn = _Conn(
        {_p(AUTHENTIK, "admin_events"): {"results": [
            {"action": "model_updated", "created": "2026-07-01T10:00:00Z",
             "user": {"username": "root"},
             "context": {"model": {"model_name": "user", "name": "bob"}}},
            {"action": "login", "created": "2026-07-01T11:00:00Z",
             "user": {"username": "bob"}},
        ]}},
        platform=AUTHENTIK,
    )
    out = events.admin_events(conn)
    assert out["returned"] == 1 and out["truncated"] is False
    assert out["events"][0]["operation"] == "model_updated"
    assert out["events"][0]["actor"] == "root"


# ── clients ─────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_list_clients_keycloak_normalizes_flags():
    conn = _Conn({
        _p(KEYCLOAK, "clients"): [
            {"id": "c1", "clientId": "spa", "publicClient": True, "enabled": True,
             "redirectUris": ["https://app.example.com/*"],
             "implicitFlowEnabled": True, "directAccessGrantsEnabled": True,
             "attributes": {"pkce.code.challenge.method": ""}},
        ]
    })
    out = clients.list_clients(conn)
    c = out["clients"][0]
    assert c["publicClient"] is True and c["implicitFlow"] is True
    assert c["directAccessGrants"] is True and c["pkceMethod"] == ""
    assert c["redirectUris"] == ["https://app.example.com/*"]


@pytest.mark.unit
def test_authentik_redirect_uris_string_and_dict_shapes():
    row_str = {"pk": 1, "client_id": "x", "client_type": "public",
               "redirect_uris": "https://a/cb\nhttp://b/cb"}
    row_dicts = {"pk": 2, "client_id": "y", "client_type": "confidential",
                 "redirect_uris": [{"matching_mode": "strict", "url": "https://c/cb"}]}
    assert clients.norm_client(row_str)["redirectUris"] == ["https://a/cb", "http://b/cb"]
    assert clients.norm_client(row_str)["publicClient"] is True
    assert clients.norm_client(row_dicts)["redirectUris"] == ["https://c/cb"]
    assert clients.norm_client(row_dicts)["publicClient"] is False


@pytest.mark.unit
def test_client_session_stats_sorts_busiest_first():
    conn = _Conn({
        _p(KEYCLOAK, "client_session_stats"): [
            {"clientId": "a", "active": "5", "offline": "0"},
            {"clientId": "b", "active": "99", "offline": "1"},
        ]
    })
    out = clients.client_session_stats(conn)
    assert out["clients"][0]["clientId"] == "b"


# ── realm / overview ────────────────────────────────────────────────────────


@pytest.mark.unit
def test_realm_info_keycloak_and_authentik_shapes():
    kc = _Conn({_p(KEYCLOAK, "realm_info"): {
        "realm": "master", "enabled": True, "bruteForceProtected": True,
        "passwordPolicy": "length(12)", "otpPolicyType": "totp"}})
    out = realm.realm_info(kc)
    assert out["bruteForceProtected"] is True and out["passwordPolicy"] == "length(12)"

    ak = _Conn(
        {_p(AUTHENTIK, "realm_info"): {
            "http_is_secure": True,
            "runtime": {"authentik_version": "2026.4.1", "environment": "native"}}},
        platform=AUTHENTIK,
    )
    out = realm.realm_info(ak)
    assert out["version"] == "2026.4.1" and out["httpIsSecure"] is True


@pytest.mark.unit
def test_list_identity_providers_both_shapes():
    kc = _Conn({_p(KEYCLOAK, "identity_providers"): [
        {"alias": "google", "providerId": "oidc", "enabled": True,
         "internalId": "i1"}]})
    out = realm.list_identity_providers(kc)
    assert out["identityProviders"][0]["name"] == "google"

    ak = _Conn(
        {_p(AUTHENTIK, "identity_providers"): {"results": [
            {"pk": 3, "slug": "ldap", "verbose_name": "LDAP Source", "enabled": False}]}},
        platform=AUTHENTIK,
    )
    out = realm.list_identity_providers(ak)
    assert out["identityProviders"][0]["enabled"] is False


@pytest.mark.unit
def test_identity_overview_resilient_shapes():
    conn = _Conn({
        _p(KEYCLOAK, "realm_info"): {"realm": "master", "bruteForceProtected": True},
        _p(KEYCLOAK, "user_count"): 12,
        _p(KEYCLOAK, "clients"): [
            {"id": "c1", "clientId": "web", "publicClient": True, "enabled": True}],
        _p(KEYCLOAK, "identity_providers"): [],
        _p(KEYCLOAK, "events"): [
            {"time": 1, "type": "LOGIN_ERROR", "error": "invalid_user_credentials"}],
    })
    out = overview.identity_overview(conn)
    assert out["platform"] == "keycloak"
    assert out["userCount"] == 12
    assert out["clientCount"] == 1 and out["publicClients"] == 1
    assert out["recentFailedLogins"] == 1
    assert out["errors"] == []
