"""Flagship analyses — pure-function tests with synthetic telemetry.

Each analysis is fed hand-built normalized rows so the classification logic
(thresholds, causes, actions) is exercised deterministically — no connection,
no clock skew (``now`` is always injected).
"""

import pytest

from identity_aiops.ops.analysis import (
    client_misconfig_audit,
    login_failure_rca,
    mfa_coverage_analysis,
    stale_access_audit,
)

NOW = 1_752_000_000.0  # fixed epoch seconds
DAY = 86400.0


def _ev(user="u", ip="1.1.1.1", client="web", error="invalid_user_credentials",
        t=NOW, etype="LOGIN_ERROR"):
    return {"time": t, "type": etype, "user": user, "ip": ip, "client": client,
            "error": error}


# ── 1. login_failure_rca ─────────────────────────────────────────────────────


@pytest.mark.unit
def test_rca_flags_password_spray_from_single_ip():
    events = [_ev(user=f"user{i % 8}", ip="9.9.9.9") for i in range(25)]
    out = login_failure_rca(events, now=NOW)
    kinds = {f["kind"] for f in out["findings"]}
    assert "password-spray" in kinds
    spray = next(f for f in out["findings"] if f["kind"] == "password-spray")
    assert spray["subject"] == "9.9.9.9"
    assert spray["failures"] == 25 and spray["distinctUsers"] == 8
    assert "cause" in spray and "action" in spray


@pytest.mark.unit
def test_rca_flags_targeted_brute_force_multi_ip():
    events = [_ev(user="admin", ip=f"10.0.0.{i}") for i in range(12)]
    out = login_failure_rca(events, now=NOW)
    f = next(f for f in out["findings"] if f["kind"] == "targeted-brute-force")
    assert f["subject"] == "admin" and f["distinctIps"] == 12


@pytest.mark.unit
def test_rca_single_ip_repeats_read_as_stale_credential_not_attack():
    events = [_ev(user="backup-job", ip="10.1.1.1") for _ in range(12)]
    out = login_failure_rca(events, now=NOW)
    kinds = {f["kind"] for f in out["findings"]}
    assert "stale-stored-credential" in kinds
    assert "targeted-brute-force" not in kinds


@pytest.mark.unit
def test_rca_flags_misconfigured_client():
    events = [_ev(user="", client="billing-svc", error="invalid_client_credentials",
                  ip=f"10.2.0.{i % 3}") for i in range(16)]
    out = login_failure_rca(events, now=NOW)
    f = next(f for f in out["findings"] if f["kind"] == "misconfigured-client")
    assert f["subject"] == "billing-svc" and f["failures"] == 16
    assert "secret" in f["action"]


@pytest.mark.unit
def test_rca_flags_expired_credential_storm_and_lockout_storm():
    expired = [_ev(user=f"emp{i}", error="expired_password") for i in range(12)]
    locked = [_ev(user=f"lock{i}", error="user_temporarily_disabled") for i in range(6)]
    out = login_failure_rca(expired + locked, now=NOW)
    kinds = {f["kind"] for f in out["findings"]}
    assert "expired-credential-storm" in kinds
    assert "lockout-storm" in kinds


@pytest.mark.unit
def test_rca_window_excludes_old_events_and_reports_thresholds():
    old = [_ev(user=f"user{i}", ip="9.9.9.9", t=NOW - 7200) for i in range(30)]
    out = login_failure_rca(old, window_minutes=60, now=NOW)
    assert out["failuresEvaluated"] == 0
    assert out["findings"] == []
    assert out["thresholds"]["sprayUserSpread"] == 5
    assert out["windowMinutes"] == 60


@pytest.mark.unit
def test_rca_empty_feed_is_calm():
    out = login_failure_rca([], now=NOW)
    assert out["failuresEvaluated"] == 0 and out["findings"] == []


# ── 2. stale_access_audit ────────────────────────────────────────────────────


def _user(username, enabled=True, last_login="", created="", svc=False):
    return {"id": username, "username": username, "enabled": enabled,
            "lastLogin": last_login, "created": created, "serviceAccount": svc}


@pytest.mark.unit
def test_stale_audit_flags_idle_users_with_day_counts():
    users = [
        _user("dormant", last_login=(NOW - 200 * DAY) * 1000),
        _user("active", last_login=(NOW - 5 * DAY) * 1000),
    ]
    out = stale_access_audit(users, stale_days=90, now=NOW)
    assert out["staleCount"] == 1
    stale = out["staleUsers"][0]
    assert stale["username"] == "dormant" and stale["daysSinceLogin"] == 200
    assert "action" in stale


@pytest.mark.unit
def test_stale_audit_uses_login_events_for_last_seen():
    users = [_user("kc-user", created=(NOW - 400 * DAY) * 1000)]
    logins = [{"time": (NOW - 2 * DAY) * 1000, "type": "LOGIN", "user": "kc-user"}]
    out = stale_access_audit(users, logins, stale_days=90, now=NOW)
    assert out["staleCount"] == 0 and out["neverLoggedInCount"] == 0


@pytest.mark.unit
def test_stale_audit_flags_never_logged_in_old_accounts_only():
    users = [
        _user("ghost", created=(NOW - 120 * DAY) * 1000),
        _user("fresh", created=(NOW - 3 * DAY) * 1000),  # too new to judge
        _user("gone", enabled=False, created=(NOW - 120 * DAY) * 1000),  # disabled
    ]
    out = stale_access_audit(users, stale_days=90, now=NOW)
    assert [u["username"] for u in out["neverLoggedIn"]] == ["ghost"]


@pytest.mark.unit
def test_stale_audit_flags_interactive_service_accounts():
    users = [_user("service-account-ci", svc=True, last_login=(NOW - DAY) * 1000)]
    out = stale_access_audit(users, stale_days=90, now=NOW)
    assert out["serviceAccountsInteractiveCount"] == 1
    assert out["staleCount"] == 0  # service accounts never counted as stale humans


@pytest.mark.unit
def test_stale_audit_flags_orphaned_sessions():
    users = [_user("alice"), _user("mallory", enabled=False)]
    sessions = [
        {"id": "s1", "username": "alice"},
        {"id": "s2", "username": "mallory"},  # disabled user
        {"id": "s3", "username": "deleted-user"},  # unknown user
    ]
    out = stale_access_audit(users, sessions=sessions, stale_days=90, now=NOW)
    assert out["orphanedSessionCount"] == 2
    assert {o["sessionId"] for o in out["orphanedSessions"]} == {"s2", "s3"}


# ── 3. client_misconfig_audit ────────────────────────────────────────────────


def _client(client_id, **kw):
    base = {"id": client_id, "clientId": client_id, "enabled": True,
            "publicClient": False, "redirectUris": ["https://ok.example.com/cb"],
            "implicitFlow": False, "directAccessGrants": False,
            "secretConfigured": False, "pkceMethod": "S256"}
    base.update(kw)
    return base


@pytest.mark.unit
def test_misconfig_flags_wildcard_and_http_redirects():
    out = client_misconfig_audit([
        _client("bad", redirectUris=["https://a/*", "http://intranet/cb"]),
    ])
    issues = {f["issue"] for f in out["ranked"][0]["findings"]}
    assert {"wildcard-redirect-uri", "http-redirect-uri"} <= issues
    assert out["ranked"][0]["riskScore"] == 60  # two high findings


@pytest.mark.unit
def test_misconfig_localhost_http_is_tolerated():
    out = client_misconfig_audit([
        _client("dev", redirectUris=["http://localhost:3000/cb"]),
    ])
    assert out["clientsFlagged"] == 0


@pytest.mark.unit
def test_misconfig_flags_public_client_with_secret_and_missing_pkce():
    out = client_misconfig_audit([
        _client("spa", publicClient=True, secretConfigured=True, pkceMethod=""),
    ])
    issues = {f["issue"] for f in out["ranked"][0]["findings"]}
    assert "public-client-with-secret" in issues
    assert "public-client-missing-pkce" in issues


@pytest.mark.unit
def test_misconfig_flags_implicit_and_password_grant_and_ranks():
    out = client_misconfig_audit([
        _client("legacy", implicitFlow=True, directAccessGrants=True),
        _client("meh", directAccessGrants=True),
        _client("clean"),
    ])
    assert out["clientsEvaluated"] == 3 and out["clientsFlagged"] == 2
    assert [r["clientId"] for r in out["ranked"]] == ["legacy", "meh"]
    assert out["ranked"][0]["riskScore"] > out["ranked"][1]["riskScore"]


@pytest.mark.unit
def test_misconfig_skips_disabled_clients():
    out = client_misconfig_audit([_client("off", enabled=False, implicitFlow=True)])
    assert out["clientsEvaluated"] == 0 and out["clientsFlagged"] == 0


# ── 4. mfa_coverage_analysis ─────────────────────────────────────────────────


@pytest.mark.unit
def test_mfa_coverage_percentages_and_gap_list():
    users = [_user("alice"), _user("bob"), _user("svc", svc=True),
             _user("off", enabled=False)]
    creds = {
        "alice": [{"type": "otp", "secondFactor": True, "confirmed": True}],
        "bob": [{"type": "password", "secondFactor": False, "confirmed": True}],
    }
    out = mfa_coverage_analysis(users, creds)
    # svc + disabled users excluded: 2 evaluated, 1 covered.
    assert out["usersEvaluated"] == 2
    assert out["coveragePct"] == 50.0
    assert out["usersWithoutMfa"] == ["bob"]


@pytest.mark.unit
def test_mfa_unconfirmed_device_does_not_count():
    users = [_user("carol")]
    creds = {"carol": [{"type": "totp", "secondFactor": True, "confirmed": False}]}
    out = mfa_coverage_analysis(users, creds)
    assert out["withoutMfa"] == 1


@pytest.mark.unit
def test_mfa_per_group_breakdown_sorted_worst_first():
    users = [_user("a"), _user("b"), _user("c")]
    creds = {"a": [{"type": "webauthn", "secondFactor": True, "confirmed": True}]}
    groups = {"a": ["eng"], "b": ["eng"], "c": ["sales"]}
    out = mfa_coverage_analysis(users, creds, groups_by_user=groups)
    assert out["perGroup"][0]["group"] == "sales"  # 0% first
    eng = next(g for g in out["perGroup"] if g["group"] == "eng")
    assert eng["coveragePct"] == 50.0 and eng["users"] == 2


@pytest.mark.unit
def test_mfa_empty_realm_is_zero_not_crash():
    out = mfa_coverage_analysis([], {})
    assert out["usersEvaluated"] == 0 and out["coveragePct"] == 0.0
