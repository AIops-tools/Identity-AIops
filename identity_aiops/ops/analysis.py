"""Flagship signature analyses over identity telemetry (pure analysis).

These are the differentiators — transparent heuristics, every flag reported
with its numbers so an operator can see *why* something was ranked, never a
black-box verdict:

  1. ``login_failure_rca`` — window the failed-auth events by user / IP /
     client and separate brute-force (spray or targeted) from a misconfigured
     client from an expired-credential storm — each finding carries a likely
     cause + recommended action.
  2. ``stale_access_audit`` — enabled users not seen for N days, accounts that
     have never logged in, service accounts with interactive logins, and
     sessions orphaned by disabled/deleted users.
  3. ``client_misconfig_audit`` — wildcard or plain-http redirect URIs, public
     clients carrying secrets, implicit flow, missing PKCE, password grant —
     ranked risk findings per client.
  4. ``mfa_coverage_analysis`` — enabled human users without a configured
     second factor, overall and per group coverage %.

All four are pure functions (no I/O): pass them the telemetry (from the reads
in the other ops modules, or injected) and they return the analysis. The live
pulls that feed them live in the ``pull_*`` helpers.
"""

from __future__ import annotations

import time
from typing import Any

from identity_aiops.ops import clients as client_ops
from identity_aiops.ops import events as event_ops
from identity_aiops.ops import users as user_ops
from identity_aiops.ops._util import epoch_seconds, s
from identity_aiops.platform import KEYCLOAK

MAX_ROWS = 100

# ── 1. login-failure / lockout-storm RCA ─────────────────────────────────────
DEFAULT_WINDOW_MINUTES = 60
BRUTE_FORCE_USER_THRESHOLD = 10  # failures against one user in the window
IP_SPRAY_USER_SPREAD = 5  # distinct users targeted from one IP
IP_FAILURE_THRESHOLD = 20  # failures from one IP in the window
CLIENT_FAILURE_THRESHOLD = 15  # client-credential failures for one client
EXPIRED_STORM_USER_THRESHOLD = 10  # distinct users with expired-credential errors
LOCKOUT_STORM_USER_THRESHOLD = 5  # distinct users hitting lockout errors

# Error vocabularies (Keycloak error codes; authentik context messages fold in).
_CLIENT_ERRORS = {"invalid_client_credentials", "invalid_client", "invalid_client_secret",
                  "client_not_found", "client_disabled", "unauthorized_client"}
_EXPIRED_ERRORS = {"expired_password", "expired_code", "invalid_token", "stale_code"}
_LOCKOUT_ERRORS = {"user_temporarily_disabled", "user_disabled", "account_locked"}


def pull_failed_logins(conn: Any, limit: int = 500) -> list[dict]:
    """[READ] Live failed-login events for the RCA."""
    return event_ops.failed_login_events(conn, max_results=limit)


def _bucket(agg: dict[str, dict], key: str, event: dict, spread_field: str) -> None:
    entry = agg.setdefault(key, {"failures": 0, "spread": set(), "errors": {}})
    entry["failures"] += 1
    spread_val = event.get(spread_field) or "?"
    entry["spread"].add(spread_val)
    err = str(event.get("error") or "unknown").lower()
    entry["errors"][err] = entry["errors"].get(err, 0) + 1


def _top_error(errors: dict[str, int]) -> str:
    return max(errors, key=lambda e: errors[e]) if errors else "unknown"


def login_failure_rca(
    events: list[dict],
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
    now: float | None = None,
) -> dict:
    """[READ] Separate brute-force / misconfigured-client / expired-credential
    storms in the failed-auth feed — cause + action per finding.

    Pure analysis over normalized event rows (from ``pull_failed_logins`` or
    injected): {time, type, user, ip, client, error}. Only events inside the
    trailing window are considered (``now`` defaults to the newest event so a
    replayed feed analyses itself). Findings:

      * **password-spray** — one IP failing against >= sprayUserSpread users.
      * **targeted-brute-force** — one user with >= bruteForceUserThreshold
        failures (multi-IP), or single-IP (reads as a stuck automation /
        stale stored credential).
      * **misconfigured-client** — one client with >= clientFailureThreshold
        client-credential errors (a rotated secret not yet deployed).
      * **expired-credential-storm** — >= expiredStormUserThreshold distinct
        users failing with expiry-type errors (policy rollout fallout).
      * **lockout-storm** — >= lockoutStormUserThreshold distinct users hitting
        lockout errors (brute-force tripping protection, or a policy change).

    Every finding carries its numbers.
    """
    rows = [e for e in (events or [])
            if str(e.get("type", "")).upper() in event_ops.LOGIN_FAIL_TYPES
            or e.get("error")]
    if now is None:
        now = max((epoch_seconds(e.get("time")) for e in rows), default=time.time())
    cutoff = now - window_minutes * 60
    windowed = [e for e in rows if epoch_seconds(e.get("time")) >= cutoff]

    by_ip: dict[str, dict] = {}
    by_user: dict[str, dict] = {}
    by_client: dict[str, dict] = {}
    for e in windowed:
        _bucket(by_ip, s(e.get("ip")) or "(unknown)", e, "user")
        _bucket(by_user, s(e.get("user")) or "(unknown)", e, "ip")
        _bucket(by_client, s(e.get("client")) or "(unknown)", e, "user")

    findings: list[dict] = []

    for ip, b in by_ip.items():
        if b["failures"] >= IP_FAILURE_THRESHOLD and len(b["spread"]) >= IP_SPRAY_USER_SPREAD:
            findings.append({
                "kind": "password-spray",
                "subject": ip,
                "failures": b["failures"],
                "distinctUsers": len(b["spread"]),
                "topError": _top_error(b["errors"]),
                "cause": f"Password spray / brute-force from one IP — {b['failures']} "
                f"failures against {len(b['spread'])} distinct users",
                "action": "Block the source IP at the edge, verify brute-force "
                "protection is enabled, and force MFA on privileged accounts.",
            })

    for user, b in by_user.items():
        if b["failures"] < BRUTE_FORCE_USER_THRESHOLD:
            continue
        top_err = _top_error(b["errors"])
        if top_err in _LOCKOUT_ERRORS:
            continue  # counted by the lockout-storm rule below
        if len(b["spread"]) > 1:
            findings.append({
                "kind": "targeted-brute-force",
                "subject": user,
                "failures": b["failures"],
                "distinctIps": len(b["spread"]),
                "topError": top_err,
                "cause": f"Targeted brute-force on one account — {b['failures']} "
                f"failures from {len(b['spread'])} IPs",
                "action": "Temporarily disable or step-up the account (require "
                "MFA + password reset) and review the source IPs.",
            })
        else:
            findings.append({
                "kind": "stale-stored-credential",
                "subject": user,
                "failures": b["failures"],
                "distinctIps": 1,
                "topError": top_err,
                "cause": f"One account failing repeatedly from a single IP — "
                f"{b['failures']} failures; reads as an automation retrying a "
                f"stale/rotated password, not an attack",
                "action": "Find the job/device at that IP and update its stored "
                "credential; consider a service account with client credentials.",
            })

    for client, b in by_client.items():
        client_errs = sum(n for e, n in b["errors"].items() if e in _CLIENT_ERRORS)
        if client_errs >= CLIENT_FAILURE_THRESHOLD:
            findings.append({
                "kind": "misconfigured-client",
                "subject": client,
                "failures": client_errs,
                "topError": _top_error(b["errors"]),
                "cause": f"Client-credential failures concentrated on one client "
                f"({client_errs} in window) — a rotated/expired client secret "
                f"still deployed somewhere",
                "action": "Update the deployed client secret (or roll it back), "
                "then rotate properly with rotate_client_secret once deploys align.",
            })

    expired_users = {u for u, b in by_user.items()
                     if any(e in _EXPIRED_ERRORS for e in b["errors"])}
    if len(expired_users) >= EXPIRED_STORM_USER_THRESHOLD:
        findings.append({
            "kind": "expired-credential-storm",
            "subject": f"{len(expired_users)} users",
            "distinctUsers": len(expired_users),
            "cause": f"{len(expired_users)} distinct users failing with expiry-type "
            f"errors — a password/OTP policy change or mass expiry is biting",
            "action": "Confirm the recent policy change, communicate it, and stage "
            "resets (require_password_reset) instead of letting lockouts pile up.",
        })

    lockout_users = {u for u, b in by_user.items()
                     if any(e in _LOCKOUT_ERRORS for e in b["errors"])}
    if len(lockout_users) >= LOCKOUT_STORM_USER_THRESHOLD:
        findings.append({
            "kind": "lockout-storm",
            "subject": f"{len(lockout_users)} users",
            "distinctUsers": len(lockout_users),
            "cause": f"{len(lockout_users)} distinct users hitting lockout errors — "
            f"brute-force tripping protection, or an aggressive lockout policy",
            "action": "Correlate with the spray/brute-force findings above before "
            "unlocking; if benign, tune the lockout thresholds.",
        })

    def _rank(f: dict) -> float:
        return float(f.get("failures", 0) or f.get("distinctUsers", 0))

    findings.sort(key=_rank, reverse=True)

    def _table(agg: dict[str, dict], spread_name: str) -> list[dict]:
        rows_out = [
            {"subject": k, "failures": b["failures"], spread_name: len(b["spread"]),
             "topError": _top_error(b["errors"])}
            for k, b in agg.items()
        ]
        rows_out.sort(key=lambda r: r["failures"], reverse=True)
        return rows_out[:10]

    return {
        "failuresEvaluated": len(windowed),
        "windowMinutes": window_minutes,
        "thresholds": {
            "bruteForceUserThreshold": BRUTE_FORCE_USER_THRESHOLD,
            "ipFailureThreshold": IP_FAILURE_THRESHOLD,
            "sprayUserSpread": IP_SPRAY_USER_SPREAD,
            "clientFailureThreshold": CLIENT_FAILURE_THRESHOLD,
            "expiredStormUserThreshold": EXPIRED_STORM_USER_THRESHOLD,
            "lockoutStormUserThreshold": LOCKOUT_STORM_USER_THRESHOLD,
        },
        "byIp": _table(by_ip, "distinctUsers"),
        "byUser": _table(by_user, "distinctIps"),
        "byClient": _table(by_client, "distinctUsers"),
        "findings": findings[:MAX_ROWS],
        "note": (
            "Advisory read-only heuristic over the failed-auth feed; findings "
            "show their numbers. Event retention on the IdP bounds what this "
            "sees — correlate before blocking or unlocking."
        ),
    }


# ── 2. stale-access audit ────────────────────────────────────────────────────
DEFAULT_STALE_DAYS = 90


def pull_stale_inputs(conn: Any, max_users: int = 500) -> tuple[list, list, list]:
    """[READ] Live users + successful-login events (+ sessions where the
    platform lists them) for the stale-access audit."""
    users_out = user_ops.list_users(conn, max_results=max_users)
    users = users_out.get("users", []) if "error" not in users_out else []
    is_kc = conn.target.platform == KEYCLOAK
    ok_type = "LOGIN" if is_kc else "login"
    ev_out = event_ops.login_events(conn, event_type=ok_type, max_results=500)
    logins = ev_out.get("events", []) if "error" not in ev_out else []
    sessions: list[dict] = []
    if conn.platform.supports("sessions"):
        try:
            rows = conn.platform.rows(
                conn.get(conn.path("sessions"), params={"page_size": 500})
            )
            sessions = [
                {
                    "id": r.get("uuid") or r.get("id") or "",
                    "username": (r.get("user") or {}).get("username", "")
                    if isinstance(r.get("user"), dict)
                    else r.get("user") or "",
                }
                for r in rows
            ]
        except Exception:  # noqa: BLE001 — sessions are optional input
            sessions = []
    return users, logins, sessions


def stale_access_audit(
    users: list[dict],
    login_events: list[dict] | None = None,
    sessions: list[dict] | None = None,
    stale_days: int = DEFAULT_STALE_DAYS,
    now: float | None = None,
) -> dict:
    """[READ] Flag stale, never-used, and mis-used accounts + orphaned sessions.

    Pure analysis over normalized user rows {id, username, enabled, created,
    lastLogin, serviceAccount}, successful-login events {time, user, type},
    and session rows {id, user, username}. Reported findings:

      * **staleUsers** — enabled human users whose last sign-in is older than
        ``stale_days`` (dormant access = takeover surface).
      * **neverLoggedIn** — enabled human users with no sign-in on record and
        an account older than ``stale_days`` (provisioned but unused).
      * **serviceAccountsInteractive** — service accounts with interactive
        sign-ins (credential drift: a human is using a machine identity).
      * **orphanedSessions** — sessions whose user is disabled or unknown
        (should have been revoked).

    Last sign-in = the user row's ``lastLogin`` (authentik) or the newest
    successful login event (Keycloak) — event retention bounds the Keycloak
    view; the note says so.
    """
    now = now if now is not None else time.time()
    cutoff = now - stale_days * 86400

    last_login: dict[str, float] = {}
    for e in login_events or []:
        if str(e.get("type", "")).upper() not in event_ops.LOGIN_OK_TYPES:
            continue
        u = str(e.get("user") or "")
        if u:
            last_login[u] = max(last_login.get(u, 0.0), epoch_seconds(e.get("time")))

    stale, never, svc_interactive = [], [], []
    enabled_by_name: dict[str, bool] = {}
    for u in users or []:
        uname = str(u.get("username") or "")
        enabled_by_name[uname] = bool(u.get("enabled", True))
        seen = max(epoch_seconds(u.get("lastLogin")), last_login.get(uname, 0.0))
        if u.get("serviceAccount"):
            if seen > 0:
                svc_interactive.append({
                    "username": s(uname),
                    "lastInteractiveLogin": s(u.get("lastLogin") or ""),
                    "cause": "Service account with an interactive sign-in — a "
                    "human is using a machine identity",
                    "action": "Rotate its credential and move the human to a "
                    "personal account; alert if unexpected.",
                })
            continue
        if not u.get("enabled", True):
            continue
        created = epoch_seconds(u.get("created"))
        if seen == 0:
            if created and created < cutoff:
                never.append({
                    "username": s(uname),
                    "created": s(u.get("created") or ""),
                    "cause": f"Enabled account, no sign-in on record, older than "
                    f"{stale_days} days",
                    "action": "Confirm with the owner/manager, then disable_user "
                    "until it is actually needed.",
                })
        elif seen < cutoff:
            stale.append({
                "username": s(uname),
                "daysSinceLogin": int((now - seen) // 86400),
                "cause": f"Enabled account idle for more than {stale_days} days",
                "action": "Disable (disable_user) or re-certify the access; "
                "dormant accounts are prime takeover targets.",
            })

    orphaned = []
    for sess in sessions or []:
        uname = str(sess.get("username") or sess.get("user") or "")
        known = enabled_by_name.get(uname)
        if known is None or known is False:
            orphaned.append({
                "sessionId": s(sess.get("id") or ""),
                "username": s(uname) or "(unknown)",
                "cause": "Session belongs to a disabled or unknown user",
                "action": "Revoke it (revoke_user_sessions) and check why "
                "disable did not cascade.",
            })

    stale.sort(key=lambda r: r["daysSinceLogin"], reverse=True)
    return {
        "usersEvaluated": len(users or []),
        "staleDays": stale_days,
        "staleCount": len(stale),
        "neverLoggedInCount": len(never),
        "serviceAccountsInteractiveCount": len(svc_interactive),
        "orphanedSessionCount": len(orphaned),
        "staleUsers": stale[:MAX_ROWS],
        "neverLoggedIn": never[:MAX_ROWS],
        "serviceAccountsInteractive": svc_interactive[:MAX_ROWS],
        "orphanedSessions": orphaned[:MAX_ROWS],
        "note": (
            "Advisory read-only heuristic. Last sign-in comes from the user "
            "record and the IdP's event feed — event retention bounds the view "
            "(a user seen 0 times may simply predate retention). Re-certify "
            "before disabling."
        ),
    }


# ── 3. client/app misconfiguration audit ─────────────────────────────────────
_LOCALHOST_MARKERS = ("http://localhost", "http://127.0.0.1", "http://[::1]")

# severity → score weight; findings rank by summed score.
_SEVERITY_SCORE = {"high": 30, "medium": 15, "low": 5}


def pull_clients(conn: Any, max_results: int = 200) -> list[dict]:
    """[READ] Live normalized client rows for the misconfiguration audit."""
    out = client_ops.list_clients(conn, max_results=max_results)
    return out.get("clients", []) if "error" not in out else []


def _client_findings(c: dict) -> list[dict]:
    findings = []
    uris = c.get("redirectUris") or []
    wildcards = [u for u in uris if "*" in u]
    if wildcards:
        findings.append({
            "issue": "wildcard-redirect-uri", "severity": "high",
            "evidence": wildcards[:5],
            "action": "Replace wildcard redirect URIs with exact URLs — wildcards "
            "enable token/code redirection to attacker pages.",
        })
    plain_http = [u for u in uris
                  if u.lower().startswith("http://") and not u.lower().startswith(
                      _LOCALHOST_MARKERS)]
    if plain_http:
        findings.append({
            "issue": "http-redirect-uri", "severity": "high",
            "evidence": plain_http[:5],
            "action": "Serve redirect URIs over https — authorization codes leak "
            "in clear text on http (localhost excepted for dev).",
        })
    if c.get("publicClient") and c.get("secretConfigured"):
        findings.append({
            "issue": "public-client-with-secret", "severity": "medium",
            "evidence": ["client_type=public but a client secret is configured"],
            "action": "Remove the secret or make the client confidential — a "
            "secret in a public client (SPA/mobile) is extractable.",
        })
    if c.get("implicitFlow"):
        findings.append({
            "issue": "implicit-flow-enabled", "severity": "high",
            "evidence": ["implicit grant enabled"],
            "action": "Disable the implicit grant and move to authorization code "
            "+ PKCE (OAuth 2.0 Security BCP).",
        })
    if c.get("publicClient") and not c.get("pkceMethod"):
        findings.append({
            "issue": "public-client-missing-pkce", "severity": "high",
            "evidence": ["no PKCE code-challenge method pinned"],
            "action": "Pin the PKCE code-challenge method to S256 for this public "
            "client — without it, code interception is exploitable.",
        })
    if c.get("directAccessGrants"):
        findings.append({
            "issue": "password-grant-enabled", "severity": "medium",
            "evidence": ["direct access (resource-owner password) grant enabled"],
            "action": "Disable the password grant — it bypasses MFA and web "
            "policies; move callers to client credentials or auth code.",
        })
    return findings


def client_misconfig_audit(clients: list[dict]) -> dict:
    """[READ] Rank enabled clients by OAuth/OIDC misconfiguration risk.

    Pure analysis over normalized client rows (from ``pull_clients`` or
    injected): {clientId, enabled, publicClient, redirectUris, implicitFlow,
    directAccessGrants, secretConfigured, pkceMethod}. Checks: wildcard and
    plain-http redirect URIs, public clients carrying secrets, implicit flow,
    missing PKCE on public clients, and the password grant. Each client gets a
    riskScore (summed severity weights) and every finding names its evidence +
    action. Disabled clients are skipped.
    """
    ranked = []
    total_findings = 0
    evaluated = 0
    for c in clients or []:
        if not c.get("enabled", True):
            continue
        evaluated += 1
        findings = _client_findings(c)
        if not findings:
            continue
        total_findings += len(findings)
        ranked.append({
            "clientId": s(c.get("clientId") or c.get("name") or c.get("id")),
            "publicClient": bool(c.get("publicClient")),
            "riskScore": sum(_SEVERITY_SCORE.get(f["severity"], 0) for f in findings),
            "findings": findings,
        })
    ranked.sort(key=lambda r: r["riskScore"], reverse=True)
    return {
        "clientsEvaluated": evaluated,
        "clientsFlagged": len(ranked),
        "findingsCount": total_findings,
        "severityWeights": dict(_SEVERITY_SCORE),
        "ranked": ranked[:MAX_ROWS],
        "note": (
            "Advisory read-only heuristic per the OAuth 2.0 Security BCP: "
            "riskScore = sum of severity weights; every finding lists its "
            "evidence. Verify intent before changing a production client."
        ),
    }


# ── 4. MFA coverage analysis ─────────────────────────────────────────────────
def pull_mfa_inputs(conn: Any, max_users: int = 200) -> tuple[list, dict]:
    """[READ] Live users + per-user credential lists for the MFA analysis.

    Credential lookup is one call per user, so the pull is bounded by
    ``max_users`` (the analysis reports the bound).
    """
    users_out = user_ops.list_users(conn, max_results=max_users)
    users = users_out.get("users", []) if "error" not in users_out else []
    creds: dict[str, list] = {}
    for u in users:
        uid = str(u.get("id") or "")
        if not uid:
            continue
        cred_out = user_ops.user_credentials(conn, uid)
        creds[str(u.get("username") or uid)] = (
            cred_out.get("credentials", []) if "error" not in cred_out else []
        )
    return users, creds


def mfa_coverage_analysis(
    users: list[dict],
    credentials_by_user: dict[str, list],
    groups_by_user: dict[str, list[str]] | None = None,
) -> dict:
    """[READ] Second-factor coverage: overall %, per group %, and the gap list.

    Pure analysis over normalized user rows and a mapping of username →
    normalized credential rows (from ``pull_mfa_inputs`` or injected). A user
    *has MFA* when at least one confirmed credential of a second-factor type
    (otp/totp/hotp/webauthn/duo/sms) exists. Only enabled human users count —
    service accounts authenticate with client credentials, not MFA. When
    ``groups_by_user`` is provided, coverage is also broken down per group.
    """
    covered, uncovered = [], []
    for u in users or []:
        if not u.get("enabled", True) or u.get("serviceAccount"):
            continue
        uname = str(u.get("username") or u.get("id") or "")
        creds = credentials_by_user.get(uname, [])
        has_mfa = any(
            c.get("secondFactor") and c.get("confirmed", True) for c in creds
        )
        (covered if has_mfa else uncovered).append(uname)

    evaluated = len(covered) + len(uncovered)
    pct = round(100.0 * len(covered) / evaluated, 1) if evaluated else 0.0

    per_group = []
    if groups_by_user:
        group_totals: dict[str, list[int]] = {}
        for uname in covered:
            for g in groups_by_user.get(uname, []):
                group_totals.setdefault(g, [0, 0])[0] += 1
        for uname in uncovered:
            for g in groups_by_user.get(uname, []):
                group_totals.setdefault(g, [0, 0])[1] += 1
        for g, (cov, uncov) in sorted(group_totals.items()):
            total = cov + uncov
            per_group.append({
                "group": s(g),
                "users": total,
                "withMfa": cov,
                "coveragePct": round(100.0 * cov / total, 1) if total else 0.0,
            })
        per_group.sort(key=lambda r: r["coveragePct"])

    return {
        "usersEvaluated": evaluated,
        "withMfa": len(covered),
        "withoutMfa": len(uncovered),
        "coveragePct": pct,
        "secondFactorTypes": sorted(user_ops.SECOND_FACTOR_TYPES),
        "perGroup": per_group[:MAX_ROWS],
        "usersWithoutMfa": [s(u) for u in uncovered[:MAX_ROWS]],
        "note": (
            "Advisory read-only heuristic: a user counts as covered when a "
            "confirmed second-factor credential exists. Enabled human users "
            "only (service accounts excluded). Credential pulls are bounded — "
            "large realms are sampled by the pull limit."
        ),
    }
