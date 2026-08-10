# Live verification status

This document records what has and has not been validated against real identity
providers, so the maturity claim is auditable rather than a vibe.

## Already live-verified ✅ — Keycloak 26.0 and authentik 2024.10 (2026-07-20)

- `doctor` against a live server: OIDC token exchange, then a user-count probe.
- **The auth model is confirmed to be service-account based**: the tool exchanges a
  confidential client's `client_id` + secret via `grant_type=client_credentials`.
  It is *not* a username/password login — a user credential fails with a 401 whose
  message names the client_id/secret as the thing to check, which is correct.
  The verified setup was a confidential client with service accounts enabled and
  the realm `admin` role granted.
- Reads: `overview`, `users list`, `clients list`.
- All four analyses ran clean against the live realm: `login_failure_rca`,
  `stale_access_audit`, `client_misconfig_audit`, `mfa_coverage_analysis`.
- Governance loop end-to-end: `disable_user` really disabled the account on the
  live server (`enabled: false` confirmed via the admin API), captured
  `{"enabled": true}` as `priorState`, and `undo_apply` re-enabled it — with all
  three calls (`disable_user`, `enable_user`, `undo_apply`) audited.

## Not yet live-verified ⚠️

- **authentik is now verified too** — `doctor`, the reads, all four analyses, and
  the governance loop (`disable_user` → `undo_apply`) against a live server. That
  run produced the self-lockout finding: disabling the account whose token the tool
  holds succeeded, then the undo failed 403. `disable_user` now refuses that, with
  the tool's own identity resolved from the Keycloak token's `sub` claim or
  authentik's `/core/users/me/`. Both paths verified live.
- ~~**Session-management writes**, non-master realms, TLS-secured Keycloak.~~
  **Closed 2026-08-10 against a live Keycloak 26.0 serving HTTPS with its own
  certificate, in a non-master realm (`labrealm`) holding three real users, four
  real sessions and thirty real failed logins.**
  - **TLS is really enforced**: with `verify_ssl: true` against the self-signed
    certificate the token exchange fails with `CERTIFICATE_VERIFY_FAILED` and
    `doctor` exits non-zero; with verification off the same target connects.
    Every read and write below ran over HTTPS against `realm: labrealm`, so the
    non-master path is exercised throughout, not asserted.
  - `revoke-sessions`: alice's **three** real sessions matched the admin API
    exactly (same ids, same client) before the call and were **0** after, while
    bob's session was untouched — the blast radius is what the payload claimed.
    Both the dry-run and the real call landed audit rows, and **no undo token was
    recorded**, which is correct for an irreversible operation.
  - `require-reset`: the flag reached the server, and it *bit* — bob could no
    longer complete a password grant ("Account is not fully set up"). `undo apply`
    cleared it and bob could sign in again. Full round trip, both ends confirmed
    on the server.
  - `rotate-secret`: refused for the tool's own client (self-lockout guard), and
    on a different client it really rotated — the server's secret changed to a
    32-character value matching the returned mask. Audited `review`; no undo,
    which is correct because the old secret is gone.
  - The refusals audited as `error` and the successes as `ok`: audit fidelity was
    right in every case. What was **wrong was the exit code** — see below.
- **Realistic analysis inputs**: `login_failure_rca` now has a real population
  (12 same-IP failures for one account, 5 for another, 3 for a nonexistent user)
  and classified the first as `stale-stored-credential` — an automation retrying
  a rotated password — which is the correct reading. `stale_access_audit`
  correctly declined to flag a never-logged-in account that was minutes old
  (`created < cutoff` guard); that is deliberate, not a miss. Still unproven at
  fleet scale: a realm with hundreds of users and a real MFA-less population.

## Fixed by the 2026-08-10 run

- **CLI governed writes exited 0 on failure.** The self-lockout refusal of
  `rotate-secret` printed its reason and exited **0**, as did a write against a
  nonexistent user — while the dry-run path already exited 1, so the preview was
  stricter than the real call. Everything downstream of a `&&`, and every CI job,
  read a refused write as a successful one. Now routed through `checked()`.
- **Timestamps were raw and platform-dependent.** `created`, `lastLogin`,
  `started`, `lastAccess` and the event `time` were emitted exactly as the IdP
  sent them: Keycloak epoch-**milliseconds** rendered as a string of digits
  (`"1786335328000"`), authentik ISO-8601. The same field name therefore carried
  two incompatible formats depending on the target, and on Keycloak it was not a
  timestamp a consumer could subtract from `now` at all — in a tool whose whole
  premise is spanning a mixed estate. All eleven now render ISO-8601 UTC, and
  absent stays `null`.
