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
- **Realistic analysis inputs**: the lab realm had one service account and one test
  user, so `login_failure_rca` and `mfa_coverage_analysis` ran but had no real
  failure history or MFA-less population to rank. They are verified as *executing
  correctly*, not as *classifying correctly at scale*.
- **Session-management writes** (`revoke-sessions`, `require-reset`,
  `rotate-secret`) and their undo paths.
- Non-master realms, and TLS-secured Keycloak endpoints.
