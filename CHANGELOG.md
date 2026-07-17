# Changelog

## v0.1.0 — 2026-07-17

Initial preview release.

- **27 MCP tools** (21 read incl. 4 flagship analyses, 6 governed writes) across
  **Keycloak** (admin REST API, client-credentials grant with refresh-on-401)
  and **authentik** (API v3, Bearer token), selected per target by a
  name-keyed platform registry.
- **Flagship analyses**: `login_failure_rca` (password spray / targeted
  brute-force / stale stored credential / misconfigured client /
  expired-credential storm / lockout storm), `stale_access_audit` (idle users,
  never-logged-in accounts, interactive service accounts, orphaned sessions),
  `client_misconfig_audit` (wildcard/http redirect URIs, public clients with
  secrets, implicit flow, missing PKCE, password grant — ranked riskScore),
  `mfa_coverage_analysis` (overall + per-group coverage %, gap list).
- **Governed writes** with dry-run previews, fetched prior state, and undo where
  reversible: `disable_user` / `enable_user` (undo pair),
  `revoke_user_sessions` (priorState session count, no undo),
  `require_password_reset` (undo clears the flag via `clear=True`),
  `update_client_redirect_uris` (undo replays the prior list),
  `rotate_client_secret` (masked priorState, no undo).
- **Secure by default**: with no `rules.yaml`, high-risk writes require a named
  approver (`IDENTITY_AUDIT_APPROVED_BY`); `init` seeds a dual-control starter
  rules file (never clobbers an operator-authored one).
- **Encrypted secret store** (`secrets.enc`, Fernet + scrypt); TLS verification
  defaults ON; central percent-encoding of every URL path segment.
- Vendored governance harness (audit / budget / risk tiers / undo / sanitize) —
  zero external skill-family dependencies.
- Preview / mock-only: modelled on the public Keycloak and authentik APIs,
  validated against mocked responses; `identity-aiops doctor` (token
  acquisition + user-count probe) is the fastest live check.
