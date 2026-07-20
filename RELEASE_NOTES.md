# Release notes — identity-aiops 0.2.1

Previous release: 0.2.0.

## Live-verified: Keycloak

No behaviour changes. This release records the first end-to-end run against a real
**Keycloak 26.0**:

- `doctor`, the reads, and all four analyses (`login_failure_rca`,
  `stale_access_audit`, `client_misconfig_audit`, `mfa_coverage_analysis`).
- Governance loop: `disable_user` really disabled the account on the live server,
  captured `{"enabled": true}` as `priorState`, and `undo_apply` re-enabled it —
  all three calls audited under a named approver.
- Confirmed the auth model: this tool authenticates as a **confidential client via
  `client_credentials`** (service account), not a username/password login. A user
  credential fails with a 401 that correctly names the client_id/secret as the thing
  to check.

See [docs/VERIFICATION.md](docs/VERIFICATION.md) — **Authentik remains unverified**,
and the lab realm was too small for the analyses to be verified as *classifying
correctly at scale* (only as executing correctly).
