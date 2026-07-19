# Live verification — identity-aiops

`identity-aiops` is published and its behaviour is exercised by a **mock-only**
test suite. It has **not** yet been validated end-to-end against a live
Keycloak or authentik instance. Until it has, we make no claim that the modelled
REST paths and field shapes match a real deployment of either platform.

This tool spans **two** platforms behind one tool surface, which doubles the
verification obligation: a green run against Keycloak says nothing about
authentik, and vice versa. The concrete REST paths are the largest verification
debt.

This document defines exactly what a live verification run must cover, and the
criteria for recording this tool as live-verified. It is deliberately
checklist-shaped so the result is reproducible and auditable — not a subjective
"seems fine".

## What the mock suite already guarantees

- Every module imports; the CLI builds; every MCP tool carries the
  `@governed_tool` harness marker (`tests/test_smoke.py`).
- The four analyses (`login_failure_rca`, `stale_access_audit`,
  `client_misconfig_audit`, `mfa_coverage_analysis`) are unit-tested against
  synthetic event feeds and user/client payloads, including their windows,
  thresholds, classifications and rankings.
- The platform registry dispatches to the right API shape per target, so a
  mixed Keycloak + authentik config resolves correctly.
- Write tools carry the correct risk tier and record the correct inverse undo
  descriptor against a mocked connection: `disable_user` ↔ `enable_user`,
  `require_password_reset` → clear-the-flag, `update_client_redirect_uris` →
  replay the captured prior list.
- `revoke_user_sessions` and `rotate_client_secret` are irreversible and record
  priorState only; rotated secrets are recorded **masked**, never in clear.

What it does **not** guarantee: that the Keycloak admin REST paths, the
authentik API v3 paths, the event type names, and the credential/session field
shapes exist as modelled on any real build of either platform.

## Prerequisites for a live run

**Live verification is cheap here** — both platforms are free and
self-hostable from a single container, so this is a realistic community
self-test.

```bash
# Keycloak
docker run -d --name kc-verify -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev

# authentik: use the project's published docker compose stack
```

Then, per platform:

- A **throwaway realm / tenant** with a handful of test users, at least one
  group, and at least one OAuth client. Never verify against a realm real
  people sign in to.
- **Keycloak**: a confidential client with the admin roles the tool needs, used
  via the client-credentials grant. **authentik**: a long-lived API token.
- Event logging **enabled** in the realm — several reads and the login-failure
  RCA depend on the event feed, and it is off by default in Keycloak.

```bash
uv tool install identity-aiops
identity-aiops init      # platform + base URL (+ realm/client_id for Keycloak)
identity-aiops doctor
```

Record the platform versions — the modelled paths are the main risk, so a
result without versions is not a usable result.

## Verification checklist

Run the checklist **once per platform**. Tick every box. A box that cannot be
ticked is a verification gap — record it, do not silently pass.

Platform under test: ☐ Keycloak ☐ authentik — version: ____________

### 1. Connectivity (the fastest live gate)
- [ ] `identity-aiops doctor` → all green: config, encrypted secret store, and
      a real authenticated call (Keycloak: the client-credentials grant against
      the realm token endpoint; authentik: the Bearer token accepted).
- [ ] Keycloak only: let the access token expire, then run any read → the
      refresh-on-401 path recovers without operator intervention.

### 2. Reads return real, well-shaped data
- [ ] `identity-aiops overview` → realm/tenant summary matches the admin UI.
- [ ] `identity-aiops users list` and `users list --search <name>` → real users
      with populated ids, usernames and enabled state.
- [ ] `identity-aiops users show <user-id>` → detail matches the admin UI.
- [ ] `identity-aiops users sessions <user-id>` → a session you deliberately
      opened in a browser shows up.
- [ ] `identity-aiops users credentials <user-id>` → an enrolled OTP factor is
      visible (this is the input to MFA coverage — a wrong shape here silently
      corrupts that analysis).
- [ ] `identity-aiops events -n 100` and `events --type LOGIN_ERROR
      --user <username>` → real events; the type names are correct for **this**
      platform (Keycloak `LOGIN`/`LOGIN_ERROR`, authentik `login`/`login_failed`).
- [ ] `identity-aiops clients list` / `clients show <client-id>` → real clients
      with redirect URIs, flow flags and public/confidential state.
- [ ] Realm settings, identity providers, groups and group members read back
      correctly (`realm_info`, `list_identity_providers`, `list_groups`,
      `group_members` via MCP).
- [ ] `user_lockout_status` (MCP) → a deliberately locked-out account reports
      as locked.

### 3. The four analyses judge correctly against reality
- [ ] MCP `login_failure_rca` → after driving ~20 deliberate bad logins against
      one test account, the run is classified as **targeted** brute-force with
      the right counts; a handful of scattered failures is not.
- [ ] MCP `stale_access_audit` → a never-logged-in test account is flagged; an
      account that signed in today is not (no false positive).
- [ ] MCP `client_misconfig_audit` → a client you deliberately gave a wildcard
      redirect URI and implicit flow scores high with that evidence; a
      correctly configured client does not.
- [ ] MCP `mfa_coverage_analysis` → the coverage percentage matches a manual
      count of which test users have a factor enrolled.

### 4. A reversible write + its undo (governance closes the loop)
- [ ] `identity-aiops users disable <test-user> --dry-run` → prints the API
      call, changes nothing, records nothing.
- [ ] `identity-aiops users disable <test-user>` → the user genuinely cannot
      sign in; the result carries an `_undo_id`; a row lands in
      `~/.identity-aiops/audit.db`.
- [ ] `identity-aiops undo apply <id>` → the user is re-enabled to the
      **prior** state (proves undo captured the fetched before-state).
- [ ] `identity-aiops users require-reset <test-user>` then `undo apply` → the
      pending reset requirement is cleared, and the user's other required
      actions are untouched.
- [ ] `identity-aiops clients set-redirect-uris <test-client> --uri
      https://example.test/cb` then `undo apply` → the **exact prior URI list**
      is restored, not an emptied or reordered one.
- [ ] `identity-aiops users revoke-sessions <test-user>` → the browser session
      from section 2 is actually terminated; it is audited with priorState and
      records **no** undo token.

### 5. Governance actually gates
- [ ] With no `~/.identity-aiops/rules.yaml`, a `high`-risk op
      (`users enable`, `clients set-redirect-uris`, `clients rotate-secret`) is
      **refused** unless `IDENTITY_AUDIT_APPROVED_BY` is set —
      secure-by-default.
- [ ] With the approver set, the op succeeds and the audit row records the
      approver and the rationale.
- [ ] `identity-aiops clients rotate-secret <test-client>` → the new secret
      works, and **neither** the old nor the new secret appears in clear in the
      audit DB or any log (masked fingerprints only). Verify by inspecting
      `~/.identity-aiops/audit.db` directly.
- [ ] A tight poll loop over the event feed trips the runaway budget guard
      rather than hammering the IdP.
- [ ] A failed operation is audited with `status=error` and records no undo.

### 6. Cleanup
- [ ] Re-enable or delete the test users; delete the test client.
- [ ] Confirm every write in the run appears in `~/.identity-aiops/audit.db`
      with the expected risk tier.
- [ ] Remove the throwaway credential from the secret store
      (`identity-aiops secret rm <name>`) and revoke it in the IdP.
- [ ] Tear down the container.

## Criteria to consider it live-verified

Record this tool as live-verified **only when all of the following hold**:

1. The full checklist is ticked against **both** platforms, with each version
   recorded (e.g. "verified on Keycloak 26.x and authentik 2025.x"). A single
   platform passing means only that platform is verified — say so explicitly
   rather than claiming the tool is verified.
2. Section 3 is ticked with the analyses judged against **deliberately induced**
   conditions, not whatever the lab happened to contain.
3. Every REST path, event-type name or field-shape mismatch found during the
   run is fixed and covered by a regression test, with the platform version
   where it differs noted.
4. The secret-masking box in section 5 is verified by direct inspection of the
   audit DB, not assumed.
5. The run is written up in this repo's release notes with the date and
   version, matching how the line records its other live-verified tools.

Until then this document stands as the accurate statement of status.

## Notes for maintainers

- `identity-aiops doctor` is the single fastest live entry point; start there.
- Expect the first failure to be the **event feed**: Keycloak ships with event
  logging disabled, so an empty `login_failure_rca` usually means the realm is
  not recording events rather than that the tool is broken.
- The two platforms drift independently. When a path is fixed for one, check
  whether the registry entry for the other needs the same fix.
- The verification story for the whole product line is tracked centrally; add
  this tool's result there once green so the verification-debt ledger stays
  accurate.
