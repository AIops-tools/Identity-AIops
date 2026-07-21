# Security Policy

## Disclaimer

Community-maintained open-source project. **Not affiliated with, endorsed by, or
sponsored by the Keycloak project, Red Hat, Authentik Security Inc., or the
authentik project.** Product and trademark names (Keycloak, authentik) belong to
their owners. Source is auditable under the MIT license.

## Reporting Vulnerabilities

Report privately via a GitHub Security Advisory on
[github.com/AIops-tools/Identity-AIops](https://github.com/AIops-tools/Identity-AIops/security/advisories)
or email zhouwei008@gmail.com. Please do not open public issues for security
reports.

## Security Design

### Credential Management
- Per-target secrets — the Keycloak confidential client's **client secret** or the
  authentik **API token** — live **encrypted** in
  `~/.identity-aiops/secrets.enc` (Fernet/AES-128 + scrypt-derived key; chmod
  600), never in `config.yaml` and never in source. The master password is never
  stored — only a per-store random salt and the ciphertext are on disk.
- A legacy plaintext env var `IDENTITY_<TARGET_NAME_UPPER>_SECRET` is still
  honoured as a fallback with a deprecation warning (migrate with
  `identity-aiops secret migrate`).
- The secret is held only in memory and never logged or echoed. Keycloak's client
  secret is exchanged at request time for a short-lived access token
  (client-credentials grant, refreshed once on a 401); authentik's API token is
  presented as a Bearer header. The config file holds only platform, base URL,
  realm, client_id, and TLS settings.
- `rotate_client_secret` never returns or records a secret in clear — old and new
  values appear only as masked fingerprints in results and the audit log.

### Governed Operations
Every MCP tool runs through the bundled `@governed_tool` harness
(`identity_aiops.governance`):
- **Audit** — every call logged to a local SQLite DB under `~/.identity-aiops/`
  (relocatable via `IDENTITY_AIOPS_HOME`), agent-attributed, secret-redacted.
- **Token/runaway budget** — hard ceilings (`IDENTITY_MAX_TOOL_CALLS` /
  `IDENTITY_MAX_TOOL_SECONDS`) plus an on-by-default guard that trips a tight
  poll/retry loop, preventing unbounded API consumption.
- **Risk-tier labelling** — each tool's `risk_level` is carried onto the audit
  row as a descriptive tier; it is a label, not a gate. There is no read-only
  switch, policy file, or approval gate — whether a write is permitted is the
  agent's judgement or the connecting account's permissions.
- **Undo-token recording** — reversible writes capture the BEFORE state (via a
  real GET) and record an inverse descriptor (`disable_user` ↔ `enable_user`;
  `require_password_reset` clears via its own `clear=True` path;
  `update_client_redirect_uris` replays the prior list) so the change can be
  rolled back.

### State-Changing Operations
Access-granting / boundary-replacing writes — `enable_user`,
`update_client_redirect_uris`, `rotate_client_secret` — are `risk_level=high`
and accept a `dry_run` preview; reversible ones capture the before-state and
record an undo token. `revoke_user_sessions` and `rotate_client_secret` are
irreversible (priorState recorded, no undo). Containment/hygiene writes —
`disable_user`, `revoke_user_sessions`, `require_password_reset` — are
`risk_level=medium`. `IDENTITY_AUDIT_APPROVED_BY` + `IDENTITY_AUDIT_RATIONALE`
are optional audit annotations, recorded when set but never required.

### SSL/TLS Verification
`verify_ssl` defaults to true; disable only for self-signed lab certificates.

### Prompt-Injection Protection
All IdP-returned text (usernames, email addresses, event messages, client names,
redirect URIs, group names) is passed through a `sanitize()` truncate +
control-character strip before reaching the agent.

### Network Scope
No webhooks, no telemetry, no outbound calls beyond the configured Keycloak /
authentik REST API endpoints. No post-install scripts or background services.

## Static Analysis

```bash
uvx bandit -r identity_aiops/ mcp_server/
uv run ruff check .
```

## Supported Versions

The latest released version receives security fixes. This is a preview (0.x);
pin a version in production.
