# Release notes — identity-aiops 0.2.2

Previous release: 0.2.1.

## New guard: refusing an operation that would destroy its own undo

`disable_user` now refuses to disable the account this tool authenticates as.

This was found the hard way against a live authentik: disabling the admin whose
token the tool was holding **succeeded**, and the undo (`enable_user`) then
failed with 403 — the credential had been revoked mid-flight. A governed,
reversible tool must not offer an action that removes the ability to reverse it.

The refusal names the concrete failure you would have hit and what to do instead
(use a different administrative credential). The guard is exact: other accounts
are unaffected, and if the tool's own identity cannot be determined it proceeds
rather than blocking — unknown is never treated as "it is me".

Identity resolution is per-platform and needs no configuration: Keycloak reads
the `sub` claim of its own access token (no extra request), authentik calls
`/core/users/me/`. Both verified live.

## Live-verified: Authentik

Authentik was previously mock-only. It has now been exercised against
**authentik 2024.10**: `doctor`, the reads, all four analyses, and the
governance loop — `disable_user` → `undo_apply` re-enabling, on a live server.

With Keycloak 26.0 verified in 0.2.1, **both platforms are now live-verified**.
See [docs/VERIFICATION.md](docs/VERIFICATION.md) — the lab realms were small, so
the analyses are verified as *executing* correctly, not as *classifying* well at
scale.
