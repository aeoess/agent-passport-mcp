# Changelog

## 4.0.0 (2026-07-31)

### Added
- MCP 2026-07-28 support through the existing stdio entry while preserving the current 2025-era flow. Modern connections receive the required `resultType`, cache hints (`ttlMs`/`cacheScope`), and server identity metadata from the SDK.

### Breaking
- Node.js 20 or later is now required by the MCP v2 SDK family.
- Corrected the input schemas for 32 fields across 23 tools. These fields were already required by their handlers but were previously declared as optional on the wire. Missing fields now fail at the validation boundary with a field-specific error instead of failing inside the handler.

### Compatibility
- All 150 tool names, profile membership, CLI entry points, and successful APS behavior are preserved.
- Existing 2025-era initialization and tool-call flows remain supported.

### Internal
- Migrated from `@modelcontextprotocol/sdk` 1.x to `@modelcontextprotocol/server` 2.0.0 and Zod 4.
- Retargeted the profile-filtering and handler-error wrapper from `.tool()` to `registerTool()`.
- Verified the packed package end to end through the remote MCP bridge.

### Note
- The essential profile contains 25 profile-gated tools. Because `list_profiles` is always exposed, an essential-profile server presents 26 tools in total.
- The `agent-passport-system` dependency remains on its current line (`^3.3.1`); updating that SDK is a separate change.

## 3.4.0 (2026-07-26)

### Fixed / Security
- **The replay nullifier is consumed after signing, not before, in `aps_capability_sign_effect`.** Consuming first meant a signing failure burned the nullifier, so a caller that retried after a transient error was rejected as a replay and the effect could never be signed. The nullifier is now claimed only once the signature exists.

### Added
- **`agent-passport-access-shim` 0.1.0**, a separate package that emits a signed `AccessReceipt` for each governed `tools/call`.

### Docs
- The browser verify page is linked and described across the navigation, footer, `llms.txt`, `AGENTS.md`, and README.
- Tool descriptions synced to the live registry entries.

### Note
- This release tracks the `agent-passport-system` 3.x line. Moving the dependency onto the 4.x SDK is a separate change with its own test pass.

## 3.3.1 (2026-07-10)

- Tracks SDK 3.3.1 (audit patch). commerce_preflight is gracefully deprecated: it returns a machine-readable moved-to-gateway result instead of calling the SDK's now-throw-only commercePreflight stub, so tools/list stays honest and the call fails cleanly. commerce_preflight also leaves the essential profile in this release (present through 3.3.0; essential is now 26 tools), since a deprecated stub must not be default-recommended. Also: server.json/.mcp/server.json version sync, README profile corrections (default full/150, essential opt-in/26), identify added to essential, mutualAuth tools added to the scope map, serverInfo and setup counts corrected.

## 3.3.0 (2026-07-10)

- Tracks SDK 3.3.0: the agent-passport-system root barrel now exposes audience-binding, bilateral-pair, revocation-observation, evidence-bundle, and jurisdiction-selection. Dependency moves from ^2.6.0-alpha to ^3.3.0; no MCP call-site changes were needed.

## 3.2.4

Dependency-hygiene patch. No tool, API, or behavior change in this server.

### Security (dependencies)
- Pinned the transitive `hono` to `^4.12.27` via an npm `overrides` entry, which clears the
  high-severity advisory (path traversal in `serve-static` on Windows, a CORS default-wildcard
  reflection, and several AWS Lambda adapter issues) reported against `hono <= 4.12.24`. `hono` is a
  transitive dependency of `@modelcontextprotocol/sdk` (via `@hono/node-server`); this is a stdio server
  that does not import or use hono's HTTP features, so the pin is for audit hygiene rather than to close
  a reachable issue here.

### Known remaining advisories
- Three moderate advisories remain (`@anthropic-ai/sdk` and `uuid`), reaching the tree transitively
  through `agent-passport-system`. They are tracked for a separate SDK dependency refresh and are not
  addressed here. `npm audit fix --force` is not used because it would downgrade `agent-passport-system`
  to a breaking older version.

## 3.2.3

Patch release. Behavior and security fixes; no new tools or public API. Tracks SDK v2.9.0.

### Fixed / Security
- **Capability-token `expires_at` is now enforced.** The challenge, authority-evaluation-request, and
  challenge-receipt verifiers (`src/capabilityToken/verify.ts`) now check `expires_at` against the
  current time, and an unparseable `expires_at` is treated as expired (fail closed) rather than ignored.
- **The M3 mint path now fails closed on an expired challenge** (`src/capabilityToken/challengeReceipt.ts`).
  `mintChallengeReceipt` minted a permit regardless of the challenge `expires_at`; it now downgrades an
  expired permit to a deny (`deny_reason: challenge_expired`).
- **Commerce spend gate reads accumulated spend.** The commerce preflight and spend-summary path now
  thread the session delegation's `spentAmount`, closing a read-but-never-written gap where the gate
  always saw 0 spent.

### Behavior changes (operations previously permitted now fail closed)
- A capability challenge that is expired, or whose `expires_at` cannot be parsed, is now rejected by the
  verifiers and denied at mint time, instead of being accepted.
