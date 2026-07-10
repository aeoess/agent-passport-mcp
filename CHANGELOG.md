# Changelog

## 3.3.1 (2026-07-10)

- Tracks SDK 3.3.1 (audit patch). commerce_preflight is gracefully deprecated: it returns a machine-readable moved-to-gateway result instead of calling the SDK's now-throw-only commercePreflight stub, so tools/list stays honest and the call fails cleanly. (Note: commerce_preflight is not part of the essential profile.) Also: server.json/.mcp/server.json version sync, README profile corrections (default full/150, essential opt-in/26), identify added to essential, mutualAuth tools added to the scope map, serverInfo and setup counts corrected.

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
