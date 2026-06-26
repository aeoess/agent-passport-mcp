# Changelog

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
