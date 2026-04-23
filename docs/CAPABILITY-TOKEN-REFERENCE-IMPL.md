# Capability Token v0.1 — Reference Implementation

**Status:** v0.1 reference implementation, branch `feat/v0.1-capability-tokens`
**Spec:** [`agent-passport-system/docs/CAPABILITY-TOKEN-SPEC-DRAFT.md`](https://github.com/aeoess/agent-passport-system/blob/main/docs/CAPABILITY-TOKEN-SPEC-DRAFT.md) (v0.1, 2026-04-23)
**Repo:** `agent-passport-mcp`

This is the first running implementation of the four-message capability-token protocol. It exists to prove that the closure property described in the spec works against real signatures and real verification — not as a running service.

## Why MCP Hosts the Reference Implementation

MCP is APS-aware by construction: every tool it exposes is an action sink, and the server itself can act as the subject in delegation chains. That makes it the natural environment for the Class A closure stack — sink, subject, and gateway can all be exercised inside a single process without any network layer.

## What This Implementation Includes

- `src/capabilityToken/types.ts` — TypeScript schemas for M1 SinkChallenge, M2 AuthorityEvaluationRequest, M3 ChallengeReceipt, M4 EffectReceipt, plus the `EpistemicType` union (`closed | witnessed | unresolved | self-asserted | witnessed-by-subject | corroborated`). Schema-enforced at the type level.
- `src/capabilityToken/sinkChallenge.ts` — `issueSinkChallenge(...)` returns a sink-signed M1.
- `src/capabilityToken/authorityEvaluation.ts` — `buildEvaluationRequest(...)` returns a subject-signed M2 carrying the M1, the delegation chain, the revealed authority-token preimage, and the freshness beacon.
- `src/capabilityToken/challengeReceipt.ts` — `mintChallengeReceipt(...)` returns a gateway-signed M3 over the sink's exact `challenge_hash`.
- `src/capabilityToken/effectReceipt.ts` — `signEffectReceipt(...)` returns a sink-signed M4 binding the consumed token to the actual effect.
- `src/capabilityToken/nullifierSet.ts` — `InMemoryNullifierSet`, the v0.1 sink-side replay defence.
- `src/capabilityToken/verify.ts` — pure verifiers for each of the four messages, plus `reconstructAttestationChain(M1, M3, M4)` that demonstrates the closure property explicitly.
- Four MCP tools (`aps_capability_issue_challenge`, `aps_capability_evaluate_authority`, `aps_capability_mint_receipt`, `aps_capability_sign_effect`) registered under a new `capability` scope.

All signatures are Ed25519 over JCS (RFC 8785) canonical serialisation, delegated to the SDK's `canonicalizeJCS`, `sign`, and `verify` helpers.

## What This Implementation Demonstrates

- The full M1 → M2 → M3 → M4 cycle runs end-to-end with four distinct signing keys (sink, subject, gateway, sink again).
- A verifier holding only `(M1, M3, M4)` can re-derive every binding without ever seeing M2 — `reconstructAttestationChain` returns `{ok: true}` for the canonical case.
- Three negative tests prove the closure property holds against the named adversarial flows from the spec:
  1. **Gateway substitutes a different `challenge_hash`** — sink-side `verifyChallengeReceipt` rejects with `challenge_hash does not match`.
  2. **Subject reuses an `authority_token_preimage`** — `InMemoryNullifierSet.consume` throws `nullifier replay` on the second attempt, even though the gateway re-signed a fresh M3 over a new sink challenge.
  3. **Gateway forges or omits `delegation_chain_root`** — verifier rejects with `delegation_chain_root missing or does not match the M2 commitment`.

## Scope (v0.1)

- In-memory nullifier set, single-process. No persistence across restarts.
- No network layer. The MCP tools all live in the same process — the spec's "S → G" and "G → S → K" arrows are direct function calls.
- Single-instance sink. Multi-party sinks (where one operator's instance issues M1 and a different instance signs M4) are out of scope.
- Delegation envelope is treated as opaque: the v0.1 implementation commits to a JCS hash of the chain rather than a Merkle tree. A v0.2 implementation will replace this with the Merkle commitment described in spec §M2 once the envelope's `authority_token_merkle_root` field stabilises.
- Freshness beacon is structurally present but not range-checked against `required_policy_freshness.max_age_seconds`. Verification is a v0.2 follow-up.

## Limitations (Documented for v0.2)

- **No MCP session-state integration.** The capability tools take all keys as arguments; they do not yet read the active passport's private key from `state.privateKey` or scope the nullifier set to the active session. A future revision should bind the sink role to the running MCP server's identity.
- **No persistence.** A process restart clears the nullifier set. For production sinks this is unsafe — replay defence requires durable storage (the spec's "v0.1 keeps it in process; v1.0 must persist" remark applies).
- **No multi-party sinks.** The `InMemoryNullifierSet` is process-local; deploying the same sink behind multiple MCP instances would let an attacker replay tokens across instances. The fix is a shared store (Redis, D1, etc.) but it is out of v0.1 scope.
- **No M3 → M4 publication semantics.** The spec leaves transparency-log publication of M4 to deployment policy (open question Q4). The reference impl returns M4 to the caller and stops there.
- **No degradation path for dumb sinks.** The spec §"Degradation Path for Dumb Web2 Sinks" describes a self-asserted variant; this implementation does not yet emit `epistemic_claims.action_canonicalization: self-asserted` or the subject-witnessed M4 form.

## How to Run

```sh
cd ~/agent-passport-mcp
git checkout feat/v0.1-capability-tokens
npm run build
npm test
```

The capability-token suite lives at `src/__tests__/capability-token-e2e.test.ts` and runs from the compiled output at `build/__tests__/capability-token-e2e.test.js`. `npm test` runs both the existing `tests/*.test.mjs` suites and the compiled capability-token tests in a single `node --test` invocation.

## Next Steps

The intent of v0.1 is to circulate a working artifact alongside the spec draft so implementers in adjacent protocols (AgentID, MolTrust, AIP, SINT) have something concrete to cross-verify against. Spec ambiguities found while building this implementation are reported separately to inform spec v0.2.
