// End-to-end test for the v0.1 capability-token reference implementation.
// Spec: agent-passport-system/docs/CAPABILITY-TOKEN-SPEC-DRAFT.md
//
// Demonstrates the closure property: any party holding (M1, M3, M4) can
// reconstruct the attestation chain with all four signatures verifying.

import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, sign } from "agent-passport-system";

import {
  issueSinkChallenge,
  buildEvaluationRequest,
  mintChallengeReceipt,
  signEffectReceipt,
  challengeHash,
  challengeReceiptHash,
  deriveDelegationChainRoot,
  InMemoryNullifierSet,
  verifySinkChallenge,
  verifyAuthorityEvaluationRequest,
  verifyChallengeReceipt,
  verifyEffectReceipt,
  reconstructAttestationChain,
  canonicalWithoutSignature,
} from "../capabilityToken/index.js";
import type {
  AuthorityTokenReveal,
  DelegationEnvelope,
  FreshnessBeacon,
  KeyPair,
  SinkAction,
} from "../capabilityToken/index.js";

// Local helper: every actor needs an Ed25519 key pair.
function newActorKey(): KeyPair {
  const k = generateKeyPair();
  return { publicKey: k.publicKey, privateKey: k.privateKey };
}

interface Actors {
  delegator: KeyPair;
  subject: KeyPair;
  sink: KeyPair;
  gateway: KeyPair;
}

function setupActors(): Actors {
  return {
    delegator: newActorKey(),
    subject: newActorKey(),
    sink: newActorKey(),
    gateway: newActorKey(),
  };
}

// Minimal valid action shape for fixture flows.
function sampleAction(): SinkAction {
  return {
    kind: "fs.write",
    target: "file:///tmp/aps-capability-test.txt",
    parameters: { content_length: 42 },
    resource_version: "v3-2026-04-22",
  };
}

// In v0.1 the delegation envelope is opaque to this protocol — the SDK's v2.x
// chain composes by reference. The reference impl commits to a JCS hash of
// the chain. For test fixtures a stub envelope is sufficient.
function sampleDelegationChain(actors: Actors): DelegationEnvelope[] {
  return [
    {
      issuer: actors.delegator.publicKey,
      subject: actors.subject.publicKey,
      scope: ["fs.write"],
      issued_at: "2026-04-22T00:00:00Z",
      not_after: "2026-04-29T00:00:00Z",
      authority_token_merkle_root: "stub-root-for-v0.1",
    },
  ];
}

function sampleAuthorityToken(): AuthorityTokenReveal {
  return {
    token_preimage: Buffer.from("preimage-001-".padEnd(32, "x")).toString("base64url"),
    merkle_proof: ["sibling-1", "sibling-2"],
    scope_class: "fs.write",
  };
}

function sampleFreshnessBeacon(actors: Actors): FreshnessBeacon {
  const ts = "2026-04-22T00:00:01Z";
  // Minimal beacon: signed timestamp from the delegator. Full spec requires
  // a richer payload; this is sufficient to exercise the flow.
  const beaconSig = sign(`beacon:${ts}`, actors.delegator.privateKey);
  return {
    delegator_id: actors.delegator.publicKey,
    beacon_timestamp: ts,
    beacon_signature: beaconSig,
  };
}

// Drives the full M1→M2→M3→M4 cycle. Returns every artifact so individual
// tests can assert on whichever step they care about.
function runFullCycle(actors: Actors, nullifiers: InMemoryNullifierSet) {
  // M1: sink issues a challenge.
  const challenge = issueSinkChallenge({
    sink_id: actors.sink.publicKey,
    subject_id: actors.subject.publicKey,
    action: sampleAction(),
    sink_key: actors.sink,
  });

  // M2: subject builds an authority-evaluation request.
  const chain = sampleDelegationChain(actors);
  const request = buildEvaluationRequest({
    challenge,
    delegation_chain: chain,
    authority_token: sampleAuthorityToken(),
    freshness_beacon: sampleFreshnessBeacon(actors),
    subject_key: actors.subject,
  });

  // M3: gateway mints a permit ChallengeReceipt over the sink's exact
  // challenge_hash and the subject's exact delegation_chain_root.
  const receipt = mintChallengeReceipt({
    request,
    decision: "permit",
    policy_digest: "policy-bundle-sha256-v0.1-fixture",
    gateway_key: actors.gateway,
  });

  // Sink-side: verify M3 binds to the M1 the sink issued, then check the
  // nullifier set, then consume the token.
  const m3Verify = verifyChallengeReceipt({
    receipt,
    expected_challenge: challenge,
    expected_delegation_chain_root: request.delegation_chain_root,
    gateway_public_key: actors.gateway.publicKey,
  });
  assert.equal(m3Verify.ok, true, "sink must accept M3");
  assert.equal(nullifiers.isConsumed(receipt.authority_token_preimage!), false);
  nullifiers.consume(receipt.authority_token_preimage!);

  // M4: sink signs an effect receipt.
  const effectReceipt = signEffectReceipt({
    challenge_receipt: receipt,
    effect: {
      executed_at: "2026-04-22T00:00:02Z",
      outcome: "success",
      result_digest: "sha256-of-effect-result",
    },
    sink_key: actors.sink,
  });

  return { challenge, request, receipt, effectReceipt, chain };
}

test("M1: sink-issued challenge has a valid sink signature", () => {
  const actors = setupActors();
  const challenge = issueSinkChallenge({
    sink_id: actors.sink.publicKey,
    subject_id: actors.subject.publicKey,
    action: sampleAction(),
    sink_key: actors.sink,
  });
  assert.equal(challenge.type, "aps.capability.v1.SinkChallenge");
  assert.equal(challenge.sink_id, actors.sink.publicKey);
  assert.ok(challenge.sink_signature.length > 0, "signature populated");

  const result = verifySinkChallenge(challenge, actors.sink.publicKey);
  assert.equal(result.ok, true);
  assert.equal(challengeHash(challenge).length, 64, "SHA-256 hex");
});

test("M2: subject-signed evaluation request verifies and carries M1 verbatim", () => {
  const actors = setupActors();
  const challenge = issueSinkChallenge({
    sink_id: actors.sink.publicKey,
    subject_id: actors.subject.publicKey,
    action: sampleAction(),
    sink_key: actors.sink,
  });
  const chain = sampleDelegationChain(actors);
  const request = buildEvaluationRequest({
    challenge,
    delegation_chain: chain,
    authority_token: sampleAuthorityToken(),
    freshness_beacon: sampleFreshnessBeacon(actors),
    subject_key: actors.subject,
  });
  assert.equal(request.delegation_depth, 1);
  assert.equal(request.delegation_chain_root, deriveDelegationChainRoot(chain));

  const result = verifyAuthorityEvaluationRequest(
    request,
    actors.subject.publicKey,
    actors.sink.publicKey,
  );
  assert.equal(result.ok, true);
});

test("M3: gateway permit binds challenge_hash + delegation_chain_root", () => {
  const actors = setupActors();
  const challenge = issueSinkChallenge({
    sink_id: actors.sink.publicKey,
    subject_id: actors.subject.publicKey,
    action: sampleAction(),
    sink_key: actors.sink,
  });
  const request = buildEvaluationRequest({
    challenge,
    delegation_chain: sampleDelegationChain(actors),
    authority_token: sampleAuthorityToken(),
    freshness_beacon: sampleFreshnessBeacon(actors),
    subject_key: actors.subject,
  });
  const receipt = mintChallengeReceipt({
    request,
    decision: "permit",
    policy_digest: "p-digest",
    gateway_key: actors.gateway,
  });
  assert.equal(receipt.challenge_hash, challengeHash(challenge));
  assert.equal(receipt.delegation_chain_root, request.delegation_chain_root);
  assert.equal(receipt.epistemic_claims.policy_evaluated, "closed");
  assert.equal(receipt.epistemic_claims.effect_occurred, "unresolved");

  const result = verifyChallengeReceipt({
    receipt,
    expected_challenge: challenge,
    expected_delegation_chain_root: request.delegation_chain_root,
    gateway_public_key: actors.gateway.publicKey,
  });
  assert.equal(result.ok, true);
});

test("E2E: full four-message cycle — every signature verifies, attestation chain reconstructs", () => {
  const actors = setupActors();
  const nullifiers = new InMemoryNullifierSet();
  const { challenge, request, receipt, effectReceipt } = runFullCycle(
    actors,
    nullifiers,
  );

  // Each individual signature verifies against the right key.
  assert.equal(verifySinkChallenge(challenge, actors.sink.publicKey).ok, true);
  assert.equal(
    verifyAuthorityEvaluationRequest(
      request,
      actors.subject.publicKey,
      actors.sink.publicKey,
    ).ok,
    true,
  );
  assert.equal(
    verifyChallengeReceipt({
      receipt,
      expected_challenge: challenge,
      expected_delegation_chain_root: request.delegation_chain_root,
      gateway_public_key: actors.gateway.publicKey,
    }).ok,
    true,
  );
  assert.equal(
    verifyEffectReceipt({
      receipt: effectReceipt,
      challenge_receipt: receipt,
      sink_public_key: actors.sink.publicKey,
    }).ok,
    true,
  );

  // M4 binds back to M3 by gateway_receipt_hash.
  assert.equal(effectReceipt.gateway_receipt_hash, challengeReceiptHash(receipt));
  assert.equal(effectReceipt.epistemic_claims.effect_occurred, "closed");
  assert.equal(effectReceipt.epistemic_claims.policy_evaluation_correct, "witnessed");

  // Closure: a verifier holding M1, M3, M4 (no M2 needed) can reconstruct the
  // chain. This is the spec's "(SinkChallenge, ChallengeReceipt, EffectReceipt)
  // is the full attestation record" claim made executable.
  const reconstructed = reconstructAttestationChain({
    challenge,
    receipt,
    effect: effectReceipt,
    sink_public_key: actors.sink.publicKey,
    gateway_public_key: actors.gateway.publicKey,
  });
  assert.equal(reconstructed.ok, true, "attestation chain must reconstruct");

  // Nullifier set consumed exactly one preimage.
  assert.equal(nullifiers.size(), 1);
});

// ─── Negative tests ───────────────────────────────────────────────────────
// Each models an adversarial gateway, a replay attempt, or an attempt to
// bypass delegation-chain validation. The protocol's closure property means
// each MUST be detected by the sink-side or any independent verifier.

test("NEGATIVE: gateway substitutes a different challenge_hash — sink rejects M3", () => {
  const actors = setupActors();
  const challenge = issueSinkChallenge({
    sink_id: actors.sink.publicKey,
    subject_id: actors.subject.publicKey,
    action: sampleAction(),
    sink_key: actors.sink,
  });
  const request = buildEvaluationRequest({
    challenge,
    delegation_chain: sampleDelegationChain(actors),
    authority_token: sampleAuthorityToken(),
    freshness_beacon: sampleFreshnessBeacon(actors),
    subject_key: actors.subject,
  });
  // Adversarial gateway swaps the challenge_hash to one of its own choosing.
  const forgedReceipt = mintChallengeReceipt({
    request,
    decision: "permit",
    policy_digest: "p-digest",
    gateway_key: actors.gateway,
    override_challenge_hash: "0".repeat(64),
  });

  // Gateway signature itself still verifies (gateway holds its own key).
  // What MUST fail: the binding check between challenge_hash and the M1 the
  // sink actually issued.
  const result = verifyChallengeReceipt({
    receipt: forgedReceipt,
    expected_challenge: challenge,
    expected_delegation_chain_root: request.delegation_chain_root,
    gateway_public_key: actors.gateway.publicKey,
  });
  assert.equal(result.ok, false);
  if (!result.ok) {
    assert.match(result.reason, /challenge_hash does not match/);
  }
});

test("NEGATIVE: subject reuses authority_token_preimage — nullifier set rejects replay", () => {
  const actors = setupActors();
  const nullifiers = new InMemoryNullifierSet();
  // First cycle succeeds.
  const first = runFullCycle(actors, nullifiers);
  assert.ok(first.effectReceipt.sink_signature.length > 0);

  // Second cycle: same actors, same authority_token_preimage. Even if the
  // gateway re-mints a fresh M3 (different challenge, different evaluated_at),
  // the sink's nullifier set MUST refuse the second consumption attempt.
  const challenge2 = issueSinkChallenge({
    sink_id: actors.sink.publicKey,
    subject_id: actors.subject.publicKey,
    action: { ...sampleAction(), parameters: { content_length: 100 } },
    sink_key: actors.sink,
  });
  const request2 = buildEvaluationRequest({
    challenge: challenge2,
    delegation_chain: sampleDelegationChain(actors),
    authority_token: sampleAuthorityToken(), // same preimage as cycle #1
    freshness_beacon: sampleFreshnessBeacon(actors),
    subject_key: actors.subject,
  });
  const receipt2 = mintChallengeReceipt({
    request: request2,
    decision: "permit",
    policy_digest: "p-digest",
    gateway_key: actors.gateway,
  });

  // Sink-side verification of M3 still passes (it's a fresh sink-authored
  // challenge with a valid gateway signature). The replay defense is
  // structurally separate: it lives in the nullifier set.
  const m3v = verifyChallengeReceipt({
    receipt: receipt2,
    expected_challenge: challenge2,
    expected_delegation_chain_root: request2.delegation_chain_root,
    gateway_public_key: actors.gateway.publicKey,
  });
  assert.equal(m3v.ok, true);

  // Replay attempt MUST throw at consume(). This is what stops the gateway
  // from batch-consuming a leaked token.
  assert.throws(
    () => nullifiers.consume(receipt2.authority_token_preimage!),
    /nullifier replay/,
  );
});

test("NEGATIVE: gateway omits or forges delegation_chain_root — verifier detects missing/invalid", () => {
  const actors = setupActors();
  const challenge = issueSinkChallenge({
    sink_id: actors.sink.publicKey,
    subject_id: actors.subject.publicKey,
    action: sampleAction(),
    sink_key: actors.sink,
  });
  const request = buildEvaluationRequest({
    challenge,
    delegation_chain: sampleDelegationChain(actors),
    authority_token: sampleAuthorityToken(),
    freshness_beacon: sampleFreshnessBeacon(actors),
    subject_key: actors.subject,
  });

  // Variant A: gateway omits the delegation_chain_root entirely (skipped
  // chain validation). Verifier MUST detect.
  const omittedRoot = mintChallengeReceipt({
    request,
    decision: "permit",
    policy_digest: "p-digest",
    gateway_key: actors.gateway,
    omit_delegation_chain_root: true,
  });
  const omittedResult = verifyChallengeReceipt({
    receipt: omittedRoot,
    expected_challenge: challenge,
    expected_delegation_chain_root: request.delegation_chain_root,
    gateway_public_key: actors.gateway.publicKey,
  });
  assert.equal(omittedResult.ok, false);
  if (!omittedResult.ok) {
    assert.match(omittedResult.reason, /delegation_chain_root/);
  }

  // Variant B: gateway forges a different chain root than the subject
  // committed to (e.g. trying to attest to a broader scope class).
  const forgedRoot = mintChallengeReceipt({
    request,
    decision: "permit",
    policy_digest: "p-digest",
    gateway_key: actors.gateway,
    override_delegation_chain_root: "deadbeef".repeat(8),
  });
  const forgedResult = verifyChallengeReceipt({
    receipt: forgedRoot,
    expected_challenge: challenge,
    expected_delegation_chain_root: request.delegation_chain_root,
    gateway_public_key: actors.gateway.publicKey,
  });
  assert.equal(forgedResult.ok, false);
  if (!forgedResult.ok) {
    assert.match(forgedResult.reason, /delegation_chain_root/);
  }
});

test("Hash stability: re-issuing M1 with the same nonce + clock yields the same challenge_hash", () => {
  const actors = setupActors();
  const fixedNow = new Date("2026-04-22T12:00:00Z");
  const fixedNonce = "deterministic-nonce-for-fixture-vector".padEnd(43, "x").slice(0, 43);
  const a = issueSinkChallenge({
    sink_id: actors.sink.publicKey,
    subject_id: actors.subject.publicKey,
    action: sampleAction(),
    sink_key: actors.sink,
    now: fixedNow,
    nonce: fixedNonce,
  });
  const b = issueSinkChallenge({
    sink_id: actors.sink.publicKey,
    subject_id: actors.subject.publicKey,
    action: sampleAction(),
    sink_key: actors.sink,
    now: fixedNow,
    nonce: fixedNonce,
  });
  // Canonical JCS payload is identical → challenge_hash matches. Signatures
  // also match because Ed25519 over identical input is deterministic.
  assert.equal(challengeHash(a), challengeHash(b));
  assert.equal(
    canonicalWithoutSignature(a, "sink_signature"),
    canonicalWithoutSignature(b, "sink_signature"),
  );
});
