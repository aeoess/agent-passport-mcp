// Signature + binding verification for the four message types.
// Verifiers are pure: they take messages and public keys, return either
// {ok: true} or {ok: false, reason}.

import { verify } from "agent-passport-system";
import type {
  AuthorityEvaluationRequest,
  ChallengeReceipt,
  EffectReceipt,
  SinkChallenge,
} from "./types.js";
import { canonicalWithoutSignature } from "./canonical.js";
import { challengeHash } from "./sinkChallenge.js";
import { challengeReceiptHash } from "./challengeReceipt.js";

export type VerifyResult = { ok: true } | { ok: false; reason: string };

export function verifySinkChallenge(
  challenge: SinkChallenge,
  sinkPublicKey: string,
): VerifyResult {
  const payload = canonicalWithoutSignature(challenge, "sink_signature");
  return verify(payload, challenge.sink_signature, sinkPublicKey)
    ? { ok: true }
    : { ok: false, reason: "sink_signature invalid" };
}

export function verifyAuthorityEvaluationRequest(
  request: AuthorityEvaluationRequest,
  subjectPublicKey: string,
  sinkPublicKey: string,
): VerifyResult {
  const payload = canonicalWithoutSignature(request, "subject_signature");
  if (!verify(payload, request.subject_signature, subjectPublicKey)) {
    return { ok: false, reason: "subject_signature invalid" };
  }
  return verifySinkChallenge(request.challenge, sinkPublicKey);
}

export interface VerifyChallengeReceiptOptions {
  receipt: ChallengeReceipt;
  expected_challenge: SinkChallenge;
  expected_delegation_chain_root: string;
  gateway_public_key: string;
}

export function verifyChallengeReceipt(
  opts: VerifyChallengeReceiptOptions,
): VerifyResult {
  const payload = canonicalWithoutSignature(opts.receipt, "gateway_signature");
  if (!verify(payload, opts.receipt.gateway_signature, opts.gateway_public_key)) {
    return { ok: false, reason: "gateway_signature invalid" };
  }
  const expectedHash = challengeHash(opts.expected_challenge);
  if (opts.receipt.challenge_hash !== expectedHash) {
    return {
      ok: false,
      reason: "challenge_hash does not match the sink-issued challenge",
    };
  }
  if (
    !opts.receipt.delegation_chain_root ||
    opts.receipt.delegation_chain_root !== opts.expected_delegation_chain_root
  ) {
    return {
      ok: false,
      reason: "delegation_chain_root missing or does not match the M2 commitment",
    };
  }
  if (opts.receipt.decision === "permit" && !opts.receipt.authority_token_preimage) {
    return {
      ok: false,
      reason: "permit ChallengeReceipt missing authority_token_preimage",
    };
  }
  return { ok: true };
}

export interface VerifyEffectReceiptOptions {
  receipt: EffectReceipt;
  challenge_receipt: ChallengeReceipt;
  sink_public_key: string;
}

export function verifyEffectReceipt(
  opts: VerifyEffectReceiptOptions,
): VerifyResult {
  const payload = canonicalWithoutSignature(opts.receipt, "sink_signature");
  if (!verify(payload, opts.receipt.sink_signature, opts.sink_public_key)) {
    return { ok: false, reason: "sink_signature invalid" };
  }
  if (opts.receipt.challenge_hash !== opts.challenge_receipt.challenge_hash) {
    return { ok: false, reason: "challenge_hash mismatch between M3 and M4" };
  }
  if (
    opts.receipt.authority_token_preimage !==
    opts.challenge_receipt.authority_token_preimage
  ) {
    return { ok: false, reason: "authority_token_preimage mismatch between M3 and M4" };
  }
  if (opts.receipt.gateway_receipt_hash !== challengeReceiptHash(opts.challenge_receipt)) {
    return { ok: false, reason: "gateway_receipt_hash does not match M3 canonical hash" };
  }
  return { ok: true };
}

// Full attestation-chain reconstruction: any party holding M1, M3, M4 can
// re-derive every binding without the subject's M2 in hand. v0.1 closure
// property smoke test.
export interface ReconstructAttestationOptions {
  challenge: SinkChallenge;
  receipt: ChallengeReceipt;
  effect: EffectReceipt;
  sink_public_key: string;
  gateway_public_key: string;
}

export function reconstructAttestationChain(
  opts: ReconstructAttestationOptions,
): VerifyResult {
  const m1 = verifySinkChallenge(opts.challenge, opts.sink_public_key);
  if (!m1.ok) return m1;

  const m3 = verifyChallengeReceipt({
    receipt: opts.receipt,
    expected_challenge: opts.challenge,
    expected_delegation_chain_root: opts.receipt.delegation_chain_root,
    gateway_public_key: opts.gateway_public_key,
  });
  if (!m3.ok) return m3;

  const m4 = verifyEffectReceipt({
    receipt: opts.effect,
    challenge_receipt: opts.receipt,
    sink_public_key: opts.sink_public_key,
  });
  if (!m4.ok) return m4;

  return { ok: true };
}
