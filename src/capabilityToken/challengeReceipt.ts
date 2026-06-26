// M3: Gateway mints a ChallengeReceipt over the sink-authored challenge.
// The gateway's signature binds to the canonical challenge_hash; it cannot
// describe a different action without producing a hash the sink will refuse.

import { sign } from "agent-passport-system";
import type {
  AuthorityEvaluationRequest,
  ChallengeReceipt,
  ChallengeReceiptEpistemicClaims,
  Decision,
  KeyPair,
} from "./types.js";
import { canonicalWithoutSignature, sha256Hex } from "./canonical.js";
import { challengeHash } from "./sinkChallenge.js";

const CLOSED_PERMIT_CLAIMS: ChallengeReceiptEpistemicClaims = {
  policy_evaluated: "closed",
  authority_consumed: "closed",
  scope_within_bounds: "closed",
  effect_occurred: "unresolved",
};

const CLOSED_DENY_CLAIMS: ChallengeReceiptEpistemicClaims = {
  policy_evaluated: "closed",
  authority_consumed: "closed",
  scope_within_bounds: "closed",
  effect_occurred: "unresolved",
};

export interface MintChallengeReceiptOptions {
  request: AuthorityEvaluationRequest;
  decision: Decision;
  deny_reason?: string;
  policy_digest: string;
  gateway_key: KeyPair;
  // Override claims when modeling adversarial gateway flows in tests.
  epistemic_claims?: ChallengeReceiptEpistemicClaims;
  // Test hooks.
  now?: Date;
  // Adversarial test hook: lets a test mint M3 with a challenge_hash that does
  // NOT match the sink's M1. The sink's verifier MUST reject this. Production
  // callers never set it.
  override_challenge_hash?: string;
  // Adversarial test hook: lets a test forge a different chain root than the
  // subject committed to in M2. Verifiers MUST detect.
  override_delegation_chain_root?: string;
  // Adversarial test hook: lets a test omit the chain root entirely.
  omit_delegation_chain_root?: boolean;
}

export function mintChallengeReceipt(
  opts: MintChallengeReceiptOptions,
): ChallengeReceipt {
  const evaluatedAt = (opts.now ?? new Date()).toISOString();
  // Fail closed on an expired challenge: expires_at is signed into the challenge, so the gateway
  // must not mint a PERMIT after it. Downgrade an expired permit to a deny. nowMs defaults to the
  // wall clock; an unparseable expires_at is treated as expired.
  const nowMs = (opts.now ?? new Date()).getTime();
  const expMs = Date.parse(opts.request.challenge.expires_at);
  let decision = opts.decision;
  let denyReason = opts.deny_reason;
  if (decision === "permit" && (!Number.isFinite(expMs) || nowMs > expMs)) {
    decision = "deny";
    denyReason = "challenge_expired";
  }

  const cHash = opts.override_challenge_hash ?? challengeHash(opts.request.challenge);
  const claims =
    opts.epistemic_claims ??
    (decision === "permit" ? CLOSED_PERMIT_CLAIMS : CLOSED_DENY_CLAIMS);

  const chainRoot = opts.omit_delegation_chain_root
    ? ""
    : opts.override_delegation_chain_root ?? opts.request.delegation_chain_root;

  const unsigned: Omit<ChallengeReceipt, "gateway_signature"> = {
    type: "aps.capability.v1.ChallengeReceipt",
    challenge_hash: cHash,
    decision: decision,
    ...(decision === "deny" && denyReason
      ? { deny_reason: denyReason }
      : {}),
    delegation_chain_root: chainRoot,
    delegation_depth: opts.request.delegation_depth,
    ...(decision === "permit"
      ? { authority_token_preimage: opts.request.authority_token.token_preimage }
      : {}),
    evaluated_at: evaluatedAt,
    policy_digest: opts.policy_digest,
    epistemic_claims: claims,
  };

  const signature = sign(
    canonicalWithoutSignature(
      { ...unsigned, gateway_signature: "" },
      "gateway_signature",
    ),
    opts.gateway_key.privateKey,
  );

  return { ...unsigned, gateway_signature: signature };
}

export function challengeReceiptHash(receipt: ChallengeReceipt): string {
  return sha256Hex(canonicalWithoutSignature(receipt, "gateway_signature"));
}
