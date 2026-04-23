// M4: After execution, the sink signs an EffectReceipt that binds the
// consumed authority token to the actual effect.

import { sign } from "agent-passport-system";
import type {
  ChallengeReceipt,
  EffectReceipt,
  EffectReceiptEpistemicClaims,
  KeyPair,
  SinkEffect,
} from "./types.js";
import { canonicalWithoutSignature } from "./canonical.js";
import { challengeReceiptHash } from "./challengeReceipt.js";

const DEFAULT_CLAIMS: EffectReceiptEpistemicClaims = {
  effect_occurred: "closed",
  effect_result_bound: "closed",
  policy_evaluation_correct: "witnessed",
};

export interface SignEffectReceiptOptions {
  challenge_receipt: ChallengeReceipt;
  effect: SinkEffect;
  sink_key: KeyPair;
  epistemic_claims?: EffectReceiptEpistemicClaims;
}

export function signEffectReceipt(
  opts: SignEffectReceiptOptions,
): EffectReceipt {
  if (opts.challenge_receipt.decision !== "permit") {
    throw new Error("EffectReceipt requires a permit ChallengeReceipt");
  }
  const preimage = opts.challenge_receipt.authority_token_preimage;
  if (!preimage) {
    throw new Error("ChallengeReceipt is missing authority_token_preimage");
  }

  const unsigned: Omit<EffectReceipt, "sink_signature"> = {
    type: "aps.capability.v1.EffectReceipt",
    challenge_hash: opts.challenge_receipt.challenge_hash,
    authority_token_preimage: preimage,
    gateway_receipt_hash: challengeReceiptHash(opts.challenge_receipt),
    effect: opts.effect,
    epistemic_claims: opts.epistemic_claims ?? DEFAULT_CLAIMS,
  };

  const signature = sign(
    canonicalWithoutSignature(
      { ...unsigned, sink_signature: "" },
      "sink_signature",
    ),
    opts.sink_key.privateKey,
  );

  return { ...unsigned, sink_signature: signature };
}
