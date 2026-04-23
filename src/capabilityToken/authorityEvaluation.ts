// M2: Subject builds an AuthorityEvaluationRequest carrying the sink challenge,
// the delegation chain, and one revealed authority-token preimage.

import { canonicalizeJCS, sign } from "agent-passport-system";
import type {
  AuthorityEvaluationRequest,
  AuthorityTokenReveal,
  DelegationEnvelope,
  FreshnessBeacon,
  KeyPair,
  SinkChallenge,
} from "./types.js";
import { canonicalWithoutSignature, sha256Hex } from "./canonical.js";

export interface BuildEvaluationRequestOptions {
  challenge: SinkChallenge;
  delegation_chain: DelegationEnvelope[];
  authority_token: AuthorityTokenReveal;
  freshness_beacon: FreshnessBeacon;
  subject_key: KeyPair;
  // Optional override; otherwise computed as SHA-256 over the canonical
  // delegation chain. The reference implementation uses this commitment as
  // the binding between M2 and M3 — the gateway's M3 echoes the same root.
  delegation_chain_root?: string;
}

export function buildEvaluationRequest(
  opts: BuildEvaluationRequestOptions,
): AuthorityEvaluationRequest {
  const root =
    opts.delegation_chain_root ?? deriveDelegationChainRoot(opts.delegation_chain);

  const unsigned: Omit<AuthorityEvaluationRequest, "subject_signature"> = {
    type: "aps.capability.v1.AuthorityEvaluationRequest",
    challenge: opts.challenge,
    delegation_chain: opts.delegation_chain,
    delegation_chain_root: root,
    delegation_depth: opts.delegation_chain.length,
    authority_token: opts.authority_token,
    freshness_beacon: opts.freshness_beacon,
  };

  const signature = sign(
    canonicalWithoutSignature(
      { ...unsigned, subject_signature: "" },
      "subject_signature",
    ),
    opts.subject_key.privateKey,
  );

  return { ...unsigned, subject_signature: signature };
}

// SHA-256 over the canonical serialization of the chain. v0.1: simple flat
// commitment, sufficient to demonstrate the closure property. The wire
// format reserves room for a richer Merkle tree in v0.2.
export function deriveDelegationChainRoot(chain: DelegationEnvelope[]): string {
  return sha256Hex(canonicalizeJCS(chain));
}
