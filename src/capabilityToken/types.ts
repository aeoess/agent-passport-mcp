// Wire-format types for the v0.1 capability-token protocol.
// Source of truth: agent-passport-system/docs/CAPABILITY-TOKEN-SPEC-DRAFT.md

export type EpistemicType =
  | "closed"
  | "witnessed"
  | "unresolved"
  | "self-asserted"
  | "witnessed-by-subject"
  | "corroborated";

export interface SinkAction {
  kind: string;
  target: string;
  parameters: Record<string, unknown>;
  resource_version: string;
}

export interface PolicyFreshnessRequirement {
  max_age_seconds: number;
  beacon_hash_required: boolean;
}

// M1: K → S
export interface SinkChallenge {
  type: "aps.capability.v1.SinkChallenge";
  sink_id: string;
  subject_id: string;
  action: SinkAction;
  nonce: string;
  issued_at: string;
  expires_at: string;
  required_policy_freshness: PolicyFreshnessRequirement;
  sink_signature: string;
}

export interface DelegationEnvelope {
  // Opaque to this protocol — the v2.x delegation envelope shape lives in the
  // SDK. The reference implementation treats the chain as carry-through and
  // commits to a Merkle root over the canonical serialization.
  [key: string]: unknown;
}

export interface AuthorityTokenReveal {
  token_preimage: string;
  merkle_proof: string[];
  scope_class: string;
}

export interface FreshnessBeacon {
  delegator_id: string;
  beacon_timestamp: string;
  beacon_signature: string;
}

// M2: S → G
export interface AuthorityEvaluationRequest {
  type: "aps.capability.v1.AuthorityEvaluationRequest";
  challenge: SinkChallenge;
  delegation_chain: DelegationEnvelope[];
  delegation_chain_root: string;
  delegation_depth: number;
  authority_token: AuthorityTokenReveal;
  freshness_beacon: FreshnessBeacon;
  subject_signature: string;
}

export type Decision = "permit" | "deny";

export interface ChallengeReceiptEpistemicClaims {
  policy_evaluated: EpistemicType;
  authority_consumed: EpistemicType;
  scope_within_bounds: EpistemicType;
  effect_occurred: EpistemicType;
}

// M3: G → S → K
export interface ChallengeReceipt {
  type: "aps.capability.v1.ChallengeReceipt";
  challenge_hash: string;
  decision: Decision;
  deny_reason?: string;
  delegation_chain_root: string;
  delegation_depth: number;
  authority_token_preimage?: string;
  evaluated_at: string;
  policy_digest: string;
  epistemic_claims: ChallengeReceiptEpistemicClaims;
  gateway_signature: string;
}

export type EffectOutcome = "success" | "failure" | "partial";

export interface SinkEffect {
  executed_at: string;
  outcome: EffectOutcome;
  result_digest: string;
}

export interface EffectReceiptEpistemicClaims {
  effect_occurred: EpistemicType;
  effect_result_bound: EpistemicType;
  policy_evaluation_correct: EpistemicType;
}

// M4: K → S
export interface EffectReceipt {
  type: "aps.capability.v1.EffectReceipt";
  challenge_hash: string;
  authority_token_preimage: string;
  gateway_receipt_hash: string;
  effect: SinkEffect;
  epistemic_claims: EffectReceiptEpistemicClaims;
  sink_signature: string;
}

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}
