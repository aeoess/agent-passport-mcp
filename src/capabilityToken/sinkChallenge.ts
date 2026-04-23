// M1: SinkChallenge issuance and challenge-hash computation.

import { randomBytes } from "node:crypto";
import { sign } from "agent-passport-system";
import type {
  KeyPair,
  PolicyFreshnessRequirement,
  SinkAction,
  SinkChallenge,
} from "./types.js";
import { canonicalWithoutSignature, sha256Hex } from "./canonical.js";

export interface IssueSinkChallengeOptions {
  sink_id: string;
  subject_id: string;
  action: SinkAction;
  validity_seconds?: number;
  required_policy_freshness?: PolicyFreshnessRequirement;
  sink_key: KeyPair;
  // Test hooks — deterministic nonce / clock for fixtures.
  now?: Date;
  nonce?: string;
}

const DEFAULT_VALIDITY_SECONDS = 60;

const DEFAULT_FRESHNESS: PolicyFreshnessRequirement = {
  max_age_seconds: 30,
  beacon_hash_required: true,
};

export function issueSinkChallenge(opts: IssueSinkChallengeOptions): SinkChallenge {
  const issued = opts.now ?? new Date();
  const validity = opts.validity_seconds ?? DEFAULT_VALIDITY_SECONDS;
  const expires = new Date(issued.getTime() + validity * 1000);
  const nonce = opts.nonce ?? randomBytes(32).toString("base64url");

  const unsigned: Omit<SinkChallenge, "sink_signature"> = {
    type: "aps.capability.v1.SinkChallenge",
    sink_id: opts.sink_id,
    subject_id: opts.subject_id,
    action: opts.action,
    nonce,
    issued_at: issued.toISOString(),
    expires_at: expires.toISOString(),
    required_policy_freshness: opts.required_policy_freshness ?? DEFAULT_FRESHNESS,
  };

  const signature = sign(
    canonicalWithoutSignature({ ...unsigned, sink_signature: "" }, "sink_signature"),
    opts.sink_key.privateKey,
  );

  return { ...unsigned, sink_signature: signature };
}

export function challengeHash(challenge: SinkChallenge): string {
  return sha256Hex(canonicalWithoutSignature(challenge, "sink_signature"));
}
