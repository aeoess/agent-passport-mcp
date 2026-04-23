// Public surface for the v0.1 capability-token reference implementation.
// Spec: agent-passport-system/docs/CAPABILITY-TOKEN-SPEC-DRAFT.md

export * from "./types.js";
export { canonicalWithoutSignature, sha256Hex, sha256Base64Url } from "./canonical.js";
export { issueSinkChallenge, challengeHash } from "./sinkChallenge.js";
export {
  buildEvaluationRequest,
  deriveDelegationChainRoot,
} from "./authorityEvaluation.js";
export { mintChallengeReceipt, challengeReceiptHash } from "./challengeReceipt.js";
export { signEffectReceipt } from "./effectReceipt.js";
export { InMemoryNullifierSet } from "./nullifierSet.js";
export type { NullifierStore } from "./nullifierSet.js";
export {
  verifySinkChallenge,
  verifyAuthorityEvaluationRequest,
  verifyChallengeReceipt,
  verifyEffectReceipt,
  reconstructAttestationChain,
} from "./verify.js";
export type { VerifyResult } from "./verify.js";
