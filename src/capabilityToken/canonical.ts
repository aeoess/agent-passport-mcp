// Helpers for canonical serialization + hashing of v0.1 capability-token
// messages. JCS (RFC 8785) canonicalization is delegated to the SDK.

import { canonicalizeJCS } from "agent-passport-system";
import { createHash } from "node:crypto";

const SIGNATURE_FIELDS = [
  "sink_signature",
  "subject_signature",
  "gateway_signature",
] as const;

type SignatureField = (typeof SIGNATURE_FIELDS)[number];

export function canonicalWithoutSignature(
  obj: object,
  signatureField: SignatureField,
): string {
  const { [signatureField]: _omit, ...rest } = obj as Record<string, unknown>;
  return canonicalizeJCS(rest);
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

export function sha256Base64Url(input: string): string {
  return createHash("sha256").update(input).digest("base64url");
}
