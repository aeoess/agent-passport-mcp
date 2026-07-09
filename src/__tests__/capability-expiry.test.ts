// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Regression: a capability SinkChallenge carries a signed expires_at that no
// verifier enforced, so an expired permit stayed redeemable forever.
// verifySinkChallenge / verifyChallengeReceipt now reject an expired challenge.
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair } from "agent-passport-system";
import { issueSinkChallenge } from "../capabilityToken/sinkChallenge.js";
import { verifySinkChallenge } from "../capabilityToken/verify.js";
import type { SinkAction } from "../capabilityToken/types.js";

const action: SinkAction = {
  kind: "fs.write",
  target: "file:///tmp/aps-capability-expiry-test.txt",
  parameters: { content_length: 1 },
  resource_version: "v1",
};

test("verifySinkChallenge accepts a live challenge and rejects an expired one", () => {
  const sink = generateKeyPair();
  const issued = new Date("2026-01-01T00:00:00.000Z");
  const challenge = issueSinkChallenge({
    sink_id: sink.publicKey,
    subject_id: "subject-1",
    action,
    sink_key: sink,
    validity_seconds: 60,
    now: issued,
  });

  // 30s after issue: within the 60s validity.
  assert.equal(verifySinkChallenge(challenge, sink.publicKey, issued.getTime() + 30_000).ok, true);

  // 120s after issue: past expiry.
  const expired = verifySinkChallenge(challenge, sink.publicKey, issued.getTime() + 120_000);
  assert.equal(expired.ok, false);
  assert.match((expired as { reason: string }).reason, /expired/);

  // A valid signature with a wrong key still fails for the signature reason, not expiry.
  const other = generateKeyPair();
  assert.equal(verifySinkChallenge(challenge, other.publicKey, issued.getTime() + 30_000).ok, false);
});
