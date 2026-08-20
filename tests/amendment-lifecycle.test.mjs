// Security properties of the amendment lifecycle that replaced evaluate_threshold,
// plus MCP's own error-propagation contract.
//
// The removed tool accepted signature records whose `signature` field defaulted to the
// empty string, counted the declared signers, and printed THRESHOLD MET. These tests
// assert the properties that made replacing it necessary, by driving the same SDK
// functions the three new tool handlers call.
//
// Run: node --test tests/amendment-lifecycle.test.mjs

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, sign,
  createCharter, createAmendment, signAmendment, verifyAmendment,
} from 'agent-passport-system'
import { canonicalWithoutSignature } from '../build/capabilityToken/canonical.js'

function makeCharter(boardKeys, requiredSignatures, founder) {
  const policy = {
    policyId: 'amend_policy',
    requirements: [{ role: 'board', requiredSignatures, eligibleKeys: boardKeys }],
    collectionTimeoutSeconds: 86400,
    onTimeout: 'reject',
    reevaluateOnRevocation: true,
  }
  return createCharter({
    name: 'Test Institution',
    offices: [{
      officeId: 'chair', name: 'Chair', holderMode: 'single',
      holderSet: [{ publicKey: founder.publicKey, appointedAt: new Date().toISOString(), appointedBy: 'charter_founding', isInterim: false }],
      delegationPolicy: { allowedScopes: ['*'], maxSpendPerAction: 1000, maxDelegationDepth: 3 },
      successionOrder: [], status: 'active', effectiveAt: new Date().toISOString(),
    }],
    amendmentPolicy: policy,
    dissolutionPolicy: { requiresThreshold: policy, gracePeriodSeconds: 86400, activeEscrowHandling: 'settle_first' },
    delegationSurvival: { onOfficeChange: 'require_reconfirmation', onCharterAmendment: 'survive_if_compatible' },
    founderPrivateKey: founder.privateKey,
    founderPublicKey: founder.publicKey,
    founderRole: 'board',
  })
}

// ── P1: a forged signature never counts toward a threshold ──────────────────
//
// This is the property the old tool did not have. It accepted a record whose
// `signature` defaulted to "" and counted it.
test('P1 forged signature: a well-formed but wrong signature does not count and is named', () => {
  const founder = generateKeyPair()
  const good = generateKeyPair()
  const forged = generateKeyPair()
  const charter = makeCharter([founder.publicKey, good.publicKey, forged.publicKey], 3, founder)

  const proposed = { ...charter, name: 'Renamed Institution' }
  let amendment = createAmendment({
    charter,
    proposedCharter: proposed,
    description: 'rename',
    proposerPrivateKey: founder.privateKey,
    proposerPublicKey: founder.publicKey,
  })

  // One genuine signature, produced by the SDK over the SDK's own preimage.
  amendment = signAmendment(amendment, good.privateKey, good.publicKey, 'board')

  // A forged record: structurally well formed, correct length, wrong bytes. It is a
  // real Ed25519 signature over unrelated content, which is the realistic forgery,
  // not an obviously empty string.
  const forgedSig = sign('content this signer never agreed to', forged.privateKey)
  amendment = {
    ...amendment,
    signatures: [...amendment.signatures, {
      publicKey: forged.publicKey,
      role: 'board',
      signedAt: new Date().toISOString(),
      signature: forgedSig,
    }],
  }
  assert.equal(forgedSig.length, 128, 'the forged signature should be well formed, not empty')

  const v = verifyAmendment(amendment, charter)

  assert.equal(v.thresholdMet, false,
    'a forged signature must not be counted toward the threshold')
  // The SDK names the signer by a truncated key prefix, so match on a prefix rather
  // than the full key. Kept tight enough to be meaningful: the error must both name
  // this signer and say the signature was invalid.
  const namesForgedSigner = v.errors.some(e =>
    e.includes(forged.publicKey) || e.includes(forged.publicKey.slice(0, 8)))
  assert.ok(
    namesForgedSigner,
    `the forged signer must be named in errors. errors were: ${JSON.stringify(v.errors)}`,
  )
  assert.ok(
    v.errors.some(e => /invalid signature/i.test(e)),
    `errors must say the signature was invalid, not merely that a threshold was short. ` +
    `errors were: ${JSON.stringify(v.errors)}`,
  )
  // The genuine signer must NOT be blamed.
  assert.ok(
    !v.errors.some(e => e.includes(good.publicKey.slice(0, 8))),
    'the valid signer must not appear in errors',
  )
})

// ── P2: a signature cannot be replayed onto a different proposed charter ────
//
// The property comes from the SDK binding proposedCharter into the preimage. This
// asserts MCP does not undo it, which is the only part MCP controls.
test('P2 replay: a signature lifted onto a different proposedCharter does not verify', () => {
  const founder = generateKeyPair()
  const signer = generateKeyPair()
  const charter = makeCharter([founder.publicKey, signer.publicKey], 2, founder)

  const amendmentA = signAmendment(
    createAmendment({
      charter,
      proposedCharter: { ...charter, name: 'Alpha' },
      description: 'rename to Alpha',
      proposerPrivateKey: founder.privateKey,
      proposerPublicKey: founder.publicKey,
    }),
    signer.privateKey, signer.publicKey, 'board',
  )

  const liftedSignature = amendmentA.signatures.find(s => s.publicKey === signer.publicKey)
  assert.ok(liftedSignature, 'expected a signature from the signer on amendment A')

  // Amendment B differs ONLY in proposedCharter. If proposedCharter were not bound
  // into the preimage, A's signature would verify here.
  const amendmentB = createAmendment({
    charter,
    proposedCharter: { ...charter, name: 'Beta' },
    description: 'rename to Alpha',
    proposerPrivateKey: founder.privateKey,
    proposerPublicKey: founder.publicKey,
  })
  const replayed = {
    ...amendmentB,
    signatures: [...amendmentB.signatures, { ...liftedSignature }],
  }

  const v = verifyAmendment(replayed, charter)
  assert.equal(v.signaturesValid, false,
    'a signature over amendment A must not verify against amendment B')
})

// ── P4: MCP's wrapper propagates the SDK's rejection rather than swallowing it ──
//
// canonicalWithoutSignature builds `rest` by rest-spread and hands it to the SDK's
// canonicalizeJCS. The contract under test is MCP's: the SDK's rejection must reach
// the caller unchanged in meaning, including the path naming the offending member.
//
// Asserted as a PROPERTY, not as a class. The SDK is free to introduce a typed error
// later; this test must survive that without being edited, so it never names TypeError.
test('P4 propagation: an explicit undefined member reaches the caller as an error naming the member', () => {
  const offending = 'subject_did'
  const obj = {
    sink_signature: 'aa'.repeat(32),
    audience: 'did:aps:gateway',
    [offending]: undefined,   // explicitly present and undefined, not absent
  }

  let threw = false
  let caught
  try {
    canonicalWithoutSignature(obj, 'sink_signature')
  } catch (e) {
    threw = true
    caught = e
  }

  assert.ok(threw,
    'canonicalWithoutSignature must not swallow the SDK rejection, coerce the member ' +
    'to null, or fall back to a value. Returning a string here would mean MCP signed ' +
    'bytes the SDK refused to produce.')

  const message = String(caught && caught.message ? caught.message : caught)
  assert.ok(
    message.includes(offending),
    `the propagated error must still name the offending member. Got: ${message}`,
  )
  // Meaning preserved, not merely "something threw": a generic wrapper message that
  // lost the path would pass a naive assertion and fail this one.
  assert.ok(
    /undefined/i.test(message),
    `the propagated error must still say what was wrong with it. Got: ${message}`,
  )
})

// Corollary named in the design: a field meant to be absent is OMITTED by the builder,
// never set to undefined. This is the shape that must keep working.
test('P4 corollary: an omitted member canonicalizes cleanly', () => {
  const s = canonicalWithoutSignature(
    { sink_signature: 'aa'.repeat(32), audience: 'did:aps:gateway' },
    'sink_signature',
  )
  assert.equal(s, '{"audience":"did:aps:gateway"}')
})
