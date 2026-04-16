// Smoke tests for the 6 Build A attribution-primitive tools added to the MCP server.
// Strategy: import the SDK directly and exercise each tool's happy-path
// SDK call (the tool handlers are thin wrappers). Also assert each tool is
// registered by string-matching src/index.ts.
//
// Run: node --test tests/attribution-primitive-tools.test.mjs

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  generateKeyPair,
  constructAttributionPrimitive,
  projectAttribution,
  verifyAttributionPrimitive,
  verifyAttributionProjection,
  checkProjectionConsistency,
  computeAttributionActionRef,
} from 'agent-passport-system'

const INDEX_SRC = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8')

const BUILD_A_TOOLS = [
  'aps_construct_attribution_primitive',
  'aps_project_attribution',
  'aps_verify_attribution_projection',
  'aps_verify_attribution_primitive',
  'aps_check_projection_consistency',
  'aps_compute_attribution_action_ref',
]

test('all 6 Build A attribution-primitive tools are registered in src/index.ts', () => {
  for (const name of BUILD_A_TOOLS) {
    assert.ok(
      INDEX_SRC.includes(`"${name}"`),
      `Tool ${name} not registered in src/index.ts`,
    )
  }
})

test('essential profile includes 2 attribution-primitive tools', () => {
  const essentialMatch = INDEX_SRC.match(/essential: new Set\(\[([\s\S]*?)\]\)/)
  assert.ok(essentialMatch)
  const body = essentialMatch[1]
  for (const name of ['aps_construct_attribution_primitive', 'aps_verify_attribution_primitive']) {
    assert.ok(body.includes(`\'${name}\'`), `${name} missing from essential profile`)
  }
})

// ── AttributionPrimitive happy-path (covers all 6 tools) ────────
test('attribution-primitive: construct → project → verify → consistency → action_ref', () => {
  const { publicKey, privateKey } = generateKeyPair()
  const issuer = 'did:aps:gateway-test'

  const action = {
    agentId: 'did:aps:agent-alpha',
    actionType: 'query.summarize',
    params: { prompt: 'demo', region: 'us-west' },
    nonce: '11111111-1111-1111-1111-111111111111',
  }

  const axes = {
    D: [
      { source_did: 'did:data:a', contribution_weight: '0.600000', access_receipt_hash: 'a'.repeat(64) },
      { source_did: 'did:data:b', contribution_weight: '0.400000', access_receipt_hash: 'b'.repeat(64) },
    ],
    P: [
      { module_id: 'redact-v2', module_version: '2.3.1', evaluation_outcome: 'approved', evaluation_receipt_hash: 'c'.repeat(64) },
    ],
    G: [
      { delegation_id: 'delegation:root', signer_did: 'did:aps:customer', scope_hash: 'f'.repeat(64), depth: 0 },
      { delegation_id: 'delegation:agent', signer_did: 'did:aps:agent', scope_hash: 'e'.repeat(64), depth: 1 },
    ],
    C: [
      { provider_did: 'did:compute:a', compute_share: '1.000000', hardware_attestation_hash: '1'.repeat(64) },
    ],
  }

  // 1) construct
  const primitive = constructAttributionPrimitive({
    action,
    axes,
    issuer,
    issuerPrivateKey: privateKey,
  })
  assert.ok(primitive.signature)
  assert.ok(primitive.merkle_root)
  assert.ok(primitive.action_ref)
  assert.equal(primitive.issuer, issuer)

  // 2) action_ref helper recomputes the same value
  const ref = computeAttributionActionRef(action)
  assert.equal(ref, primitive.action_ref)

  // 3) verify full primitive (all four axes)
  const fullVerify = verifyAttributionPrimitive(primitive, publicKey)
  assert.equal(fullVerify.valid, true)

  // 4) project onto D axis
  const projection = projectAttribution(primitive, 'D')
  assert.equal(projection.axis_tag, 'D')
  assert.ok(Array.isArray(projection.merkle_path))

  // 5) verify projection against issuer key
  const projVerify = verifyAttributionProjection(projection, publicKey)
  assert.equal(projVerify.valid, true)

  // 6) check projection consistency: projection derived from the same primitive
  //    should report same_receipt relative to another projection of the same
  //    primitive on a different axis
  const projectionP = projectAttribution(primitive, 'P')
  const consistency = checkProjectionConsistency(projection, projectionP)
  assert.equal(consistency.same_receipt, true, consistency.reason ?? 'expected same_receipt')
})
