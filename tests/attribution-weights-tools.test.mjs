// Smoke tests for the 2 Build B attribution-weights tools added to the
// MCP server. Strategy mirrors attribution-primitive-tools.test.mjs:
// import the SDK directly and exercise each tool's happy path (the tool
// handlers are thin wrappers). Also assert each tool is registered in
// src/index.ts and wired into the 'attribution' scope, not in essential.
//
// Run: node --test tests/attribution-weights-tools.test.mjs

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  computeDataAxisWeights,
  computeComputeAxisWeights,
  DEFAULT_WEIGHT_PROFILE,
  hashWeightProfile,
  validateWeightProfile,
  constructAttributionPrimitive,
  projectAttribution,
  verifyAttributionProjection,
  generateKeyPair,
} from 'agent-passport-system'

const INDEX_SRC = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8')

const BUILD_B_TOOLS = [
  'aps_compute_data_axis_weights',
  'aps_compute_compute_axis_weights',
]

test('both Build B attribution-weights tools are registered in src/index.ts', () => {
  for (const name of BUILD_B_TOOLS) {
    assert.ok(
      INDEX_SRC.includes(`"${name}"`),
      `Tool ${name} not registered in src/index.ts`,
    )
  }
})

test('both Build B tools are wired into the attribution scope', () => {
  for (const name of BUILD_B_TOOLS) {
    assert.ok(
      INDEX_SRC.includes(`'${name}': 'attribution'`),
      `Tool ${name} not mapped to 'attribution' scope`,
    )
  }
})

test('Build B tools are NOT in the essential profile (integration layer)', () => {
  const essentialMatch = INDEX_SRC.match(/essential: new Set\(\[([\s\S]*?)\]\)/)
  assert.ok(essentialMatch)
  const body = essentialMatch[1]
  for (const name of BUILD_B_TOOLS) {
    assert.ok(!body.includes(`'${name}'`), `${name} should NOT appear in essential profile`)
  }
})

// ── D-axis weight computation happy-path ────────────────────────
test('aps_compute_data_axis_weights: canonical 6-digit weights that sum to ~1.0', () => {
  const sources = [
    { source_did: 'did:data:a', access_receipt_hash: 'a'.repeat(64), role: 'primary_source', timestamp: '2026-04-15T00:00:00.000Z', content_length: 2000 },
    { source_did: 'did:data:b', access_receipt_hash: 'b'.repeat(64), role: 'supporting_evidence', timestamp: '2026-04-10T00:00:00.000Z', content_length: 1000 },
    { source_did: 'did:data:c', access_receipt_hash: 'c'.repeat(64), role: 'context_only', timestamp: '2026-04-14T00:00:00.000Z', content_length: 500 },
  ]
  const entries = computeDataAxisWeights(sources, { action_timestamp: '2026-04-16T12:00:00.000Z' })
  assert.equal(entries.length, 3)
  for (const e of entries) {
    assert.match(e.contribution_weight, /^\d+\.\d{6}$/)
    assert.match(e.access_receipt_hash, /^[a-f0-9]{64}$/)
  }
  const sum = entries.reduce((a, e) => a + Number.parseFloat(e.contribution_weight), 0)
  assert.ok(Math.abs(sum - 1) < 1e-5, `sum=${sum}`)
})

// ── C-axis weight computation happy-path ────────────────────────
test('aps_compute_compute_axis_weights: canonical 6-digit shares that sum to ~1.0', () => {
  const providers = [
    { provider_did: 'did:compute:anthropic', hardware_attestation_hash: '1'.repeat(64), prompt_tokens: 1000, completion_tokens: 500 },
    { provider_did: 'did:compute:openai', hardware_attestation_hash: '2'.repeat(64), prompt_tokens: 800, completion_tokens: 400 },
  ]
  const entries = computeComputeAxisWeights(providers)
  assert.equal(entries.length, 2)
  for (const e of entries) {
    assert.match(e.compute_share, /^\d+\.\d{6}$/)
  }
  const sum = entries.reduce((a, e) => a + Number.parseFloat(e.compute_share), 0)
  assert.ok(Math.abs(sum - 1) < 1e-5, `sum=${sum}`)
})

// ── Profile surface: default, validation, hash ──────────────────
test('DEFAULT_WEIGHT_PROFILE validates, hashes stably, and produces deterministic output', () => {
  const result = validateWeightProfile(DEFAULT_WEIGHT_PROFILE)
  assert.equal(result.valid, true, result.errors.join('; '))
  const h1 = hashWeightProfile(DEFAULT_WEIGHT_PROFILE)
  const h2 = hashWeightProfile(DEFAULT_WEIGHT_PROFILE)
  assert.equal(h1, h2)
  assert.match(h1, /^[0-9a-f]{64}$/)
})

// ── Build A + Build B wiring: compute → construct → project → verify ──
test('Build B weights feed Build A primitive construction end-to-end', () => {
  const { publicKey, privateKey } = generateKeyPair()
  const actionTs = '2026-04-16T12:00:00.000Z'
  const D = computeDataAxisWeights([
    { source_did: 'did:data:a', access_receipt_hash: 'a'.repeat(64), role: 'primary_source', timestamp: '2026-04-15T00:00:00.000Z', content_length: 2000 },
    { source_did: 'did:data:b', access_receipt_hash: 'b'.repeat(64), role: 'supporting_evidence', timestamp: '2026-04-10T00:00:00.000Z', content_length: 1000 },
  ], { action_timestamp: actionTs })
  const C = computeComputeAxisWeights([
    { provider_did: 'did:compute:x', hardware_attestation_hash: '1'.repeat(64), prompt_tokens: 500, completion_tokens: 250 },
  ])
  const primitive = constructAttributionPrimitive({
    action: {
      agentId: 'did:aps:agent-beta',
      actionType: 'query.summarize',
      params: { topic: 'demo' },
      nonce: '22222222-2222-2222-2222-222222222222',
    },
    axes: {
      D,
      P: [{ module_id: 'm1', module_version: '1.0.0', evaluation_outcome: 'approved', evaluation_receipt_hash: 'e'.repeat(64) }],
      G: [{ delegation_id: 'd1', signer_did: 'did:aps:owner', scope_hash: 'f'.repeat(64), depth: 0 }],
      C,
    },
    issuer: 'did:aps:issuer',
    issuerPrivateKey: privateKey,
    timestamp: actionTs,
  })
  const projection = projectAttribution(primitive, 'D')
  const verdict = verifyAttributionProjection(projection, publicKey)
  assert.equal(verdict.valid, true, verdict.reason)
})
