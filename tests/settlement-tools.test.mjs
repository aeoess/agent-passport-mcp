// Smoke tests for the 3 Build C attribution-settlement tools added to
// the MCP server. Strategy mirrors attribution-weights-tools.test.mjs:
// import the SDK directly and exercise each tool's happy path (the tool
// handlers are thin wrappers). Also assert each tool is registered and
// wired into the new 'settlement' scope, not in essentials.
//
// Run: node --test tests/settlement-tools.test.mjs

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  aggregateAttributionPrimitives,
  buildContributorQueryResponse,
  constructAttributionPrimitive,
  publicKeyFromPrivate,
  signSettlementRecord,
  verifyContributorQueryResponse,
  verifySettlementRecord,
} from 'agent-passport-system'

const INDEX_SRC = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8')

const BUILD_C_TOOLS = [
  'aps_aggregate_settlement',
  'aps_verify_settlement',
  'aps_build_contributor_query',
]

test('all 3 Build C settlement tools are registered in src/index.ts', () => {
  for (const name of BUILD_C_TOOLS) {
    assert.ok(
      INDEX_SRC.includes(`"${name}"`),
      `Tool ${name} not registered in src/index.ts`,
    )
  }
})

test('all 3 Build C tools are wired into the settlement scope (not essentials)', () => {
  for (const name of BUILD_C_TOOLS) {
    assert.ok(
      INDEX_SRC.includes(`'${name}': 'settlement'`),
      `Tool ${name} missing from TOOL_SCOPE_MAP`,
    )
  }
  const essentialMatch = INDEX_SRC.match(/essential: new Set\(\[([\s\S]*?)\]\)/)
  assert.ok(essentialMatch)
  for (const name of BUILD_C_TOOLS) {
    assert.ok(
      !essentialMatch[1].includes(`'${name}'`),
      `${name} must NOT appear in essentials profile (integration-layer only)`,
    )
  }
})

// ─────────────────────────────────────────────────────────────
// Happy-path: aggregate → sign → verify → contributor query → verify
// ─────────────────────────────────────────────────────────────

const GATEWAY_PRIV = 'a'.repeat(64)
const GATEWAY_PUB = publicKeyFromPrivate(GATEWAY_PRIV)
const GATEWAY_DID = `did:gateway:mcp-test-${GATEWAY_PUB.slice(0, 12)}`

test('aggregate → verify → contributor query full round-trip', () => {
  const t0 = '2026-04-10T00:00:00.000Z'
  const t1 = '2026-04-11T00:00:00.000Z'
  const period = { t0, t1, period_id: 'mcp-settlement-smoke' }

  const receipts = []
  const baseMs = Date.parse(t0)
  for (let i = 0; i < 5; i++) {
    const axes = {
      D: [
        { source_did: `did:data:src-${i}`, contribution_weight: '0.700000', access_receipt_hash: 'a'.repeat(64) },
        { source_did: `did:data:alt-${i}`, contribution_weight: '0.300000', access_receipt_hash: 'b'.repeat(64) },
      ],
      P: [],
      G: [{ delegation_id: `d-${i}`, signer_did: 'did:gov:root', scope_hash: 'f'.repeat(64), depth: 0 }],
      C: [{ provider_did: 'did:compute:main', compute_share: '1.000000', hardware_attestation_hash: '1'.repeat(64) }],
    }
    receipts.push(constructAttributionPrimitive({
      action: { agentId: 'did:agent:mcp', actionType: 'gen', params: { i }, nonce: `n-${i}` },
      axes,
      issuer: GATEWAY_DID,
      issuerPrivateKey: GATEWAY_PRIV,
      timestamp: new Date(baseMs + i * 60_000).toISOString(),
    }))
  }

  const unsigned = aggregateAttributionPrimitives(receipts, period, {
    gateway_did: GATEWAY_DID,
    issued_at: '2026-04-11T00:00:00.001Z',
  })
  const signature = signSettlementRecord(unsigned, GATEWAY_PRIV)
  const record = { ...unsigned, signature }

  const verdict = verifySettlementRecord(record, { gatewayPublicKeyHex: GATEWAY_PUB })
  assert.equal(verdict.valid, true, JSON.stringify(verdict))

  const q = buildContributorQueryResponse(record, 'did:compute:main')
  assert.ok(q)
  const qv = verifyContributorQueryResponse(q, { gatewayPublicKeyHex: GATEWAY_PUB })
  assert.equal(qv.valid, true, JSON.stringify(qv))
  assert.ok(q.per_axis.C, 'expected C-axis body for did:compute:main')
})

test('verify flags a tampered record with a specific reason', () => {
  const t0 = '2026-04-12T00:00:00.000Z'
  const t1 = '2026-04-13T00:00:00.000Z'
  const period = { t0, t1, period_id: 'mcp-tamper' }
  const receipts = [constructAttributionPrimitive({
    action: { agentId: 'did:agent:mcp', actionType: 'gen', params: {}, nonce: 'one' },
    axes: {
      D: [{ source_did: 'did:data:x', contribution_weight: '1.000000', access_receipt_hash: 'a'.repeat(64) }],
      P: [],
      G: [{ delegation_id: 'dx', signer_did: 'did:gov:root', scope_hash: 'f'.repeat(64), depth: 0 }],
      C: [{ provider_did: 'did:compute:x', compute_share: '1.000000', hardware_attestation_hash: '1'.repeat(64) }],
    },
    issuer: GATEWAY_DID,
    issuerPrivateKey: GATEWAY_PRIV,
    timestamp: t0,
  })]
  const unsigned = aggregateAttributionPrimitives(receipts, period, { gateway_did: GATEWAY_DID, issued_at: '2026-04-13T00:00:00.001Z' })
  const signature = signSettlementRecord(unsigned, GATEWAY_PRIV)
  const record = { ...unsigned, signature }

  const tampered = JSON.parse(JSON.stringify(record))
  tampered.signature = 'b'.repeat(128)
  const verdict = verifySettlementRecord(tampered, { gatewayPublicKeyHex: GATEWAY_PUB })
  assert.equal(verdict.valid, false)
  assert.equal(verdict.reason, 'SIGNATURE_INVALID')
})
