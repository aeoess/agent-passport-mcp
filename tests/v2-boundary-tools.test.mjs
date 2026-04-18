// Smoke tests for the 11 v2 boundary primitive tools added to the MCP server.
// Strategy: import the SDK directly and exercise each tool's happy-path
// SDK call (the tool handlers are thin wrappers). Also assert each tool is
// registered by string-matching src/index.ts.
//
// Run: node --test tests/v2-boundary-tools.test.mjs

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  generateKeyPair, sign,
  createHybridTimestamp,
  createAttributionReceipt, signAttributionConsent,
  verifyAttributionConsent, checkArtifactCitations, receiptCore,
  createProvisional, promoteStatement, verifyPromotion,
  withdrawProvisional, withdrawalPayload, isBinding,
  promotionSigningPayload,
  checkEscalationRequired, requestOwnerConfirmation, recordOwnerConfirmation,
  createV2Delegation, createPolicyContext,
} from 'agent-passport-system'

const INDEX_SRC = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8')

const NEW_TOOLS = [
  'aps_create_attribution_receipt',
  'aps_sign_attribution_consent',
  'aps_verify_attribution_consent',
  'aps_check_artifact_citations',
  'aps_attribution_receipt_id',
  'aps_create_provisional',
  'aps_promote_statement',
  'aps_verify_promotion',
  'aps_withdraw_provisional',
  'aps_check_escalation_required',
  'aps_record_owner_confirmation',
]

test('all 11 v2 boundary tools are registered in src/index.ts', () => {
  for (const name of NEW_TOOLS) {
    assert.ok(
      INDEX_SRC.includes(`"${name}"`),
      `Tool ${name} not registered in src/index.ts`,
    )
  }
})

test('tool count is exactly 142 (v3.0.0 — 12 tools removed, 10 gateway stubs retained)', () => {
  const count = (INDEX_SRC.match(/server\.tool\(/g) || []).length
  assert.equal(count, 142, `Expected 142 server.tool( calls, got ${count}`)
})

test('essential profile includes 3 new boundary tools', () => {
  const essentialMatch = INDEX_SRC.match(/essential: new Set\(\[([\s\S]*?)\]\)/)
  assert.ok(essentialMatch)
  const body = essentialMatch[1]
  for (const name of ['aps_create_attribution_receipt', 'aps_create_provisional', 'aps_check_escalation_required']) {
    assert.ok(body.includes(`'${name}'`), `${name} missing from essential profile`)
  }
})

// ── AttributionConsent happy-path (covers 5 tools) ──────────────
test('attribution-consent: create → sign → verify → check_citations → receipt_id', async () => {
  const citer = generateKeyPair()
  const principal = generateKeyPair()
  const created_at = createHybridTimestamp('mcp-test')
  const expires_at = createHybridTimestamp('mcp-test')
  expires_at.wallClockEarliest = created_at.wallClockEarliest + 3600_000
  expires_at.wallClockLatest = created_at.wallClockLatest + 3600_000

  const receipt = createAttributionReceipt({
    citer: citer.publicKey,
    citer_public_key: citer.publicKey,
    citer_private_key: citer.privateKey,
    cited_principal: principal.publicKey,
    cited_principal_public_key: principal.publicKey,
    citation_content: 'Principal endorses baseline floor F-001.',
    binding_context: 'charter:demo',
    created_at, expires_at,
  })
  assert.ok(receipt.id && receipt.citer_signature)
  assert.equal(receipt.cited_principal_signature, undefined)

  // Pre-consent: verify should fail
  const pre = verifyAttributionConsent(receipt)
  assert.equal(pre.valid, false)

  const signed = signAttributionConsent(receipt, principal.privateKey)
  const post = verifyAttributionConsent(signed)
  assert.equal(post.valid, true, post.reason)

  const artifact = {
    citations: [{
      receipt_id: signed.id,
      cited_principal: signed.cited_principal,
      citation_content: signed.citation_content,
    }],
  }
  const gate = checkArtifactCitations(artifact, [signed], { binding_context: 'charter:demo' })
  assert.equal(gate.valid, true, gate.reason)

  // receipt_id helper: recompute id from core
  const { createHash } = await import('node:crypto')
  const recomputed = createHash('sha256').update(receiptCore(signed)).digest('hex')
  assert.equal(recomputed, signed.id)
})

// ── ProvisionalStatement happy-path (covers 4 tools) ────────────
test('provisional-statement: create → promote → verify → withdraw variants', () => {
  const author = generateKeyPair()
  const principal = generateKeyPair()

  const statement = createProvisional({
    author: author.publicKey,
    author_principal: principal.publicKey,
    content: 'Offer: 100 units @ price 5',
    authorPrivateKey: author.privateKey,
    gatewayId: 'mcp-test',
  })
  assert.equal(statement.status, 'provisional')
  assert.equal(isBinding(statement), false)

  const policy = {
    id: 'policy-1of1',
    required_signers: [principal.publicKey],
    threshold: 1,
    max_time_to_promote: 60_000,
  }
  const promoted_at = createHybridTimestamp('mcp-test')
  const payload = promotionSigningPayload({
    statement_id: statement.id,
    kind: 'principal_signature',
    promoted_at,
    promoter: principal.publicKey,
    policy_reference: policy.id,
  })
  const event = {
    kind: 'principal_signature',
    promoted_at,
    promoter: principal.publicKey,
    promoter_signature: sign(payload, principal.privateKey),
    policy_reference: policy.id,
  }
  const promoted = promoteStatement(statement, event, policy)
  assert.equal(isBinding(promoted), true)
  assert.equal(verifyPromotion(promoted, policy).valid, true)

  // Withdraw path on a separate fresh statement
  const fresh = createProvisional({
    author: author.publicKey,
    author_principal: principal.publicKey,
    content: 'Another offer',
    authorPrivateKey: author.privateKey,
    gatewayId: 'mcp-test',
  })
  const withdrawSig = sign(withdrawalPayload(fresh.id), author.privateKey)
  const withdrawn = withdrawProvisional(fresh, withdrawSig)
  assert.equal(withdrawn.status, 'withdrawn')
})

// ── HumanEscalationFlag happy-path (covers 2 tools) ─────────────
test('human-escalation: check_escalation_required + record_owner_confirmation', () => {
  const owner = generateKeyPair()
  const agent = generateKeyPair()
  const ctx = createPolicyContext({
    policy_version: '2.0.0', values_floor_version: '1.0.0',
    trust_epoch: 1, issuer_id: owner.publicKey,
    valid_until: new Date(Date.now() + 86400_000).toISOString(),
  })
  const delegation = createV2Delegation({
    delegator: owner.publicKey,
    delegatee: agent.publicKey,
    scope: {
      action_categories: ['org'],
      escalation_requirements: [{
        action_class: 'org_creation',
        requires_owner_confirmation: true,
        confirmation_scope: 'per_action',
        confirmation_ttl_ms: 3600_000,
      }],
    },
    policy_context: ctx,
    delegator_private_key: owner.privateKey,
  })

  const flagged = checkEscalationRequired(delegation, {
    action_class: 'org_creation',
    action_details: { name: 'NewOrg' },
    session_id: null,
  })
  assert.equal(flagged.required, true)

  const unflagged = checkEscalationRequired(delegation, {
    action_class: 'benign_read',
    action_details: {},
    session_id: null,
  })
  assert.equal(unflagged.required, false)

  const request = requestOwnerConfirmation(delegation, {
    action_class: 'org_creation',
    action_details: { name: 'NewOrg' },
    session_id: null,
  })
  const confirmation = recordOwnerConfirmation({
    request, delegation, owner_private_key: owner.privateKey,
  })
  assert.ok(confirmation.signature)
  assert.equal(confirmation.action_class, 'org_creation')
})
