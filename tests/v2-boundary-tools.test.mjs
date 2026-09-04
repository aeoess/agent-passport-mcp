// Smoke tests for the 11 v2 boundary primitive tools added to the MCP server.
// Strategy: import the SDK directly and exercise each tool's happy-path
// SDK call (the tool handlers are thin wrappers). Also assert each tool is
// registered by string-matching src/index.ts.
//
// Run: node --test tests/v2-boundary-tools.test.mjs

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import {
  generateKeyPair, sign, createDID,
  createHybridTimestamp,
  createAttributionReceipt, signAttributionConsent,
  verifyAttributionConsent, checkArtifactCitations, receiptCore,
  createProvisional, promoteStatement, verifyPromotion,
  withdrawProvisional, withdrawalPayload, isBinding,
  promotionSigningPayload,
  checkEscalationRequired, requestOwnerConfirmation, recordOwnerConfirmation,
  createV2Delegation, createPolicyContext,
  createCharter, verifyCharter,
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

// The tool inventory is asserted against the RUNTIME registry, not against a literal
// and not by counting `server.registerTool(` in source text.
//
// Counting call sites in source is what let a downstream consumer silently report zero
// once the registration API was renamed: the grep still ran, still matched nothing, and
// still looked like a result. This asserts the two things that must agree, the live
// registry and the generated manifest, so adding a tool cannot leave a stale number
// anywhere and cannot be faked by editing a string.
test('generated manifest equals the runtime tool registry, names and count', async () => {
  // createSandboxServer() suppresses the deferred main(). Without it the module
  // connects a stdio transport and the test run never exits.
  const mod = await import('../build/index.js')
  mod.createSandboxServer()
  const { REGISTERED_TOOL_NAMES } = mod
  const manifest = JSON.parse(readFileSync(new URL('../tools-manifest.json', import.meta.url), 'utf8'))

  assert.equal(
    manifest.count, REGISTERED_TOOL_NAMES.length,
    `manifest count ${manifest.count} != runtime registry ${REGISTERED_TOOL_NAMES.length}. ` +
    `Run npm run build to regenerate tools-manifest.json.`,
  )
  assert.deepEqual(
    [...manifest.tools].sort(), [...REGISTERED_TOOL_NAMES].sort(),
    'manifest tool NAMES differ from the runtime registry, not just the count',
  )
  assert.equal(new Set(REGISTERED_TOOL_NAMES).size, REGISTERED_TOOL_NAMES.length,
    'a tool name is registered twice')
})

// The registry is populated BEFORE the wrapper's profile filter returns early. If that
// ordering is ever reversed the manifest silently becomes a function of whatever
// APS_PROFILE was set when the build ran, which is the same defect one layer up.
test('the manifest is a property of the source, not of APS_PROFILE', () => {
  const gen = fileURLToPath(new URL('../scripts/generate-manifest.mjs', import.meta.url))
  const root = fileURLToPath(new URL('..', import.meta.url))
  const read = () => readFileSync(new URL('../tools-manifest.json', import.meta.url), 'utf8')

  const before = read()
  execFileSync(process.execPath, [gen], { cwd: root, env: { ...process.env, APS_PROFILE: 'governance' }, stdio: 'pipe' })
  const underGovernance = read()
  execFileSync(process.execPath, [gen], { cwd: root, env: { ...process.env, APS_PROFILE: 'full' }, stdio: 'pipe' })
  const underFull = read()

  assert.equal(
    underGovernance, underFull,
    'tools-manifest.json differs between APS_PROFILE=governance and APS_PROFILE=full. ' +
    'The registry push must happen BEFORE the profile filter returns early in the ' +
    'registerTool wrapper, or the inventory becomes environment-dependent.',
  )
  assert.equal(before, underFull, 'regeneration was not idempotent')
})

test('evaluate_threshold is gone and the amendment lifecycle replaced it', () => {
  const manifest = JSON.parse(readFileSync(new URL('../tools-manifest.json', import.meta.url), 'utf8'))
  assert.ok(!manifest.tools.includes('evaluate_threshold'),
    'evaluate_threshold counted declared signers without verifying them; it must not come back')
  for (const t of ['propose_amendment', 'sign_amendment', 'verify_amendment']) {
    assert.ok(manifest.tools.includes(t), `${t} missing from the manifest`)
  }
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

  // 6.0.0 binds each party to the key beside it, so a party is named by a
  // self-certifying DID and not by the bare key. createDID emits the multibase
  // did:aps form; the hex form from createDIDHex does not self-certify.
  const receipt = createAttributionReceipt({
    citer: createDID(citer.publicKey),
    citer_public_key: citer.publicKey,
    citer_private_key: citer.privateKey,
    cited_principal: createDID(principal.publicKey),
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

// ── AttributionConsent under the 6.0.0 binding contract ─────────
// The advisory's attacker case for this surface: a receipt carrying a victim's
// identifier next to an attacker's key. 6.0.0 binds each named party to the key
// beside it, so the identifier alone no longer speaks for the victim.
test('attribution-consent: a victim identifier beside an attacker key is refused', () => {
  const attacker = generateKeyPair()
  const victim = generateKeyPair()
  const created_at = createHybridTimestamp('mcp-test')
  const expires_at = createHybridTimestamp('mcp-test')
  expires_at.wallClockEarliest = created_at.wallClockEarliest + 3600_000
  expires_at.wallClockLatest = created_at.wallClockLatest + 3600_000

  // The receipt names the victim, and carries the attacker's key beside that name.
  const receipt = createAttributionReceipt({
    citer: createDID(attacker.publicKey),
    citer_public_key: attacker.publicKey,
    citer_private_key: attacker.privateKey,
    cited_principal: createDID(victim.publicKey),
    cited_principal_public_key: attacker.publicKey,
    citation_content: 'The victim endorses this.',
    binding_context: 'charter:demo',
    created_at, expires_at,
  })
  const signed = signAttributionConsent(receipt, attacker.privateKey)
  const result = verifyAttributionConsent(signed)
  assert.equal(result.valid, false, 'a victim DID beside an attacker key must not verify')
  assert.match(String(result.reason), /cited_principal binding rejected/)

  // The citation gate inherits the refusal rather than reaching its own verdict.
  const artifact = {
    citations: [{
      receipt_id: signed.id,
      cited_principal: signed.cited_principal,
      citation_content: signed.citation_content,
    }],
  }
  const gate = checkArtifactCitations(artifact, [signed], { binding_context: 'charter:demo' })
  assert.equal(gate.valid, false, 'checkArtifactCitations must inherit the binding refusal')
})

test('attribution-consent: identifiers that do not self-certify are refused, not assumed', () => {
  const citer = generateKeyPair()
  const principal = generateKeyPair()
  const created_at = createHybridTimestamp('mcp-test')
  const expires_at = createHybridTimestamp('mcp-test')
  expires_at.wallClockEarliest = created_at.wallClockEarliest + 3600_000
  expires_at.wallClockLatest = created_at.wallClockLatest + 3600_000

  const mint = (citerName, principalName) => signAttributionConsent(
    createAttributionReceipt({
      citer: citerName,
      citer_public_key: citer.publicKey,
      citer_private_key: citer.privateKey,
      cited_principal: principalName,
      cited_principal_public_key: principal.publicKey,
      citation_content: 'Principal endorses baseline floor F-001.',
      binding_context: 'charter:demo',
      created_at, expires_at,
    }),
    principal.privateKey,
  )

  // A bare public key names nothing that commits to a key.
  const bare = verifyAttributionConsent(mint(citer.publicKey, principal.publicKey))
  assert.equal(bare.valid, false, 'a bare public key is not a self-certifying identifier')
  assert.match(String(bare.reason), /unresolved/)

  // An opaque application identifier is refused for the same reason.
  const opaque = verifyAttributionConsent(mint('agent:citer', 'agent:principal'))
  assert.equal(opaque.valid, false, 'an opaque identifier is not a self-certifying identifier')

  // The canonical form from createDID is the migration, and it verifies.
  const good = verifyAttributionConsent(mint(createDID(citer.publicKey), createDID(principal.publicKey)))
  assert.equal(good.valid, true, good.reason)
})

// ── verify_charter now depends on a gate the tool has to be given ─────
// 6.0.0 added an AttributionConsent gate to verifyCharter. A charter that
// declares citations cannot verify unless the caller supplies the receipts, so
// the MCP tool exposes attribution_receipts and passes it through.
test('verify_charter: a cited charter fails closed without receipts and passes with them', () => {
  const founder = generateKeyPair()
  const citer = generateKeyPair()
  const principal = generateKeyPair()

  const created_at = createHybridTimestamp('mcp-test')
  const expires_at = createHybridTimestamp('mcp-test')
  expires_at.wallClockEarliest = created_at.wallClockEarliest + 3600_000
  expires_at.wallClockLatest = created_at.wallClockLatest + 3600_000

  const receipt = signAttributionConsent(createAttributionReceipt({
    citer: createDID(citer.publicKey),
    citer_public_key: citer.publicKey,
    citer_private_key: citer.privateKey,
    cited_principal: createDID(principal.publicKey),
    cited_principal_public_key: principal.publicKey,
    citation_content: 'Principal endorses the founding purpose.',
    binding_context: 'charter:test',
    created_at, expires_at,
  }), principal.privateKey)

  const now = new Date().toISOString()
  const policy = {
    policyId: 'amend_policy',
    requirements: [{ role: 'board', requiredSignatures: 1, eligibleKeys: [founder.publicKey] }],
    collectionTimeoutSeconds: 86400,
    onTimeout: 'reject',
    reevaluateOnRevocation: true,
  }
  const charter = createCharter({
    name: 'Test Charter',
    offices: [{
      officeId: 'board',
      name: 'Board',
      holderMode: 'single',
      holderSet: [{ publicKey: founder.publicKey, appointedAt: now, appointedBy: 'charter_founding', isInterim: false }],
      delegationPolicy: { allowedScopes: ['governance'], maxSpendPerAction: 0, maxDelegationDepth: 1 },
      successionOrder: [],
      status: 'active',
      effectiveAt: now,
      incompatibleOffices: [],
    }],
    amendmentPolicy: policy,
    dissolutionPolicy: { requiresThreshold: policy, gracePeriodSeconds: 86400, activeEscrowHandling: 'settle_first' },
    delegationSurvival: { onOfficeChange: 'require_reconfirmation', onCharterAmendment: 'survive_if_compatible' },
    founderPrivateKey: founder.privateKey,
    founderPublicKey: founder.publicKey,
    founderRole: 'board',
    citations: [{
      receipt_id: receipt.id,
      cited_principal: receipt.cited_principal,
      citation_content: receipt.citation_content,
    }],
  })

  // No receipts: the gate fails closed rather than skipping itself.
  const without = verifyCharter(charter)
  assert.equal(without.valid, false, 'a cited charter must not verify without receipts')
  assert.ok(
    without.errors.some(e => /citations present but no receipts supplied/.test(e)),
    `expected the citation error, got: ${JSON.stringify(without.errors)}`,
  )

  // With the receipts, the citation gate is satisfied and stops being the blocker.
  const withReceipts = verifyCharter(charter, [receipt])
  assert.ok(
    !withReceipts.errors.some(e => /citations present but no receipts supplied|AttributionConsent/.test(e)),
    `citation gate should be satisfied, got: ${JSON.stringify(withReceipts.errors)}`,
  )

  // The tool threads the input through rather than dropping it.
  assert.match(INDEX_SRC, /verifyCharter\(charter, args\.attribution_receipts/)
  assert.match(INDEX_SRC, /attribution_receipts: z\.array\(z\.any\(\)\)\.optional\(\)/)
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
