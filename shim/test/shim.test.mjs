// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, verify, canonicalize } from 'agent-passport-system'
import {
  instrumentToolHandler,
  createAccessReceipt,
  verifyAccessReceipt,
  ACCESS_RECEIPT_PROFILE,
} from '../index.mjs'

const signer = generateKeyPair()
const HEX64 = /^[0-9a-f]{64}$/

// A dummy MCP-style tool handler that echoes its arguments.
function dummyHandler(args) {
  return { content: [{ type: 'text', text: JSON.stringify({ ok: true, echo: args }) }] }
}

test('wraps a handler, emits a receipt, and the SDK verifier accepts it', async () => {
  const receipts = []
  const governed = instrumentToolHandler('search_matches', dummyHandler, {
    sourceId: 'crm://accounts',
    signerPublicKey: signer.publicKey,
    signerPrivateKey: signer.privateKey,
    onReceipt: (r) => receipts.push(r),
  })

  const result = await governed({ query: 'acme' })

  // Handler result is returned unchanged.
  assert.deepEqual(result, dummyHandler({ query: 'acme' }))

  assert.equal(receipts.length, 1)
  const r = receipts[0]
  assert.equal(r.profile, ACCESS_RECEIPT_PROFILE)
  assert.equal(r.tool, 'search_matches')
  assert.equal(r.source_id, 'crm://accounts')
  assert.match(r.request_digest, HEX64)
  assert.match(r.response_digest, HEX64)
  assert.equal(typeof r.signer_did, 'string')
  assert.equal(r.signer_public_key, signer.publicKey)
  assert.equal(typeof r.accessed_at, 'string')
  assert.ok(r.receiptId.startsWith('acr_'))

  // The shim verifier accepts it.
  const v = verifyAccessReceipt(r)
  assert.equal(v.valid, true)
  assert.equal(v.signatureValid, true)
  assert.deepEqual(v.errors, [])

  // Independently: the SDK verifier accepts the same signed bytes. The shim
  // does not reimplement verification; verify() is the SDK's.
  const { signature, ...unsigned } = r
  assert.equal(verify(canonicalize(unsigned), signature, r.signer_public_key), true)
})

test('requester identity is recorded only when supplied', async () => {
  const receipts = []
  const governed = instrumentToolHandler('search_matches', dummyHandler, {
    sourceId: 'crm://accounts',
    signerPublicKey: signer.publicKey,
    signerPrivateKey: signer.privateKey,
    onReceipt: (r) => receipts.push(r),
    getRequester: (_args, extra) => extra?.requester,
  })

  // No requester supplied -> key absent entirely (not empty string).
  await governed({ query: 'a' })
  assert.equal('requester' in receipts[0], false)

  // Requester supplied -> recorded verbatim, and still SDK-verifiable.
  await governed({ query: 'b' }, { requester: 'did:aps:principal-1' })
  assert.equal(receipts[1].requester, 'did:aps:principal-1')
  assert.equal(verifyAccessReceipt(receipts[1]).valid, true)
})

test('request and response digests bind the exact call', async () => {
  const a = createAccessReceipt({
    tool: 't', sourceId: 's', request: { q: 1 }, response: { r: 1 },
    signerPublicKey: signer.publicKey, signerPrivateKey: signer.privateKey,
  })
  const b = createAccessReceipt({
    tool: 't', sourceId: 's', request: { q: 2 }, response: { r: 1 },
    signerPublicKey: signer.publicKey, signerPrivateKey: signer.privateKey,
  })
  assert.notEqual(a.request_digest, b.request_digest)
  assert.equal(a.response_digest, b.response_digest)
})

test('tampering breaks verification under the SDK verifier', () => {
  const r = createAccessReceipt({
    tool: 'search_matches', sourceId: 'crm://accounts',
    request: { query: 'acme' }, response: { ok: true },
    signerPublicKey: signer.publicKey, signerPrivateKey: signer.privateKey,
  })

  // Flip the tool name after signing.
  const tampered = { ...r, tool: 'delete_everything' }
  assert.equal(verifyAccessReceipt(tampered).valid, false)
  const { signature, ...unsigned } = tampered
  assert.equal(verify(canonicalize(unsigned), signature, tampered.signer_public_key), false)

  // Wrong signer key rejects a valid receipt.
  const other = generateKeyPair()
  assert.equal(verifyAccessReceipt({ ...r, signer_public_key: other.publicKey }).valid, false)
})

test('only allowlisted tools emit a receipt', async () => {
  const receipts = []
  const config = {
    sourceId: 'crm://accounts',
    signerPublicKey: signer.publicKey,
    signerPrivateKey: signer.privateKey,
    onReceipt: (r) => receipts.push(r),
    tools: ['search_matches'],
  }
  const governed = instrumentToolHandler('search_matches', dummyHandler, config)
  const ungoverned = instrumentToolHandler('list_agents', dummyHandler, config)

  await governed({ query: 'a' })
  await ungoverned({ query: 'b' })

  assert.equal(receipts.length, 1)
  assert.equal(receipts[0].tool, 'search_matches')
})
