// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// agent-passport-access-shim: an adapter that emits a signed AccessReceipt for
// each governed MCP tools/call. It does NOT define a new cryptographic scheme
// or verifier. Signing is the SDK's sign() over canonicalize(); verification is
// the SDK's verify() over the same canonical bytes; identity is the SDK's
// createDID(). The shim only maps a tools/call into those primitives.

import { createHash } from 'node:crypto'
import { sign, verify, canonicalize, createDID } from 'agent-passport-system'

export const ACCESS_RECEIPT_PROFILE = 'aps:access-receipt:v1'

function sha256Hex(input) {
  return createHash('sha256').update(input).digest('hex')
}

// Digest of any JSON-serializable value: SHA-256 over the SDK's canonical
// bytes, the same commit pattern SDK receipts use for member payloads.
function digest(value) {
  return sha256Hex(canonicalize(value ?? null))
}

/**
 * Build and sign an AccessReceipt for one governed tool call.
 *
 * The receipt carries: tool name, request digest, response digest, source id,
 * timestamp, and signer identity. Requester identity is recorded ONLY when
 * supplied; otherwise the key is absent from the signed bytes (never invented).
 *
 * @param {object} opts
 * @param {string} opts.tool             MCP tool name.
 * @param {string} opts.sourceId         Configured source id the call ran against.
 * @param {unknown} opts.request         Tool arguments (digested, not stored).
 * @param {unknown} opts.response        Tool result (digested, not stored).
 * @param {string} opts.signerPublicKey  Ed25519 public key (hex) of the signer.
 * @param {string} opts.signerPrivateKey Ed25519 private key (hex) of the signer.
 * @param {string} [opts.requester]      Requester identity, only if the caller supplied one.
 * @param {string} [opts.accessedAt]     ISO 8601 timestamp; defaults to now.
 * @returns {object} the signed AccessReceipt.
 */
export function createAccessReceipt(opts) {
  const { tool, sourceId, request, response, signerPublicKey, signerPrivateKey, requester, accessedAt } = opts || {}
  if (!tool || !sourceId || !signerPublicKey || !signerPrivateKey) {
    throw new Error('createAccessReceipt: tool, sourceId, signerPublicKey, signerPrivateKey are required')
  }

  const accessed_at = accessedAt ?? new Date().toISOString()
  const signer_did = createDID(signerPublicKey)
  const request_digest = digest(request)
  const response_digest = digest(response)
  const receiptId = 'acr_' + sha256Hex(`${signer_did}:${sourceId}:${tool}:${accessed_at}:${request_digest}`).slice(0, 24)

  const unsigned = {
    profile: ACCESS_RECEIPT_PROFILE,
    receiptId,
    tool,
    source_id: sourceId,
    request_digest,
    response_digest,
    signer_did,
    signer_public_key: signerPublicKey,
    accessed_at,
  }
  // Requester is included only when supplied, so the signed bytes never assert
  // an identity that was not provided.
  if (requester != null && String(requester).length > 0) {
    unsigned.requester = String(requester)
  }

  const signature = sign(canonicalize(unsigned), signerPrivateKey)
  return { ...unsigned, signature }
}

/**
 * Verify an AccessReceipt. Verification is the SDK's verify() over the same
 * canonical bytes the receipt was signed over; the shim never reimplements
 * signature checking.
 *
 * @param {object} receipt
 * @returns {{ valid: boolean, signatureValid: boolean, errors: string[] }}
 */
export function verifyAccessReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object') {
    return { valid: false, signatureValid: false, errors: ['receipt is not an object'] }
  }
  const { signature, ...unsigned } = receipt
  const errors = []
  if (unsigned.profile !== ACCESS_RECEIPT_PROFILE) {
    errors.push(`unexpected profile "${unsigned.profile}"`)
  }
  if (typeof signature !== 'string' || typeof unsigned.signer_public_key !== 'string') {
    errors.push('missing signature or signer_public_key')
    return { valid: false, signatureValid: false, errors }
  }
  let signatureValid = false
  try {
    signatureValid = verify(canonicalize(unsigned), signature, unsigned.signer_public_key)
  } catch {
    signatureValid = false
  }
  if (!signatureValid) errors.push('signature does not verify under signer_public_key')
  return { valid: signatureValid && errors.length === 0, signatureValid, errors }
}

/**
 * Wrap one MCP tool handler so each call against the configured source emits a
 * signed AccessReceipt. The handler runs unchanged and its result is returned
 * verbatim; the receipt is emitted after the handler resolves and delivered to
 * config.onReceipt.
 *
 * @param {string} toolName
 * @param {(args: unknown, extra?: object) => unknown} handler  The original tool handler.
 * @param {object} config
 * @param {string} config.sourceId
 * @param {string} config.signerPublicKey
 * @param {string} config.signerPrivateKey
 * @param {(receipt: object) => void} [config.onReceipt]        Sink for emitted receipts.
 * @param {string[]} [config.tools]                             Allowlist of governed tool names; omit to govern all.
 * @param {(args: unknown, extra?: object) => (string|undefined)} [config.getRequester]
 *        Extract the requester identity from the call, only when the caller supplied one.
 * @returns {(args: unknown, extra?: object) => Promise<unknown>}
 */
export function instrumentToolHandler(toolName, handler, config) {
  if (!config || !config.sourceId || !config.signerPublicKey || !config.signerPrivateKey) {
    throw new Error('instrumentToolHandler: config.sourceId, signerPublicKey, signerPrivateKey are required')
  }
  const governed = !config.tools || config.tools.includes(toolName)
  return async (args, extra) => {
    const response = await handler(args, extra)
    if (governed) {
      const requester = config.getRequester
        ? config.getRequester(args, extra)
        : (extra && typeof extra === 'object' ? extra.requester : undefined)
      const receipt = createAccessReceipt({
        tool: toolName,
        sourceId: config.sourceId,
        request: args,
        response,
        signerPublicKey: config.signerPublicKey,
        signerPrivateKey: config.signerPrivateKey,
        requester,
      })
      if (config.onReceipt) config.onReceipt(receipt)
    }
    return response
  }
}
