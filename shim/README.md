# agent-passport-access-shim

An adapter that emits a signed `AccessReceipt` for each governed MCP `tools/call`. Instrument a tool handler, and every call against a configured source produces a receipt carrying the tool name, request and response digests, source id, timestamp, and signer identity. A requester identity is recorded only when the caller supplies one.

This is proof of governed access; access is not contribution, and contribution is not value.

## What it reuses

The shim defines no cryptography of its own. Signing is the `agent-passport-system` SDK's `sign()` over `canonicalize()`, verification is the SDK's `verify()` over the same canonical bytes, and the signer DID is the SDK's `createDID()`. The shim maps a tools/call onto those primitives and nothing more.

## Receipt fields

| Field | Meaning |
|---|---|
| `profile` | `aps:access-receipt:v1` |
| `receiptId` | `acr_` + digest of signer, source, tool, time, request |
| `tool` | MCP tool name |
| `source_id` | Configured source the call ran against |
| `request_digest` | SHA-256 of the canonical request arguments |
| `response_digest` | SHA-256 of the canonical response |
| `signer_did` | DID derived from the signer public key |
| `signer_public_key` | Ed25519 public key (hex) |
| `requester` | Present only when the caller supplied a requester identity |
| `accessed_at` | ISO 8601 timestamp |
| `signature` | Ed25519 signature over the canonical receipt (SDK `sign`) |

## Usage

```js
import { instrumentToolHandler, verifyAccessReceipt } from 'agent-passport-access-shim'
import { generateKeyPair } from 'agent-passport-system'

const signer = generateKeyPair()
const receipts = []

const governed = instrumentToolHandler('search_matches', searchHandler, {
  sourceId: 'crm://accounts',
  signerPublicKey: signer.publicKey,
  signerPrivateKey: signer.privateKey,
  onReceipt: (r) => receipts.push(r),
  getRequester: (_args, extra) => extra?.requester, // omitted when absent
})

await governed({ query: 'acme' }, { requester: 'did:aps:...' })
verifyAccessReceipt(receipts[0]) // { valid: true, signatureValid: true, errors: [] }
```

## License

Apache-2.0.
