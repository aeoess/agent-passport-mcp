// Regression: the MCP must not ship an SDK whose verifier accepts inadmissible key material.
//
// GHSA-72cm-hhw9-f66f: the Ed25519 verifier in agent-passport-system through 4.5.1 accepts a
// small-order public key. With the Edwards identity as the key, R as the identity encoding and
// S zero, one signature verifies for arbitrary messages, so verification establishes no
// possession of a secret key. MCP 5.0.0 and 5.0.1 declared "agent-passport-system": "^4.4.0",
// a range that cannot resolve the fixed 5.x, and aps_verify_attribution_primitive forwards a
// peer-supplied primitive and a peer-supplied issuer key straight into that verifier.
//
// This pins three things: the resolved SDK refuses the construction, an ordinary key still
// verifies, and the declared range cannot slip back to a line that carries the defect.
//
// Run: node --test tests/sdk-admissibility-dependency.test.mjs

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { verify, sign, generateKeyPair } from 'agent-passport-system'

const IDENTITY_KEY = '01' + '00'.repeat(31)
const DEGENERATE_SIG = IDENTITY_KEY + '00'.repeat(32)

const PKG = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
const SDK_PKG = JSON.parse(
  readFileSync(new URL('../node_modules/agent-passport-system/package.json', import.meta.url), 'utf8'),
)
const INDEX_SRC = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8')

test('the declared SDK range excludes the affected 4.x line', () => {
  const range = PKG.dependencies['agent-passport-system']
  assert.ok(range, 'the SDK must be a declared runtime dependency')
  assert.ok(
    !/^[\^~]?4\./.test(range.replace(/^[\^~><= ]*/, (m) => m)) && !range.includes('4.'),
    `declared range ${range} must not admit the 4.x line, which is affected by GHSA-72cm-hhw9-f66f`,
  )
})

test('the resolved SDK is 5.x or later', () => {
  const major = Number(SDK_PKG.version.split('.')[0])
  assert.ok(major >= 5, `resolved SDK ${SDK_PKG.version} predates the admissibility fix`)
})

test('the resolved verifier refuses the small-order construction', () => {
  for (const message of ['alpha', 'bravo', 'charlie']) {
    let accepted
    try {
      accepted = verify(message, DEGENERATE_SIG, IDENTITY_KEY)
    } catch {
      accepted = false
    }
    assert.equal(accepted, false, `the degenerate signature must not verify for "${message}"`)
  }
})

test('an ordinary key and signature still verify, so the refusal is not blanket', () => {
  const kp = generateKeyPair()
  const message = 'control-message'
  assert.equal(verify(message, sign(message, kp.privateKey), kp.publicKey), true)
})

test('the attribution tool forwards the caller-supplied issuer key unchanged', () => {
  // The reachability that makes the dependency range matter. If this call-through is ever
  // wrapped in its own key handling, this test should be revisited rather than deleted.
  assert.ok(
    /verifyAttributionPrimitive\(\s*args\.primitive\s*,\s*args\.issuer_public_key\s*\)/.test(INDEX_SRC),
    'aps_verify_attribution_primitive must be a transparent call-through to the SDK verifier',
  )
})
