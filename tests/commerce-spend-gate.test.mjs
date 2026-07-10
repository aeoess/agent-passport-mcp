// Regression: the MCP commerce spend gate must not be a structural no-op.
//
// commerce_preflight and get_commerce_spend used to rebuild a fresh CommerceDelegation with
// spentAmount hardcoded to 0, discarding any spend recorded on the session delegation, so the
// spend gate always saw the full limit remaining. The fix threads sessionDel.spentAmount into the
// commerce delegation. This test uses only the installed SDK (recordSpend ships in the next SDK
// release; this MCP closes the no-op by feeding the gate the real session spentAmount) plus a
// source-match guard against a regression to the hardcoded 0.
//
// Run: node --test tests/commerce-spend-gate.test.mjs

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createCommerceDelegation, checkSpendGate } from 'agent-passport-system'

const INDEX_SRC = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8')

test('checkSpendGate denies when the delegation already has non-zero spentAmount', () => {
  // This is the value the MCP fix now feeds the gate from session state. With the old hardcoded
  // spentAmount: 0 this purchase passed; with a real spent of 60 it is correctly denied.
  const d = { ...createCommerceDelegation({ agentId: 'a', delegationId: 'd', spendLimit: 100 }), spentAmount: 60 }
  assert.equal(checkSpendGate(d, { amount: 60, currency: 'usd' }).passed, false)
  assert.equal(checkSpendGate({ ...d, spentAmount: 0 }, { amount: 60, currency: 'usd' }).passed, true)
})

test('get_commerce_spend threads session spend instead of discarding it', () => {
  // commerce_preflight was deprecated in agent-passport-system 3.3.0 (orchestration moved to the
  // gateway; the SDK export is now a throw-only stub), so it no longer composes a delegation or
  // touches the spend gate. get_commerce_spend still runs locally and must keep threading the real
  // session spentAmount rather than reverting to the hardcoded 0.
  const matches = INDEX_SRC.match(/spentAmount:\s*\(sessionDel/g) || []
  assert.ok(matches.length >= 1, 'get_commerce_spend must read sessionDel.spentAmount, not hardcode 0')
  assert.ok(INDEX_SRC.includes('a metering record path is a'), 'the metering caveat must be documented in source')
})

test('commerce_preflight returns a machine-readable gateway deprecation instead of throwing', () => {
  // The SDK commercePreflight() is a throw-only migration stub in 3.3.0. The tool must surface a
  // clean deprecation result pointing to the gateway, not let the stub throw an unhandled error.
  assert.ok(INDEX_SRC.includes('commerce_preflight_moved_to_gateway'), 'deprecation error code must be present')
  // The old handler invoked the stub as commercePreflight({ ... }); ensure no such call remains.
  assert.ok(!INDEX_SRC.includes('commercePreflight({'), 'the throw-only SDK stub must no longer be called')
})
