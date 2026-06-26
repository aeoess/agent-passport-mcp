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

test('commerce_preflight and get_commerce_spend thread session spend instead of discarding it', () => {
  const matches = INDEX_SRC.match(/spentAmount:\s*\(sessionDel/g) || []
  assert.ok(matches.length >= 2, 'both commerce tools must read sessionDel.spentAmount, not hardcode 0')
  assert.ok(INDEX_SRC.includes('a metering decision flagged'), 'the metering caveat must be documented in source')
})
