// Regression: register_agora_agent must actually register.
//
// The handler called registerAgent(state.agoraRegistry, {...}) and discarded the return value.
// The SDK's registerAgent is immutable: it builds and returns a new AgoraRegistry rather than
// mutating its argument. So the session registry never changed, while the tool answered
// registered: true with the unchanged registrySize. The fix assigns the returned registry back
// to session state.
//
// The session registry is process-local state created by createRegistry(). Persistence is a
// separate surface (AGENTS_PATH, the public Agora) and is deliberately out of scope here.
//
// Run: node --test tests/agora-register-persists.test.mjs

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRegistry, registerAgent, createAgoraMessage, verifyAgoraMessage, generateKeyPair } from 'agent-passport-system'

const INDEX_SRC = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8')

const agent = (n, publicKey) => ({
  agentId: `agent-${n}`,
  agentName: `Agent ${n}`,
  publicKey,
  joinedAt: new Date().toISOString(),
  role: 'member',
})

test('registerAgent is immutable, which is why the discarded return was a no-op', () => {
  const empty = createRegistry()
  const next = registerAgent(empty, agent(1, 'k1'))
  assert.equal(empty.agents.length, 0, 'the argument must be left untouched')
  assert.equal(next.agents.length, 1, 'the returned registry carries the agent')
})

test('an empty registry reports size 1 after one registration', () => {
  const r = registerAgent(createRegistry(), agent(1, 'k1'))
  assert.equal(r.agents.length, 1)
})

test('the registered key is recognised afterwards', () => {
  const kp = generateKeyPair()
  const before = createRegistry()
  const after = registerAgent(before, agent(1, kp.publicKey))
  const msg = createAgoraMessage({
    agentId: 'agent-1',
    agentName: 'Agent 1',
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
    topic: 'general',
    type: 'discussion',
    subject: 's',
    content: 'c',
  })
  assert.equal(verifyAgoraMessage(msg, before).knownAgent, false, 'unknown before registration')
  assert.equal(verifyAgoraMessage(msg, after).knownAgent, true, 'known after registration')
})

test('registering the same key twice updates rather than duplicates', () => {
  let r = registerAgent(createRegistry(), agent(1, 'k1'))
  r = registerAgent(r, { ...agent(1, 'k1'), agentName: 'Renamed' })
  assert.equal(r.agents.length, 1, 'size stays 1')
  assert.equal(r.agents[0].agentName, 'Renamed', 'the record is updated in place')
})

test('a second distinct key produces size 2', () => {
  let r = registerAgent(createRegistry(), agent(1, 'k1'))
  r = registerAgent(r, agent(2, 'k2'))
  assert.equal(r.agents.length, 2)
})

test('the handler assigns the returned registry back to session state', () => {
  // Source guard against a regression to the discarded call. registered: true must never be
  // returned by a code path that leaves the session registry unchanged.
  assert.ok(
    /state\.agoraRegistry\s*=\s*registerAgent\(\s*state\.agoraRegistry/.test(INDEX_SRC),
    'register_agora_agent must assign the result of registerAgent back to state.agoraRegistry',
  )
  const discarded = INDEX_SRC.match(/^\s*registerAgent\(\s*state\.agoraRegistry/gm) || []
  assert.equal(discarded.length, 0, 'no call site may discard the returned registry')
})
