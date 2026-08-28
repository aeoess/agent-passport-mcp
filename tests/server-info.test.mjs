// The server's advertised version must be the package's own version, and the
// implementation name must stay stable on the wire.
//
// WHY THIS TEST EXISTS. serverInfo.version was a hardcoded literal that had
// drifted: 3.3.0 against a package at 5.0.0. Nothing failed, because nothing
// compared them. The name is pinned on purpose: it is the MCP implementation
// identity, not the npm package name, and a change to it is a compatibility
// event that must be deliberate.
//
// The assertion is against the RUNTIME export, not against a string match in
// src/index.ts. A source grep would pass on a literal that happens to spell
// the right version today and would say nothing about what the built server
// actually announces.
//
// Run: node --test tests/server-info.test.mjs

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))

test('serverInfo.version equals package.json; serverInfo.name is the stable implementation identity', async () => {
  // createSandboxServer() suppresses the deferred main(). Without it the module
  // connects a stdio transport and the test run never exits.
  const mod = await import('../build/index.js')
  mod.createSandboxServer()

  assert.equal(
    mod.SERVER_INFO.version, pkg.version,
    `serverInfo.version ${mod.SERVER_INFO.version} != package.json version ${pkg.version}`,
  )
  assert.equal(
    mod.SERVER_INFO.name, 'agent-passport-mcp',
    `serverInfo.name ${mod.SERVER_INFO.name} changed; renaming the implementation is a compatibility-visible change`,
  )
})
