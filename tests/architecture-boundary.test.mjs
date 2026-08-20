// Architectural CI gate for the MCP/SDK boundary.
//
// THE RULE: MCP never constructs a signing preimage, never canonicalizes governance
// content, and never accepts signed bytes from a caller. Every cryptographic meaning
// comes from an SDK call. An MCP-side copy of a preimage would be a second preimage on
// a second release cadence.
//
// WHY THIS IS NOT A GREP. The obvious gate is `grep -rn "canonicaliz" src/`. It does
// not work, and it already does not work on this repo: src/index.ts carries the word
// inside a tool DESCRIPTION string, and the boundary comment above the amendment tools
// carries it too. A substring gate would fail on both, teaching everyone to ignore it,
// and would still miss a real violation imported under an alias or renamed upstream.
//
// The invariant is architectural, so it is asserted architecturally, against the
// TypeScript AST:
//
//   A. Import-binding allowlist: which files may BIND a canonicalization symbol.
//   B. Amendment path purity: what the three amendment handlers actually CALL.
//
// Run: node --test tests/architecture-boundary.test.mjs

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import ts from 'typescript'

const SRC = fileURLToPath(new URL('../src', import.meta.url))
const ROOT = fileURLToPath(new URL('..', import.meta.url))

/** Only these two files may bind a canonicalization-family symbol. */
const CANONICALIZATION_ALLOWLIST = new Set([
  'src/capabilityToken/canonical.ts',
  'src/capabilityToken/authorityEvaluation.ts',
])

/** A bound name that carries canonicalization meaning. */
const isCanonicalizationSymbol = (name) => /canonical/i.test(name)

/** A call that would mean MCP built a preimage or hashed governance content itself. */
const isForbiddenCall = (name) =>
  /canonical/i.test(name) || /^sha256/i.test(name) || name === 'createHash' ||
  /SignContent$/.test(name) || /preimage/i.test(name)

function tsFiles(dir) {
  const out = []
  for (const e of readdirSync(dir)) {
    const p = join(dir, e)
    if (statSync(p).isDirectory()) out.push(...tsFiles(p))
    else if (e.endsWith('.ts') && !e.endsWith('.d.ts')) out.push(p)
  }
  return out
}

const parse = (p) =>
  ts.createSourceFile(p, readFileSync(p, 'utf8'), ts.ScriptTarget.Latest, true)

// ── A. Import-binding allowlist ─────────────────────────────────────────────
test('A. only the two allowlisted files bind a canonicalization symbol from the SDK', () => {
  const violations = []

  for (const file of tsFiles(SRC)) {
    const rel = relative(ROOT, file)
    const sf = parse(file)

    for (const stmt of sf.statements) {
      if (!ts.isImportDeclaration(stmt)) continue
      if (!ts.isStringLiteral(stmt.moduleSpecifier)) continue
      if (stmt.moduleSpecifier.text !== 'agent-passport-system') continue
      const clause = stmt.importClause
      if (!clause || !clause.namedBindings) continue
      if (!ts.isNamedImports(clause.namedBindings)) continue

      for (const el of clause.namedBindings.elements) {
        // propertyName is the SDK-side name when imported under an alias, so an
        // alias cannot hide a canonicalization binding from this check.
        const sdkName = (el.propertyName ?? el.name).text
        const localName = el.name.text
        if (!isCanonicalizationSymbol(sdkName) && !isCanonicalizationSymbol(localName)) continue
        if (CANONICALIZATION_ALLOWLIST.has(rel)) continue
        violations.push({ file: rel, symbol: sdkName, boundAs: localName })
      }
    }
  }

  assert.deepEqual(
    violations, [],
    'ARCHITECTURAL RULE BROKEN: MCP must not canonicalize governance content.\n' +
    violations.map(v =>
      `  ${v.file} binds "${v.symbol}"${v.boundAs !== v.symbol ? ` as "${v.boundAs}"` : ''} ` +
      `from agent-passport-system.\n` +
      `  Only ${[...CANONICALIZATION_ALLOWLIST].join(' and ')} may do that.\n` +
      `  A preimage built here would be a second preimage on a second release cadence.`
    ).join('\n'),
  )

  // The allowlist must not rot into a description of nothing.
  const binders = tsFiles(SRC).filter(f => {
    const sf = parse(f)
    return sf.statements.some(stmt =>
      ts.isImportDeclaration(stmt) && ts.isStringLiteral(stmt.moduleSpecifier) &&
      stmt.moduleSpecifier.text === 'agent-passport-system' &&
      stmt.importClause?.namedBindings && ts.isNamedImports(stmt.importClause.namedBindings) &&
      stmt.importClause.namedBindings.elements.some(el =>
        isCanonicalizationSymbol((el.propertyName ?? el.name).text)))
  }).map(f => relative(ROOT, f))

  assert.deepEqual(
    [...binders].sort(), [...CANONICALIZATION_ALLOWLIST].sort(),
    'the allowlist no longer matches reality; update it deliberately, not reflexively',
  )
})

// ── B. Amendment path purity ────────────────────────────────────────────────
test('B. the three amendment handlers call only the SDK lifecycle, never a canonicalizer', () => {
  const sf = parse(join(SRC, 'index.ts'))
  const EXPECTED = {
    propose_amendment: 'createAmendment',
    sign_amendment: 'signAmendment',
    verify_amendment: 'verifyAmendment',
  }
  const found = {}

  const visit = (node) => {
    if (ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'registerTool' &&
        node.arguments.length > 0 &&
        ts.isStringLiteral(node.arguments[0]) &&
        node.arguments[0].text in EXPECTED) {
      const toolName = node.arguments[0].text
      const handler = node.arguments[node.arguments.length - 1]

      // Collect the identifier of every call expression inside the handler body.
      const calls = new Set()
      const walk = (n) => {
        if (ts.isCallExpression(n)) {
          if (ts.isIdentifier(n.expression)) calls.add(n.expression.text)
          else if (ts.isPropertyAccessExpression(n.expression)) calls.add(n.expression.name.text)
        }
        ts.forEachChild(n, walk)
      }
      walk(handler)
      found[toolName] = calls
    }
    ts.forEachChild(node, visit)
  }
  visit(sf)

  for (const [tool, sdkFn] of Object.entries(EXPECTED)) {
    assert.ok(found[tool], `handler for ${tool} not found in src/index.ts`)
    assert.ok(
      found[tool].has(sdkFn),
      `${tool} must resolve to the SDK's ${sdkFn}. Calls found: ${[...found[tool]].join(', ')}`,
    )
    const forbidden = [...found[tool]].filter(isForbiddenCall)
    assert.deepEqual(
      forbidden, [],
      `ARCHITECTURAL RULE BROKEN: ${tool} calls ${forbidden.join(', ')}.\n` +
      `  The amendment path must derive every cryptographic value from the SDK.\n` +
      `  MCP does not build signing preimages and does not hash governance content.`,
    )
  }

  // Cross-check: no handler reaches for another handler's SDK function, which would
  // mean the lifecycle got wired to the wrong call.
  assert.ok(!found.propose_amendment.has('verifyAmendment'), 'propose must not verify')
  assert.ok(!found.verify_amendment.has('signAmendment'), 'verify must not sign')
})

// ── The design document's own acceptance check, recorded as a fact ──────────
//
// The design makes `grep -rn "canonicaliz" src/` its acceptance criterion. That grep
// is ALREADY false on unmodified main: src/index.ts:4655 carries the word inside a
// tool description. Rather than delete the criterion or weaken it, this records what
// is actually true: the word appears in prose in index.ts, and the only files that
// BIND such a symbol are the two allowlisted ones. Assertion A above is the gate.
test('the two allowlisted files are the only canonicalization implementations', () => {
  const canonicalTs = readFileSync(join(SRC, 'capabilityToken/canonical.ts'), 'utf8')
  assert.ok(canonicalTs.includes('canonicalizeJCS'),
    'canonical.ts should still delegate JCS to the SDK rather than implementing it')
  assert.ok(!/function\s+canonicalizeJCS|const\s+canonicalizeJCS\s*=/.test(canonicalTs),
    'canonical.ts must DELEGATE canonicalization to the SDK, never define its own')
})
