# Contributing to Agent Passport System MCP Server

Thanks for your interest in contributing! This is the MCP server for the [Agent Passport System](https://github.com/aeoess/agent-passport-system) — 132 tools across the full protocol surface for AI agent identity, trust, governance, and commerce.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<your-username>/agent-passport-mcp.git`
3. Install dependencies: `npm install --include=dev`
4. Build the project: `npm run build`

## Development

The MCP server is a single-file TypeScript implementation (`src/index.ts`) that wraps the Agent Passport System SDK. All protocol logic lives in the SDK; this repo provides the MCP tool interface.

### Building

```bash
npm run build
```

Build must succeed with zero TypeScript errors before submitting a PR.

### Code Style

- TypeScript throughout
- Single-file architecture (`src/index.ts`)
- Each MCP tool follows the same pattern: validation, SDK call, JSON response
- Use `zod` for input validation

## Submitting Changes

1. Create a feature branch from `main`
2. Make your changes with clear, descriptive commits
3. Ensure `npm run build` succeeds with zero errors
4. Open a pull request with a description of what you changed and why

## Reporting Issues

Open an issue on GitHub with:

- A clear title and description
- Steps to reproduce (if applicable)
- Expected vs actual behavior
- Your environment (Node.js version, OS, MCP client)

## Adding New Tools

If you're adding new MCP tools, follow the existing pattern in `src/index.ts`:

1. Add the SDK import
2. Register the tool with `server.tool()` including zod schema
3. Update the README tool table
4. Update the tool count in the README header

---

## What makes a PR mergeable

1. **Build passes.** `npm run build` succeeds with zero TypeScript errors.
2. **SDK alignment.** If you're exposing a new SDK capability as an MCP tool, the SDK function must already exist and be tested. This repo wraps; it doesn't redefine.
3. **Tool naming consistency.** Follow existing naming conventions (`snake_case`, verb-first for actions).
4. **Zod schemas.** Every tool registers a zod input schema — no untyped parameters.
5. **README table updated.** New tools show up in the README tool table with their category.
6. **Scope discipline.** One concern per PR. Refactors ride alongside in separate PRs.

## Stability expectations

Follows semantic versioning. New tools land in minor releases. Changes to tool signatures (renames, parameter changes) are breaking and require a major version bump with migration notes. SDK version alignment is tracked in `package.json` peer dependencies.

## Out of scope

- **New protocol logic.** All protocol behavior lives in `agent-passport-system`. This repo exposes it via MCP.
- **Disabling zod validation** for convenience — validation is load-bearing for MCP client safety.
- **Named integrations woven into tool implementations** — integration examples belong in documentation or a sibling adapter repo.
- **Breaking changes to tool signatures** without major version bump and migration documentation.

---

## How review works

Every PR is evaluated against five questions, applied to every contributor equally:

1. **Identity.** Is the contributor identifiable, with a real GitHub presence?
2. **Format.** Does the change match existing patterns (tool registration, zod schema, README table)?
3. **Substance.** Does the new tool actually wrap tested SDK functionality?
4. **Scope.** Does the PR stay scoped to its stated purpose?
5. **Reversibility.** Can the change be reverted cleanly if a downstream issue surfaces?

Substantive declines include the reason.

---

## Practical details

- **Maintainer:** [@aeoess](https://github.com/aeoess) (Tymofii Pidlisnyi)
- **Review timing:** maintainer-bandwidth dependent. If a PR has had no response after 5 business days, ping it.
- **CLA / DCO:** no CLA is required. Contributions accepted on the understanding that the submitter has the right to contribute under the Apache-2.0 license.
- **Publishing:** maintainers handle npm release publishing. Please do not bump version numbers in PRs. If your change requires a version bump, call that out in the PR description.
- **Security issues:** open a private security advisory via GitHub rather than a public issue.
- **Code of Conduct:** Contributor Covenant 2.1 — see [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).

---

## License

By contributing, you agree that your contributions will be licensed under the project's Apache-2.0 license. See [`LICENSE`](./LICENSE).
