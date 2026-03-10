# Contributing to Agent Passport System MCP Server

Thanks for your interest in contributing! This is the MCP server for the [Agent Passport System](https://github.com/aeoess/agent-passport-system) — 49 tools across 8 protocol layers for AI agent identity, trust, governance, and commerce.

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

## License

By contributing, you agree that your contributions will be licensed under the project's Apache-2.0 license.
