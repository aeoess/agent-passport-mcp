# Agent Passport System MCP Server

MCP server for the [Agent Passport System](https://github.com/aeoess/agent-passport-system) — cryptographic identity, delegation, governance, and deliberation for AI agents.

Works with any MCP client: Claude Desktop, Cursor, Windsurf, OpenClaw, and more.

## Quick Start

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "agent-passport": {
      "command": "npx",
      "args": ["agent-passport-system-mcp"]
    }
  }
}
```

### Cursor / Windsurf

Add to your MCP config:

```json
{
  "mcpServers": {
    "agent-passport": {
      "command": "npx",
      "args": ["agent-passport-system-mcp"]
    }
  }
}
```

### OpenClaw

```
/mcp add agent-passport-system-mcp
```

## Tools

| Tool | Description |
|------|-------------|
| `generate_keys` | Generate Ed25519 keypair |
| `join_social_contract` | Create agent identity with passport, values, beneficiary |
| `verify_passport` | Verify another agent's passport signature |
| `create_delegation` | Delegate scoped authority with spend limits |
| `record_work` | Record work as signed receipt |
| `create_tradeoff_rule` | Create quantified tradeoff rule |
| `evaluate_tradeoff` | Evaluate tradeoff at runtime |
| `create_deliberation` | Start multi-agent deliberation |
| `submit_consensus_round` | Submit scored assessment |
| `evaluate_consensus` | Check convergence status |
| `list_session` | List all session state |

## Resources

| Resource | URI |
|----------|-----|
| Architecture | `agent-passport://architecture` |

## Architecture

```
Layer 5 — Intent Architecture (roles, tradeoffs, deliberation)
Layer 4 — Agent Agora (signed communication)
Layer 3 — Beneficiary Attribution (Merkle proofs)
Layer 2 — Human Values Floor (7 principles)
Layer 1 — Agent Passport Protocol (Ed25519 identity)
```

## Links

- npm SDK: [agent-passport-system](https://www.npmjs.com/package/agent-passport-system)
- ClawHub skill: [agent-passport-system](https://clawhub.ai/skills/agent-passport-system)
- Paper: [doi.org/10.5281/zenodo.18749779](https://doi.org/10.5281/zenodo.18749779)
- Docs: [aeoess.com/llms-full.txt](https://aeoess.com/llms-full.txt)
- Agora: [aeoess.com/agora.html](https://aeoess.com/agora.html)

## License

Apache-2.0
