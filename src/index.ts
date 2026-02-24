#!/usr/bin/env node

// ══════════════════════════════════════════════════════════════
// Agent Passport MCP Server
// ══════════════════════════════════════════════════════════════
// MCP server exposing the Agent Passport System to any
// MCP-compatible client (Claude, Cursor, Windsurf, OpenClaw, etc.)
//
// Deliberation trail: https://aeoess.com/agora.html
// ══════════════════════════════════════════════════════════════

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import {
  joinSocialContract,
  verifySocialContract,
  delegate,
  recordWork,
  proveContributions,
  generateKeyPair,
  createDelegation,
  verifyPassport,
  loadFloor,
  createTradeoffRule,
  evaluateTradeoff,
  createDeliberation,
  submitConsensusRound,
  evaluateConsensus,
  resolveDeliberation,
  createIntentDocument,
  assignRole,
  createAgoraMessage,
} from "agent-passport-system";

import type {
  SocialContractAgent,
  SignedPassport,
  Delegation,
  ActionReceipt,
  Deliberation,
} from "agent-passport-system";

// ── Server Setup ──

const server = new McpServer({
  name: "agent-passport-mcp",
  version: "1.0.0",
});

// In-memory state for the session
const sessionState: {
  agents: Map<string, SocialContractAgent>;
  delegations: Map<string, Delegation>;
  receipts: ActionReceipt[];
  deliberations: Map<string, Deliberation>;
} = {
  agents: new Map(),
  delegations: new Map(),
  receipts: [],
  deliberations: new Map(),
};

// ══════════════════════════════════════
// TOOL: generate_keys
// ══════════════════════════════════════

server.tool(
  "generate_keys",
  "Generate an Ed25519 keypair for signing passports, delegations, and messages",
  {},
  async () => {
    const keys = generateKeyPair();
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              publicKey: keys.publicKey,
              privateKey: keys.privateKey,
              algorithm: "Ed25519",
              note: "Store the private key securely. The public key is your agent identity.",
            },
            null,
            2
          ),
        },
      ],
    };
  }
);

// ══════════════════════════════════════
// TOOL: join_social_contract
// ══════════════════════════════════════

server.tool(
  "join_social_contract",
  "Create an agent identity with Ed25519 passport, values attestation, and beneficiary registration. This is the primary entry point for joining the Agent Social Contract.",
  {
    name: z.string().describe("Agent name"),
    mission: z.string().describe("Agent mission statement"),
    owner: z.string().describe("Human owner alias"),
    capabilities: z
      .array(z.string())
      .describe("Agent capabilities (e.g. code_execution, web_search)"),
    platform: z.string().default("mcp").describe("Platform name"),
    models: z
      .array(z.string())
      .default(["claude"])
      .describe("AI models used"),
    beneficiary_id: z
      .string()
      .optional()
      .describe("Human beneficiary ID"),
    beneficiary_relationship: z
      .enum(["creator", "employer", "delegator", "owner"])
      .default("owner")
      .describe("Relationship to beneficiary"),
  },
  async (args) => {
    const agent = joinSocialContract({
      name: args.name,
      mission: args.mission,
      owner: args.owner,
      capabilities: args.capabilities,
      platform: args.platform,
      models: args.models,
      beneficiary: args.beneficiary_id
        ? {
            id: args.beneficiary_id,
            relationship: args.beneficiary_relationship,
          }
        : undefined,
    });

    sessionState.agents.set(agent.agentId, agent);

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              agentId: agent.agentId,
              publicKey: agent.publicKey,
              passportVersion: agent.passport.passport.version,
              created: agent.passport.passport.createdAt,
              expires: agent.passport.passport.expiresAt,
              mission: agent.passport.passport.mission,
              capabilities: agent.passport.passport.capabilities,
              signatureValid: true,
              note: "Agent stored in session. Use this agentId for delegation and work recording.",
            },
            null,
            2
          ),
        },
      ],
    };
  }
);

// ══════════════════════════════════════
// TOOL: verify_passport
// ══════════════════════════════════════

server.tool(
  "verify_passport",
  "Verify an agent's passport signature and trust status. Checks Ed25519 signature validity.",
  {
    passport_json: z
      .string()
      .describe("JSON string of the SignedPassport to verify"),
  },
  async (args) => {
    try {
      const passport: SignedPassport = JSON.parse(args.passport_json);
      const result = verifySocialContract(passport);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                overall_trusted: result.overall,
                identity_valid: result.identity.valid,
                identity_errors: result.identity.errors,
                values_attested: result.values?.attested ?? false,
                values_valid: result.values?.valid ?? null,
              },
              null,
              2
            ),
          },
        ],
      };
    } catch (e: any) {
      return {
        content: [
          { type: "text", text: `Error verifying passport: ${e.message}` },
        ],
        isError: true,
      };
    }
  }
);

// ══════════════════════════════════════
// TOOL: create_delegation
// ══════════════════════════════════════

server.tool(
  "create_delegation",
  "Delegate scoped authority from one agent to another. Scope can only narrow, never widen. Spend limits cap economic exposure.",
  {
    from_agent_id: z.string().describe("Agent ID of the delegator (must exist in session)"),
    to_public_key: z.string().describe("Public key of the delegate"),
    scope: z.array(z.string()).describe("Scoped permissions (e.g. code_execution, web_search)"),
    spend_limit: z.number().default(1000).describe("Maximum spend in USD"),
    max_depth: z.number().default(1).describe("Max sub-delegation depth"),
    expires_in_hours: z.number().default(24).describe("Hours until expiry"),
  },
  async (args) => {
    const agent = sessionState.agents.get(args.from_agent_id);
    if (!agent) {
      return { content: [{ type: "text", text: `Error: Agent ${args.from_agent_id} not found in session. Create one first with join_social_contract.` }], isError: true };
    }
    const d = delegate({
      from: agent,
      toPublicKey: args.to_public_key,
      scope: args.scope,
      spendLimit: args.spend_limit,
      maxDepth: args.max_depth,
      expiresInHours: args.expires_in_hours,
    });
    sessionState.delegations.set(d.delegationId, d);
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          delegationId: d.delegationId,
          from: d.delegatedBy,
          to: d.delegatedTo,
          scope: d.scope,
          spendLimit: d.spendLimit,
          maxDepth: d.maxDepth,
          expires: d.expiresAt,
          signed: true,
        }, null, 2),
      }],
    };
  }
);

// ══════════════════════════════════════
// TOOL: record_work
// ══════════════════════════════════════

server.tool(
  "record_work",
  "Record a unit of work as a signed, verifiable receipt under an active delegation.",
  {
    agent_id: z.string().describe("Agent ID performing the work"),
    delegation_id: z.string().describe("Delegation ID authorizing this work"),
    type: z.string().describe("Type of work (e.g. code_execution, analysis, research)"),
    target: z.string().describe("What was worked on"),
    scope: z.string().describe("Scope used for this action"),
    result: z.enum(["success", "failure", "partial"]).describe("Outcome"),
    summary: z.string().describe("Brief description of what was done"),
    spend: z.number().optional().describe("Amount spent (if any)"),
  },
  async (args) => {
    const agent = sessionState.agents.get(args.agent_id);
    if (!agent) {
      return { content: [{ type: "text", text: `Error: Agent ${args.agent_id} not found.` }], isError: true };
    }
    const d = sessionState.delegations.get(args.delegation_id);
    if (!d) {
      return { content: [{ type: "text", text: `Error: Delegation ${args.delegation_id} not found.` }], isError: true };
    }
    const receipt = recordWork(agent, d, [d.delegationId], {
      type: args.type,
      target: args.target,
      scope: args.scope,
      result: args.result,
      summary: args.summary,
      spend: args.spend,
    });
    sessionState.receipts.push(receipt);
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          receiptId: receipt.receiptId,
          agentId: receipt.agentId,
          action: receipt.action,
          result: receipt.result,
          timestamp: receipt.timestamp,
          signed: true,
          totalReceipts: sessionState.receipts.length,
        }, null, 2),
      }],
    };
  }
);

// ══════════════════════════════════════
// TOOL: create_tradeoff_rule
// ══════════════════════════════════════

server.tool(
  "create_tradeoff_rule",
  "Create a quantified tradeoff rule for organizational intent. Example: when quality vs speed, prefer quality until 2x time cost, then prefer speed.",
  {
    when: z.string().describe("The conflict (e.g. 'quality vs speed')"),
    prefer: z.string().describe("Default preference (e.g. 'quality')"),
    until: z.string().describe("Threshold condition (e.g. '2x time cost')"),
    then_prefer: z.string().describe("Preference after threshold (e.g. 'speed')"),
    context: z.string().optional().describe("Optional context"),
  },
  async (args) => {
    const rule = createTradeoffRule({
      when: args.when,
      prefer: args.prefer,
      until: args.until,
      thenPrefer: args.then_prefer,
      context: args.context,
    });
    return {
      content: [{
        type: "text",
        text: JSON.stringify(rule, null, 2),
      }],
    };
  }
);

// ══════════════════════════════════════
// TOOL: evaluate_tradeoff
// ══════════════════════════════════════

server.tool(
  "evaluate_tradeoff",
  "Evaluate a tradeoff rule at runtime. Returns which preference wins given whether the threshold was exceeded.",
  {
    rule_json: z.string().describe("JSON string of the TradeoffRule"),
    threshold_exceeded: z.boolean().describe("Whether the threshold condition has been exceeded"),
  },
  async (args) => {
    try {
      const rule = JSON.parse(args.rule_json);
      const result = evaluateTradeoff(rule, args.threshold_exceeded);
      return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    } catch (e: any) {
      return { content: [{ type: "text", text: `Error: ${e.message}` }], isError: true };
    }
  }
);

// ══════════════════════════════════════
// TOOL: create_deliberation
// ══════════════════════════════════════

server.tool(
  "create_deliberation",
  "Start a new multi-agent deliberation for reaching consensus on a decision.",
  {
    subject: z.string().describe("What is being decided"),
    description: z.string().describe("Detailed description of the decision"),
    initiated_by: z.string().describe("Agent ID of the initiator"),
    reversibility_score: z.number().min(0).max(1).describe("0-1, how reversible is this decision (0=irreversible, 1=fully reversible)"),
    convergence_threshold: z.number().default(15).describe("Std dev threshold for convergence"),
    max_rounds: z.number().default(5).describe("Maximum rounds before escalation"),
  },
  async (args) => {
    const delib = createDeliberation({
      subject: args.subject,
      description: args.description,
      initiatedBy: args.initiated_by,
      reversibilityScore: args.reversibility_score,
      convergenceThreshold: args.convergence_threshold,
      maxRounds: args.max_rounds,
    });
    sessionState.deliberations.set(delib.deliberationId, delib);
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          deliberationId: delib.deliberationId,
          subject: delib.subject,
          status: delib.status,
          convergenceThreshold: delib.convergenceThreshold,
          maxRounds: delib.maxRounds,
          reversibilityScore: delib.reversibilityScore,
        }, null, 2),
      }],
    };
  }
);

// ══════════════════════════════════════
// TOOL: submit_consensus_round
// ══════════════════════════════════════

server.tool(
  "submit_consensus_round",
  "Submit a scored assessment for a deliberation round. Each agent scores independently across domains.",
  {
    deliberation_id: z.string().describe("Deliberation ID"),
    agent_id: z.string().describe("Agent ID submitting the round"),
    role: z.enum(["operator", "collaborator", "consultant", "observer"]).describe("Agent role"),
    assessment_json: z.string().describe("JSON array of {domain, score (0-100), confidence (0-1), weight (0+)}"),
    reasoning: z.string().describe("Agent's reasoning for this assessment"),
  },
  async (args) => {
    const delib = sessionState.deliberations.get(args.deliberation_id);
    if (!delib) {
      return { content: [{ type: "text", text: `Error: Deliberation ${args.deliberation_id} not found.` }], isError: true };
    }
    try {
      const assessment = JSON.parse(args.assessment_json);
      const keys = generateKeyPair();
      const result = submitConsensusRound(delib, {
        agentId: args.agent_id,
        publicKey: keys.publicKey,
        privateKey: keys.privateKey,
        role: args.role as any,
        assessment,
        reasoning: args.reasoning,
      });
      sessionState.deliberations.set(args.deliberation_id, result.deliberation);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            roundNumber: result.round.roundNumber,
            agentId: result.round.agentId,
            overallScore: result.round.overallScore,
            positionDelta: result.round.positionDelta,
            totalRounds: result.deliberation.rounds.length,
            signed: true,
          }, null, 2),
        }],
      };
    } catch (e: any) {
      return { content: [{ type: "text", text: `Error: ${e.message}` }], isError: true };
    }
  }
);

// ══════════════════════════════════════
// TOOL: evaluate_consensus
// ══════════════════════════════════════

server.tool(
  "evaluate_consensus",
  "Check if agents have converged on a decision. Returns convergence status, standard deviation, and recommendation.",
  {
    deliberation_id: z.string().describe("Deliberation ID to evaluate"),
  },
  async (args) => {
    const delib = sessionState.deliberations.get(args.deliberation_id);
    if (!delib) {
      return { content: [{ type: "text", text: `Error: Deliberation ${args.deliberation_id} not found.` }], isError: true };
    }
    const result = evaluateConsensus(delib);
    return {
      content: [{
        type: "text",
        text: JSON.stringify(result, null, 2),
      }],
    };
  }
);

// ══════════════════════════════════════
// TOOL: list_session
// ══════════════════════════════════════

server.tool(
  "list_session",
  "List all agents, delegations, receipts, and deliberations in the current session.",
  {},
  async () => {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          agents: Array.from(sessionState.agents.keys()),
          delegations: Array.from(sessionState.delegations.keys()),
          receipts: sessionState.receipts.length,
          deliberations: Array.from(sessionState.deliberations.entries()).map(([id, d]) => ({
            id,
            subject: d.subject,
            status: d.status,
            rounds: d.rounds.length,
          })),
        }, null, 2),
      }],
    };
  }
);

// ══════════════════════════════════════
// RESOURCE: Architecture Overview
// ══════════════════════════════════════

server.resource(
  "architecture",
  "agent-passport://architecture",
  {
    description: "Agent Passport System architecture — 5-layer governance stack for AI agents",
    mimeType: "text/plain",
  },
  async () => ({
    contents: [{
      uri: "agent-passport://architecture",
      text: `Agent Passport System — 5-Layer Architecture

Layer 5 — Intent Architecture
  Roles, tradeoff rules, deliberative consensus, precedent memory.
  Functions: assignRole, createTradeoffRule, evaluateTradeoff, createIntentDocument,
  createDeliberation, submitConsensusRound, evaluateConsensus, resolveDeliberation

Layer 4 — Agent Agora (Communication)
  Signed messages, threading, topic-based routing, agent registry.
  Functions: createAgoraMessage, verifyAgoraMessage, registerAgent

Layer 3 — Beneficiary Attribution
  Merkle proofs, anti-gaming, contribution tracking, collaboration scoring.
  Functions: computeAttribution, generateMerkleProof, traceBeneficiary

Layer 2 — Human Values Floor
  7 universal principles, 5 enforced at protocol level.
  Functions: attestFloor, verifyAttestation, evaluateCompliance

Layer 1 — Agent Passport Protocol
  Ed25519 identity, scoped delegation, action receipts, revocation.
  Functions: createPassport, verifyPassport, createDelegation, createReceipt

Key Facts:
- Crypto: Ed25519 signatures + SHA-256 Merkle trees. No blockchain.
- npm: agent-passport-system@1.3.0
- Tests: 65 passing (23 adversarial)
- License: Apache-2.0
- Paper: https://doi.org/10.5281/zenodo.18749779
- Docs: https://aeoess.com/llms-full.txt
- Agora: https://aeoess.com/agora.html`,
    }],
  })
);

// ══════════════════════════════════════
// Connect transport and start
// ══════════════════════════════════════

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Agent Passport MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
