#!/usr/bin/env node

// ══════════════════════════════════════════════════════════════
// Agent Passport MCP Server v2.0
// ══════════════════════════════════════════════════════════════
// Coordination-native MCP server for multi-agent task units.
//
// Any MCP-compatible agent connects → identifies with key →
// gets role-scoped tools + role-specific prompts automatically.
//
// Start: AGENT_KEY=<pubkey> npx agent-passport-system-mcp
//   or:  call the identify tool first
// ══════════════════════════════════════════════════════════════

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

import {
  // Identity + Crypto
  joinSocialContract, verifySocialContract, generateKeyPair,
  delegate, recordWork, sign,
  // Agent Context (enforcement middleware)
  createAgentContext, AgentContext,
  // Coordination (Layer 6)
  createTaskBrief, verifyTaskBrief,
  assignTask, acceptTask,
  submitEvidence, verifyEvidence,
  reviewEvidence, verifyReview,
  handoffEvidence, verifyHandoff,
  submitDeliverable, verifyDeliverable,
  completeTask, verifyCompletion,
  createTaskUnit, getTaskStatus, validateTaskUnit,
  // Delegation (Layer 1)
  createDelegation, verifyDelegation, revokeDelegation,
  subDelegate, cascadeRevoke, clearStores,
  // Agora (Layer 4)
  createAgoraMessage, createFeed, appendToFeed,
  getThread, getByTopic, getTopics,
  createRegistry, registerAgent, verifyAgoraMessage,
  // Values/Policy (Layer 2 + 5)
  loadFloor, attestFloor, verifyAttestation,
  createActionIntent, evaluateIntent,
  FloorValidatorV1,
  // Commerce (Layer 8)
  commercePreflight, createCommerceDelegation,
  getSpendSummary, requestHumanApproval,
  // Integration bridges
  commerceWithIntent, coordinationToAgora,
  postTaskCreated, postReviewCompleted, postTaskCompleted,
} from "agent-passport-system";

import type {
  CoordinationEventType,
} from "agent-passport-system";

import type {
  SocialContractAgent, Delegation, ActionReceipt,
  TaskBrief, TaskUnit, EvidencePacket, ReviewDecision,
  CoordinationRole, AgoraFeed, AgoraRegistry, ActionIntent,
  ValuesFloor, EnforcementLevel, ExecuteResult,
} from "agent-passport-system";

// ═══════════════════════════════════════
// State Management
// ═══════════════════════════════════════

const STORE_PATH = join(process.env.HOME || '.', '.agent-passport-tasks.json');
const COMMS_PATH = process.env.COMMS_PATH || join(process.env.HOME || '.', 'aeoess_web', 'comms');
const AGENTS_PATH = process.env.AGENTS_PATH || join(process.env.HOME || '.', 'aeoess_web', 'agora', 'agents.json');
const AGORA_PATH = process.env.AGORA_PATH || join(process.env.HOME || '.', 'aeoess_web', 'agora', 'messages.json');

interface SessionState {
  // Identity
  agentKey: string | null;
  agentRole: CoordinationRole | null;
  agentId: string | null;
  agents: Map<string, SocialContractAgent>;
  delegations: Map<string, Delegation>;
  receipts: ActionReceipt[];
  // Private key (for signing, loaded from env)
  privateKey: string | null;
  // Coordination
  taskUnits: Map<string, TaskUnit>;
  // Agora (Layer 4)
  agoraFeed: AgoraFeed;
  agoraRegistry: AgoraRegistry;
  // Values (Layer 2)
  floorYaml: string | null;
  // Commerce (Layer 8)
  commerceSpendLog: Array<{ amount: number; currency: string; merchant: string; timestamp: string }>;
  // Intents (for policy evaluation chain)
  intents: Map<string, ActionIntent>;
  // Agent Context (enforcement middleware)
  agentContext: AgentContext | null;
  floor: ValuesFloor | null;
  pendingActions: Map<string, ExecuteResult>;
}

const state: SessionState = {
  agentKey: process.env.AGENT_KEY || null,
  agentRole: null,
  agentId: process.env.AGENT_ID || null,
  agents: new Map(),
  delegations: new Map(),
  receipts: [],
  privateKey: process.env.AGENT_PRIVATE_KEY || null,
  taskUnits: new Map(),
  agoraFeed: createFeed(),
  agoraRegistry: createRegistry(),
  floorYaml: null,
  commerceSpendLog: [],
  intents: new Map(),
  agentContext: null,
  floor: null,
  pendingActions: new Map(),
};

// Load persisted task state
function loadTasks(): void {
  if (existsSync(STORE_PATH)) {
    try {
      const raw = JSON.parse(readFileSync(STORE_PATH, 'utf-8'));
      for (const [id, unit] of Object.entries(raw.taskUnits || {})) {
        state.taskUnits.set(id, unit as TaskUnit);
      }
      // Look up this agent's role
      if (state.agentKey) {
        for (const [_, unit] of state.taskUnits) {
          for (const assignment of unit.assignments) {
            if (assignment.agentPublicKey === state.agentKey) {
              state.agentRole = assignment.role as CoordinationRole;
              state.agentId = assignment.agentId;
            }
          }
        }
      }
    } catch (e) {
      console.error('Failed to load task store:', e);
    }
  }
}

function saveTasks(): void {
  const data = {
    taskUnits: Object.fromEntries(state.taskUnits),
  };
  writeFileSync(STORE_PATH, JSON.stringify(data, null, 2));
}

// Role permission check
function requireRole(allowed: CoordinationRole[]): string | null {
  if (!state.agentRole) {
    return 'Not identified. Call identify tool first or set AGENT_KEY env var.';
  }
  if (!allowed.includes(state.agentRole)) {
    return `Role "${state.agentRole}" cannot use this tool. Allowed: ${allowed.join(', ')}`;
  }
  return null;
}

function requireKey(): string | null {
  if (!state.agentKey || !state.privateKey) {
    return 'No agent keys configured. Set AGENT_KEY and AGENT_PRIVATE_KEY env vars, or call identify.';
  }
  return null;
}

// ═══════════════════════════════════════
// Comms Helpers
// ═══════════════════════════════════════

interface CommsMessage {
  id: string;
  timestamp: string;
  from: string;
  to: string;
  type: string;
  priority?: string;
  subject: string;
  message: string;
  data?: Record<string, unknown>;
  signature?: string;
  processed?: boolean;
}

function readCommsFile(filePath: string): CommsMessage[] {
  if (!existsSync(filePath)) return [];
  try {
    return JSON.parse(readFileSync(filePath, 'utf-8'));
  } catch { return []; }
}

function writeCommsFile(filePath: string, messages: CommsMessage[]): void {
  writeFileSync(filePath, JSON.stringify(messages, null, 2));
}

function getAgentName(): string {
  // Derive agent name from agentId (e.g., "claude-001" → "claude")
  if (state.agentId) return state.agentId.replace(/-\d+$/, '');
  if (state.agentKey) return state.agentKey.slice(0, 8);
  return 'unknown';
}

// ── Agora bridge: auto-post coordination events ──

// Load existing Agora feed from disk on startup
function loadAgoraFeed(): void {
  if (!existsSync(AGORA_PATH)) return;
  try {
    const raw = JSON.parse(readFileSync(AGORA_PATH, 'utf-8'));
    if (raw.messages && Array.isArray(raw.messages)) {
      state.agoraFeed = {
        version: raw.version || '1.0',
        protocol: raw.protocol || 'agent-social-contract',
        lastUpdated: raw.lastUpdated || new Date().toISOString(),
        messageCount: raw.messages.length,
        messages: raw.messages,
      };
    }
  } catch {
    // Non-fatal: start with empty feed if file is corrupted
  }
}

// Persist Agora feed to disk after changes
function persistAgoraFeed(): void {
  try {
    const data = {
      version: state.agoraFeed.version,
      protocol: state.agoraFeed.protocol,
      lastUpdated: new Date().toISOString(),
      messageCount: state.agoraFeed.messages.length,
      messages: state.agoraFeed.messages,
    };
    writeFileSync(AGORA_PATH, JSON.stringify(data, null, 2));

    // Also update latest.json (lightweight polling endpoint)
    const latestPath = AGORA_PATH.replace('messages.json', 'latest.json');
    const last = state.agoraFeed.messages[state.agoraFeed.messages.length - 1];
    const latest = {
      lastMessageId: last?.id || null,
      lastMessageTimestamp: last?.timestamp || null,
      messageCount: state.agoraFeed.messages.length,
      lastUpdated: data.lastUpdated,
      feedUrl: 'https://aeoess.com/agora/messages.json',
      registryUrl: 'https://aeoess.com/.well-known/agents.json',
    };
    writeFileSync(latestPath, JSON.stringify(latest, null, 2) + '\n');
  } catch {
    // Non-fatal: coordination still works even if persistence fails
  }
}

function emitAgoraEvent(
  event: CoordinationEventType,
  taskId: string,
  detail: string,
): void {
  // Skip if no identity — can't sign messages
  if (!state.agentKey || !state.privateKey) return;

  try {
    const result = coordinationToAgora({
      event,
      taskId,
      agentId: state.agentId || 'anonymous',
      agentName: getAgentName(),
      publicKey: state.agentKey,
      privateKey: state.privateKey,
      feed: state.agoraFeed,
      registry: state.agoraRegistry,
      detail,
    });
    state.agoraFeed = result.feed;
    persistAgoraFeed();
  } catch {
    // Non-fatal: coordination still works even if Agora post fails
  }
}

function loadAgentsRegistry(): Array<{ agentId: string; agentName: string; publicKey: string; status: string; role: string; runtime: string; capabilities: string[] }> {
  if (!existsSync(AGENTS_PATH)) return [];
  try {
    const data = JSON.parse(readFileSync(AGENTS_PATH, 'utf-8'));
    return data.agents || [];
  } catch { return []; }
}

async function signMessage(content: string): Promise<string> {
  if (!state.privateKey) return '';
  try {
    return await sign(content, state.privateKey);
  } catch { return ''; }
}

// ═══════════════════════════════════════
// Server Setup
// ═══════════════════════════════════════

const server = new McpServer({
  name: "agent-passport-mcp",
  version: "2.0.0",
});

// ═══════════════════════════════════════
// TOOL: identify
// ═══════════════════════════════════════

server.tool(
  "identify",
  "Identify yourself to the coordination server. Sets your role and scopes tools accordingly.",
  {
    public_key: z.string().describe("Your Ed25519 public key"),
    private_key: z.string().describe("Your Ed25519 private key (for signing)"),
    agent_id: z.string().optional().describe("Your agent ID"),
  },
  async (args) => {
    state.agentKey = args.public_key;
    state.privateKey = args.private_key;
    state.agentId = args.agent_id || null;

    // Look up role from task assignments
    for (const [_, unit] of state.taskUnits) {
      for (const assignment of unit.assignments) {
        if (assignment.agentPublicKey === args.public_key) {
          state.agentRole = assignment.role as CoordinationRole;
          state.agentId = assignment.agentId;
        }
      }
    }

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          identified: true,
          publicKey: state.agentKey.slice(0, 16) + '...',
          role: state.agentRole || 'unassigned',
          agentId: state.agentId,
          note: state.agentRole
            ? `You are assigned as ${state.agentRole}. Use get_my_role for your instructions.`
            : 'No task assignment found. An operator needs to assign you a role first.',
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════
// TOOL: generate_keys
// ═══════════════════════════════════════

server.tool(
  "generate_keys",
  "Generate an Ed25519 keypair for agent identity.",
  {},
  async () => {
    const keys = generateKeyPair();
    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          publicKey: keys.publicKey,
          privateKey: keys.privateKey,
          algorithm: "Ed25519",
          note: "Use these with the identify tool or AGENT_KEY/AGENT_PRIVATE_KEY env vars.",
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════
// TOOL: get_my_role
// ═══════════════════════════════════════

server.tool(
  "get_my_role",
  "Get your current role, assigned tasks, and role-specific instructions.",
  {},
  async () => {
    if (!state.agentRole) {
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            role: null,
            message: 'You have no role assigned. An operator must assign you to a task first.',
          }, null, 2),
        }],
      };
    }

    const instructions = ROLE_PROMPTS[state.agentRole] || ROLE_PROMPTS['default'];

    // Find my active tasks
    const myTasks: any[] = [];
    for (const [taskId, unit] of state.taskUnits) {
      const myAssignment = unit.assignments.find(a => a.agentPublicKey === state.agentKey);
      if (myAssignment) {
        myTasks.push({
          taskId,
          title: unit.brief.title,
          role: myAssignment.role,
          status: getTaskStatus(unit),
          accepted: !!myAssignment.acceptedAt,
        });
      }
    }

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          role: state.agentRole,
          agentId: state.agentId,
          tasks: myTasks,
          instructions,
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════
// Role-Specific Instructions
// ═══════════════════════════════════════

const ROLE_PROMPTS: Record<string, string> = {
  operator: `You are the OPERATOR for this task unit. Your job:
1. Decompose work into roles and assign agents
2. Review evidence quality (score against threshold)
3. Approve or request rework on evidence
4. Hand off approved evidence to the analyst
5. Complete the task when deliverables are ready

TOOLS YOU SHOULD USE:
- create_task_brief: Define the task with roles, deliverables, acceptance criteria
- assign_agent: Link an agent to a role with a delegation
- review_evidence: Score evidence and approve/rework
- handoff_evidence: Transfer approved evidence between roles
- complete_task: Close the task with metrics and retrospective

YOU MUST NOT: Search the web, write content, or synthesize data. You coordinate, you don't produce.`,

  researcher: `You are the RESEARCHER for this task unit. Your job:
1. Accept your task assignment
2. Search for and extract evidence with citations
3. Submit evidence as a signed packet with source URLs
4. Every claim needs a quote of 10+ words from the source
5. Mark claims you cannot find as confidence: "not_found"

TOOLS YOU SHOULD USE:
- accept_assignment: Confirm you accept the task
- submit_evidence: Submit your research as a signed evidence packet

YOU MUST NOT: Synthesize, summarize, draw conclusions, or produce final deliverables. You gather raw evidence with citations. If you can't find something, say so — do NOT make it up.`,

  analyst: `You are the ANALYST for this task unit. Your job:
1. Accept your task assignment
2. Wait for evidence to be handed off to you
3. Synthesize evidence into deliverables (matrix, summary, etc.)
4. Cite every claim by evidence packet ID
5. Flag gaps explicitly — do NOT fill from your own knowledge

TOOLS YOU SHOULD USE:
- accept_assignment: Confirm you accept the task
- get_evidence: Retrieve evidence that was handed off to you
- submit_deliverable: Submit your final output

YOU MUST NOT: Search the web, fetch URLs, or do independent research. You work ONLY with the evidence you receive. If evidence is missing, flag it as [EVIDENCE GAP].`,

  builder: `You are the BUILDER for this task unit. Your job:
1. Accept your task assignment
2. Receive specifications or evidence from other roles
3. Build the requested output (code, documents, artifacts)
4. Submit your work as a signed deliverable

TOOLS YOU SHOULD USE:
- accept_assignment: Confirm you accept the task
- get_evidence: Retrieve specifications handed off to you
- submit_deliverable: Submit your built output

YOU MUST NOT: Make architectural decisions without operator approval. Follow specs exactly.`,

  reviewer: `You are the REVIEWER for this task unit. Your job:
1. Accept your task assignment
2. Review deliverables for correctness and completeness
3. Submit review findings back to the operator

TOOLS YOU SHOULD USE:
- accept_assignment: Confirm you accept the task
- get_evidence: Retrieve deliverables to review

YOU MUST NOT: Modify deliverables directly. Report issues to the operator.`,

  default: `You are connected to the Agent Passport coordination server but have no role assigned yet. An operator needs to assign you to a task. Available actions: identify, generate_keys, get_my_role, list_tasks.`,
};

// ═══════════════════════════════════════
// OPERATOR TOOLS
// ═══════════════════════════════════════

server.tool(
  "create_task_brief",
  "[OPERATOR] Create a new task with roles, deliverables, and acceptance criteria.",
  {
    title: z.string().describe("Task title"),
    description: z.string().describe("What needs to be done"),
    roles: z.array(z.object({
      role: z.string().describe("Role name (researcher, analyst, builder, reviewer, or custom)"),
      description: z.string().describe("What this role does"),
      allowed_scopes: z.array(z.string()).describe("What this role CAN do"),
      forbidden_scopes: z.array(z.string()).describe("What this role CANNOT do"),
      required_capabilities: z.array(z.string()).optional().describe("Agent must have these capabilities"),
    })).describe("Roles needed for this task"),
    deliverables: z.array(z.object({
      name: z.string(),
      description: z.string(),
      format: z.string(),
      produced_by: z.string().describe("Which role produces this"),
    })).describe("Expected outputs"),
    acceptance_criteria: z.array(z.string()).describe("What 'done' looks like"),
    deadline: z.string().optional().describe("ISO 8601 deadline"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    const brief = createTaskBrief({
      title: args.title,
      description: args.description,
      operatorPublicKey: state.agentKey!,
      operatorPrivateKey: state.privateKey!,
      roles: args.roles.map(r => ({
        role: r.role,
        description: r.description,
        allowedScopes: r.allowed_scopes,
        forbiddenScopes: r.forbidden_scopes,
        requiredCapabilities: r.required_capabilities,
      })),
      deliverables: args.deliverables.map(d => ({
        name: d.name,
        description: d.description,
        format: d.format,
        producedBy: d.produced_by,
      })),
      acceptanceCriteria: args.acceptance_criteria,
      deadline: args.deadline,
    });

    const unit = createTaskUnit(brief);
    state.taskUnits.set(brief.taskId, unit);
    saveTasks();

    // Bridge → Agora: announce task creation
    emitAgoraEvent('task_created', brief.taskId,
      `Task "${brief.title}" created with ${brief.roles.length} roles and ${brief.deliverables.length} deliverables. ${brief.description}`);

    // Set this agent as operator
    state.agentRole = 'operator';

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          taskId: brief.taskId,
          title: brief.title,
          roles: brief.roles.map(r => r.role),
          deliverables: brief.deliverables.map(d => d.name),
          status: 'draft',
          note: 'Task created. Now assign agents to each role with assign_agent.',
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "assign_agent",
  "[OPERATOR] Assign an agent to a role in a task. Creates a delegation automatically.",
  {
    task_id: z.string().describe("Task ID"),
    role: z.string().describe("Role to assign"),
    agent_id: z.string().describe("Agent ID"),
    agent_public_key: z.string().describe("Agent's Ed25519 public key"),
    scope: z.array(z.string()).describe("Delegation scopes"),
    spend_limit: z.number().default(500).describe("Max spend"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    const unit = state.taskUnits.get(args.task_id);
    if (!unit) return { content: [{ type: "text" as const, text: `Task ${args.task_id} not found.` }], isError: true };

    // Create delegation for this role
    const delegation = createDelegation({
      delegatedBy: state.agentKey!,
      delegatedTo: args.agent_public_key,
      scope: args.scope,
      spendLimit: args.spend_limit,
      maxDepth: 1,
      expiresInHours: 24,
      privateKey: state.privateKey!,
    });

    const { assignment, updatedBrief } = assignTask({
      brief: unit.brief,
      role: args.role,
      agentId: args.agent_id,
      agentPublicKey: args.agent_public_key,
      delegationId: delegation.delegationId,
      operatorPrivateKey: state.privateKey!,
    });

    unit.brief = updatedBrief;
    unit.assignments.push(assignment);
    saveTasks();

    // Bridge → Agora: announce assignment
    emitAgoraEvent('task_assigned', args.task_id,
      `Agent ${args.agent_id} assigned as ${args.role} with delegation ${delegation.delegationId}.`);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          assignmentId: assignment.assignmentId,
          role: args.role,
          agentId: args.agent_id,
          delegationId: delegation.delegationId,
          scope: args.scope,
          taskStatus: getTaskStatus(unit),
          note: `Agent ${args.agent_id} assigned as ${args.role}. They need to call accept_assignment.`,
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "review_evidence",
  "[OPERATOR] Review an evidence packet. Score it and approve, rework, or reject.",
  {
    task_id: z.string().describe("Task ID"),
    packet_id: z.string().describe("Evidence packet ID to review"),
    verdict: z.enum(["approve", "rework", "reject"]).describe("Your verdict"),
    score: z.number().min(0).max(100).describe("Quality score 0-100"),
    threshold: z.number().default(70).describe("Minimum passing score"),
    rationale: z.string().describe("Why this verdict"),
    issues: z.array(z.object({
      claim_id: z.string(),
      issue: z.string(),
      severity: z.enum(["critical", "major", "minor"]),
    })).optional().describe("Specific issues found"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    const unit = state.taskUnits.get(args.task_id);
    if (!unit) return { content: [{ type: "text" as const, text: `Task ${args.task_id} not found.` }], isError: true };

    const packet = unit.evidencePackets.find(p => p.packetId === args.packet_id);
    if (!packet) return { content: [{ type: "text" as const, text: `Packet ${args.packet_id} not found.` }], isError: true };

    try {
      const review = reviewEvidence({
        taskId: args.task_id,
        packet,
        reviewerPublicKey: state.agentKey!,
        reviewerPrivateKey: state.privateKey!,
        verdict: args.verdict,
        score: args.score,
        threshold: args.threshold,
        rationale: args.rationale,
        issues: args.issues?.map(i => ({ claimId: i.claim_id, issue: i.issue, severity: i.severity })),
      });

      unit.reviews.push(review);
      saveTasks();

      // Bridge → Agora: announce review result
      emitAgoraEvent('review_completed', args.task_id,
        `Review verdict: ${review.verdict} (score: ${review.score}/${review.threshold}). ${review.rationale}`);

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            reviewId: review.reviewId,
            verdict: review.verdict,
            score: review.score,
            threshold: review.threshold,
            issueCount: review.issues?.length || 0,
            note: review.verdict === 'approve'
              ? 'Evidence approved. Use handoff_evidence to pass to analyst.'
              : 'Evidence needs rework. Researcher must resubmit.',
          }, null, 2),
        }],
      };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: `Error: ${e.message}` }], isError: true };
    }
  }
);

server.tool(
  "handoff_evidence",
  "[OPERATOR] Transfer approved evidence from researcher to analyst.",
  {
    task_id: z.string().describe("Task ID"),
    packet_id: z.string().describe("Approved evidence packet ID"),
    review_id: z.string().describe("Review ID that approved it"),
    to_role: z.string().describe("Destination role (e.g. analyst)"),
    to_agent_key: z.string().describe("Destination agent's public key"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    const unit = state.taskUnits.get(args.task_id);
    if (!unit) return { content: [{ type: "text" as const, text: `Task ${args.task_id} not found.` }], isError: true };

    const packet = unit.evidencePackets.find(p => p.packetId === args.packet_id);
    const review = unit.reviews.find(r => r.reviewId === args.review_id);
    if (!packet || !review) return { content: [{ type: "text" as const, text: 'Packet or review not found.' }], isError: true };

    try {
      const handoff = handoffEvidence({
        taskId: args.task_id,
        packet,
        review,
        fromRole: 'researcher',
        toRole: args.to_role,
        toAgentPublicKey: args.to_agent_key,
        operatorPrivateKey: state.privateKey!,
      });

      unit.handoffs.push(handoff);
      saveTasks();

      // Bridge → Agora: announce handoff
      emitAgoraEvent('evidence_handed_off', args.task_id,
        `Evidence ${args.packet_id} handed off from researcher to ${args.to_role}.`);

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            handoffId: handoff.handoffId,
            fromRole: handoff.fromRole,
            toRole: handoff.toRole,
            packetId: handoff.packetId,
            note: `Evidence handed off to ${args.to_role}. They can now retrieve it with get_evidence.`,
          }, null, 2),
        }],
      };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: `Error: ${e.message}` }], isError: true };
    }
  }
);

server.tool(
  "complete_task",
  "[OPERATOR] Close the task unit with final status and retrospective.",
  {
    task_id: z.string().describe("Task ID"),
    status: z.enum(["completed", "failed", "partial"]).describe("Final status"),
    retrospective: z.string().optional().describe("What went well, what didn't"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    const unit = state.taskUnits.get(args.task_id);
    if (!unit) return { content: [{ type: "text" as const, text: `Task ${args.task_id} not found.` }], isError: true };

    const completion = completeTask({
      brief: unit.brief,
      unit,
      operatorPublicKey: state.agentKey!,
      operatorPrivateKey: state.privateKey!,
      status: args.status,
      retrospective: args.retrospective,
    });

    unit.completion = completion;
    saveTasks();

    // Bridge → Agora: announce task completion
    emitAgoraEvent('task_completed', args.task_id,
      `Status: ${completion.status}. Agents: ${completion.metrics.agentCount}, ` +
      `Duration: ${completion.metrics.totalDuration}s, ` +
      `Rework cycles: ${completion.metrics.reworkCount}. ` +
      (args.retrospective || ''));

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          taskId: args.task_id,
          status: completion.status,
          metrics: completion.metrics,
          retrospective: completion.retrospective,
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════
// WORKER TOOLS (any assigned role)
// ═══════════════════════════════════════

server.tool(
  "accept_assignment",
  "[ANY ROLE] Accept your task assignment. Confirms you're ready to work.",
  {
    task_id: z.string().describe("Task ID to accept"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    const unit = state.taskUnits.get(args.task_id);
    if (!unit) return { content: [{ type: "text" as const, text: `Task ${args.task_id} not found.` }], isError: true };

    const myAssignment = unit.assignments.find(a => a.agentPublicKey === state.agentKey);
    if (!myAssignment) return { content: [{ type: "text" as const, text: 'You are not assigned to this task.' }], isError: true };

    const accepted = acceptTask(myAssignment, state.privateKey!);
    // Replace in array
    const idx = unit.assignments.indexOf(myAssignment);
    unit.assignments[idx] = accepted;
    state.agentRole = accepted.role as CoordinationRole;
    saveTasks();

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          accepted: true,
          role: accepted.role,
          taskId: args.task_id,
          title: unit.brief.title,
          instructions: ROLE_PROMPTS[accepted.role] || ROLE_PROMPTS['default'],
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "submit_evidence",
  "[RESEARCHER] Submit research evidence as a signed packet with citations.",
  {
    task_id: z.string().describe("Task ID"),
    claims: z.array(z.object({
      dimension: z.string().describe("Evaluation dimension"),
      subject: z.string().describe("What's being evaluated"),
      claim: z.string().describe("The factual claim"),
      quote: z.string().describe("Supporting quote from source (10+ words)"),
      source_url: z.string().describe("Verifiable source URL"),
      confidence: z.enum(["high", "medium", "low", "not_found"]).describe("Confidence level"),
    })).describe("Evidence claims with citations"),
    methodology: z.string().describe("How you gathered this evidence"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    const unit = state.taskUnits.get(args.task_id);
    if (!unit) return { content: [{ type: "text" as const, text: `Task ${args.task_id} not found.` }], isError: true };

    const packet = submitEvidence({
      taskId: args.task_id,
      submitterPublicKey: state.agentKey!,
      submitterPrivateKey: state.privateKey!,
      role: (state.agentRole || 'researcher') as CoordinationRole,
      claims: args.claims.map(c => ({
        dimension: c.dimension,
        subject: c.subject,
        claim: c.claim,
        quote: c.quote,
        sourceUrl: c.source_url,
        confidence: c.confidence,
      })),
      methodology: args.methodology,
    });

    unit.evidencePackets.push(packet);
    saveTasks();

    // Bridge → Agora: announce evidence submission
    emitAgoraEvent('evidence_submitted', args.task_id,
      `Evidence packet with ${packet.metadata.totalClaims} claims (${packet.metadata.citedClaims} cited, ${packet.metadata.gapCount} gaps).`);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          packetId: packet.packetId,
          totalClaims: packet.metadata.totalClaims,
          citedClaims: packet.metadata.citedClaims,
          gapCount: packet.metadata.gapCount,
          sourcesSearched: packet.metadata.sourcesSearched,
          signed: true,
          note: 'Evidence submitted. Operator will review.',
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "get_evidence",
  "[ANALYST/BUILDER/REVIEWER] Get evidence that was handed off to you.",
  {
    task_id: z.string().describe("Task ID"),
  },
  async (args) => {
    const unit = state.taskUnits.get(args.task_id);
    if (!unit) return { content: [{ type: "text" as const, text: `Task ${args.task_id} not found.` }], isError: true };

    // Find handoffs to this agent
    const myHandoffs = unit.handoffs.filter(h => h.toAgent === state.agentKey);
    if (myHandoffs.length === 0) {
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            message: 'No evidence has been handed off to you yet. Wait for the operator to approve and hand off evidence.',
            taskStatus: getTaskStatus(unit),
          }, null, 2),
        }],
      };
    }

    // Get the actual evidence packets
    const evidenceForMe = myHandoffs.map(h => {
      const packet = unit.evidencePackets.find(p => p.packetId === h.packetId);
      return {
        handoffId: h.handoffId,
        fromRole: h.fromRole,
        packetId: h.packetId,
        claims: packet?.claims || [],
        metadata: packet?.metadata,
      };
    });

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          evidencePackets: evidenceForMe,
          totalClaims: evidenceForMe.reduce((s, e) => s + e.claims.length, 0),
          note: 'Use these evidence packets to produce your deliverable. Cite by packet ID.',
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "submit_deliverable",
  "[ANALYST/BUILDER] Submit your final output tied to evidence.",
  {
    task_id: z.string().describe("Task ID"),
    spec_id: z.string().describe("Deliverable spec ID from the brief"),
    content: z.string().describe("The deliverable content"),
    evidence_packet_ids: z.array(z.string()).describe("Evidence packet IDs used"),
    citation_count: z.number().describe("Number of citations in output"),
    gaps_flagged: z.number().describe("Number of gaps explicitly flagged"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    const unit = state.taskUnits.get(args.task_id);
    if (!unit) return { content: [{ type: "text" as const, text: `Task ${args.task_id} not found.` }], isError: true };

    const deliverable = submitDeliverable({
      taskId: args.task_id,
      specId: args.spec_id,
      submitterPublicKey: state.agentKey!,
      submitterPrivateKey: state.privateKey!,
      role: (state.agentRole || 'analyst') as CoordinationRole,
      content: args.content,
      evidencePacketIds: args.evidence_packet_ids,
      citationCount: args.citation_count,
      gapsFlagged: args.gaps_flagged,
    });

    unit.deliverables.push(deliverable);
    saveTasks();

    // Bridge → Agora: announce deliverable
    emitAgoraEvent('deliverable_submitted', args.task_id,
      `Deliverable for spec ${args.spec_id} submitted by ${state.agentRole || 'agent'} with ${args.citation_count} citations.`);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          deliverableId: deliverable.deliverableId,
          role: deliverable.role,
          citations: deliverable.citationCount,
          gapsFlagged: deliverable.gapsFlagged,
          signed: true,
          note: 'Deliverable submitted. Operator will review and close the task.',
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════
// SHARED TOOLS (any agent)
// ═══════════════════════════════════════

server.tool(
  "list_tasks",
  "List all tasks in the coordination store.",
  {},
  async () => {
    const tasks = Array.from(state.taskUnits.entries()).map(([id, unit]) => ({
      taskId: id,
      title: unit.brief.title,
      status: getTaskStatus(unit),
      roles: unit.brief.roles.map(r => ({
        role: r.role,
        assigned: !!r.assignedTo,
        agentKey: r.assignedTo ? r.assignedTo.slice(0, 12) + '...' : null,
      })),
      evidencePackets: unit.evidencePackets.length,
      reviews: unit.reviews.length,
      deliverables: unit.deliverables.length,
      completed: !!unit.completion,
    }));

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({ tasks, total: tasks.length }, null, 2),
      }],
    };
  }
);

server.tool(
  "get_task_detail",
  "Get full details of a specific task including all evidence, reviews, and deliverables.",
  {
    task_id: z.string().describe("Task ID"),
  },
  async (args) => {
    const unit = state.taskUnits.get(args.task_id);
    if (!unit) return { content: [{ type: "text" as const, text: `Task ${args.task_id} not found.` }], isError: true };

    const validation = validateTaskUnit(unit);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          brief: {
            taskId: unit.brief.taskId,
            title: unit.brief.title,
            description: unit.brief.description,
            roles: unit.brief.roles,
            deliverables: unit.brief.deliverables,
            acceptanceCriteria: unit.brief.acceptanceCriteria,
            status: getTaskStatus(unit),
          },
          assignments: unit.assignments.map(a => ({
            role: a.role,
            agentId: a.agentId,
            accepted: !!a.acceptedAt,
          })),
          evidencePackets: unit.evidencePackets.map(p => ({
            packetId: p.packetId,
            role: p.role,
            totalClaims: p.metadata.totalClaims,
            gapCount: p.metadata.gapCount,
          })),
          reviews: unit.reviews.map(r => ({
            reviewId: r.reviewId,
            packetId: r.packetId,
            verdict: r.verdict,
            score: r.score,
          })),
          handoffs: unit.handoffs.map(h => ({
            handoffId: h.handoffId,
            fromRole: h.fromRole,
            toRole: h.toRole,
          })),
          deliverables: unit.deliverables.map(d => ({
            deliverableId: d.deliverableId,
            role: d.role,
            citations: d.citationCount,
            gaps: d.gapsFlagged,
          })),
          completion: unit.completion ? {
            status: unit.completion.status,
            metrics: unit.completion.metrics,
          } : null,
          validation,
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════
// DELEGATION TOOLS (Layer 1)
// ═══════════════════════════════════════

server.tool(
  "create_delegation",
  "[OPERATOR] Create a scoped delegation from one agent to another.",
  {
    delegated_to: z.string().describe("Public key of the agent receiving delegation"),
    scope: z.array(z.string()).describe("Scopes to grant (e.g. ['web_search', 'code_execution'])"),
    spend_limit: z.number().default(500).describe("Maximum spend allowed"),
    max_depth: z.number().default(1).describe("How many levels of sub-delegation"),
    expires_in_hours: z.number().default(24).describe("Delegation validity in hours"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    const delegation = createDelegation({
      delegatedBy: state.agentKey!,
      delegatedTo: args.delegated_to,
      scope: args.scope,
      spendLimit: args.spend_limit,
      maxDepth: args.max_depth,
      expiresInHours: args.expires_in_hours,
      privateKey: state.privateKey!,
    });

    state.delegations.set(delegation.delegationId, delegation);
    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          delegationId: delegation.delegationId,
          delegatedTo: args.delegated_to.slice(0, 16) + '...',
          scope: delegation.scope,
          spendLimit: delegation.spendLimit,
          maxDepth: delegation.maxDepth,
          expiresAt: delegation.expiresAt,
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "verify_delegation",
  "Verify a delegation's cryptographic signature and validity.",
  {
    delegation_id: z.string().describe("Delegation ID to verify"),
  },
  async (args) => {
    const delegation = state.delegations.get(args.delegation_id);
    if (!delegation) return { content: [{ type: "text" as const, text: `Delegation ${args.delegation_id} not found in session.` }], isError: true };

    const result = verifyDelegation(delegation);
    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          delegationId: args.delegation_id,
          valid: result.valid,
          errors: result.errors,
          scope: delegation.scope,
          expired: new Date(delegation.expiresAt) < new Date(),
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "revoke_delegation",
  "[OPERATOR] Revoke a delegation. Optionally cascade to all sub-delegations.",
  {
    delegation_id: z.string().describe("Delegation ID to revoke"),
    reason: z.string().describe("Why the delegation is being revoked"),
    cascade: z.boolean().default(true).describe("Also revoke all sub-delegations"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    if (args.cascade) {
      const result = cascadeRevoke(args.delegation_id, state.agentKey!, args.reason, state.privateKey!);
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            revokedCount: result.totalRevoked,
            rootRevocation: { delegationId: result.rootRevocation.delegationId, revokedAt: result.rootRevocation.revokedAt },
            cascadedCount: result.cascadedRevocations.length,
            reason: args.reason,
          }, null, 2),
        }],
      };
    } else {
      const revocation = revokeDelegation(args.delegation_id, state.agentKey!, args.reason, state.privateKey!);
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            delegationId: args.delegation_id,
            revokedAt: revocation.revokedAt,
            reason: args.reason,
          }, null, 2),
        }],
      };
    }
  }
);

server.tool(
  "sub_delegate",
  "Sub-delegate authority to another agent (must be within your delegation scope and depth).",
  {
    parent_delegation_id: z.string().describe("Your delegation ID"),
    delegated_to: z.string().describe("Public key of the agent receiving sub-delegation"),
    scope: z.array(z.string()).describe("Scopes to grant (must be subset of parent)"),
    spend_limit: z.number().describe("Maximum spend (must be <= parent)"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    try {
      const parentDel = state.delegations.get(args.parent_delegation_id);
      if (!parentDel) return { content: [{ type: "text" as const, text: `Parent delegation ${args.parent_delegation_id} not found in session.` }], isError: true };

      const sub = subDelegate({
        parentDelegation: parentDel,
        delegatedTo: args.delegated_to,
        scope: args.scope,
        spendLimit: args.spend_limit,
        privateKey: state.privateKey!,
      });

      state.delegations.set(sub.delegationId, sub);
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            delegationId: sub.delegationId,
            parentId: args.parent_delegation_id,
            scope: sub.scope,
            spendLimit: sub.spendLimit,
            depth: sub.currentDepth,
          }, null, 2),
        }],
      };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: `Sub-delegation failed: ${e.message}` }], isError: true };
    }
  }
);

// ═══════════════════════════════════════
// AGORA TOOLS (Layer 4)
// ═══════════════════════════════════════

server.tool(
  "post_agora_message",
  "Post a signed message to the Agora feed. Anyone can read, everything is signed.",
  {
    topic: z.string().describe("Topic channel (e.g. 'coordination', 'governance', 'general')"),
    type: z.enum(["announcement", "proposal", "discussion", "request", "ack", "vote"]).describe("Message type"),
    subject: z.string().describe("One-line summary"),
    content: z.string().describe("Message body (markdown)"),
    reply_to: z.string().optional().describe("Message ID to reply to (for threading)"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    const message = createAgoraMessage({
      agentId: state.agentId || 'anonymous',
      agentName: state.agentId || 'anonymous',
      publicKey: state.agentKey!,
      privateKey: state.privateKey!,
      topic: args.topic,
      type: args.type,
      subject: args.subject,
      content: args.content,
      replyTo: args.reply_to,
    });

    state.agoraFeed = appendToFeed(state.agoraFeed, message);
    persistAgoraFeed();
    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          messageId: message.id,
          topic: message.topic,
          subject: message.subject,
          signed: !!message.signature,
          feedSize: state.agoraFeed.messages.length,
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "get_agora_topics",
  "List all topics in the Agora feed with message counts.",
  {},
  async () => {
    const topics = getTopics(state.agoraFeed);
    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          topics: topics.map(t => ({ topic: t.topic, count: t.count })),
          totalMessages: state.agoraFeed.messages.length,
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "get_agora_thread",
  "Get a message thread from the Agora feed.",
  {
    message_id: z.string().describe("Root message ID to get thread for"),
  },
  async (args) => {
    const thread = getThread(state.agoraFeed, args.message_id);
    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          threadLength: thread.length,
          messages: thread.map(m => ({
            id: m.id,
            author: m.author.agentId,
            subject: m.subject,
            content: m.content.slice(0, 200) + (m.content.length > 200 ? '...' : ''),
            replyTo: m.replyTo,
          })),
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "get_agora_by_topic",
  "Get all messages in a topic.",
  {
    topic: z.string().describe("Topic to filter by"),
  },
  async (args) => {
    const messages = getByTopic(state.agoraFeed, args.topic);
    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          topic: args.topic,
          count: messages.length,
          messages: messages.map(m => ({
            id: m.id,
            author: m.author.agentId,
            type: m.type,
            subject: m.subject,
            content: m.content.slice(0, 200) + (m.content.length > 200 ? '...' : ''),
            timestamp: m.timestamp,
          })),
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "register_agora_agent",
  "Register an agent in the Agora so their messages can be verified.",
  {
    agent_id: z.string().describe("Agent ID"),
    agent_name: z.string().describe("Display name"),
    public_key: z.string().describe("Ed25519 public key"),
  },
  async (args) => {
    registerAgent(state.agoraRegistry, {
      agentId: args.agent_id,
      agentName: args.agent_name,
      publicKey: args.public_key,
      joinedAt: new Date().toISOString(),
      role: 'member',
    });
    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          registered: true,
          agentId: args.agent_id,
          registrySize: state.agoraRegistry.agents.length,
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════
// COMMS TOOLS (Agent-to-Agent Communication)
// ═══════════════════════════════════════

server.tool(
  "send_message",
  "Send a signed message to another agent. Message is written to comms/to-{agent}.json.",
  {
    to: z.string().describe("Recipient agent name (e.g., 'aeoess', 'portalx2', 'claude')"),
    subject: z.string().describe("Message subject"),
    message: z.string().describe("Message body"),
    type: z.string().optional().describe("Message type (default: 'message')"),
    priority: z.string().optional().describe("Priority: low, normal, high, critical"),
    data: z.record(z.unknown()).optional().describe("Structured data payload"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }] };

    const fromName = getAgentName();
    const toFile = join(COMMS_PATH, `to-${args.to}.json`);
    const fromFile = join(COMMS_PATH, `from-${fromName}.json`);

    const msg: CommsMessage = {
      id: `msg-${fromName}-${Date.now()}`,
      timestamp: new Date().toISOString(),
      from: state.agentId || fromName,
      to: args.to,
      type: args.type || 'message',
      priority: args.priority || 'normal',
      subject: args.subject,
      message: args.message,
      data: args.data || {},
      signature: await signMessage(args.subject + args.message),
    };

    // Write to recipient's inbox
    const inbox = readCommsFile(toFile);
    inbox.push(msg);
    writeCommsFile(toFile, inbox);

    // Write to sender's outbox
    const outbox = readCommsFile(fromFile);
    outbox.push(msg);
    writeCommsFile(fromFile, outbox);

    return {
      content: [{ type: "text" as const, text: JSON.stringify({
        sent: true, id: msg.id, to: args.to, subject: args.subject,
      }, null, 2) }],
    };
  }
);

server.tool(
  "check_messages",
  "Check messages addressed to you. Reads from comms/to-{your-agent-name}.json.",
  {
    unprocessed_only: z.boolean().optional().describe("Only show unprocessed messages (default: true)"),
    mark_read: z.boolean().optional().describe("Mark returned messages as processed (default: false)"),
  },
  async (args) => {
    const name = getAgentName();
    const filePath = join(COMMS_PATH, `to-${name}.json`);
    let messages = readCommsFile(filePath);

    const unprocessedOnly = args.unprocessed_only !== false;
    if (unprocessedOnly) {
      messages = messages.filter(m => !m.processed);
    }

    if (args.mark_read && messages.length > 0) {
      const all = readCommsFile(filePath);
      const ids = new Set(messages.map(m => m.id));
      for (const m of all) { if (ids.has(m.id)) m.processed = true; }
      writeCommsFile(filePath, all);
    }

    return {
      content: [{ type: "text" as const, text: JSON.stringify({
        agent: name, count: messages.length,
        messages: messages.map(m => ({
          id: m.id, from: m.from, subject: m.subject,
          priority: m.priority, timestamp: m.timestamp,
          message: m.message, data: m.data,
        })),
      }, null, 2) }],
    };
  }
);

server.tool(
  "broadcast",
  "Send a signed message to all agents via comms/broadcast.json.",
  {
    subject: z.string().describe("Message subject"),
    message: z.string().describe("Message body"),
    type: z.string().optional().describe("Message type (default: 'broadcast')"),
    priority: z.string().optional().describe("Priority: low, normal, high, critical"),
    data: z.record(z.unknown()).optional().describe("Structured data payload"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }] };

    const fromName = getAgentName();
    const broadcastFile = join(COMMS_PATH, 'broadcast.json');

    const msg: CommsMessage = {
      id: `bcast-${fromName}-${Date.now()}`,
      timestamp: new Date().toISOString(),
      from: state.agentId || fromName,
      to: 'all',
      type: args.type || 'broadcast',
      priority: args.priority || 'normal',
      subject: args.subject,
      message: args.message,
      data: args.data || {},
      signature: await signMessage(args.subject + args.message),
    };

    const broadcasts = readCommsFile(broadcastFile);
    broadcasts.push(msg);
    writeCommsFile(broadcastFile, broadcasts);

    return {
      content: [{ type: "text" as const, text: JSON.stringify({
        broadcast: true, id: msg.id, subject: args.subject,
      }, null, 2) }],
    };
  }
);

server.tool(
  "list_agents",
  "List registered agents from the agent registry (agora/agents.json).",
  {
    status_filter: z.string().optional().describe("Filter by status: active, pending, retired (default: all)"),
  },
  async (args) => {
    let agents = loadAgentsRegistry();

    if (args.status_filter) {
      agents = agents.filter(a => a.status === args.status_filter);
    }

    return {
      content: [{ type: "text" as const, text: JSON.stringify({
        count: agents.length,
        agents: agents.map(a => ({
          agentId: a.agentId, name: a.agentName,
          status: a.status, role: a.role,
          runtime: a.runtime, capabilities: a.capabilities,
        })),
      }, null, 2) }],
    };
  }
);

// ═══════════════════════════════════════
// VALUES / POLICY TOOLS (Layer 2 + 5)
// ═══════════════════════════════════════

server.tool(
  "load_values_floor",
  "Load a Values Floor from YAML. Sets the floor principles for policy evaluation.",
  {
    yaml: z.string().describe("Values Floor YAML content"),
  },
  async (args) => {
    try {
      const floor = loadFloor(args.yaml);
      state.floorYaml = args.yaml;
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            loaded: true,
            version: floor.version,
            principles: floor.floor.length,
            names: floor.floor.map((p: any) => p.name),
          }, null, 2),
        }],
      };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: `Failed to load floor: ${e.message}` }], isError: true };
    }
  }
);

server.tool(
  "attest_to_floor",
  "Attest that your agent agrees to abide by the loaded Values Floor.",
  {
    floor_version: z.string().describe("Version of the floor to attest to"),
    extensions: z.array(z.string()).optional().describe("Optional additional extensions"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };
    if (!state.floorYaml) return { content: [{ type: "text" as const, text: 'No floor loaded. Use load_values_floor first.' }], isError: true };

    const floor = loadFloor(state.floorYaml);
    const attestation = attestFloor(
      state.agentId || 'anonymous',
      state.agentKey!,
      args.floor_version,
      args.extensions || [],
      state.privateKey!,
    );

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          attested: true,
          agentId: attestation.agentId,
          floorVersion: attestation.floorVersion,
          extensions: attestation.extensions,
          signed: !!attestation.commitment,
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "create_intent",
  "Declare an intent to perform an action. First step of the 3-signature chain.",
  {
    action_type: z.string().describe("What type of action (e.g. 'web_search', 'commerce:checkout')"),
    target: z.string().describe("What the action operates on"),
    scope_required: z.string().describe("Which delegation scope is needed"),
    spend_amount: z.number().optional().describe("Expected spend amount"),
    spend_currency: z.string().optional().describe("Spend currency (e.g. 'usd')"),
    context: z.string().optional().describe("Why the agent wants to do this"),
    delegation_id: z.string().describe("Delegation ID authorizing this action"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    const intent = createActionIntent({
      agentId: state.agentId || 'anonymous',
      agentPublicKey: state.agentKey!,
      delegationId: args.delegation_id,
      action: {
        type: args.action_type,
        target: args.target,
        scopeRequired: args.scope_required,
        spend: args.spend_amount ? { amount: args.spend_amount, currency: args.spend_currency || 'usd' } : undefined,
      },
      context: args.context,
      privateKey: state.privateKey!,
    });

    state.intents.set(intent.intentId, intent);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          intentId: intent.intentId,
          action: intent.action,
          signed: !!intent.signature,
          note: 'Intent created. Use evaluate_intent for policy decision (signature 2 of 3).',
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "evaluate_intent",
  "[OPERATOR] Evaluate an intent against the Values Floor policy engine. Returns real pass/fail verdict.",
  {
    intent_id: z.string().describe("Intent ID from create_intent"),
    delegation_scope: z.array(z.string()).describe("Delegation scope for context"),
    delegation_spend_limit: z.number().describe("Delegation spend limit"),
    delegation_spent: z.number().default(0).describe("Amount already spent"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };
    if (!state.floorYaml) return { content: [{ type: "text" as const, text: 'No floor loaded. Use load_values_floor first.' }], isError: true };

    const intent = state.intents.get(args.intent_id);
    if (!intent) return { content: [{ type: "text" as const, text: `Intent ${args.intent_id} not found. Use create_intent first.` }], isError: true };

    const floor = loadFloor(state.floorYaml);
    const validator = new FloorValidatorV1();

    const validationContext = {
      floorVersion: floor.version,
      floorPrinciples: floor.floor.map((p: any) => ({
        id: p.id, name: p.name,
        enforcement: p.enforcement,
        weight: p.weight,
      })),
      delegation: {
        scope: args.delegation_scope,
        spendLimit: args.delegation_spend_limit,
        spentAmount: args.delegation_spent,
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        revoked: false,
        currentDepth: 0,
        maxDepth: 2,
      },
      agentRegistered: true,
      agentAttestationValid: true,
    };

    try {
      const decision = evaluateIntent({
        intent,
        validator,
        validationContext,
        evaluatorId: state.agentId || 'mcp-evaluator',
        evaluatorPublicKey: state.agentKey!,
        evaluatorPrivateKey: state.privateKey!,
      });

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            decisionId: decision.decisionId,
            intentId: decision.intentId,
            verdict: decision.verdict,
            reason: decision.reason,
            principlesEvaluated: decision.principlesEvaluated.length,
            constraints: decision.constraints,
            floorVersion: decision.floorVersion,
            signed: true,
          }, null, 2),
        }],
      };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: `Policy evaluation failed: ${e.message}` }], isError: true };
    }
  }
);

// ═══════════════════════════════════════
// COMMERCE TOOLS (Layer 8)
// ═══════════════════════════════════════

server.tool(
  "commerce_preflight",
  "Run preflight checks before a purchase. Validates passport, delegation, merchant, and spend limits.",
  {
    merchant_name: z.string().describe("Merchant to purchase from"),
    amount: z.number().describe("Purchase amount"),
    currency: z.string().default("usd").describe("Currency code"),
    delegation_id: z.string().describe("Commerce delegation ID"),
    agent_id: z.string().describe("Agent making the purchase"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    // Create a passport for preflight (uses session agent)
    const agent = joinSocialContract({
      name: args.agent_id,
      mission: 'Commerce operation',
      owner: 'mcp-session',
      capabilities: ['commerce:checkout', 'commerce:browse'],
      platform: 'node',
      models: ['mcp'],
    });

    // Look up or create commerce delegation
    const commerceDel = createCommerceDelegation({
      agentId: args.agent_id,
      delegationId: args.delegation_id,
      spendLimit: 1000, // Default, should come from actual delegation
      approvedMerchants: [], // Empty = all merchants allowed
    });

    const result = commercePreflight({
      signedPassport: agent.passport,
      delegation: commerceDel,
      merchantName: args.merchant_name,
      estimatedTotal: { amount: args.amount, currency: args.currency },
    });

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          permitted: result.permitted,
          checks: result.checks,
          warnings: result.warnings,
          blockedReason: result.blockedReason,
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "get_commerce_spend",
  "Get spend analytics for a commerce delegation.",
  {
    agent_id: z.string().describe("Agent ID"),
    delegation_id: z.string().describe("Commerce delegation ID"),
    spend_limit: z.number().describe("Total allowed spend"),
  },
  async (args) => {
    const commerceDel = createCommerceDelegation({
      agentId: args.agent_id,
      delegationId: args.delegation_id,
      spendLimit: args.spend_limit,
    });

    const summary = getSpendSummary(commerceDel);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify(summary, null, 2),
      }],
    };
  }
);

server.tool(
  "request_human_approval",
  "Request human approval for a high-value purchase.",
  {
    agent_id: z.string().describe("Agent requesting approval"),
    merchant: z.string().describe("Merchant name"),
    amount: z.number().describe("Purchase amount"),
    currency: z.string().default("usd").describe("Currency"),
    reason: z.string().describe("Why this purchase is needed"),
    expires_minutes: z.number().default(30).describe("Minutes until approval expires"),
  },
  async (args) => {
    const approval = requestHumanApproval({
      agentId: args.agent_id,
      delegationId: 'pending',
      merchantName: args.merchant,
      items: [{ id: 'item-1', skuId: 'manual', name: args.reason, quantity: 1, unitPrice: { amount: args.amount, currency: args.currency }, totalPrice: { amount: args.amount, currency: args.currency } }],
      totalAmount: { amount: args.amount, currency: args.currency },
      reason: args.reason,
      expiresInMinutes: args.expires_minutes,
    });

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          requestId: approval.requestId,
          status: approval.status,
          expiresAt: approval.expiresAt,
          note: 'Approval request created. Human must approve before checkout can proceed.',
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════
// AGENT CONTEXT — Enforcement Middleware
// ═══════════════════════════════════════

server.tool(
  "create_agent_context",
  "Create an enforcement context that automatically runs every action through the 3-signature policy chain. Without this, policy checks are opt-in. With this, agents physically cannot skip enforcement.",
  {
    name: z.string().describe("Agent name"),
    mission: z.string().describe("Agent mission statement"),
    enforcement: z.enum(["auto", "manual", "strict"]).default("auto").describe("Enforcement level: auto (every action checked), manual (tracking only), strict (auto + additional constraints)"),
    delegated_scopes: z.array(z.string()).default([]).describe("Scopes to delegate (e.g. ['data:read', 'api:fetch', 'commerce:checkout'])"),
    spend_limit: z.number().default(1000).describe("Maximum spend allowed"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    if (!state.floorYaml) {
      return { content: [{ type: "text" as const, text: 'No floor loaded. Use load_values_floor first.' }], isError: true };
    }

    try {
      const floor = loadFloor(state.floorYaml);

      // Create the agent with floor attestation
      const agent = joinSocialContract({
        name: args.name,
        mission: args.mission,
        owner: 'mcp-session',
        capabilities: args.delegated_scopes,
        platform: 'node',
        models: ['mcp'],
        floor,
      });

      // Create the enforced context
      const ctx = createAgentContext(agent, floor, {
        enforcement: args.enforcement as EnforcementLevel,
      });

      // Add delegation if scopes provided
      if (args.delegated_scopes.length > 0) {
        const principal = joinSocialContract({
          name: 'mcp-principal',
          mission: 'MCP session principal',
          owner: 'human',
          capabilities: ['admin'],
          platform: 'node',
          models: ['mcp'],
          floor,
        });

        const del = delegate({
          from: principal,
          toPublicKey: agent.publicKey,
          scope: args.delegated_scopes,
          spendLimit: args.spend_limit,
          maxDepth: 3,
          expiresInHours: 24,
        });

        ctx.addDelegation(del);
      }

      state.agentContext = ctx;
      state.floor = floor;

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            created: true,
            enforcement: args.enforcement,
            agentId: agent.agentId,
            scopes: args.delegated_scopes,
            spendLimit: args.spend_limit,
            note: `Agent Context active (${args.enforcement} mode). Use execute_with_context to run actions through the 3-signature chain.`,
          }, null, 2),
        }],
      };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: `Failed to create context: ${e.message}` }], isError: true };
    }
  }
);

server.tool(
  "execute_with_context",
  "Execute an action through the enforcement context. Automatically runs the 3-signature chain: creates intent (sig 1), evaluates against floor + delegation (sig 2), returns verdict. Action is DENIED if outside delegated scope.",
  {
    action_type: z.string().describe("Action type (e.g. 'api:fetch', 'data:write', 'commerce:checkout')"),
    target: z.string().describe("Target of the action (e.g. URL, file path, resource ID)"),
    scope: z.string().describe("Required scope for this action (must match a delegated scope)"),
    estimated_spend: z.number().optional().describe("Estimated spend for commerce actions"),
  },
  async (args) => {
    if (!state.agentContext) {
      return { content: [{ type: "text" as const, text: 'No agent context. Use create_agent_context first.' }], isError: true };
    }

    try {
      const result = state.agentContext.execute({
        type: args.action_type,
        target: args.target,
        scope: args.scope,
        spend: args.estimated_spend ? { amount: args.estimated_spend, currency: 'USD' } : undefined,
      });

      // Store for later completion
      if (result.permitted && result.intent) {
        state.pendingActions.set(result.intent.intentId, result);
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            permitted: result.permitted,
            verdict: result.verdict,
            intentId: result.intent?.intentId,
            evaluatorId: result.decision?.evaluatorId,
            reason: result.reason,
            stats: state.agentContext.stats,
            note: result.permitted
              ? `Action PERMITTED. Call complete_action with intent_id="${result.intent.intentId}" when done.`
              : `Action DENIED: ${result.reason}`,
          }, null, 2),
        }],
      };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: `Execute failed: ${e.message}` }], isError: true };
    }
  }
);

server.tool(
  "complete_action",
  "Complete a permitted action and get the full 3-signature proof chain (intent + decision + receipt + policy receipt). Call this after successfully executing the action.",
  {
    intent_id: z.string().describe("Intent ID from execute_with_context result"),
    status: z.enum(["success", "failure", "partial"]).describe("Outcome of the action"),
    summary: z.string().describe("Brief description of what was accomplished"),
  },
  async (args) => {
    if (!state.agentContext) {
      return { content: [{ type: "text" as const, text: 'No agent context. Use create_agent_context first.' }], isError: true };
    }

    // Find the pending execute result
    const executeResult = state.pendingActions.get(args.intent_id);

    if (!executeResult) {
      return { content: [{ type: "text" as const, text: `No pending action found for intent ${args.intent_id}. Was it permitted?` }], isError: true };
    }

    try {
      const completed = state.agentContext.complete(executeResult, {
        status: args.status,
        summary: args.summary,
      });

      // Clean up
      state.pendingActions.delete(args.intent_id);

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            completed: true,
            receiptId: completed.receipt.receiptId,
            policyReceiptId: completed.policyReceipt?.receiptId,
            signatures: {
              intent: '✓ (agent declared intent)',
              decision: '✓ (policy engine evaluated)',
              receipt: '✓ (execution recorded)',
            },
            stats: state.agentContext.stats,
            auditTrail: state.agentContext.auditLog.length + ' entries',
          }, null, 2),
        }],
      };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: `Complete failed: ${e.message}` }], isError: true };
    }
  }
);

// ═══════════════════════════════════════
// MCP Prompts — Role-Specific
// ═══════════════════════════════════════

server.prompt(
  "coordination_role",
  "Get instructions for your assigned coordination role",
  {},
  async () => {
    const role = state.agentRole || 'default';
    const instructions = ROLE_PROMPTS[role] || ROLE_PROMPTS['default'];

    return {
      messages: [{
        role: "user" as const,
        content: {
          type: "text" as const,
          text: `You are connected to the Agent Passport Coordination Server.\n\nYour role: ${role}\nYour agent ID: ${state.agentId || 'unknown'}\n\n${instructions}\n\nCall get_my_role to see your active tasks.`,
        },
      }],
    };
  }
);

// ═══════════════════════════════════════
// Connect and start
// ═══════════════════════════════════════

async function main() {
  loadTasks();
  loadAgoraFeed();

  const roleInfo = state.agentRole
    ? ` | Role: ${state.agentRole}`
    : ' | No role (call identify or set AGENT_KEY)';

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`Agent Passport MCP Server v2.0 running${roleInfo}`);
  console.error(`Tasks loaded: ${state.taskUnits.size} | Agora messages: ${state.agoraFeed.messages.length}`);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
