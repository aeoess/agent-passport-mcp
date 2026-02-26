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
  // Identity
  joinSocialContract, verifySocialContract, generateKeyPair,
  delegate, recordWork,
  // Coordination (Layer 6)
  createTaskBrief, verifyTaskBrief,
  assignTask, acceptTask,
  submitEvidence, verifyEvidence,
  reviewEvidence, verifyReview,
  handoffEvidence, verifyHandoff,
  submitDeliverable, verifyDeliverable,
  completeTask, verifyCompletion,
  createTaskUnit, getTaskStatus, validateTaskUnit,
  // Delegation
  createDelegation, clearStores,
} from "agent-passport-system";

import type {
  SocialContractAgent, Delegation, ActionReceipt,
  TaskBrief, TaskUnit, EvidencePacket, ReviewDecision,
  CoordinationRole,
} from "agent-passport-system";

// ═══════════════════════════════════════
// State Management
// ═══════════════════════════════════════

const STORE_PATH = join(process.env.HOME || '.', '.agent-passport-tasks.json');

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

  const roleInfo = state.agentRole
    ? ` | Role: ${state.agentRole}`
    : ' | No role (call identify or set AGENT_KEY)';

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`Agent Passport MCP Server v2.0 running${roleInfo}`);
  console.error(`Tasks loaded: ${state.taskUnits.size}`);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
