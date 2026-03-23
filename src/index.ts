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
import { join, resolve } from "node:path";

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
  // Principal Identity
  createPrincipalIdentity, endorseAgent, verifyEndorsement,
  revokeEndorsement, createDisclosure, verifyDisclosure,
  createFleet, addToFleet, getFleetStatus, revokeFromFleet,
  endorsePassport, verifyPassportEndorsement, hasPrincipalEndorsement,
  // Reputation-Gated Authority (Layer 9)
  computeEffectiveScore, createScopedReputation,
  resolveAuthorityTier, checkTierForIntent, advisoryTierPrecheck,
  createPromotionReview, validatePromotionReview,
  triggerDemotion, updateReputationFromResult,
  DEFAULT_TIERS, DEFAULT_PROMOTION_REQUIREMENTS,
  meetsPromotionRequirements,
  // Proxy Gateway (Enforcement Boundary)
  ProxyGateway, createProxyGateway,
  // Intent Network (Agent-Mediated Matching) — card creation only, API handles persistence
  createIntentCard, verifyIntentCard,
  // v2: Constitutional Governance Extensions
  createPolicyContext, isPolicyContextActive, isPolicyContextInGrace,
  createArtifactProvenance, verifyArtifactIntegrity,
  computeDecayedWeight,
  getUncertaintyRequirements, resolveUncertaintyLevel,
  evaluateConditions,
  v1DelegationToV2, v2DelegationToV1,
  // v2: Delegation Versioning
  createV2Delegation, supersedeV2Delegation, renewV2Delegation,
  revokeV2Delegation, validateV2Delegation, traceV2DelegationHistory,
  clearV2DelegationStore, isScopeExpansion,
  // v2: Outcome Registration
  createV2OutcomeRecord, addV2PrincipalReport, addV2AdjudicatedReport,
  getV2EffectiveDivergence, isV2AgentFlaggedForReview, clearV2OutcomeStore,
  // v2: Anomaly Detection
  recordV2Action, checkV2FirstMaxAuthority, validateV2UncertaintyCompliance,
  computeV2ConcentrationMetrics, clearV2AnomalyStores,
  // v2: Emergency Pathways
  defineV2EmergencyPathway, activateV2Emergency, logV2EmergencyAction,
  reviewV2Emergency, getV2ActiveEmergencies, clearV2EmergencyStores,
  // v2: Migration
  requestV2Migration, approveV2Migration, executeV2Migration,
  isV2InProbation, computeV2MigrationDiscount, traceV2MigrationLineage,
  rollbackV2Migration, clearV2MigrationStores,
  // v2: Attestation
  createV2Attestation, assessV2AttestationQuality, getV2AgentAttestationQualityAvg,
  clearV2AttestationStore,
} from "agent-passport-system";

import type {
  CoordinationEventType,
  PolicyContext, V2Delegation, OutcomeRecord,
  AnomalyFlag, ConcentrationMetrics, ContextualAttestation,
  MigrationRecord, ArtifactProvenance,
} from "agent-passport-system";

import type {
  SocialContractAgent, Delegation, ActionReceipt,
  TaskBrief, TaskUnit, EvidencePacket, ReviewDecision,
  CoordinationRole, AgoraFeed, AgoraRegistry, ActionIntent,
  ValuesFloor, EnforcementLevel, ExecuteResult,
  PrincipalIdentity, PrincipalEndorsement, FleetRecord,
  ScopedReputation, AuthorityTier, TierCheckContext,
  EvidencePortfolio, TierEscalation,
  GatewayConfig, ToolCallRequest, ToolExecutor,
} from "agent-passport-system";

// Data Governance (Modules 36A, 38, 39 + Enforcement Gate + Training Attribution)
import {
  registerSelfAttestedSource, recordDataAccess, checkTermsCompliance,
  buildDataAccessMerkleRoot, verifyDataAccessReceipt,
  createContributionLedger, recordContribution, queryContributions,
  getSourceMetrics, getAgentDataFootprint,
  generateSettlement, verifySettlement, generateComplianceReport,
  DataEnforcementGate,
  createTrainingAttribution, verifyTrainingAttribution,
  createTrainingLedger, recordTrainingAttribution,
  getModelDataSources, getSourceTrainingCount,
} from "agent-passport-system";

import type {
  SourceReceipt, DataAccessReceipt, DataTerms,
  ContributionLedger, ContributionRecord, SettlementRecord,
  TrainingAttributionReceipt, TrainingAttributionLedger,
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
  // Principal Identity
  principal: PrincipalIdentity | null;
  principalPrivateKey: string | null;
  endorsements: Map<string, PrincipalEndorsement>;
  fleet: FleetRecord | null;
  // Reputation-Gated Authority (Layer 9)
  reputations: Map<string, ScopedReputation>;   // key: "principalId:agentId:scope"
  promotionHistory: Array<{ review: any; appliedAt: string }>;
  // Proxy Gateway
  gateway: ProxyGateway | null;
  gatewayKeys: { publicKey: string; privateKey: string } | null;
  // Data Governance (Modules 36A, 38, 39)
  dataEnforcementGate: DataEnforcementGate | null;
  contributionLedger: ContributionLedger;
  sourceReceipts: Map<string, SourceReceipt>;
  trainingLedger: TrainingAttributionLedger;
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
  principal: null,
  principalPrivateKey: null,
  endorsements: new Map(),
  fleet: null,
  reputations: new Map(),
  promotionHistory: [],
  gateway: null,
  gatewayKeys: null,
  dataEnforcementGate: null,
  contributionLedger: createContributionLedger(),
  sourceReceipts: new Map(),
  trainingLedger: createTrainingLedger(),
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
      console.error('Failed to load task store');
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

// Sanitize agent name to prevent path traversal (R2-PX2-020)
function sanitizeAgentName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_-]/g, '');
}

// Validate that a resolved path stays within the allowed directory
function isPathWithin(filePath: string, allowedDir: string): boolean {
  return resolve(filePath).startsWith(resolve(allowedDir) + '/');
}

// Sanitize error messages before returning to clients
function safeError(prefix: string, e: unknown): string {
  if (e instanceof Error) {
    const msg = e.message.replace(/\/[^\s:]+/g, '[path]').replace(/at\s+.+/g, '').slice(0, 200);
    return `${prefix}: ${msg}`.trim();
  }
  return `${prefix}: operation failed`;
}

function getAgentName(): string {
  // Derive agent name from agentId — always sanitize to prevent path traversal
  let name = 'unknown';
  if (state.agentId) name = state.agentId.replace(/-\d+$/, '');
  else if (state.agentKey) name = state.agentKey.slice(0, 8);
  return sanitizeAgentName(name) || 'unknown';
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
    console.error('Agora feed read failed — starting with empty feed');
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
  } catch { /* file read failed */ return []; }
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
      return { content: [{ type: "text" as const, text: safeError("Error", e) }], isError: true };
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
      return { content: [{ type: "text" as const, text: safeError("Error", e) }], isError: true };
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

    // Validate delegation scopes
    if (!args.scope || args.scope.length === 0) {
      return { content: [{ type: "text" as const, text: "Delegation must include at least one scope." }], isError: true };
    }
    const SCOPE_PATTERN = /^[a-zA-Z0-9_.:/-]+$/;
    for (const s of args.scope) {
      if (s === '*' || s === '**') {
        return { content: [{ type: "text" as const, text: `Wildcard scope "${s}" not allowed. Use explicit scopes.` }], isError: true };
      }
      if (s.length > 128) {
        return { content: [{ type: "text" as const, text: `Scope exceeds max length (128 chars).` }], isError: true };
      }
      if (!SCOPE_PATTERN.test(s)) {
        return { content: [{ type: "text" as const, text: `Scope "${s}" contains invalid characters.` }], isError: true };
      }
    }

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

      // F-3 fix: pre-check revocation before attempting sub-delegation
      const parentStatus = verifyDelegation(parentDel);
      if (!parentStatus.valid) {
        return { content: [{ type: "text" as const, text: `Sub-delegation failed: Parent delegation ${args.parent_delegation_id} is invalid (${parentStatus.errors.join(', ')}).` }], isError: true };
      }

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
      return { content: [{ type: "text" as const, text: safeError("Sub-delegation failed", e) }], isError: true };
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

server.tool(
  "register_agora_public",
  "Register your agent in the PUBLIC Agora registry at aeoess.com. Creates a GitHub issue that is auto-processed by a GitHub Action in ~30 seconds. Requires GITHUB_TOKEN env var or pass token directly. After registration, your agent can post signed messages visible at aeoess.com/agora.",
  {
    token: z.string().optional().describe("GitHub personal access token (or set GITHUB_TOKEN env var)"),
    runtime: z.string().optional().describe("Agent runtime platform (e.g., 'claude', 'gpt-telegram', 'openclaw-github')"),
    capabilities: z.array(z.string()).optional().describe("Agent capabilities"),
    owner: z.string().optional().describe("Who operates this agent"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }] };

    const agentId = state.agentId || 'unknown';
    const agentName = getAgentName();
    const publicKey = state.agentKey || '';

    if (!publicKey) {
      return { content: [{ type: "text" as const, text: "❌ No public key. Run identify or generate_keys first." }] };
    }

    const token = args.token || process.env.GITHUB_TOKEN;
    if (!token) {
      const regJSON = JSON.stringify({
        agentId, agentName, publicKey,
        owner: args.owner || '', runtime: args.runtime || '',
        capabilities: args.capabilities || [], role: 'member'
      }, null, 2);

      const title = encodeURIComponent(`Agora Register: ${agentName}`);
      const body = encodeURIComponent(`Register agent via MCP.\n\n\`\`\`json\n${regJSON}\n\`\`\`\n`);
      const url = `https://github.com/aeoess/aeoess_web/issues/new?title=${title}&body=${body}&labels=agora-register`;

      return { content: [{ type: "text" as const, text: `No GITHUB_TOKEN found. Open this URL to register manually:\n\n${url}` }] };
    }

    const registrationJSON = {
      agentId, agentName, publicKey,
      owner: args.owner || '', runtime: args.runtime || '',
      capabilities: args.capabilities || [], role: 'member'
    };

    const issueTitle = `Agora Register: ${agentName}`;
    const issueBody = `Register agent via MCP (agent-passport-system-mcp).\n\n\`\`\`json\n${JSON.stringify(registrationJSON, null, 2)}\n\`\`\`\n`;

    try {
      const response = await fetch('https://api.github.com/repos/aeoess/aeoess_web/issues', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/vnd.github+json',
          'Content-Type': 'application/json',
          'X-GitHub-Api-Version': '2022-11-28',
          'User-Agent': 'agent-passport-mcp'
        },
        body: JSON.stringify({
          title: issueTitle,
          body: issueBody,
          labels: ['agora-register']
        })
      });

      if (!response.ok) {
        const err = await response.text();
        return { content: [{ type: "text" as const, text: `❌ GitHub API error (${response.status}): ${err.slice(0, 300)}\nCheck your token has "repo" or "public_repo" scope.` }] };
      }

      const issue = await response.json() as { html_url: string; number: number };
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            registered: true,
            agentId,
            publicKey: publicKey.slice(0, 16) + '...',
            issueUrl: issue.html_url,
            issueNumber: issue.number,
            note: 'GitHub Action will process this in ~30 seconds. Check aeoess.com/agora after.'
          }, null, 2),
        }],
      };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("Failed to create issue", e) }] };
    }
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

    const safeTo = sanitizeAgentName(args.to);
    if (!safeTo) return { content: [{ type: "text" as const, text: "Invalid recipient name" }] };

    const fromName = getAgentName();
    const toFile = join(COMMS_PATH, `to-${safeTo}.json`);
    const fromFile = join(COMMS_PATH, `from-${fromName}.json`);

    if (!isPathWithin(toFile, COMMS_PATH) || !isPathWithin(fromFile, COMMS_PATH)) {
      return { content: [{ type: "text" as const, text: "Invalid path — recipient name rejected" }] };
    }

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
    if (!isPathWithin(filePath, COMMS_PATH)) {
      return { content: [{ type: "text" as const, text: "Invalid agent name — path rejected" }] };
    }
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
      return { content: [{ type: "text" as const, text: safeError("Failed to load floor", e) }], isError: true };
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
      return { content: [{ type: "text" as const, text: safeError("Policy evaluation failed", e) }], isError: true };
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

    // F-1 fix: look up actual delegation from session state for real scope/spend
    const sessionDel = state.delegations.get(args.delegation_id);
    const actualSpendLimit = sessionDel?.spendLimit ?? 1000;
    const hasCommerceScope = sessionDel
      ? sessionDel.scope.some((s: string) => s === 'commerce' || s === 'commerce:checkout' || s.startsWith('commerce'))
      : (state.agentContext ? true : false); // fallback to context if no delegation found

    // Create a passport for preflight (uses session agent)
    const agent = joinSocialContract({
      name: args.agent_id,
      mission: 'Commerce operation',
      owner: 'mcp-session',
      capabilities: hasCommerceScope ? ['commerce:checkout', 'commerce:browse'] : [],
      platform: 'node',
      models: ['mcp'],
    });

    // Look up or create commerce delegation using actual scope/spend
    const commerceDel = createCommerceDelegation({
      agentId: args.agent_id,
      delegationId: args.delegation_id,
      spendLimit: actualSpendLimit,
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

      // F-4 fix: also register in state.agents so gateway and other tools can find this agent
      state.agents.set(agent.agentId, agent as any);

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
      return { content: [{ type: "text" as const, text: safeError("Failed to create context", e) }], isError: true };
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
      return { content: [{ type: "text" as const, text: safeError("Execute failed", e) }], isError: true };
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
      return { content: [{ type: "text" as const, text: safeError("Complete failed", e) }], isError: true };
    }
  }
);

// ═══════════════════════════════════════
// PRINCIPAL IDENTITY TOOLS
// ═══════════════════════════════════════

server.tool(
  "create_principal",
  "Create a principal identity (human or org behind agents). Gets its own Ed25519 keypair.",
  {
    display_name: z.string().describe("Human-readable name (e.g. 'Tima', 'Acme Corp')"),
    domain: z.string().optional().describe("Verifiable domain (e.g. 'aeoess.com')"),
    jurisdiction: z.string().optional().describe("Legal jurisdiction (e.g. 'US', 'EU')"),
    contact_channel: z.string().optional().describe("Contact method (e.g. 'telegram:@aeoess')"),
    disclosure_level: z.enum(["public", "verified-only", "minimal"]).default("public").describe("How much identity to reveal"),
  },
  async (args) => {
    const { principal, keyPair } = createPrincipalIdentity({
      displayName: args.display_name,
      domain: args.domain,
      jurisdiction: args.jurisdiction,
      contactChannel: args.contact_channel,
      disclosureLevel: args.disclosure_level,
    });

    state.principal = principal;
    state.principalPrivateKey = keyPair.privateKey;
    state.fleet = createFleet(principal);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          principalId: principal.principalId,
          displayName: principal.displayName,
          publicKey: principal.publicKey.slice(0, 16) + '...',
          privateKey: keyPair.privateKey.slice(0, 16) + '... (store securely)',
          domain: principal.domain,
          disclosureLevel: principal.disclosureLevel,
          note: 'Principal created. Use endorse_agent to sign off on agents.',
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "endorse_agent",
  "Endorse an agent as a principal. Creates a cryptographic chain: principal → agent.",
  {
    agent_id: z.string().describe("Agent ID to endorse"),
    agent_public_key: z.string().describe("Agent's Ed25519 public key"),
    scope: z.array(z.string()).describe("What the agent can do on principal's behalf"),
    relationship: z.enum(["creator", "operator", "employer", "sponsor"]).describe("How principal relates to agent"),
    expires_in_days: z.number().default(365).describe("Days until endorsement expires"),
  },
  async (args) => {
    if (!state.principal || !state.principalPrivateKey) {
      return { content: [{ type: "text" as const, text: 'No principal identity. Call create_principal first.' }], isError: true };
    }

    const endorsement = endorseAgent({
      principal: state.principal,
      principalPrivateKey: state.principalPrivateKey,
      agentId: args.agent_id,
      agentPublicKey: args.agent_public_key,
      scope: args.scope,
      relationship: args.relationship,
      expiresInDays: args.expires_in_days,
    });

    state.endorsements.set(endorsement.endorsementId, endorsement);
    if (state.fleet) {
      state.fleet = addToFleet(state.fleet, endorsement);
    }

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          endorsementId: endorsement.endorsementId,
          principalId: endorsement.principalId,
          agentId: endorsement.agentId,
          relationship: endorsement.relationship,
          scope: endorsement.scope,
          expiresAt: endorsement.expiresAt,
          note: 'Agent endorsed. The endorsement signature can be embedded in the agent\'s passport via endorse_passport.',
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "verify_endorsement",
  "Verify a principal's endorsement of an agent. Checks cryptographic signature.",
  {
    endorsement_id: z.string().describe("Endorsement ID to verify"),
  },
  async (args) => {
    const endorsement = state.endorsements.get(args.endorsement_id);
    if (!endorsement) {
      return { content: [{ type: "text" as const, text: `Endorsement ${args.endorsement_id} not found in session.` }], isError: true };
    }

    const result = verifyEndorsement(endorsement);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          valid: result.valid,
          expired: result.expired,
          revoked: result.revoked,
          principalId: result.principalId,
          agentId: result.agentId,
          errors: result.errors,
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "revoke_endorsement",
  "Revoke a principal's endorsement of an agent. 'I no longer authorize this agent.'",
  {
    endorsement_id: z.string().describe("Endorsement ID to revoke"),
    reason: z.string().describe("Why the endorsement is being revoked"),
  },
  async (args) => {
    const endorsement = state.endorsements.get(args.endorsement_id);
    if (!endorsement) {
      return { content: [{ type: "text" as const, text: `Endorsement ${args.endorsement_id} not found.` }], isError: true };
    }

    const revoked = revokeEndorsement(endorsement, args.reason);
    state.endorsements.set(args.endorsement_id, revoked);

    if (state.fleet) {
      state.fleet = revokeFromFleet(state.fleet, revoked.agentId);
    }

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          revoked: true,
          endorsementId: revoked.endorsementId,
          agentId: revoked.agentId,
          reason: revoked.revokedReason,
          revokedAt: revoked.revokedAt,
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "create_disclosure",
  "Create a selective disclosure of principal identity. Controls how much info is revealed.",
  {
    level: z.enum(["public", "verified-only", "minimal"]).describe("Disclosure level: public (everything), verified-only (id+key+domain), minimal (hash+DID only)"),
  },
  async (args) => {
    if (!state.principal || !state.principalPrivateKey) {
      return { content: [{ type: "text" as const, text: 'No principal identity. Call create_principal first.' }], isError: true };
    }

    const disclosure = createDisclosure(state.principal, state.principalPrivateKey, args.level);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          disclosureId: disclosure.disclosureId,
          level: disclosure.level,
          revealedFields: disclosure.revealedFields,
          proof: disclosure.proof.slice(0, 16) + '...',
          note: 'Share this disclosure with other agents. They can verify it with verify_disclosure.',
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "get_fleet_status",
  "Get status of all agents endorsed by the current principal.",
  {},
  async () => {
    if (!state.fleet) {
      return { content: [{ type: "text" as const, text: 'No fleet. Call create_principal first.' }], isError: true };
    }

    const status = getFleetStatus(state.fleet);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify(status, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════
// Reputation-Gated Authority (Layer 9)
// ═══════════════════════════════════════

/** Helper: resolve tier and build full AuthorityTier from TierDefinition */
function resolveTier(score: number, demotionCount: number = 0): AuthorityTier {
  const def = resolveAuthorityTier(score, demotionCount, DEFAULT_TIERS);
  return { ...def, origin: 'earned' as const, demotionCount };
}

server.tool(
  "resolve_authority",
  "Compute effective reputation score and authority tier for an agent in a given scope. Returns tier name, autonomy level, spend limit, and effective score.",
  {
    agentId: z.string().describe("Agent ID to check"),
    principalId: z.string().describe("Principal who delegated authority"),
    scope: z.string().describe("Scope to check reputation in (e.g. 'code_execution', 'commerce')"),
  },
  async ({ agentId, principalId, scope }) => {
    const key = `${principalId}:${agentId}:${scope}`;
    let rep = state.reputations.get(key);

    if (!rep) {
      rep = createScopedReputation(principalId, agentId, scope);
      state.reputations.set(key, rep);
    }

    const effectiveScore = computeEffectiveScore(rep.mu, rep.sigma);
    const tier = resolveTier(effectiveScore);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          agentId, principalId, scope,
          mu: rep.mu, sigma: rep.sigma,
          effectiveScore,
          tier: { name: tier.name, level: tier.tier, origin: tier.origin },
          autonomyLevel: tier.autonomyLevel,
          maxSpend: tier.maxSpendPerAction,
          maxDelegationDepth: tier.maxDelegationDepth,
          receiptCount: rep.receiptCount,
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "check_tier",
  "Check if an agent's earned tier permits an action at a given autonomy level and spend amount. Returns null if permitted, or escalation details if tier is insufficient.",
  {
    agentId: z.string().describe("Agent ID"),
    principalId: z.string().describe("Principal ID"),
    scope: z.string().describe("Reputation scope"),
    requestedAutonomy: z.number().optional().describe("Requested autonomy level (1-5)"),
    requestedSpend: z.number().optional().describe("Requested spend amount in dollars"),
    requestedDepth: z.number().optional().describe("Requested delegation depth"),
  },
  async ({ agentId, principalId, scope, requestedAutonomy, requestedSpend, requestedDepth }) => {
    const key = `${principalId}:${agentId}:${scope}`;
    let rep = state.reputations.get(key);

    if (!rep) {
      rep = createScopedReputation(principalId, agentId, scope);
      state.reputations.set(key, rep);
    }

    const effectiveScore = computeEffectiveScore(rep.mu, rep.sigma);
    const tier = resolveTier(effectiveScore);
    const ctx: TierCheckContext = { agentTier: tier, effectiveScore };

    const escalation = checkTierForIntent({
      tierContext: ctx,
      requestedAutonomy: requestedAutonomy as any,
      requestedSpend,
      requestedDepth,
    });

    // Also get advisory warnings
    const warnings = advisoryTierPrecheck({
      tierContext: ctx,
      requestedAutonomy: requestedAutonomy as any,
      requestedSpend,
    });

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          permitted: escalation === null,
          currentTier: tier.name,
          effectiveScore,
          escalation,
          warnings,
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "review_promotion",
  "Create a signed promotion review for another agent. Reviewer must have 'earned' origin and tier above target. Returns signed review artifact.",
  {
    agentId: z.string().describe("Agent being reviewed for promotion"),
    principalId: z.string().describe("Principal who delegated to the agent"),
    scope: z.string().describe("Scope of the promotion"),
    toTier: z.number().describe("Target tier level (0-4)"),
    verdict: z.enum(['promoted', 'denied']).describe("Promotion verdict"),
    reasoning: z.string().describe("Explanation for the verdict"),
    probationDays: z.number().optional().describe("Probation period in days (default: 7)"),
  },
  async ({ agentId, principalId, scope, toTier, verdict, reasoning, probationDays }) => {
    if (!state.privateKey || !state.agentId) {
      return { content: [{ type: "text" as const, text: 'Identity required. Call identify or set AGENT_KEY first.' }], isError: true };
    }

    // Get target agent's current reputation
    const key = `${principalId}:${agentId}:${scope}`;
    let rep = state.reputations.get(key);
    if (!rep) {
      rep = createScopedReputation(principalId, agentId, scope);
      state.reputations.set(key, rep);
    }

    const effectiveScore = computeEffectiveScore(rep.mu, rep.sigma);
    const currentTier = resolveTier(effectiveScore);

    // Get reviewer's tier (from their own reputation in same scope)
    const reviewerKey = `${principalId}:${state.agentId}:${scope}`;
    let reviewerRep = state.reputations.get(reviewerKey);
    if (!reviewerRep) {
      reviewerRep = createScopedReputation(principalId, state.agentId!, scope);
      state.reputations.set(reviewerKey, reviewerRep);
    }
    const reviewerScore = computeEffectiveScore(reviewerRep.mu, reviewerRep.sigma);
    const reviewerTier = resolveTier(reviewerScore);

    // Build evidence portfolio from receipt count (simplified — real impl would aggregate from task history)
    const evidence: EvidencePortfolio = {
      scope,
      totalReceipts: rep.receiptCount,
      classCounts: { trivial: 0, standard: rep.receiptCount, complex: 0, critical: 0 },
      distinctReviewers: 1,
      distinctTaskTypes: 1,
      failureRate: 0,
      interventionRate: 0,
    };

    try {
      const review = createPromotionReview({
        agentId, principalId, scope,
        fromTier: currentTier.tier,
        toTier,
        reviewerId: state.agentId!,
        reviewerTier: reviewerTier.tier,
        reviewerOrigin: reviewerTier.origin,
        evidence,
        effectiveScore,
        verdict,
        reasoning,
        reviewerPrivateKey: state.privateKey,
        probationDays,
      });

      state.promotionHistory.push({ review, appliedAt: new Date().toISOString() });

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify(review, null, 2),
        }],
      };
    } catch (err: any) {
      return { content: [{ type: "text" as const, text: safeError("Promotion review failed", err) }], isError: true };
    }
  }
);

server.tool(
  "update_reputation",
  "Update an agent's reputation after a task result. Success increases mu and decreases sigma; failure does the opposite. Higher evidence class = larger effect.",
  {
    agentId: z.string().describe("Agent whose reputation to update"),
    principalId: z.string().describe("Principal ID"),
    scope: z.string().describe("Reputation scope"),
    success: z.boolean().describe("Whether the task succeeded"),
    evidenceClass: z.enum(['trivial', 'standard', 'complex', 'critical']).describe("Complexity of the task"),
  },
  async ({ agentId, principalId, scope, success, evidenceClass }) => {
    const key = `${principalId}:${agentId}:${scope}`;
    let rep = state.reputations.get(key);

    if (!rep) {
      rep = createScopedReputation(principalId, agentId, scope);
    }

    const updated = updateReputationFromResult(rep, success, evidenceClass as any);
    state.reputations.set(key, updated);

    const effectiveScore = computeEffectiveScore(updated.mu, updated.sigma);
    const tier = resolveTier(effectiveScore);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          agentId, scope,
          mu: updated.mu, sigma: updated.sigma,
          effectiveScore,
          tier: tier.name,
          receiptCount: updated.receiptCount,
          result: success ? 'success' : 'failure',
          evidenceClass,
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "get_promotion_history",
  "Get the promotion review history for this session.",
  {},
  async () => {
    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          count: state.promotionHistory.length,
          reviews: state.promotionHistory,
        }, null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════
// Proxy Gateway (Enforcement Boundary)
// ═══════════════════════════════════════

server.tool(
  "create_gateway",
  "Create a ProxyGateway enforcement boundary. The gateway validates identity, delegation scope, policy compliance, and provides replay protection for every tool call. Returns gateway ID and public key.",
  {
    gatewayId: z.string().optional().describe("Custom gateway ID (auto-generated if omitted)"),
    approvalTTLSeconds: z.number().optional().describe("Two-phase approval timeout in seconds (default: 300)"),
    maxPendingPerAgent: z.number().optional().describe("Max pending approvals per agent (default: 10)"),
  },
  async ({ gatewayId, approvalTTLSeconds, maxPendingPerAgent }) => {
    const keys = generateKeyPair();
    const id = gatewayId || `gateway-${Date.now().toString(36)}`;

    if (!state.floor) {
      return { content: [{ type: "text" as const, text: "Error: Load a Values Floor first (load_values_floor)" }] };
    }

    const config: GatewayConfig = {
      gatewayId: id,
      gatewayPublicKey: keys.publicKey,
      gatewayPrivateKey: keys.privateKey,
      floor: state.floor,
      approvalTTLSeconds: approvalTTLSeconds ?? 300,
      maxPendingPerAgent: maxPendingPerAgent ?? 10,
      recheckRevocationOnExecute: true,
    };

    // Default executor echoes tool calls — real execution is done by MCP client
    const executor: ToolExecutor = async (tool: string, params: Record<string, unknown>) => {
      return { success: true, result: { tool, params, executedVia: 'mcp-gateway' } };
    };

    state.gateway = createProxyGateway(config, executor);
    state.gatewayKeys = keys;

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          created: true,
          gatewayId: id,
          publicKey: keys.publicKey,
          approvalTTLSeconds: config.approvalTTLSeconds,
          maxPendingPerAgent: config.maxPendingPerAgent,
          note: "Gateway ready. Register agents with register_gateway_agent, then process calls with gateway_process_tool_call.",
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "register_gateway_agent",
  "Register an agent with the gateway. The agent must have a valid passport and floor attestation. Delegations define what scopes the agent can use through the gateway.",
  {
    agentId: z.string().describe("Agent ID to register"),
  },
  async ({ agentId }) => {
    if (!state.gateway) {
      return { content: [{ type: "text" as const, text: "Error: Create gateway first (create_gateway)" }] };
    }
    // F-4 fix: check both state.agents AND state.agentContext for agent data
    let agent = state.agents.get(agentId);
    if (!agent && state.agentContext && state.agentId === agentId) {
      // Agent was created via create_agent_context, bridge to gateway
      const ctx = state.agentContext;
      agent = {
        passport: (ctx as any).agent?.passport || (ctx as any).passport,
        publicKey: state.agentKey!,
        agentId: state.agentId!,
        attestation: (ctx as any).agent?.attestation || (ctx as any).attestation,
      } as any;
    }
    if (!agent) {
      return { content: [{ type: "text" as const, text: `Error: Agent "${agentId}" not found in session. Join social contract or create_agent_context first.` }] };
    }

    const agentDelegations = Array.from(state.delegations.values()).filter(
      d => d.delegatedTo === agent.publicKey
    );

    if (agentDelegations.length === 0) {
      return { content: [{ type: "text" as const, text: `Error: No delegations found for agent "${agentId}". Create a delegation first.` }] };
    }

    if (!agent.attestation) {
      return { content: [{ type: "text" as const, text: `Error: Agent "${agentId}" has no floor attestation. Attest to floor first.` }] };
    }

    state.gateway.registerAgent(agent.passport, agent.attestation, agentDelegations);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          registered: true,
          agentId,
          delegationCount: agentDelegations.length,
          scopes: agentDelegations.flatMap(d => d.scope),
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "gateway_process_tool_call",
  "Process a tool call through the gateway enforcement boundary. Validates identity, delegation, policy, and replay protection in a single atomic operation. Returns execution result with full 3-signature proof chain.",
  {
    agentId: z.string().describe("ID of the requesting agent"),
    tool: z.string().describe("Tool name to execute"),
    params: z.record(z.unknown()).optional().describe("Tool parameters"),
    scopeRequired: z.string().describe("Delegation scope needed for this tool"),
    spendAmount: z.number().optional().describe("Spend amount if commerce action"),
    spendCurrency: z.string().optional().describe("Currency code (e.g. USD)"),
    context: z.string().optional().describe("Human-readable context for audit"),
  },
  async ({ agentId, tool, params, scopeRequired, spendAmount, spendCurrency, context }) => {
    if (!state.gateway) {
      return { content: [{ type: "text" as const, text: "Error: Create gateway first (create_gateway)" }] };
    }

    const agent = state.agents.get(agentId);
    if (!agent) {
      return { content: [{ type: "text" as const, text: `Error: Agent "${agentId}" not found in session.` }] };
    }

    const { canonicalize } = await import("agent-passport-system");
    const requestId = `mcp-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const payload = canonicalize({ requestId, agentId, tool, params: params || {}, scopeRequired, spend: spendAmount ? { amount: spendAmount, currency: spendCurrency || 'USD' } : undefined });

    const request: ToolCallRequest = {
      requestId,
      agentId,
      agentPublicKey: agent.publicKey,
      signature: sign(payload, agent.keyPair.privateKey),
      tool,
      params: params || {},
      scopeRequired,
      spend: spendAmount ? { amount: spendAmount, currency: spendCurrency || 'USD' } : undefined,
      context,
    };

    const result = await state.gateway.processToolCall(request);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          executed: result.executed,
          requestId: result.requestId,
          result: result.result ?? undefined,
          denialReason: result.denialReason ?? undefined,
          toolError: result.toolError ?? undefined,
          ...(result.decision && { verdict: result.decision.verdict, reason: result.decision.reason }),
          ...(result.proof && {
            proof: {
              hasRequestSignature: !!result.proof.requestSignature,
              hasDecisionSignature: !!result.proof.decisionSignature,
              hasReceiptSignature: !!result.proof.receiptSignature,
              policyReceiptId: result.proof.policyReceipt?.policyReceiptId,
            },
          }),
          ...(result.receipt && {
            receipt: {
              receiptId: result.receipt.receiptId,
              agentId: result.receipt.agentId,
              action: result.receipt.action,
            },
          }),
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "gateway_approve",
  "Two-phase execution: approve a tool call without executing it. Returns an approval ID that can be executed later with gateway_execute_approval. Useful for human-in-the-loop workflows.",
  {
    agentId: z.string().describe("ID of the requesting agent"),
    tool: z.string().describe("Tool name to approve"),
    params: z.record(z.unknown()).optional().describe("Tool parameters"),
    scopeRequired: z.string().describe("Delegation scope needed"),
    context: z.string().optional().describe("Human-readable context"),
  },
  async ({ agentId, tool, params, scopeRequired, context }) => {
    if (!state.gateway) {
      return { content: [{ type: "text" as const, text: "Error: Create gateway first (create_gateway)" }] };
    }

    const agent = state.agents.get(agentId);
    if (!agent) {
      return { content: [{ type: "text" as const, text: `Error: Agent "${agentId}" not found in session.` }] };
    }

    const { canonicalize } = await import("agent-passport-system");
    const requestId = `mcp-approve-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const payload = canonicalize({ requestId, agentId, tool, params: params || {}, scopeRequired, spend: undefined });

    const request: ToolCallRequest = {
      requestId,
      agentId,
      agentPublicKey: agent.publicKey,
      signature: sign(payload, agent.keyPair.privateKey),
      tool,
      params: params || {},
      scopeRequired,
      context,
    };

    const result = state.gateway.approve(request);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          approved: result.approved,
          ...(result.approval && {
            approvalId: result.approval.approvalId,
            expiresAt: result.approval.expiresAt,
            nonce: result.approval.nonce,
          }),
          ...(result.denial && { denial: result.denial }),
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "gateway_execute_approval",
  "Execute a previously approved tool call. Rechecks delegation validity before execution — if delegation was revoked since approval, execution is denied.",
  {
    approvalId: z.string().describe("Approval ID from gateway_approve"),
  },
  async ({ approvalId }) => {
    if (!state.gateway) {
      return { content: [{ type: "text" as const, text: "Error: Create gateway first (create_gateway)" }] };
    }

    const result = await state.gateway.executeApproval(approvalId);

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify({
          executed: result.executed,
          requestId: result.requestId,
          result: result.result ?? undefined,
          denialReason: result.denialReason ?? undefined,
          ...(result.proof && {
            proof: {
              policyReceiptId: result.proof.policyReceipt?.policyReceiptId,
            },
          }),
        }, null, 2),
      }],
    };
  }
);

server.tool(
  "gateway_stats",
  "Get gateway statistics: total requests, permits, denials, replay attempts blocked, active agents, and pending approvals.",
  {},
  async () => {
    if (!state.gateway) {
      return { content: [{ type: "text" as const, text: "Error: Create gateway first (create_gateway)" }] };
    }

    return {
      content: [{
        type: "text" as const,
        text: JSON.stringify(state.gateway.getStats(), null, 2),
      }],
    };
  }
);

// ═══════════════════════════════════════
// Intent Network (Agent-Mediated Matching)
// Calls the hosted API at api.aeoess.com
// ═══════════════════════════════════════

const INTENT_API = process.env.INTENT_API_URL || 'https://api.aeoess.com';

async function intentApiFetch(path: string, opts?: RequestInit): Promise<any> {
  const res = await fetch(`${INTENT_API}${path}`, {
    ...opts,
    headers: { 'Content-Type': 'application/json', 'X-Agent-Id': state.agentId || '', 'X-Public-Key': state.agentKey || '', ...opts?.headers },
  });
  return res.json();
}

server.tool(
  "publish_intent_card",
  "Publish an IntentCard to the Intent Network at aeoess.com. Your card is visible to all agents on the network. Cards are Ed25519 signed, scoped, and expire automatically.",
  {
    principal_alias: z.string().describe("Human's display name or alias"),
    needs: z.array(z.object({
      category: z.string().describe("Category (e.g. 'engineering', 'design', 'funding')"),
      description: z.string().describe("What is needed"),
      priority: z.enum(["critical", "high", "medium", "low"]).default("medium"),
      tags: z.array(z.string()).optional(),
      budget_amount: z.number().optional(),
      budget_currency: z.string().optional(),
    })).optional().describe("What the human needs"),
    offers: z.array(z.object({
      category: z.string().describe("Category of what's offered"),
      description: z.string().describe("What is offered"),
      priority: z.enum(["critical", "high", "medium", "low"]).default("medium"),
      tags: z.array(z.string()).optional(),
      budget_amount: z.number().optional(),
      budget_currency: z.string().optional(),
    })).optional().describe("What the human offers"),
    open_to: z.array(z.string()).optional().describe("Categories open to (e.g. ['introductions', 'partnerships'])"),
    not_open_to: z.array(z.string()).optional().describe("Categories explicitly not open to"),
    approval_required: z.array(z.string()).optional().describe("What needs human approval before sharing"),
    visibility: z.enum(["public", "verified", "minimal"]).default("public"),
    ttl_hours: z.number().default(24).describe("Hours until card expires"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    const mapItem = (item: any) => ({
      category: item.category,
      description: item.description,
      priority: item.priority || 'medium',
      tags: item.tags || [],
      budget: item.budget_amount ? { amount: item.budget_amount, currency: item.budget_currency || 'USD' } : undefined,
      visibility: 'public' as const,
    });

    const card = createIntentCard({
      agentId: state.agentId || 'anonymous',
      principalAlias: args.principal_alias,
      publicKey: state.agentKey!,
      privateKey: state.privateKey!,
      needs: (args.needs || []).map(mapItem),
      offers: (args.offers || []).map(mapItem),
      openTo: args.open_to || [],
      notOpenTo: args.not_open_to || [],
      approvalRequired: args.approval_required || [],
      ttlSeconds: (args.ttl_hours || 24) * 3600,
    });

    try {
      const result = await intentApiFetch('/api/cards', {
        method: 'POST',
        body: JSON.stringify({ ...card, publicKey: state.agentKey, signature: card.signature }),
      });

      if (result.error) {
        return { content: [{ type: "text" as const, text: `Failed to publish: ${result.error}` }], isError: true };
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            published: true,
            cardId: result.cardId,
            agentId: card.agentId,
            principalAlias: card.principalAlias,
            needs: card.needs.length,
            offers: card.offers.length,
            expiresAt: result.expiresAt,
            networkSize: result.networkSize,
            note: 'Card published to Intent Network (api.aeoess.com). Other agents worldwide can now discover matches.',
          }, null, 2),
        }],
      };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("API error", e) }], isError: true };
    }
  }
);

server.tool(
  "search_matches",
  "Search the Intent Network for people relevant to you. Returns ranked matches from all agents worldwide based on need/offer overlap, tag similarity, and budget compatibility.",
  {
    min_score: z.number().optional().describe("Minimum relevance score 0-1 (default: 0.1)"),
    max_results: z.number().optional().describe("Maximum results to return (default: 10)"),
    category_filter: z.string().optional().describe("Only match within this category"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    const agentId = state.agentId || 'anonymous';
    try {
      const params = new URLSearchParams();
      if (args.min_score) params.set('minScore', String(args.min_score));
      if (args.max_results) params.set('max', String(args.max_results));
      const result = await intentApiFetch(`/api/matches/${agentId}?${params}`);

      if (result.error) {
        return { content: [{ type: "text" as const, text: result.error }], isError: true };
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            matchCount: result.matchCount,
            totalCandidates: result.totalCandidates,
            matches: (result.matches || []).map((m: any) => ({
              matchId: m.matchId,
              otherAgent: m.agentA === agentId ? m.agentB : m.agentA,
              score: m.score,
              mutual: m.mutual,
              explanation: m.explanation,
              needOfferMatches: (m.needOfferMatches || []).map((nom: any) => ({
                needCategory: nom.need?.category,
                offerCategory: nom.offer?.category,
                matchType: nom.matchType,
              })),
            })),
          }, null, 2),
        }],
      };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("API error", e) }], isError: true };
    }
  }
);

server.tool(
  "get_digest",
  "Get a personalized digest from the Intent Network: relevant matches, pending intro requests, and incoming intros. The killer feature — 'what matters to me right now?'",
  {},
  async () => {
    const agentId = state.agentId || 'anonymous';
    try {
      const digest = await intentApiFetch(`/api/digest/${agentId}`);

      if (digest.error) {
        return { content: [{ type: "text" as const, text: digest.error }], isError: true };
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            agentId: digest.agentId,
            generatedAt: digest.generatedAt,
            summary: digest.summary,
            hasCard: digest.hasCard,
            networkSize: digest.networkSize,
            matchCount: (digest.matches || []).length,
            topMatches: (digest.matches || []).slice(0, 5).map((m: any) => ({
              otherAgent: m.agentA === agentId ? m.agentB : m.agentA,
              score: m.score,
              explanation: m.explanation,
            })),
            introsPending: (digest.introsPending || []).length,
            introsReceived: (digest.introsReceived || []).length,
            introsReceivedDetail: (digest.introsReceived || []).map((intro: any) => ({
              introId: intro.introId,
              fromAgent: intro.requestedBy,
              message: intro.message,
              status: intro.status,
            })),
            note: !digest.hasCard ? 'No card published yet. Use publish_intent_card to join the network.' : undefined,
          }, null, 2),
        }],
      };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("API error", e) }], isError: true };
    }
  }
);

server.tool(
  "request_intro",
  "Request an introduction to another agent's human based on a match. Both sides must approve before real information crosses.",
  {
    match_id: z.string().describe("Match ID from search_matches"),
    target_card_id: z.string().describe("Card ID of the agent you want an intro to"),
    message: z.string().describe("Brief message explaining why this intro would be valuable"),
    disclose_fields: z.array(z.string()).optional().describe("Fields you're willing to share (e.g. ['needs', 'offers', 'openTo'])"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    try {
      const result = await intentApiFetch('/api/intros', {
        method: 'POST',
        body: JSON.stringify({
          matchId: args.match_id,
          targetAgentId: args.target_card_id,
          message: args.message,
          fieldsToDisclose: args.disclose_fields || ['needs', 'offers'],
          agentId: state.agentId,
          publicKey: state.agentKey,
          signature: state.privateKey ? sign(args.match_id + args.message, state.privateKey) : '',
        }),
      });

      if (result.error) {
        return { content: [{ type: "text" as const, text: `Intro request failed: ${result.error}` }], isError: true };
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            introId: result.introId,
            status: result.status,
            targetAgent: result.targetAgentId,
            note: 'Intro request sent via Intent Network. The other agent\'s human will see this in their digest.',
          }, null, 2),
        }],
      };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("Intro request failed", e) }], isError: true };
    }
  }
);

server.tool(
  "respond_to_intro",
  "Respond to an introduction request. Approve to share your disclosed information, or decline.",
  {
    intro_id: z.string().describe("Intro request ID"),
    approved: z.boolean().describe("Whether to approve the introduction"),
    message: z.string().optional().describe("Optional response message"),
    disclose_fields: z.array(z.string()).optional().describe("Fields you're willing to share back"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    try {
      const result = await intentApiFetch(`/api/intros/${args.intro_id}`, {
        method: 'PUT',
        body: JSON.stringify({
          verdict: args.approved ? 'approve' : 'decline',
          message: args.message,
          disclosedFields: args.disclose_fields ? Object.fromEntries(args.disclose_fields.map(f => [f, 'disclosed'])) : undefined,
          agentId: state.agentId,
          publicKey: state.agentKey,
          signature: state.privateKey ? sign(args.intro_id + (args.approved ? 'approve' : 'decline'), state.privateKey) : '',
        }),
      });

      if (result.error) {
        return { content: [{ type: "text" as const, text: `Intro response failed: ${result.error}` }], isError: true };
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            introId: result.introId,
            status: result.status,
            approved: args.approved,
            note: args.approved
              ? 'Introduction approved. Both parties can now see disclosed information.'
              : 'Introduction declined.',
          }, null, 2),
        }],
      };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("Intro response failed", e) }], isError: true };
    }
  }
);

server.tool(
  "remove_intent_card",
  "Remove your IntentCard from the Intent Network. Use when your needs or offers have changed.",
  {
    card_id: z.string().describe("Card ID to remove"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };

    try {
      const result = await intentApiFetch(`/api/cards/${args.card_id}`, {
        method: 'DELETE',
        body: JSON.stringify({
          agentId: state.agentId,
          publicKey: state.agentKey,
          signature: state.privateKey ? sign(args.card_id, state.privateKey) : '',
        }),
      });

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            removed: result.removed || false,
            cardId: args.card_id,
            error: result.error,
          }, null, 2),
        }],
      };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("API error", e) }], isError: true };
    }
  }
);

// ═══════════════════════════════════════
// v2: Constitutional Governance Tools
// ═══════════════════════════════════════

server.tool(
  "create_policy_context",
  "Create a v2 PolicyContext with mandatory sunset. Every v2 object requires one.",
  {
    policy_version: z.string().default("2.0.0"),
    values_floor_version: z.string().default("1.0.0"),
    trust_epoch: z.number().default(1),
    valid_until: z.string().describe("ISO 8601 expiration (mandatory, max 180 days)"),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };
    try {
      const ctx = createPolicyContext({
        policy_version: args.policy_version,
        values_floor_version: args.values_floor_version,
        trust_epoch: args.trust_epoch,
        issuer_id: state.agentKey!,
        valid_until: args.valid_until,
      });
      return { content: [{ type: "text" as const, text: JSON.stringify(ctx, null, 2) }] };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("PolicyContext creation failed", e) }], isError: true };
    }
  }
);

server.tool(
  "create_v2_delegation",
  "Create a v2 delegation with versioning, mandatory sunset, and PolicyContext binding.",
  {
    delegatee: z.string().describe("Public key of the agent receiving authority"),
    scope_categories: z.array(z.string()).describe("Action categories (e.g., ['analysis', 'communication'])"),
    valid_until: z.string().describe("ISO 8601 expiration"),
    trust_epoch: z.number().default(1),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };
    try {
      const ctx = createPolicyContext({
        policy_version: "2.0.0", values_floor_version: "1.0.0",
        trust_epoch: args.trust_epoch, issuer_id: state.agentKey!,
        valid_until: args.valid_until,
      });
      const del = createV2Delegation({
        delegator: state.agentKey!, delegatee: args.delegatee,
        scope: { action_categories: args.scope_categories },
        policy_context: ctx, delegator_private_key: state.privateKey!,
      });
      return { content: [{ type: "text" as const, text: JSON.stringify(del, null, 2) }] };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("v2 delegation failed", e) }], isError: true };
    }
  }
);

server.tool(
  "supersede_v2_delegation",
  "Supersede a v2 delegation. Scope narrowing needs justification. Scope expansion also needs independent reviewer.",
  {
    original_delegation_id: z.string(),
    new_scope_categories: z.array(z.string()),
    justification: z.string(),
    valid_until: z.string(),
    trust_epoch: z.number().default(1),
    expansion_reviewer: z.string().optional().describe("Required if scope expands"),
    expansion_reviewer_private_key: z.string().optional(),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };
    try {
      const ctx = createPolicyContext({
        policy_version: "2.0.0", values_floor_version: "1.0.0",
        trust_epoch: args.trust_epoch, issuer_id: state.agentKey!,
        valid_until: args.valid_until,
      });
      const del = supersedeV2Delegation({
        original_delegation_id: args.original_delegation_id,
        new_scope: { action_categories: args.new_scope_categories },
        justification: args.justification,
        policy_context: ctx, delegator_private_key: state.privateKey!,
        expansion_reviewer: args.expansion_reviewer,
        expansion_reviewer_private_key: args.expansion_reviewer_private_key,
      });
      return { content: [{ type: "text" as const, text: JSON.stringify(del, null, 2) }] };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("Supersession failed", e) }], isError: true };
    }
  }
);

server.tool(
  "create_outcome_record",
  "Register an action outcome (agent perspective). Part of three-way reporting.",
  {
    action_id: z.string(), declared_intent: z.string(),
    semantic_uncertainty: z.enum(["low", "medium", "high", "critical"]),
    observed_outcome: z.string(),
    outcome_class: z.enum(["success", "partial_success", "failure", "unintended_effect", "unknown"]),
    divergence_score: z.number().min(0).max(1),
    valid_until: z.string(),
    trust_epoch: z.number().default(1),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };
    try {
      const ctx = createPolicyContext({
        policy_version: "2.0.0", values_floor_version: "1.0.0",
        trust_epoch: args.trust_epoch, issuer_id: state.agentKey!,
        valid_until: args.valid_until,
      });
      const record = createV2OutcomeRecord({
        action_id: args.action_id, agent_id: state.agentKey!,
        declared_intent: args.declared_intent,
        semantic_uncertainty: args.semantic_uncertainty as any,
        observed_outcome: args.observed_outcome,
        outcome_class: args.outcome_class as any,
        divergence_score: args.divergence_score,
        agent_private_key: state.privateKey!,
        policy_context: ctx,
      });
      return { content: [{ type: "text" as const, text: JSON.stringify(record, null, 2) }] };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("Outcome registration failed", e) }], isError: true };
    }
  }
);

server.tool(
  "add_principal_report",
  "Add principal's perspective to an outcome record. Enables three-way divergence reporting.",
  {
    outcome_id: z.string(), observed_outcome: z.string(),
    outcome_class: z.enum(["success", "partial_success", "failure", "unintended_effect", "unknown"]),
    divergence_score: z.number().min(0).max(1),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };
    try {
      const record = addV2PrincipalReport({
        outcome_id: args.outcome_id, principal_id: state.agentKey!,
        observed_outcome: args.observed_outcome,
        outcome_class: args.outcome_class as any,
        divergence_score: args.divergence_score,
        principal_private_key: state.privateKey!,
      });
      return { content: [{ type: "text" as const, text: JSON.stringify({ id: record.id, consensus: record.consensus, effective_divergence: getV2EffectiveDivergence(record) }, null, 2) }] };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("Principal report failed", e) }], isError: true };
    }
  }
);

server.tool(
  "define_emergency_pathway",
  "Define a pre-authorized emergency pathway at delegation time. Only the delegator can define these.",
  {
    delegation_ref: z.string(), description: z.string(),
    trigger_field: z.string(), trigger_operator: z.enum(["eq", "neq", "gt", "lt", "gte", "lte"]),
    trigger_value: z.union([z.string(), z.number(), z.boolean()]),
    expanded_scope_categories: z.array(z.string()),
    max_duration: z.string().default("PT1H"),
    review_deadline: z.string().default("PT24H"),
    review_authority: z.string(),
    valid_until: z.string(), trust_epoch: z.number().default(1),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };
    try {
      const ctx = createPolicyContext({
        policy_version: "2.0.0", values_floor_version: "1.0.0",
        trust_epoch: args.trust_epoch, issuer_id: state.agentKey!,
        valid_until: args.valid_until,
      });
      const pw = defineV2EmergencyPathway({
        delegation_ref: args.delegation_ref,
        trigger_conditions: { any_of: [{ field: args.trigger_field, operator: args.trigger_operator, value: args.trigger_value }] },
        expanded_scope: { action_categories: args.expanded_scope_categories },
        max_duration: args.max_duration, mandatory_review_deadline: args.review_deadline,
        review_authority: args.review_authority, description: args.description,
        policy_context: ctx, delegator_private_key: state.privateKey!,
      });
      return { content: [{ type: "text" as const, text: JSON.stringify(pw, null, 2) }] };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("Emergency pathway failed", e) }], isError: true };
    }
  }
);

server.tool(
  "activate_emergency",
  "Activate a pre-authorized emergency pathway with evidence.",
  {
    pathway_id: z.string(),
    trigger_evidence: z.string().describe("Evidence that trigger conditions are met"),
    valid_until: z.string(), trust_epoch: z.number().default(1),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };
    try {
      const ctx = createPolicyContext({
        policy_version: "2.0.0", values_floor_version: "1.0.0",
        trust_epoch: args.trust_epoch, issuer_id: state.agentKey!,
        valid_until: args.valid_until,
      });
      const act = activateV2Emergency({
        pathway_id: args.pathway_id, agent_id: state.agentKey!,
        trigger_evidence: args.trigger_evidence,
        agent_private_key: state.privateKey!, policy_context: ctx,
      });
      return { content: [{ type: "text" as const, text: JSON.stringify(act, null, 2) }] };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("Emergency activation failed", e) }], isError: true };
    }
  }
);

server.tool(
  "create_attestation",
  "Create a contextual attestation — pre-action reasoning record for medium+ risk actions.",
  {
    action_id: z.string(), delegation_ref: z.string(),
    context_understanding: z.string().describe("Agent's assessment of the situation"),
    factors_considered: z.array(z.string()).describe("Key decision factors"),
    alternatives_rejected: z.array(z.object({ alternative: z.string(), reason: z.string() })).default([]),
    expected_outcome: z.string(),
    confidence: z.number().min(0).max(1),
    semantic_uncertainty: z.enum(["low", "medium", "high", "critical"]),
    required: z.boolean().default(true),
    valid_until: z.string(), trust_epoch: z.number().default(1),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };
    try {
      const ctx = createPolicyContext({
        policy_version: "2.0.0", values_floor_version: "1.0.0",
        trust_epoch: args.trust_epoch, issuer_id: state.agentKey!,
        valid_until: args.valid_until,
      });
      const att = createV2Attestation({
        action_id: args.action_id, agent_id: state.agentKey!,
        delegation_ref: args.delegation_ref,
        context_understanding: args.context_understanding,
        factors_considered: args.factors_considered,
        alternatives_rejected: args.alternatives_rejected,
        expected_outcome: args.expected_outcome,
        confidence: args.confidence,
        semantic_uncertainty: args.semantic_uncertainty as any,
        required: args.required, policy_context: ctx,
        agent_private_key: state.privateKey!,
      });
      const quality = assessV2AttestationQuality(att);
      return { content: [{ type: "text" as const, text: JSON.stringify({ attestation: att, quality }, null, 2) }] };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("Attestation failed", e) }], isError: true };
    }
  }
);

server.tool(
  "request_migration",
  "Request fork-and-sunset migration when current delegation scope is insufficient.",
  {
    source_delegation: z.string(),
    limitation: z.string().describe("What the agent cannot do under current scope"),
    requested_scope_change: z.string(),
    justification: z.string(),
    valid_until: z.string(), trust_epoch: z.number().default(1),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };
    try {
      const ctx = createPolicyContext({
        policy_version: "2.0.0", values_floor_version: "1.0.0",
        trust_epoch: args.trust_epoch, issuer_id: state.agentKey!,
        valid_until: args.valid_until,
      });
      const req = requestV2Migration({
        source_agent: state.agentKey!, source_delegation: args.source_delegation,
        limitation: args.limitation, requested_scope_change: args.requested_scope_change,
        justification: args.justification, agent_private_key: state.privateKey!,
        policy_context: ctx,
      });
      return { content: [{ type: "text" as const, text: JSON.stringify(req, null, 2) }] };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("Migration request failed", e) }], isError: true };
    }
  }
);

server.tool(
  "create_artifact_provenance",
  "Tag an agent-generated artifact with provenance metadata (content hash, risk class, authoring agent).",
  {
    delegation_ref: z.string(), intended_use: z.string(),
    risk_class: z.enum(["low", "medium", "high", "critical"]),
    requires_human_execution: z.boolean().default(false),
    content: z.string().describe("The artifact content (used for hash, not stored)"),
    artifact_type: z.string().describe("e.g. email_draft, code_script, database_query"),
    valid_until: z.string(), trust_epoch: z.number().default(1),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };
    try {
      const ctx = createPolicyContext({
        policy_version: "2.0.0", values_floor_version: "1.0.0",
        trust_epoch: args.trust_epoch, issuer_id: state.agentKey!,
        valid_until: args.valid_until,
      });
      const prov = createArtifactProvenance({
        authoring_agent: state.agentKey!,
        authority_scope: { action_categories: ["*"] },
        delegation_ref: args.delegation_ref, intended_use: args.intended_use,
        risk_class: args.risk_class as any,
        requires_human_execution: args.requires_human_execution,
        content: args.content, artifact_type: args.artifact_type,
        policy_context: ctx, agent_private_key: state.privateKey!,
      });
      return { content: [{ type: "text" as const, text: JSON.stringify(prov, null, 2) }] };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("Provenance failed", e) }], isError: true };
    }
  }
);

server.tool(
  "check_anomaly",
  "Record an action and check for anomalies (first-max-authority, concentration).",
  {
    action_id: z.string(), authority_level: z.number(),
    semantic_uncertainty: z.enum(["low", "medium", "high", "critical"]),
    risk_class: z.enum(["low", "medium", "high", "critical"]),
    delegation_ref: z.string(),
    was_delegated: z.boolean().default(false),
    complexity: z.number().min(0).max(1).default(0.5),
  },
  async (args) => {
    const keyErr = requireKey();
    if (keyErr) return { content: [{ type: "text" as const, text: keyErr }], isError: true };
    try {
      const record = {
        action_id: args.action_id, agent_id: state.agentKey!,
        authority_level: args.authority_level,
        semantic_uncertainty: args.semantic_uncertainty as any,
        risk_class: args.risk_class as any,
        delegation_ref: args.delegation_ref,
        was_delegated: args.was_delegated,
        complexity: args.complexity,
        timestamp: new Date().toISOString(),
      };
      recordV2Action(record);
      const anomaly = checkV2FirstMaxAuthority(record);
      const concentration = computeV2ConcentrationMetrics(state.agentKey!);
      return { content: [{ type: "text" as const, text: JSON.stringify({
        action_recorded: true, anomaly_flag: anomaly, concentration,
      }, null, 2) }] };
    } catch (e: any) {
      return { content: [{ type: "text" as const, text: safeError("Anomaly check failed", e) }], isError: true };
    }
  }
);

// ═══════════════════════════════════════
// Data Governance Tools (Modules 36A, 38, 39)
// ═══════════════════════════════════════

server.tool(
  "register_data_source",
  "Register a data source with terms for agent access. Returns a signed SourceReceipt.",
  {
    contentDescriptor: z.string().describe("Human-readable description of the data"),
    contentCommitment: z.string().describe("SHA-256 hash of the data content"),
    contentType: z.enum(["dataset", "article", "api", "database", "file", "stream", "model_output"]).describe("Type of data"),
    allowedPurposes: z.array(z.string()).describe("Allowed purposes: read, analyze, summarize, generate, recommend, train, embed, redistribute, commercial"),
    requireAttribution: z.boolean().default(true),
    compensationType: z.enum(["none", "attribution_only", "per_access", "negotiate"]).default("none"),
    compensationAmount: z.number().optional().describe("Amount per access (for per_access type)"),
    compensationCurrency: z.string().default("usd"),
    maxAccessCount: z.number().optional().describe("Max total accesses allowed"),
    derivativePolicy: z.enum(["unrestricted", "same_terms", "attribution_required", "no_derivatives"]).default("attribution_required"),
  },
  async (p) => {
    if (!state.agentKey || !state.privateKey) return { content: [{ type: "text", text: "❌ Not identified. Call identify first." }] };
    const comp = p.compensationType === 'per_access'
      ? { type: 'per_access' as const, amount: p.compensationAmount || 0.01, currency: p.compensationCurrency }
      : p.compensationType === 'attribution_only' ? { type: 'attribution_only' as const }
      : p.compensationType === 'negotiate' ? { type: 'negotiate' as const, contact: state.agentId || '' }
      : { type: 'none' as const };
    const terms: DataTerms = {
      allowedPurposes: p.allowedPurposes as any[],
      requireAttribution: p.requireAttribution,
      requireNotification: false,
      compensation: comp,
      derivativePolicy: p.derivativePolicy,
      auditVisibility: 'source_and_principal',
      revocable: false,
      maxAccessCount: p.maxAccessCount,
    };
    const receipt = registerSelfAttestedSource({
      ownerPrincipalId: state.principal?.principalId || state.agentId || 'unknown',
      ownerPublicKey: state.agentKey,
      ownerPrivateKey: state.privateKey,
      contentCommitment: p.contentCommitment,
      contentType: p.contentType,
      contentDescriptor: p.contentDescriptor,
      dataTerms: terms,
    });
    state.sourceReceipts.set(receipt.sourceReceiptId, receipt);
    return { content: [{ type: "text", text: `✅ Data source registered.\n\nSource Receipt ID: ${receipt.sourceReceiptId}\nDescriptor: ${p.contentDescriptor}\nAllowed purposes: ${p.allowedPurposes.join(', ')}\nCompensation: ${p.compensationType}${p.compensationAmount ? ' $' + p.compensationAmount : ''}\nMax accesses: ${p.maxAccessCount || 'unlimited'}\nDerivative policy: ${p.derivativePolicy}` }] };
  }
);

server.tool(
  "create_data_enforcement_gate",
  "Create a data enforcement gate that checks terms before allowing data access. Modes: enforce (block violations), audit (log only), off.",
  {
    mode: z.enum(["enforce", "audit", "off"]).default("enforce").describe("Enforcement mode"),
  },
  async (p) => {
    const kp = generateKeyPair();
    state.dataEnforcementGate = new DataEnforcementGate({
      gatewayId: 'gw_data_' + Date.now().toString(36),
      gatewayPublicKey: kp.publicKey,
      gatewayPrivateKey: kp.privateKey,
      mode: p.mode,
    }, state.contributionLedger);
    // Register all known sources
    for (const [id, receipt] of state.sourceReceipts) {
      state.dataEnforcementGate.registerSource(receipt, receipt.contentDescriptor);
    }
    return { content: [{ type: "text", text: `✅ Data enforcement gate created.\n\nMode: ${p.mode}\nRegistered sources: ${state.sourceReceipts.size}\nContribution ledger: active` }] };
  }
);

server.tool(
  "check_data_access",
  "Check if an agent can access a data source through the enforcement gate. Generates receipt and feeds contribution ledger.",
  {
    sourceReceiptId: z.string().describe("Source receipt ID to access"),
    declaredPurpose: z.enum(["read", "analyze", "summarize", "generate", "recommend", "train", "embed", "redistribute", "commercial"]).describe("Declared purpose"),
    accessMethod: z.enum(["api_call", "file_read", "database_query", "web_fetch", "memory_retrieval", "embedding_lookup", "stream", "human_provided"]).default("api_call"),
  },
  async (p) => {
    if (!state.dataEnforcementGate) return { content: [{ type: "text", text: "❌ No enforcement gate. Call create_data_enforcement_gate first." }] };
    if (!state.agentKey) return { content: [{ type: "text", text: "❌ Not identified." }] };
    const decision = state.dataEnforcementGate.checkAccess({
      agentId: state.agentId || 'unknown',
      agentPublicKey: state.agentKey,
      principalId: state.principal?.principalId || 'unknown',
      sourceReceiptId: p.sourceReceiptId,
      declaredPurpose: p.declaredPurpose,
      accessMethod: p.accessMethod,
      accessScope: 'data:' + p.declaredPurpose,
      executionFrameId: 'frame_' + Date.now().toString(36),
    });
    const status = decision.allowed ? '✅ Access ALLOWED' : '❌ Access DENIED';
    let text = `${status}\n\nSource: ${p.sourceReceiptId}\nPurpose: ${p.declaredPurpose}`;
    if (decision.hardViolations.length) text += `\nViolations: ${decision.hardViolations.join('; ')}`;
    if (decision.advisoryWarnings.length) text += `\nWarnings: ${decision.advisoryWarnings.join('; ')}`;
    if (decision.receipt) text += `\nReceipt ID: ${decision.receipt.accessReceiptId}`;
    if (decision.accessesRemaining !== undefined) text += `\nAccesses remaining: ${decision.accessesRemaining}`;
    return { content: [{ type: "text", text }] };
  }
);

server.tool(
  "query_contributions",
  "Query the data contribution ledger. Filter by source, agent, principal, purpose, or time range.",
  {
    sourceReceiptId: z.string().optional(),
    agentId: z.string().optional(),
    principalId: z.string().optional(),
    purpose: z.string().optional(),
    minAccessCount: z.number().optional(),
  },
  async (p) => {
    const records = queryContributions(state.contributionLedger, p);
    if (records.length === 0) return { content: [{ type: "text", text: "No contributions found matching query." }] };
    const lines = records.map(r =>
      `• ${r.sourceDescriptor || r.sourceReceiptId}: ${r.accessCount} accesses by ${r.agentId}, purposes: ${r.purposes.join('/')}, owed: $${r.compensationAccrued.totalOwed.toFixed(4)}`
    );
    return { content: [{ type: "text", text: `📊 ${records.length} contribution records:\n\n${lines.join('\n')}` }] };
  }
);

server.tool(
  "get_source_metrics",
  "Get aggregate metrics for a data source: total accesses, unique agents, compensation owed.",
  {
    sourceReceiptId: z.string().describe("Source receipt ID"),
  },
  async (p) => {
    const metrics = getSourceMetrics(state.contributionLedger, p.sourceReceiptId);
    if (!metrics) return { content: [{ type: "text", text: "No data found for this source." }] };
    return { content: [{ type: "text", text: `📊 Source Metrics: ${metrics.sourceDescriptor}\n\nTotal accesses: ${metrics.totalAccesses}\nUnique agents: ${metrics.uniqueAgents}\nUnique principals: ${metrics.uniquePrincipals}\nCompensation owed: $${metrics.compensationOwed.totalOwed.toFixed(4)} ${metrics.compensationOwed.currency}\nPurpose breakdown: ${JSON.stringify(metrics.purposeBreakdown)}\nTop agents: ${metrics.topAgents.map(a => `${a.agentId} (${a.accessCount})`).join(', ')}` }] };
  }
);

server.tool(
  "get_agent_data_footprint",
  "Show every data source an agent has accessed, with compensation status.",
  {
    agentId: z.string().describe("Agent ID to check"),
  },
  async (p) => {
    const footprint = getAgentDataFootprint(state.contributionLedger, p.agentId);
    if (!footprint) return { content: [{ type: "text", text: "No data access found for this agent." }] };
    const sources = footprint.sourcesAccessed.map(s =>
      `• ${s.sourceDescriptor || s.sourceReceiptId}: ${s.accessCount} accesses, purposes: ${s.purposes.join('/')}, status: ${s.compensationStatus}`
    );
    return { content: [{ type: "text", text: `🔍 Agent Data Footprint: ${p.agentId}\n\nTotal sources: ${footprint.totalSources}\nTotal accesses: ${footprint.totalAccesses}\nTotal compensation accrued: $${footprint.totalCompensationAccrued.toFixed(4)} ${footprint.currency}\n\nSources:\n${sources.join('\n')}` }] };
  }
);

server.tool(
  "generate_settlement",
  "Generate a Merkle-committed, signed settlement record for a period. Shows what's owed to each data source.",
  {
    startDate: z.string().describe("Period start (YYYY-MM-DD)"),
    endDate: z.string().describe("Period end (YYYY-MM-DD)"),
    periodLabel: z.string().describe("Label (e.g. '2026-Q1', '2026-03')"),
  },
  async (p) => {
    const kp = generateKeyPair();
    const settlement = generateSettlement(
      state.contributionLedger,
      { startDate: p.startDate, endDate: p.endDate, periodLabel: p.periodLabel },
      kp.publicKey, kp.privateKey,
    );
    const verification = verifySettlement(settlement);
    const lines = settlement.lineItems.map(li =>
      `• ${li.sourceDescriptor || li.sourceReceiptId}: ${li.accessCount} accesses, $${li.amount.toFixed(4)} (${li.compensationModel})`
    );
    return { content: [{ type: "text", text: `📋 Settlement Record: ${settlement.settlementId}\n\nPeriod: ${p.periodLabel}\nTotal: $${settlement.totalAmount.toFixed(4)} ${settlement.currency}\nTotal accesses: ${settlement.totalAccesses}\nUnique sources: ${settlement.uniqueSources}\nUnique payers: ${settlement.uniquePayers}\nMerkle root: ${settlement.merkleRoot.slice(0, 16)}...\nVerification: ${verification.valid ? '✅ VALID' : '❌ INVALID'}\n\nLine items:\n${lines.join('\n')}` }] };
  }
);

server.tool(
  "generate_compliance_report",
  "Generate a GDPR Article 30 / EU AI Act Article 10 / SOC 2 compliance report.",
  {
    reportType: z.enum(["gdpr_article30", "euai_article10", "soc2_data", "general"]).describe("Report type"),
    startDate: z.string().describe("Period start"),
    endDate: z.string().describe("Period end"),
    periodLabel: z.string().describe("Label"),
    agentId: z.string().optional().describe("Filter by agent"),
    principalId: z.string().optional().describe("Filter by principal"),
  },
  async (p) => {
    const kp = generateKeyPair();
    const report = generateComplianceReport(
      state.contributionLedger,
      { startDate: p.startDate, endDate: p.endDate, periodLabel: p.periodLabel },
      p.reportType, kp.privateKey,
      { agentId: p.agentId, principalId: p.principalId },
    );
    return { content: [{ type: "text", text: `📋 Compliance Report: ${report.reportId}\n\nType: ${p.reportType}\nPeriod: ${p.periodLabel}\nTotal data accesses: ${report.summary.totalDataAccesses}\nUnique data sources: ${report.summary.uniqueDataSources}\nPurpose breakdown: ${JSON.stringify(report.summary.purposeBreakdown)}\nCompensation: $${report.summary.compensationSummary.total.toFixed(4)} (pending: $${report.summary.compensationSummary.pending.toFixed(4)})\nTerms violations: ${report.summary.termsViolations}\nAdvisory warnings: ${report.summary.advisoryWarnings}\nSigned: ✅` }] };
  }
);

server.tool(
  "record_training_use",
  "Record that agent output derived from data sources was used for training/fine-tuning/embedding. Creates a signed training attribution receipt.",
  {
    trainingUseType: z.enum(["fine_tune", "lora_adapter", "embedding", "rag_index", "distillation", "evaluation", "synthetic_data"]).describe("Type of training use"),
    modelId: z.string().describe("Model being trained"),
    sourceAccessReceiptIds: z.array(z.string()).describe("Access receipt IDs of source data used"),
    outputContentHash: z.string().describe("SHA-256 of the output used for training"),
    contributionWeights: z.record(z.number()).optional().describe("Fractional weights per source (sum to 1.0)"),
    datasetSize: z.number().optional().describe("Number of training examples"),
  },
  async (p) => {
    if (!state.agentKey || !state.privateKey) return { content: [{ type: "text", text: "❌ Not identified." }] };
    const receipt = createTrainingAttribution({
      trainingUseType: p.trainingUseType,
      modelId: p.modelId,
      trainerId: state.agentId || 'unknown',
      trainerPublicKey: state.agentKey,
      trainerPrivateKey: state.privateKey,
      sourceAccessReceiptIds: p.sourceAccessReceiptIds,
      executionFrameId: 'frame_train_' + Date.now().toString(36),
      outputContentHash: p.outputContentHash,
      inputDataHashes: p.sourceAccessReceiptIds.map(id => id), // simplified
      contributionWeights: p.contributionWeights,
      datasetSize: p.datasetSize,
    });
    recordTrainingAttribution(state.trainingLedger, receipt);
    const v = verifyTrainingAttribution(receipt);
    return { content: [{ type: "text", text: `✅ Training attribution recorded.\n\nReceipt: ${receipt.trainingReceiptId}\nType: ${p.trainingUseType}\nModel: ${p.modelId}\nSources: ${p.sourceAccessReceiptIds.length}\nDataset size: ${p.datasetSize || 'N/A'}\nWeights: ${p.contributionWeights ? JSON.stringify(p.contributionWeights) : 'equal'}\nVerification: ${v.valid ? '✅' : '❌'}` }] };
  }
);

server.tool(
  "get_model_data_sources",
  "Show which data sources contributed to a model's training, with fractional weights.",
  {
    modelId: z.string().describe("Model ID to check"),
  },
  async (p) => {
    const sources = getModelDataSources(state.trainingLedger, p.modelId);
    if (sources.length === 0) return { content: [{ type: "text", text: "No training data found for this model." }] };
    const lines = sources.map(s =>
      `• ${s.accessReceiptId}: weight ${s.weight.toFixed(4)}, type: ${s.trainingUseType}`
    );
    return { content: [{ type: "text", text: `🧠 Model Training Sources: ${p.modelId}\n\n${sources.length} data sources contributed:\n${lines.join('\n')}` }] };
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
// Smithery sandbox export (for publish scanning)
// ═══════════════════════════════════════

let _sandboxMode = false;

export function createSandboxServer() {
  _sandboxMode = true;
  loadTasks();
  loadAgoraFeed();
  return server;
}

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

// Deferred startup: gives createSandboxServer() a chance to set the flag
// before main() runs. This is required for Smithery publish scanning.

setTimeout(() => {
  if (!_sandboxMode) {
    main().catch((error) => {
      console.error("Fatal error:", error);
      process.exit(1);
    });
  }
}, 0);
