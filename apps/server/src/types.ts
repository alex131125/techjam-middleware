import type { CommandClass, FrozenBudget } from "./middleware/capability.js";
import type { PolicyViolationDetail, ViolationKind } from "./middleware/policy.js";

export type AgentStatus = "ready" | "busy" | "stopped" | "error";
export type RunStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type MessageRole = "user" | "assistant";

export interface Agent {
  id: string;
  name: string;
  description: string;
  instructions: string;
  status: AgentStatus;
  workspacePath: string;
  codexThreadId: string | null;
  lastError: string | null;
  /** Operator-set narrowing applied on top of the platform ceiling. Never widens it. */
  budgetPolicy: AgentBudgetPolicy | null;
  createdAt: string;
  updatedAt: string;
}

/** An operator-supplied narrowing request. Every field may only remove capability. */
export interface AgentBudgetPolicy {
  commandClasses?: CommandClass[] | undefined;
  egressAllowlist?: string[] | undefined;
  maxSteps?: number | undefined;
  allowOutsideWorkspace?: boolean | undefined;
}

export interface Message {
  id: string;
  agentId: string;
  runId: string;
  role: MessageRole;
  content: string;
  createdAt: string;
}

export interface RunUsage {
  inputTokens?: number;
  cachedInputTokens?: number;
  outputTokens?: number;
}

export type TraceEventType =
  | "budget.frozen"
  | "command.started"
  | "command.completed"
  | "file.change"
  | "model.call"
  | "policy.violation"
  | "run.aborted"
  | "agent.message"
  | "reasoning"
  | "runtime.degraded";

export interface TraceEvent {
  id: string;
  runId: string;
  agentId: string;
  sequence: number;
  type: TraceEventType;
  at: string;
  summary: string;
  detail: Record<string, unknown> | null;
}

export interface PolicyViolation {
  id: string;
  runId: string;
  agentId: string;
  kind: ViolationKind;
  detail: string;
  command: string;
  at: string;
  /** Whether this violation is what caused the turn to be aborted. */
  terminal: boolean;
}

/**
 * A control that the current Runtime profile cannot enforce. Reported rather than hidden,
 * because a silently degraded boundary is worse than a documented one.
 */
export interface DegradedControl {
  control: string;
  reason: string;
}

export interface AgentRun {
  id: string;
  agentId: string;
  status: RunStatus;
  prompt: string;
  output: string | null;
  error: string | null;
  usage: RunUsage | null;
  budget: FrozenBudget | null;
  violationCount: number;
  redactions: string[];
  tainted: boolean;
  degraded: DegradedControl[];
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
}

export interface Database {
  version: 1;
  agents: Agent[];
  messages: Message[];
  runs: AgentRun[];
  traces: TraceEvent[];
  violations: PolicyViolation[];
}

export interface CreateAgentInput {
  name: string;
  description?: string | undefined;
  instructions?: string | undefined;
  budgetPolicy?: AgentBudgetPolicy | undefined;
}

export interface UpdateAgentInput {
  name?: string | undefined;
  description?: string | undefined;
  instructions?: string | undefined;
  budgetPolicy?: AgentBudgetPolicy | null | undefined;
}

export interface RunnerResult {
  output: string;
  threadId: string | null;
  usage: RunUsage | null;
  violations: PolicyViolationDetail[];
  tainted: boolean;
  taintReasons: string[];
  commandCount: number;
}

/** Emitted by the Runtime as the Codex event stream is consumed. */
export type RunnerEvent =
  | { kind: "command.started"; command: string; stepIndex: number }
  | { kind: "command.completed"; command: string; exitCode: number | null; output: string }
  | { kind: "file.change"; detail: Record<string, unknown> }
  | { kind: "reasoning"; text: string }
  | { kind: "agent.message"; text: string }
  | { kind: "policy.violation"; command: string; violations: PolicyViolationDetail[]; terminal: boolean };

export interface RunnerRequest {
  agentId: string;
  runId: string;
  workspacePath: string;
  prompt: string;
  threadId: string | null;
  /** Frozen before untrusted content is read; the Runtime treats it as read-only. */
  budget: FrozenBudget;
  /** Per-agent Codex home, so one Agent cannot read another Agent's sessions. */
  codexHome: string;
  /** Run-scoped Ark credential. The real key never reaches the Runtime. */
  brokerToken: string;
  brokerBaseUrl: string;
  onEvent?: (event: RunnerEvent) => void;
}

export interface AgentRunner {
  run(request: RunnerRequest): Promise<RunnerResult>;
  cancel(agentId: string): Promise<boolean>;
  isAvailable(): Promise<boolean>;
  /** Controls this profile cannot enforce, surfaced on /api/system and on each Run. */
  degradedControls(): DegradedControl[];
  /** Address at which the Runtime can reach the control plane credential broker. */
  brokerHost(): string;
  /** One-time preparation, e.g. creating the isolated Runtime network. */
  prepare?(): Promise<void>;
}
