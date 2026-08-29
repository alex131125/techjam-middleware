export type AgentStatus = "ready" | "busy" | "stopped" | "error";
export type RunStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export type CommandClass =
  | "read"
  | "write"
  | "build"
  | "vcs"
  | "network"
  | "process"
  | "privilege";

export interface CapabilityBudget {
  version: 1;
  commandClasses: CommandClass[];
  egressAllowlist: string[];
  maxSteps: number;
  allowOutsideWorkspace: boolean;
}

export interface FrozenBudget extends CapabilityBudget {
  agentId: string;
  runId: string;
  frozenAt: string;
  narrowedBy: string[];
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
  kind: string;
  detail: string;
  command: string;
  at: string;
  terminal: boolean;
}

export interface DegradedControl {
  control: string;
  reason: string;
}

export interface Agent {
  id: string;
  name: string;
  description: string;
  instructions: string;
  status: AgentStatus;
  workspacePath: string;
  codexThreadId: string | null;
  lastError: string | null;
  budgetPolicy: Partial<CapabilityBudget> | null;
  createdAt: string;
  updatedAt: string;
}

export interface Message {
  id: string;
  agentId: string;
  runId: string;
  role: "user" | "assistant";
  content: string;
  createdAt: string;
}

export interface AgentRun {
  id: string;
  agentId: string;
  status: RunStatus;
  prompt: string;
  output: string | null;
  error: string | null;
  usage: {
    inputTokens?: number;
    cachedInputTokens?: number;
    outputTokens?: number;
  } | null;
  budget: FrozenBudget | null;
  violationCount: number;
  redactions: string[];
  tainted: boolean;
  degraded: DegradedControl[];
  createdAt: string;
}

export interface SystemInfo {
  arkConfigured: boolean;
  arkBaseUrl: string;
  arkModel: string | null;
  codexAvailable: boolean;
  codexSandboxMode: string;
  runtimeProvider: "local-process" | "container";
  containerEngine: string | null;
  runtime: string;
  middleware: {
    policyEnforcement: "enforce" | "monitor";
    spotlightPreamble: "on" | "off";
    ceiling: CapabilityBudget;
    credentialBroker: {
      enabled: boolean;
      port: number;
      runtimeBaseUrl: string;
      activeLeases: number;
    };
    egressAllowlistEnforced: boolean;
    runtimeNetwork: string | null;
    perAgentCodexHome: boolean;
    degraded: DegradedControl[];
  };
}
