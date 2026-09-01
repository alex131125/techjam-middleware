import { randomUUID } from "node:crypto";
import { rm } from "node:fs/promises";
import type { AppConfig } from "./config.js";
import {
  agentCodexHome,
  isModelConfigured,
  modelProviderSetupHint,
  writeCodexConfig,
} from "./config.js";
import { PolicyAbortError } from "./codex-runner.js";
import { HttpError, RunCancelledError } from "./errors.js";
import {
  freeze,
  narrowStrict,
  platformCeiling,
  BudgetExpansionError,
  type CapabilityBudget,
  type FrozenBudget,
} from "./middleware/capability.js";
import { ArkBroker } from "./middleware/broker.js";
import { redact, SecretRegistry } from "./middleware/redact.js";
import { buildSpotlightPreamble } from "./middleware/spotlight.js";
import { TraceRecorder } from "./middleware/trace.js";
import { JsonStore } from "./store.js";
import type {
  Agent,
  AgentBudgetPolicy,
  AgentRun,
  AgentRunner,
  CreateAgentInput,
  DegradedControl,
  Message,
  PolicyViolation,
  RunnerEvent,
  TraceEvent,
  UpdateAgentInput,
} from "./types.js";
import { WorkspaceManager } from "./workspace.js";

const now = () => new Date().toISOString();

export class AgentService {
  private readonly activeExecutions = new Map<string, Promise<void>>();
  private readonly cancellationRequests = new Set<string>();
  private readonly secrets = new SecretRegistry();
  private readonly recorder = new TraceRecorder(this.secrets);
  private readonly broker: ArkBroker;

  constructor(
    private readonly config: AppConfig,
    private readonly store: JsonStore,
    private readonly workspaces: WorkspaceManager,
    private readonly runner: AgentRunner,
  ) {
    this.secrets.register(config.modelProvider.apiKey);
    this.secrets.register(config.authToken);
    this.broker = new ArkBroker({
      arkBaseUrl: config.modelProvider.baseUrl,
      arkApiKey: config.modelProvider.apiKey,
      host: config.brokerHost,
      port: config.brokerPort,
      maxCallsPerRun: config.maxModelCallsPerRun,
      onCall: (record) => {
        this.recorder.record(
          record.agentId,
          record.runId,
          "model.call",
          "Model call " + record.path + " -> " + record.status,
          {
            status: record.status,
            durationMs: record.durationMs,
            path: record.path,
          },
        );
      },
    });
  }

  async initialize(): Promise<void> {
    await this.store.initialize();
    await this.workspaces.initialize();
    await this.migrate();
    await this.runner.prepare?.();
    await this.broker.start();
    await this.store.mutate((database) => {
      for (const run of database.runs) {
        if (run.status === "queued" || run.status === "running") {
          run.status = "cancelled";
          run.error = "Server restarted while this run was active";
          run.completedAt = now();
        }
      }
      for (const agent of database.agents) {
        if (agent.status === "busy") {
          agent.status = "ready";
          agent.updatedAt = now();
        }
      }
    });
  }

  async shutdown(): Promise<void> {
    await this.broker.stop();
  }

  /** Bring records written by the pre-middleware schema up to date in place. */
  private async migrate(): Promise<void> {
    await this.store.mutate((database) => {
      database.traces ??= [];
      database.violations ??= [];
      for (const agent of database.agents) {
        agent.budgetPolicy ??= null;
      }
      for (const run of database.runs) {
        run.budget ??= null;
        run.violationCount ??= 0;
        run.redactions ??= [];
        run.tainted ??= false;
        run.degraded ??= [];
      }
    });
  }

  listAgents(): Agent[] {
    return this.store
      .snapshot()
      .agents.sort((left, right) =>
        right.updatedAt.localeCompare(left.updatedAt),
      );
  }

  getAgent(id: string): Agent {
    const agent = this.store.snapshot().agents.find((item) => item.id === id);
    if (!agent) {
      throw new HttpError(404, "Agent not found");
    }
    return agent;
  }

  async createAgent(input: CreateAgentInput): Promise<Agent> {
    const timestamp = now();
    const id = randomUUID();
    const agent: Agent = {
      id,
      name: input.name.trim(),
      description: input.description?.trim() ?? "",
      instructions: input.instructions?.trim() ?? "",
      status: "ready",
      workspacePath: this.workspaces.workspacePath(id),
      codexThreadId: null,
      lastError: null,
      budgetPolicy: input.budgetPolicy
        ? this.validatePolicy(input.budgetPolicy)
        : null,
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    await this.workspaces.create(agent);
    // A private Codex home per Agent, written before the Agent can ever run.
    await writeCodexConfig(
      this.config,
      agentCodexHome(this.config, id),
      this.broker.baseUrlFor(this.runner.brokerHost()),
    );
    await this.store.mutate((database) => database.agents.push(agent));
    return agent;
  }

  async updateAgent(id: string, input: UpdateAgentInput): Promise<Agent> {
    const current = this.getAgent(id);
    if (current.status === "busy") {
      throw new HttpError(409, "Stop the active run before editing this Agent");
    }
    let nextPolicy: AgentBudgetPolicy | null | undefined;
    if (input.budgetPolicy === undefined) {
      nextPolicy = undefined;
    } else if (input.budgetPolicy === null) {
      if (current.budgetPolicy) {
        throw new HttpError(
          409,
          "Agent budget policy cannot be cleared after narrowing",
        );
      }
      nextPolicy = null;
    } else {
      nextPolicy = this.validatePolicy(
        input.budgetPolicy,
        this.effectiveBudget(current),
      );
    }
    const updated = await this.store.mutate((database) => {
      const agent = database.agents.find((item) => item.id === id);
      if (!agent) {
        throw new HttpError(404, "Agent not found");
      }
      if (agent.status === "busy") {
        throw new HttpError(
          409,
          "Stop the active run before editing this Agent",
        );
      }
      if (input.name !== undefined) agent.name = input.name.trim();
      if (input.description !== undefined)
        agent.description = input.description.trim();
      if (input.instructions !== undefined)
        agent.instructions = input.instructions.trim();
      if (nextPolicy !== undefined) agent.budgetPolicy = nextPolicy;
      agent.lastError = null;
      agent.updatedAt = now();
      return structuredClone(agent);
    });
    await this.workspaces.writeInstructions(updated);
    return updated;
  }

  async deleteAgent(id: string): Promise<{ archivedWorkspace: string }> {
    const agent = this.getAgent(id);
    await this.cancelExecution(id);
    const archivedWorkspace = await this.workspaces.archive(agent);
    await rm(agentCodexHome(this.config, id), { recursive: true, force: true });
    await this.store.mutate((database) => {
      database.agents = database.agents.filter((item) => item.id !== id);
      database.messages = database.messages.filter(
        (item) => item.agentId !== id,
      );
      database.runs = database.runs.filter((item) => item.agentId !== id);
      database.traces = database.traces.filter((item) => item.agentId !== id);
      database.violations = database.violations.filter(
        (item) => item.agentId !== id,
      );
    });
    return { archivedWorkspace };
  }

  async startAgent(id: string): Promise<Agent> {
    return this.setStatus(id, "ready");
  }

  async stopAgent(id: string): Promise<Agent> {
    this.getAgent(id);
    await this.cancelExecution(id);
    return this.setStatus(id, "stopped");
  }

  getMessages(agentId: string): Message[] {
    this.getAgent(agentId);
    return this.store
      .snapshot()
      .messages.filter((message) => message.agentId === agentId)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  getRun(runId: string): AgentRun {
    const run = this.store.snapshot().runs.find((item) => item.id === runId);
    if (!run) {
      throw new HttpError(404, "Run not found");
    }
    return run;
  }

  getRuns(agentId: string): AgentRun[] {
    this.getAgent(agentId);
    return this.store
      .snapshot()
      .runs.filter((run) => run.agentId === agentId)
      .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
  }

  /** Persisted events plus anything buffered for a Run that is still in flight. */
  getTrace(runId: string): TraceEvent[] {
    const run = this.getRun(runId);
    const persisted = this.store
      .snapshot()
      .traces.filter((event) => event.runId === run.id);
    const merged = [...persisted, ...this.recorder.pending(run.id)];
    return merged.sort((left, right) => left.sequence - right.sequence);
  }

  getViolations(agentId?: string): PolicyViolation[] {
    const violations = this.store.snapshot().violations;
    const scoped = agentId
      ? violations.filter((item) => item.agentId === agentId)
      : violations;
    return scoped.sort((left, right) => right.at.localeCompare(left.at));
  }

  // ---------------------------------------------------------------------------
  // L1 - capability budget
  // ---------------------------------------------------------------------------

  /** The platform ceiling. No Agent budget may exceed it. */
  ceiling(): CapabilityBudget {
    return platformCeiling(
      this.config.modelProvider.baseUrl,
      this.config.maxStepsPerRun,
    );
  }

  /** The effective budget for an Agent: the ceiling narrowed by the operator's policy. */
  effectiveBudget(agent: Agent): CapabilityBudget {
    const ceiling = this.ceiling();
    if (!agent.budgetPolicy) return ceiling;
    try {
      return narrowStrict(ceiling, agent.budgetPolicy);
    } catch {
      // A stale or corrupted policy must never restore capabilities that it once removed.
      return narrowStrict(ceiling, {
        commandClasses: [],
        egressAllowlist: [],
        maxSteps: 1,
        allowOutsideWorkspace: false,
      });
    }
  }

  /**
   * Apply an operator-proposed narrowing. Rejects any proposal that would widen, which is
   * the Progent expansion check: this is deterministic and consults no model, so a
   * proposal shaped by injected content cannot escalate privilege.
   */
  async narrowAgentBudget(
    id: string,
    proposal: AgentBudgetPolicy,
  ): Promise<Agent> {
    const agent = this.getAgent(id);
    const current = this.effectiveBudget(agent);
    let narrowed: CapabilityBudget;
    try {
      narrowed = narrowStrict(current, proposal);
    } catch (error) {
      if (error instanceof BudgetExpansionError) {
        throw new HttpError(409, error.message);
      }
      throw error;
    }
    return this.updateAgent(id, {
      budgetPolicy: {
        commandClasses: [...narrowed.commandClasses],
        egressAllowlist: [...narrowed.egressAllowlist],
        maxSteps: narrowed.maxSteps,
        allowOutsideWorkspace: narrowed.allowOutsideWorkspace,
      },
    });
  }

  private validatePolicy(
    policy: AgentBudgetPolicy,
    base: CapabilityBudget = this.ceiling(),
  ): AgentBudgetPolicy {
    try {
      const narrowed = narrowStrict(base, policy);
      return {
        commandClasses: [...narrowed.commandClasses],
        egressAllowlist: [...narrowed.egressAllowlist],
        maxSteps: narrowed.maxSteps,
        allowOutsideWorkspace: narrowed.allowOutsideWorkspace,
      };
    } catch (error) {
      if (error instanceof BudgetExpansionError) {
        throw new HttpError(409, error.message);
      }
      throw error;
    }
  }

  async sendMessage(
    agentId: string,
    prompt: string,
  ): Promise<{ run: AgentRun; message: Message }> {
    if (!isModelConfigured(this.config)) {
      throw new HttpError(
        503,
        this.config.modelProvider.name +
          " is not configured. " +
          modelProviderSetupHint(this.config),
      );
    }
    const timestamp = now();
    const runId = randomUUID();
    const run: AgentRun = {
      id: runId,
      agentId,
      status: "queued",
      prompt,
      output: null,
      error: null,
      usage: null,
      budget: null,
      violationCount: 0,
      redactions: [],
      tainted: false,
      degraded: this.runner.degradedControls(),
      startedAt: null,
      completedAt: null,
      createdAt: timestamp,
    };
    const message: Message = {
      id: randomUUID(),
      agentId,
      runId,
      role: "user",
      content: prompt,
      createdAt: timestamp,
    };
    const agentAtStart = await this.store.mutate((database) => {
      const storedAgent = database.agents.find((item) => item.id === agentId);
      if (!storedAgent) {
        throw new HttpError(404, "Agent not found");
      }
      if (storedAgent.status === "stopped") {
        throw new HttpError(409, "Start the Agent before sending a message");
      }
      if (storedAgent.status === "busy") {
        throw new HttpError(409, "This Agent is already running");
      }
      database.runs.push(run);
      database.messages.push(message);
      const snapshot = structuredClone(storedAgent);
      storedAgent.status = "busy";
      storedAgent.lastError = null;
      storedAgent.updatedAt = timestamp;
      return snapshot;
    });
    const execution = this.executeRun(agentAtStart, run);
    this.activeExecutions.set(agentId, execution);
    void execution
      .finally(() => {
        if (this.activeExecutions.get(agentId) === execution) {
          this.activeExecutions.delete(agentId);
        }
      })
      .catch(() => undefined);
    return { run, message };
  }

  async systemInfo(): Promise<Record<string, unknown>> {
    const configured = isModelConfigured(this.config);
    const provider = this.config.modelProvider;
    const degraded = this.runner.degradedControls();
    return {
      modelConfigured: configured,
      modelProvider: provider.id,
      modelProviderName: provider.name,
      modelBaseUrl: provider.baseUrl,
      model: provider.model || null,
      // Compatibility aliases for the Starter Kit Web UI.
      arkConfigured: configured,
      arkBaseUrl: provider.baseUrl,
      arkModel: provider.model || null,
      codexAvailable: await this.runner.isAvailable(),
      codexSandboxMode: this.config.codexSandboxMode,
      runtimeProvider: this.config.runtimeProvider,
      containerEngine:
        this.config.runtimeProvider === "container"
          ? this.config.containerEngine
          : null,
      runtime:
        this.config.runtimeProvider === "container"
          ? "Codex CLI in " + this.config.containerEngine + " Runtime"
          : "Codex CLI in application container",
      middleware: {
        policyEnforcement: this.config.policyEnforcement,
        spotlightPreamble: this.config.spotlightPreamble,
        ceiling: this.ceiling(),
        credentialBroker: {
          // The Runtime is given a run-scoped token; the Ark key stays in this process.
          enabled: true,
          port: this.broker.port,
          runtimeBaseUrl: this.broker.baseUrlFor(this.runner.brokerHost()),
          activeLeases: this.broker.activeLeaseCount(),
        },
        egressAllowlistEnforced: degraded.every(
          (item) => item.control !== "egress-allowlist",
        ),
        runtimeNetwork:
          this.config.runtimeProvider === "container"
            ? this.config.runtimeNetwork
            : null,
        perAgentCodexHome: true,
        degraded,
      },
    };
  }

  private async executeRun(agentAtStart: Agent, run: AgentRun): Promise<void> {
    const violations: PolicyViolation[] = [];
    let brokerToken: string | null = null;

    try {
      // ---- L1: freeze the budget BEFORE any untrusted content can be read. ----
      const budget: FrozenBudget = freeze(
        this.effectiveBudget(agentAtStart),
        agentAtStart.id,
        run.id,
        agentAtStart.budgetPolicy
          ? ["platform-ceiling", "agent-policy"]
          : ["platform-ceiling"],
      );
      brokerToken = this.broker.issue(agentAtStart.id, run.id);
      const codexHome = agentCodexHome(this.config, agentAtStart.id);
      const brokerBaseUrl = this.broker.baseUrlFor(this.runner.brokerHost());
      // Rewritten every turn: the address the Runtime uses to reach the broker depends on
      // where the control plane is placed, which can change between restarts.
      await writeCodexConfig(this.config, codexHome, brokerBaseUrl);

      await this.store.mutate((database) => {
        const storedRun = database.runs.find((item) => item.id === run.id);
        if (storedRun) {
          storedRun.status = "running";
          storedRun.startedAt = now();
          storedRun.budget = budget;
        }
      });

      this.recorder.record(
        agentAtStart.id,
        run.id,
        "budget.frozen",
        "Capability budget frozen",
        {
          commandClasses: [...budget.commandClasses],
          egressAllowlist: [...budget.egressAllowlist],
          maxSteps: budget.maxSteps,
          allowOutsideWorkspace: budget.allowOutsideWorkspace,
          narrowedBy: [...budget.narrowedBy],
        },
      );
      for (const item of this.runner.degradedControls()) {
        this.recorder.record(
          agentAtStart.id,
          run.id,
          "runtime.degraded",
          "Control not enforced by this Runtime profile: " + item.control,
          { control: item.control, reason: item.reason },
        );
      }

      const onEvent = (event: RunnerEvent): void =>
        this.onRunnerEvent(agentAtStart, run, event, violations);

      if (this.cancellationRequests.has(agentAtStart.id)) {
        throw new RunCancelledError();
      }
      const result = await this.runner.run({
        agentId: agentAtStart.id,
        runId: run.id,
        workspacePath: agentAtStart.workspacePath,
        // L1: the spotlight preamble states the frozen budget and the data/instruction
        // split. It is advisory only — a model that ignores it still meets L2 and L3.
        prompt:
          this.config.spotlightPreamble === "on"
            ? buildSpotlightPreamble(budget) + run.prompt
            : run.prompt,
        threadId: agentAtStart.codexThreadId,
        budget,
        codexHome,
        brokerToken,
        brokerBaseUrl,
        onEvent,
      });

      // ---- L4: redact before anything is persisted or returned. ----
      const redacted = redact(result.output, this.secrets);
      const completedAt = now();
      const events = this.recorder.drain(run.id);
      await this.store.mutate((database) => {
        const storedRun = database.runs.find((item) => item.id === run.id);
        const agent = database.agents.find(
          (item) => item.id === agentAtStart.id,
        );
        database.traces.push(...events);
        database.violations.push(...violations);
        if (!storedRun || !agent) return;
        storedRun.status = "completed";
        storedRun.output = redacted.text;
        storedRun.usage = result.usage;
        storedRun.completedAt = completedAt;
        storedRun.violationCount = violations.length;
        storedRun.redactions = redacted.redactions;
        storedRun.tainted = result.tainted;
        database.messages.push({
          id: randomUUID(),
          agentId: agent.id,
          runId: run.id,
          role: "assistant",
          content: redacted.text,
          createdAt: completedAt,
        });
        agent.status = "ready";
        agent.codexThreadId = result.threadId;
        agent.lastError = null;
        agent.updatedAt = completedAt;
      });
    } catch (error) {
      const completedAt = now();
      const cancelled = error instanceof RunCancelledError;
      const policyAborted = error instanceof PolicyAbortError;
      const rawMessage = error instanceof Error ? error.message : String(error);
      const message = redact(rawMessage, this.secrets).text;
      if (policyAborted) {
        this.recorder.record(
          agentAtStart.id,
          run.id,
          "run.aborted",
          "Turn aborted by policy enforcement",
          { reason: message },
        );
        // Mark the violation that ended the turn, for the operator-facing list.
        const terminal = violations.at(-1);
        if (terminal) terminal.terminal = true;
      }
      const events = this.recorder.drain(run.id);
      await this.store.mutate((database) => {
        const storedRun = database.runs.find((item) => item.id === run.id);
        const agent = database.agents.find(
          (item) => item.id === agentAtStart.id,
        );
        database.traces.push(...events);
        database.violations.push(...violations);
        if (storedRun) {
          storedRun.status = cancelled ? "cancelled" : "failed";
          storedRun.error = message;
          storedRun.completedAt = completedAt;
          storedRun.violationCount = violations.length;
          if (policyAborted) {
            storedRun.tainted = error.consumer.tainted;
          }
        }
        if (agent) {
          if (agent.status !== "stopped") {
            agent.status = cancelled ? "ready" : "error";
          }
          agent.lastError = cancelled ? null : message;
          agent.updatedAt = completedAt;
        }
      });
    } finally {
      // The run-scoped credential dies with the run.
      this.broker.revoke(brokerToken);
      this.broker.revokeRun(run.id);
    }
  }

  private onRunnerEvent(
    agent: Agent,
    run: AgentRun,
    event: RunnerEvent,
    violations: PolicyViolation[],
  ): void {
    switch (event.kind) {
      case "command.started":
        this.recorder.record(
          agent.id,
          run.id,
          "command.started",
          event.command,
          {
            stepIndex: event.stepIndex,
            command: event.command,
          },
        );
        return;
      case "command.completed":
        this.recorder.record(
          agent.id,
          run.id,
          "command.completed",
          "exit " + (event.exitCode ?? "?") + ": " + event.command,
          {
            command: event.command,
            exitCode: event.exitCode,
            output: event.output,
          },
        );
        return;
      case "file.change":
        this.recorder.record(
          agent.id,
          run.id,
          "file.change",
          "Workspace file change",
          event.detail,
        );
        return;
      case "reasoning":
        this.recorder.record(agent.id, run.id, "reasoning", event.text, {
          text: event.text,
        });
        return;
      case "agent.message":
        this.recorder.record(agent.id, run.id, "agent.message", event.text, {
          text: event.text,
        });
        return;
      case "policy.violation": {
        for (const detail of event.violations) {
          const violation: PolicyViolation = {
            id: randomUUID(),
            runId: run.id,
            agentId: agent.id,
            kind: detail.kind,
            detail: detail.detail,
            command: redact(event.command, this.secrets).text,
            at: now(),
            terminal: event.terminal,
          };
          violations.push(violation);
          this.recorder.record(
            agent.id,
            run.id,
            "policy.violation",
            detail.kind + ": " + detail.detail,
            {
              kind: detail.kind,
              command: violation.command,
              terminal: event.terminal,
            },
          );
        }
        return;
      }
      default:
        return;
    }
  }

  private async setStatus(id: string, status: Agent["status"]): Promise<Agent> {
    return this.store.mutate((database) => {
      const agent = database.agents.find((item) => item.id === id);
      if (!agent) {
        throw new HttpError(404, "Agent not found");
      }
      if (status === "ready" && agent.status === "busy") {
        throw new HttpError(
          409,
          "Stop the active run before starting this Agent",
        );
      }
      agent.status = status;
      if (status === "ready") agent.lastError = null;
      agent.updatedAt = now();
      return structuredClone(agent);
    });
  }

  private async cancelExecution(agentId: string): Promise<void> {
    this.cancellationRequests.add(agentId);
    try {
      await this.runner.cancel(agentId);
      const execution = this.activeExecutions.get(agentId);
      if (execution) {
        await execution;
      }
    } finally {
      this.cancellationRequests.delete(agentId);
    }
  }
}

export type { DegradedControl };
