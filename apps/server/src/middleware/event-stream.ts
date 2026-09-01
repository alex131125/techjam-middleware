/**
 * L3 - Structured consumption of the Codex `--json` event stream.
 *
 * The baseline Runtime parsed only `agent_message`, `thread.started`, `turn.completed`
 * and `error`, which meant every command the Agent executed was invisible to the control
 * plane. This consumer parses the whole stream, turns it into trace events, and evaluates
 * each `command_execution` against the frozen budget.
 *
 * Enforcement semantics: `item.started` carries the command string but races with the
 * command actually running, so a terminal violation aborts the TURN (stopping every
 * subsequent step) rather than the individual command. That distinction is deliberate and
 * is documented as such — the preventive boundary is L2.
 */

import type { FrozenBudget } from "./capability.js";
import { evaluateCommand, type PolicyViolationDetail } from "./policy.js";
import { detectTaint } from "./spotlight.js";
import type { RunUsage, RunnerEvent } from "../types.js";

export interface ConsumerOptions {
  budget: FrozenBudget;
  /** Path the workspace is mounted at inside the Runtime ("/workspace" or the host path). */
  workspaceMount: string;
  enforcement: "enforce" | "monitor";
  onEvent?: ((event: RunnerEvent) => void) | undefined;
  /** Invoked once, when a violation should terminate the turn. */
  onTerminalViolation: (reason: string) => void;
}

export class CodexEventConsumer {
  readonly messages: string[] = [];
  readonly errors: string[] = [];
  readonly violations: PolicyViolationDetail[] = [];
  readonly taintReasons = new Set<string>();
  threadId: string | null = null;
  usage: RunUsage | null = null;
  commandCount = 0;
  aborted = false;
  abortReason: string | null = null;

  constructor(private readonly options: ConsumerOptions) {}

  get tainted(): boolean {
    return this.taintReasons.size > 0;
  }

  consumeLine(line: string): void {
    const trimmed = line.trim();
    if (!trimmed) return;
    let event: Record<string, unknown>;
    try {
      event = JSON.parse(trimmed) as Record<string, unknown>;
    } catch {
      return;
    }

    if (event.type === "thread.started" && typeof event.thread_id === "string") {
      this.threadId = event.thread_id;
      return;
    }

    if (event.type === "turn.completed" && event.usage && typeof event.usage === "object") {
      const usage = event.usage as Record<string, unknown>;
      this.usage = {
        ...(typeof usage.input_tokens === "number" ? { inputTokens: usage.input_tokens } : {}),
        ...(typeof usage.cached_input_tokens === "number"
          ? { cachedInputTokens: usage.cached_input_tokens }
          : {}),
        ...(typeof usage.output_tokens === "number" ? { outputTokens: usage.output_tokens } : {}),
      };
      return;
    }

    if (event.type === "error") {
      this.errors.push(this.errorMessage(event));
      return;
    }

    if (event.type !== "item.started" && event.type !== "item.completed") return;
    const item = event.item;
    if (!item || typeof item !== "object") return;
    const record = item as Record<string, unknown>;

    switch (record.type) {
      case "agent_message":
        if (typeof record.text === "string") {
          this.messages.push(record.text);
          if (event.type === "item.completed") {
            this.options.onEvent?.({ kind: "agent.message", text: record.text });
          }
        }
        return;
      case "reasoning":
        if (event.type === "item.completed" && typeof record.text === "string") {
          this.options.onEvent?.({ kind: "reasoning", text: record.text });
        }
        return;
      case "error":
        if (typeof record.message === "string") this.errors.push(record.message);
        return;
      case "file_change":
      case "patch_apply":
        if (event.type === "item.completed") {
          this.options.onEvent?.({ kind: "file.change", detail: record });
        }
        return;
      case "command_execution":
        this.handleCommand(event.type as "item.started" | "item.completed", record);
        return;
      default:
        return;
    }
  }

  private handleCommand(
    phase: "item.started" | "item.completed",
    record: Record<string, unknown>,
  ): void {
    const command = typeof record.command === "string" ? record.command : "";
    if (!command) return;

    if (phase === "item.started") {
      const stepIndex = this.commandCount;
      this.commandCount += 1;
      this.options.onEvent?.({ kind: "command.started", command, stepIndex });

      const taint = detectTaint(command);
      for (const reason of taint.reasons) this.taintReasons.add(reason);

      const decision = evaluateCommand(this.options.budget, command, {
        workspaceMount: this.options.workspaceMount,
        stepIndex,
      });
      if (decision.allowed) return;

      this.violations.push(...decision.violations);
      const terminal = this.options.enforcement === "enforce" && !this.aborted;
      this.options.onEvent?.({
        kind: "policy.violation",
        command,
        violations: decision.violations,
        terminal,
      });
      if (terminal) {
        this.aborted = true;
        this.abortReason =
          "Policy violation: " + decision.violations.map((item) => item.detail).join("; ");
        this.options.onTerminalViolation(this.abortReason);
      }
      return;
    }

    const output = typeof record.aggregated_output === "string" ? record.aggregated_output : "";
    this.options.onEvent?.({
      kind: "command.completed",
      command,
      exitCode: typeof record.exit_code === "number" ? record.exit_code : null,
      output,
    });
  }

  private errorMessage(event: Record<string, unknown>): string {
    if (typeof event.message === "string") return event.message;
    if (typeof event.error === "string") return event.error;
    return "Codex reported an unknown error";
  }
}
