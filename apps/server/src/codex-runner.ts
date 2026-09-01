import { execFile } from "node:child_process";
import { spawn, type ChildProcess } from "node:child_process";
import { promisify } from "node:util";
import { MODEL_API_KEY_ENV, type AppConfig } from "./config.js";
import { RunCancelledError } from "./errors.js";
import { sandboxModeForBudget } from "./middleware/capability.js";
import { CodexEventConsumer } from "./middleware/event-stream.js";
import type {
  AgentRunner,
  DegradedControl,
  RunnerRequest,
  RunnerResult,
} from "./types.js";

const execFileAsync = promisify(execFile);

export function buildCodexArgs(
  request: Pick<RunnerRequest, "workspacePath" | "prompt" | "threadId">,
  sandboxMode: AppConfig["codexSandboxMode"],
  workspacePath = request.workspacePath,
): string[] {
  const args = [
    "exec",
    "--json",
    "--sandbox",
    sandboxMode,
    "--skip-git-repo-check",
    "-C",
    workspacePath,
  ];
  if (request.threadId) {
    args.push("resume", request.threadId, request.prompt);
  } else {
    args.push(request.prompt);
  }
  return args;
}

/**
 * Local-process profile: Codex runs as a child of the control plane.
 *
 * L2's credential broker and per-Agent Codex home still apply here, but the network and
 * filesystem boundaries do NOT — the child shares this process's namespaces. That gap is
 * reported through `degradedControls()` rather than hidden, and shows up on every Run and
 * on /api/system.
 */
export class CodexRunner implements AgentRunner {
  private readonly active = new Map<
    string,
    {
      child: ChildProcess;
      cancelled: boolean;
      timedOut: boolean;
      outputExceeded: boolean;
      policyAborted: string | null;
      settled: Promise<void>;
      forceKillTimer: NodeJS.Timeout | null;
    }
  >();

  constructor(private readonly config: AppConfig) {}

  degradedControls(): DegradedControl[] {
    return [
      {
        control: "egress-allowlist",
        reason:
          "local-process Runtime shares the control plane network namespace; set " +
          "RUNTIME_PROVIDER=container for deterministic egress denial",
      },
      {
        control: "readonly-workspace",
        reason:
          "local-process Runtime cannot mount the workspace read-only; a read-only " +
          "budget is enforced only by the Codex sandbox, not by the mount",
      },
    ];
  }

  brokerHost(): string {
    return "127.0.0.1";
  }

  async isAvailable(): Promise<boolean> {
    try {
      await execFileAsync(this.config.codexBin, ["--version"], {
        timeout: 5_000,
        env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", NO_COLOR: "1" },
      });
      return true;
    } catch {
      return false;
    }
  }

  async cancel(agentId: string): Promise<boolean> {
    const active = this.active.get(agentId);
    if (!active) {
      return false;
    }
    active.cancelled = true;
    this.terminate(active);
    await active.settled;
    return true;
  }

  async run(request: RunnerRequest): Promise<RunnerResult> {
    if (this.active.has(request.agentId)) {
      throw new Error("Agent already has an active Codex process");
    }

    // The Codex sandbox level follows the frozen budget, clamped to the configured
    // ceiling. This profile cannot additionally mount the workspace read-only, which is
    // reported through degradedControls().
    const args = buildCodexArgs(
      request,
      sandboxModeForBudget(request.budget, this.config.codexSandboxMode),
    );
    const child = spawn(this.config.codexBin, args, {
      cwd: request.workspacePath,
      env: this.childEnvironment(request),
      stdio: ["ignore", "pipe", "pipe"],
    });
    const settled = new Promise<void>((resolve) => {
      child.once("close", () => resolve());
      child.once("error", () => resolve());
    });
    const active = {
      child,
      cancelled: false,
      timedOut: false,
      outputExceeded: false,
      policyAborted: null as string | null,
      settled,
      forceKillTimer: null as NodeJS.Timeout | null,
    };
    this.active.set(request.agentId, active);

    const consumer = new CodexEventConsumer({
      budget: request.budget,
      workspaceMount: request.workspacePath,
      enforcement: this.config.policyEnforcement,
      onEvent: request.onEvent,
      onTerminalViolation: (reason) => {
        active.policyAborted = reason;
        this.terminate(active);
      },
    });

    let stdout = "";
    let stderr = "";
    let totalBytes = 0;

    const consume = (chunk: Buffer, target: "stdout" | "stderr") => {
      totalBytes += chunk.byteLength;
      if (totalBytes > this.config.codexMaxOutputBytes) {
        active.outputExceeded = true;
        this.terminate(active);
        return;
      }
      if (target === "stdout") {
        stdout += chunk.toString("utf8");
        const lines = stdout.split(/\r?\n/);
        stdout = lines.pop() ?? "";
        for (const line of lines) {
          consumer.consumeLine(line);
        }
      } else {
        stderr += chunk.toString("utf8");
        if (stderr.length > 16_384) {
          stderr = stderr.slice(-16_384);
        }
      }
    };

    child.stdout.on("data", (chunk: Buffer) => consume(chunk, "stdout"));
    child.stderr.on("data", (chunk: Buffer) => consume(chunk, "stderr"));

    const timeout = setTimeout(() => {
      active.timedOut = true;
      this.terminate(active);
    }, this.config.codexTimeoutMs);
    timeout.unref();

    try {
      const exitCode = await new Promise<number>((resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code) => resolve(code ?? 1));
      });
      if (stdout.trim()) {
        consumer.consumeLine(stdout.trim());
      }
      if (active.policyAborted) {
        throw new PolicyAbortError(active.policyAborted, consumer);
      }
      if (active.cancelled) {
        throw new RunCancelledError();
      }
      if (active.timedOut) {
        throw new Error("Codex timed out after " + this.config.codexTimeoutMs + " ms");
      }
      if (active.outputExceeded) {
        throw new Error("Codex output exceeded CODEX_MAX_OUTPUT_BYTES");
      }
      if (exitCode !== 0) {
        const detail = consumer.errors.at(-1) ?? stderr.trim() ?? "No error detail";
        throw new Error("Codex exited with code " + exitCode + ": " + detail);
      }
      const output = consumer.messages.at(-1)?.trim();
      if (!output) {
        throw new Error("Codex completed without an agent message");
      }
      return {
        output,
        threadId: consumer.threadId,
        usage: consumer.usage,
        violations: consumer.violations,
        tainted: consumer.tainted,
        taintReasons: [...consumer.taintReasons],
        commandCount: consumer.commandCount,
      };
    } finally {
      clearTimeout(timeout);
      if (active.forceKillTimer) clearTimeout(active.forceKillTimer);
      this.active.delete(request.agentId);
    }
  }

  private terminate(active: {
    child: ChildProcess;
    forceKillTimer: NodeJS.Timeout | null;
  }): void {
    if (active.child.exitCode !== null || active.child.signalCode !== null) return;
    active.child.kill("SIGTERM");
    if (!active.forceKillTimer) {
      active.forceKillTimer = setTimeout(() => active.child.kill("SIGKILL"), 3_000);
      active.forceKillTimer.unref();
    }
  }

  /**
   * MODEL_API_KEY here is the run-scoped broker token, never the real provider key.
   * Nothing in this environment survives the run.
   */
  private childEnvironment(request: RunnerRequest): NodeJS.ProcessEnv {
    const inheritedNames = [
      "PATH",
      "TMPDIR",
      "LANG",
      "LC_ALL",
      "SSL_CERT_FILE",
      "SSL_CERT_DIR",
      "NODE_EXTRA_CA_CERTS",
      "TERM",
    ] as const;
    const environment: NodeJS.ProcessEnv = {
      CODEX_HOME: request.codexHome,
      HOME: request.workspacePath,
      [MODEL_API_KEY_ENV]: request.brokerToken,
      NO_COLOR: "1",
    };
    for (const name of inheritedNames) {
      if (process.env[name] !== undefined) environment[name] = process.env[name];
    }
    return environment;
  }
}

/** Thrown when the turn was killed because the budget was violated. */
export class PolicyAbortError extends Error {
  constructor(
    message: string,
    readonly consumer: CodexEventConsumer,
  ) {
    super(message);
    this.name = "PolicyAbortError";
  }
}
