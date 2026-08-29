import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";
import {
  buildContainerRunArgs,
  containerName,
  toHostPath,
} from "./container-codex-runner.js";
import { freeze, platformCeiling } from "./middleware/capability.js";
import type { RunnerRequest } from "./types.js";

const budget = freeze(
  platformCeiling("https://ark.cn-beijing.volces.com/api/v3", 40),
  "agent",
  "run",
  ["platform-ceiling"],
);

const runnerRequest = (overrides: Partial<RunnerRequest>): RunnerRequest => ({
  agentId: "agent",
  runId: "run-1",
  workspacePath: "/tmp/workspace",
  prompt: "do the thing",
  threadId: null,
  budget,
  codexHome: "/tmp/codex-home/agents/agent",
  brokerToken: "ark-run-ephemeral-token",
  brokerBaseUrl: "http://172.30.0.1:3001/ark",
  ...overrides,
});

describe("Container Codex runner", () => {
  it("builds an isolated Docker/Podman-compatible invocation", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      ARK_API_KEY: "secret-that-must-not-appear-in-argv",
      ARK_MODEL: "ep-test",
      CODEX_HOME: "/tmp/codex-home",
      RUNTIME_PROVIDER: "container",
      CONTAINER_ENGINE: "podman",
      CONTAINER_RUNTIME_IMAGE: "runtime:test",
      CONTAINER_USER: "501:20",
      RUNTIME_INSTANCE_ID: "test-instance",
    });
    const args = buildContainerRunArgs(
      runnerRequest({
        agentId: "agent/unsafe",
        workspacePath: "/tmp/agent-workspace",
        prompt: "write a small program",
        codexHome: "/tmp/codex-home/agents/agent-unsafe",
      }),
      config,
      "launchpad-runtime",
    );

    expect(containerName("agent/unsafe", "test-instance")).toBe(
      "launchpad-test-instance-agent-unsafe",
    );
    expect(args).toContain("runtime:test");
    expect(args).toContain("type=bind,src=/tmp/agent-workspace,dst=/workspace");
    expect(args).toContain(
      "type=bind,src=/tmp/codex-home/agents/agent-unsafe,dst=/codex-home",
    );
    expect(args).toContain("501:20");
    expect(args).toContain("workspace-write");
    expect(args).toContain("/workspace");
    expect(args).toContain("io.codejam.instance-id=test-instance");
    expect(args).toContain("keep-id");
    expect(args).not.toContain("secret-that-must-not-appear-in-argv");
  });

  // L2, the deterministic half of the defence. Each of these is a fix for a verified
  // hole in the baseline Runtime.
  it("places the Runtime on the internal network and withholds the Ark key", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      ARK_API_KEY: "ark-real-key-that-must-not-reach-the-runtime",
      ARK_MODEL: "ep-test",
      CODEX_HOME: "/tmp/codex-home",
      RUNTIME_PROVIDER: "container",
      RUNTIME_NETWORK: "launchpad-runtime",
    });
    const args = buildContainerRunArgs(runnerRequest({}), config, "launchpad-runtime");
    const flat = args.join(" ");

    // V2: no bridge network, so the Runtime has no route off the host.
    expect(args).toContain("launchpad-runtime");
    expect(flat).not.toContain("--network bridge");
    // V1: the Runtime receives a run-scoped token, never the real key.
    expect(args).toContain("ARK_API_KEY=ark-run-ephemeral-token");
    expect(flat).not.toContain("ark-real-key-that-must-not-reach-the-runtime");
    // V3: a Codex home scoped to this Agent alone.
    expect(args).toContain("type=bind,src=/tmp/codex-home/agents/agent,dst=/codex-home");
    expect(args).not.toContain("type=bind,src=/tmp/codex-home,dst=/codex-home");
    // Baseline hardening is kept.
    expect(args).toContain("no-new-privileges");
    expect(args).toContain("ALL");
  });

  // When the control plane is itself containerised, the engine resolves mount sources on
  // the host, so an untranslated /app path would silently mount an empty directory.
  it("rewrites bind-mount sources to host paths for sibling containers", () => {
    expect(toHostPath("/app/workspaces/a1", "/app/workspaces", "/srv/launchpad/workspaces")).toBe(
      "/srv/launchpad/workspaces/a1",
    );
    expect(toHostPath("/app/workspaces", "/app/workspaces", "/srv/w")).toBe("/srv/w");
    // No mapping configured: the path is used as-is.
    expect(toHostPath("/app/workspaces/a1", "/app/workspaces", null)).toBe("/app/workspaces/a1");
    // A path outside the mapped root is never rewritten.
    expect(toHostPath("/elsewhere/a1", "/app/workspaces", "/srv/w")).toBe("/elsewhere/a1");
    // A prefix that only looks similar must not match.
    expect(toHostPath("/app/workspaces-other/a1", "/app/workspaces", "/srv/w")).toBe(
      "/app/workspaces-other/a1",
    );
  });

  it("uses the host mount roots when the control plane is containerised", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      ARK_API_KEY: "ark-key",
      ARK_MODEL: "ep-test",
      AGENT_WORKSPACE_ROOT: "/app/workspaces",
      CODEX_HOME: "/app/codex-home",
      RUNTIME_PROVIDER: "container",
      RUNTIME_HOST_WORKSPACE_ROOT: "/srv/launchpad/workspaces",
      RUNTIME_HOST_CODEX_HOME: "/srv/launchpad/codex-home",
    });
    const args = buildContainerRunArgs(
      runnerRequest({
        workspacePath: "/app/workspaces/agent",
        codexHome: "/app/codex-home/agents/agent",
      }),
      config,
      "launchpad-runtime",
    );
    expect(args).toContain("type=bind,src=/srv/launchpad/workspaces/agent,dst=/workspace");
    expect(args).toContain(
      "type=bind,src=/srv/launchpad/codex-home/agents/agent,dst=/codex-home",
    );
  });

  // A: with no `write` class the workspace is not writable at all, so an obfuscated
  // write (`base64 -d | sh`) fails on the filesystem rather than having to be recognised.
  it("mounts the workspace read-only when the budget grants no write", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      ARK_API_KEY: "ark-key",
      ARK_MODEL: "ep-test",
      CODEX_HOME: "/tmp/codex-home",
      RUNTIME_PROVIDER: "container",
    });
    const readOnly = freeze(
      { ...platformCeiling("https://ark.cn-beijing.volces.com/api/v3", 40), commandClasses: ["read"] },
      "agent",
      "run",
      ["platform-ceiling", "agent-policy"],
    );
    const args = buildContainerRunArgs(
      runnerRequest({ budget: readOnly }),
      config,
      "launchpad-runtime",
    );
    expect(args).toContain("type=bind,src=/tmp/workspace,dst=/workspace,readonly");
    // B: and the Codex sandbox is tightened to match.
    expect(args).toContain("read-only");
    expect(args).not.toContain("workspace-write");
  });

  it("keeps the workspace writable when the budget grants write", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      ARK_API_KEY: "ark-key",
      ARK_MODEL: "ep-test",
      CODEX_HOME: "/tmp/codex-home",
      RUNTIME_PROVIDER: "container",
    });
    const args = buildContainerRunArgs(runnerRequest({}), config, "launchpad-runtime");
    expect(args).toContain("type=bind,src=/tmp/workspace,dst=/workspace");
    expect(args.join(" ")).not.toContain(",readonly");
    expect(args).toContain("workspace-write");
  });

  it("resumes a thread inside the mounted Runtime workspace", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      CODEX_HOME: "/tmp/codex-home",
      RUNTIME_PROVIDER: "container",
    });
    const args = buildContainerRunArgs(
      runnerRequest({ prompt: "continue", threadId: "thread-123" }),
      config,
      "launchpad-runtime",
    );
    expect(args.slice(-3)).toEqual(["resume", "thread-123", "continue"]);
    expect(args).not.toContain("keep-id");
  });
});
