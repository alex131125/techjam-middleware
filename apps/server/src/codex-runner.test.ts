import { describe, expect, it } from "vitest";
import { buildCodexArgs } from "./codex-runner.js";

describe("Codex runner protocol", () => {
  it("builds a new-session invocation", () => {
    const args = buildCodexArgs(
      { workspacePath: "/tmp/workspace", prompt: "build a calculator", threadId: null },
      "workspace-write",
    );
    expect(args).toEqual([
      "exec",
      "--json",
      "--sandbox",
      "workspace-write",
      "--skip-git-repo-check",
      "-C",
      "/tmp/workspace",
      "build a calculator",
    ]);
  });

  it("resumes a stored Codex thread", () => {
    const args = buildCodexArgs(
      { workspacePath: "/tmp/workspace", prompt: "add tests", threadId: "thread-123" },
      "workspace-write",
    );
    expect(args.slice(-3)).toEqual(["resume", "thread-123", "add tests"]);
  });
});
