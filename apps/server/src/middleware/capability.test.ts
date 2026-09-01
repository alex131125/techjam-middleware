import { describe, expect, it } from "vitest";
import {
  BudgetExpansionError,
  assertNarrowing,
  freeze,
  narrow,
  narrowStrict,
  platformCeiling,
  sandboxModeForBudget,
  workspaceIsWritable,
} from "./capability.js";

const ceiling = platformCeiling("https://ark.cn-beijing.volces.com/api/v3", 40);

describe("capability budget", () => {
  it("derives a conservative ceiling that excludes network and privilege", () => {
    expect(ceiling.commandClasses).not.toContain("network");
    expect(ceiling.commandClasses).not.toContain("privilege");
    expect(ceiling.egressAllowlist).toEqual(["ark.cn-beijing.volces.com"]);
    expect(ceiling.allowOutsideWorkspace).toBe(false);
  });

  it("narrows the command classes to the intersection", () => {
    const narrowed = narrow(ceiling, { commandClasses: ["read", "build"] });
    expect(narrowed.commandClasses).toEqual(["read", "build"]);
    expect(() => assertNarrowing(ceiling, narrowed)).not.toThrow();
  });

  // This is the Progent expansion check, and it is the property the whole L1 story
  // rests on: a proposal shaped by injected content still cannot escalate.
  it("rejects a proposal that adds a command class", () => {
    expect(() => narrowStrict(ceiling, { commandClasses: ["read", "network"] })).toThrow(
      BudgetExpansionError,
    );
  });

  it("rejects a proposal that adds an egress host", () => {
    expect(() => narrowStrict(ceiling, { egressAllowlist: ["attacker.tld"] })).toThrow(
      BudgetExpansionError,
    );
  });

  it("rejects a proposal that raises maxSteps", () => {
    expect(() => narrowStrict(ceiling, { maxSteps: 500 })).toThrow(BudgetExpansionError);
  });

  it("rejects a proposal that turns on workspace escape", () => {
    expect(() => narrowStrict(ceiling, { allowOutsideWorkspace: true })).toThrow(
      BudgetExpansionError,
    );
  });

  it("rejects an unknown command class instead of ignoring it", () => {
    expect(() => narrowStrict(ceiling, { commandClasses: ["exfiltrate"] })).toThrow(
      BudgetExpansionError,
    );
  });

  it("stays monotonic across repeated narrowing", () => {
    const once = narrowStrict(ceiling, { commandClasses: ["read", "build"], maxSteps: 20 });
    const twice = narrowStrict(once, { commandClasses: ["read"], maxSteps: 5 });
    expect(twice.commandClasses).toEqual(["read"]);
    expect(twice.maxSteps).toBe(5);
    // Widening back up from the narrowed budget is still refused.
    expect(() => narrowStrict(twice, { commandClasses: ["read", "build"] })).toThrow(
      BudgetExpansionError,
    );
  });

  it("marks the workspace writable only when the budget grants write", () => {
    expect(workspaceIsWritable({ commandClasses: ["read", "write"] })).toBe(true);
    expect(workspaceIsWritable({ commandClasses: ["read", "build"] })).toBe(false);
  });

  it("freezes a budget with its provenance", () => {
    const frozen = freeze(ceiling, "agent-1", "run-1", ["platform-ceiling"]);
    expect(frozen.agentId).toBe("agent-1");
    expect(frozen.runId).toBe("run-1");
    expect(frozen.narrowedBy).toEqual(["platform-ceiling"]);
    expect(Date.parse(frozen.frozenAt)).not.toBeNaN();
  });
});

// Moving "no writes" and "stay in the workspace" onto Codex's own sandbox takes them out
// of command-text matching, where an encoded command could slip past, and puts them where
// the kernel decides.
describe("budget to sandbox mapping", () => {
  it("uses the read-only sandbox when the budget grants no write", () => {
    expect(
      sandboxModeForBudget(
        { commandClasses: ["read", "build"], allowOutsideWorkspace: false },
        "workspace-write",
      ),
    ).toBe("read-only");
  });

  it("uses workspace-write when the budget grants write inside the workspace", () => {
    expect(
      sandboxModeForBudget(
        { commandClasses: ["read", "write"], allowOutsideWorkspace: false },
        "workspace-write",
      ),
    ).toBe("workspace-write");
  });

  // The important direction: a budget may tighten the sandbox, never loosen it.
  it("never widens past the configured ceiling", () => {
    expect(
      sandboxModeForBudget(
        { commandClasses: ["read", "write"], allowOutsideWorkspace: true },
        "workspace-write",
      ),
    ).toBe("workspace-write");
    expect(
      sandboxModeForBudget(
        { commandClasses: ["read", "write"], allowOutsideWorkspace: false },
        "read-only",
      ),
    ).toBe("read-only");
  });

  it("tightens a danger-full-access ceiling down to what the budget implies", () => {
    expect(
      sandboxModeForBudget(
        { commandClasses: ["read"], allowOutsideWorkspace: false },
        "danger-full-access",
      ),
    ).toBe("read-only");
    expect(
      sandboxModeForBudget(
        { commandClasses: ["read", "write"], allowOutsideWorkspace: false },
        "danger-full-access",
      ),
    ).toBe("workspace-write");
  });
});
