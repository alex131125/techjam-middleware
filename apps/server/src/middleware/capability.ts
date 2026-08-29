/**
 * L1 - Capability budget derivation and freezing.
 *
 * Design origin:
 *  - "Design Patterns for Securing LLM Agents against Prompt Injections" (arXiv:2506.08837),
 *    Plan-Then-Execute: the plan is fixed before untrusted data enters the context.
 *  - Progent (arXiv:2504.11703), monotonic confinement: a policy update may only ever
 *    narrow privileges. An expansion is rejected deterministically, so a policy proposal
 *    that has been manipulated by injected data cannot silently escalate.
 *
 * The budget is derived from trusted inputs only (platform ceiling + Agent configuration +
 * the operator's own prompt), frozen, and then handed to the Runtime as immutable
 * container parameters. Nothing the model reads afterwards can widen it.
 */

export const COMMAND_CLASSES = [
  "read",
  "write",
  "build",
  "vcs",
  "network",
  "process",
  "privilege",
] as const;

export type CommandClass = (typeof COMMAND_CLASSES)[number];

export interface CapabilityBudget {
  readonly version: 1;
  /** Command classes the Runtime may execute. Anything outside this set is a violation. */
  readonly commandClasses: readonly CommandClass[];
  /** Hostnames the Runtime may reach. Enforced deterministically at the network boundary. */
  readonly egressAllowlist: readonly string[];
  /** Maximum number of command executions in one turn. */
  readonly maxSteps: number;
  /** Whether the Runtime may touch paths outside its own workspace. */
  readonly allowOutsideWorkspace: boolean;
}

/** Codex's own sandbox levels, ordered from most to least confined. */
export type SandboxMode = "read-only" | "workspace-write" | "danger-full-access";

const SANDBOX_RANK: Record<SandboxMode, number> = {
  "read-only": 0,
  "workspace-write": 1,
  "danger-full-access": 2,
};

/**
 * Derive the Codex sandbox level a budget implies, then clamp it to the configured
 * ceiling. The result is always the NARROWER of the two, so a budget can tighten the
 * sandbox but can never loosen what the operator configured.
 *
 * This moves "no writes" and "stay in the workspace" out of command-text matching and
 * into Codex's own Landlock-backed enforcement, where an encoded or obfuscated command
 * has no advantage: the kernel does not read the command string.
 */
export function sandboxModeForBudget(
  budget: Pick<CapabilityBudget, "commandClasses" | "allowOutsideWorkspace">,
  configured: SandboxMode,
): SandboxMode {
  const implied: SandboxMode = !budget.commandClasses.includes("write")
    ? "read-only"
    : budget.allowOutsideWorkspace
      ? "danger-full-access"
      : "workspace-write";
  return SANDBOX_RANK[implied] <= SANDBOX_RANK[configured] ? implied : configured;
}

/** Whether the Agent workspace should be mounted writable for this budget. */
export function workspaceIsWritable(
  budget: Pick<CapabilityBudget, "commandClasses">,
): boolean {
  return budget.commandClasses.includes("write");
}

export interface FrozenBudget extends CapabilityBudget {
  readonly agentId: string;
  readonly runId: string;
  readonly frozenAt: string;
  /** Ordered record of how the ceiling was narrowed, for audit. */
  readonly narrowedBy: readonly string[];
}

/** A proposal may only remove capabilities. Fields left undefined are left unchanged. */
export interface BudgetProposal {
  commandClasses?: readonly string[] | undefined;
  egressAllowlist?: readonly string[] | undefined;
  maxSteps?: number | undefined;
  allowOutsideWorkspace?: boolean | undefined;
}

export class BudgetExpansionError extends Error {
  constructor(readonly detail: string) {
    super("Budget proposal would expand privileges: " + detail);
    this.name = "BudgetExpansionError";
  }
}

function isCommandClass(value: string): value is CommandClass {
  return (COMMAND_CLASSES as readonly string[]).includes(value);
}

/** Normalise a hostname for comparison: lowercase, no trailing dot, no port. */
export function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, "").replace(/:\d+$/, "");
}

/**
 * The platform ceiling. No budget may ever exceed this, and it is deliberately
 * conservative: no network class, no privilege class, egress limited to the model
 * endpoint, and the workspace is the only writable location.
 */
export function platformCeiling(arkBaseUrl: string, maxSteps: number): CapabilityBudget {
  let arkHost = "";
  try {
    arkHost = normalizeHost(new URL(arkBaseUrl).hostname);
  } catch {
    arkHost = "";
  }
  return {
    version: 1,
    commandClasses: ["read", "write", "build", "vcs", "process"],
    egressAllowlist: arkHost ? [arkHost] : [],
    maxSteps,
    allowOutsideWorkspace: false,
  };
}

/**
 * Deterministically check that `candidate` is no wider than `base`, in every dimension.
 * This is the Progent expansion check and it is the reason an injected policy proposal
 * cannot escalate: the check does not consult a model.
 */
export function assertNarrowing(base: CapabilityBudget, candidate: CapabilityBudget): void {
  const baseClasses = new Set(base.commandClasses);
  for (const item of candidate.commandClasses) {
    if (!baseClasses.has(item)) {
      throw new BudgetExpansionError("command class '" + item + "' is not in the current budget");
    }
  }
  const baseHosts = new Set(base.egressAllowlist.map(normalizeHost));
  for (const host of candidate.egressAllowlist) {
    if (!baseHosts.has(normalizeHost(host))) {
      throw new BudgetExpansionError("egress host '" + host + "' is not in the current budget");
    }
  }
  if (candidate.maxSteps > base.maxSteps) {
    throw new BudgetExpansionError(
      "maxSteps " + candidate.maxSteps + " exceeds the current budget of " + base.maxSteps,
    );
  }
  if (candidate.allowOutsideWorkspace && !base.allowOutsideWorkspace) {
    throw new BudgetExpansionError("allowOutsideWorkspace cannot be turned on");
  }
}

/**
 * Apply a proposal to a budget. Every field is intersected with the current value, so the
 * result is narrower-or-equal by construction; the explicit assertNarrowing afterwards
 * guards against a future edit breaking that invariant.
 */
export function narrow(base: CapabilityBudget, proposal: BudgetProposal): CapabilityBudget {
  const unknownClasses = (proposal.commandClasses ?? []).filter((item) => !isCommandClass(item));
  if (unknownClasses.length > 0) {
    throw new BudgetExpansionError("unknown command class '" + unknownClasses[0] + "'");
  }
  const requestedClasses = proposal.commandClasses as readonly CommandClass[] | undefined;
  const next: CapabilityBudget = {
    version: 1,
    commandClasses: requestedClasses
      ? base.commandClasses.filter((item) => requestedClasses.includes(item))
      : base.commandClasses,
    egressAllowlist: proposal.egressAllowlist
      ? base.egressAllowlist.filter((host) =>
          proposal.egressAllowlist!.map(normalizeHost).includes(normalizeHost(host)),
        )
      : base.egressAllowlist,
    maxSteps:
      proposal.maxSteps === undefined
        ? base.maxSteps
        : Math.max(1, Math.min(base.maxSteps, Math.floor(proposal.maxSteps))),
    allowOutsideWorkspace:
      proposal.allowOutsideWorkspace === undefined
        ? base.allowOutsideWorkspace
        : proposal.allowOutsideWorkspace && base.allowOutsideWorkspace,
  };
  assertNarrowing(base, next);
  return next;
}

/**
 * Reject a proposal that tries to widen, instead of silently clamping it. Used on the
 * operator-facing API so a caller learns their request was refused rather than trimmed.
 */
export function narrowStrict(base: CapabilityBudget, proposal: BudgetProposal): CapabilityBudget {
  if (proposal.commandClasses) {
    for (const item of proposal.commandClasses) {
      if (!isCommandClass(item)) {
        throw new BudgetExpansionError("unknown command class '" + item + "'");
      }
      if (!base.commandClasses.includes(item)) {
        throw new BudgetExpansionError(
          "command class '" + item + "' is not in the current budget",
        );
      }
    }
  }
  if (proposal.egressAllowlist) {
    const baseHosts = base.egressAllowlist.map(normalizeHost);
    for (const host of proposal.egressAllowlist) {
      if (!baseHosts.includes(normalizeHost(host))) {
        throw new BudgetExpansionError("egress host '" + host + "' is not in the current budget");
      }
    }
  }
  if (proposal.maxSteps !== undefined && proposal.maxSteps > base.maxSteps) {
    throw new BudgetExpansionError(
      "maxSteps " + proposal.maxSteps + " exceeds the current budget of " + base.maxSteps,
    );
  }
  if (proposal.allowOutsideWorkspace && !base.allowOutsideWorkspace) {
    throw new BudgetExpansionError("allowOutsideWorkspace cannot be turned on");
  }
  return narrow(base, proposal);
}

/**
 * Freeze the budget for one turn. Called before the prompt is assembled and before any
 * untrusted content is read, which is precisely what makes the result trustworthy.
 */
export function freeze(
  budget: CapabilityBudget,
  agentId: string,
  runId: string,
  narrowedBy: readonly string[],
): FrozenBudget {
  return {
    ...budget,
    commandClasses: [...budget.commandClasses],
    egressAllowlist: [...budget.egressAllowlist],
    agentId,
    runId,
    frozenAt: new Date().toISOString(),
    narrowedBy: [...narrowedBy],
  };
}
