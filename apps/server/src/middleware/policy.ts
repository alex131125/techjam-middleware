/**
 * L3 - Command classification and policy evaluation.
 *
 * This runs against the Codex `--json` event stream, on `item.started` for a
 * `command_execution` item. That event carries the full command string but arrives
 * concurrently with the command actually starting, so this layer is honestly a
 * DETECT-AND-CONTAIN control, not a preventive one: it can abort the turn and stop every
 * subsequent step, but it cannot un-run the step that tripped it.
 *
 * The preventive control lives at the container boundary (L2), where the operating system
 * enforces the budget and no model output is involved.
 */

import type { CapabilityBudget, CommandClass } from "./capability.js";
import { normalizeHost } from "./capability.js";

export type ViolationKind =
  | "command-class"
  | "egress"
  | "privilege"
  | "outside-workspace"
  | "credential-access"
  | "max-steps";

export interface PolicyViolationDetail {
  kind: ViolationKind;
  detail: string;
}

export interface CommandAnalysis {
  classes: CommandClass[];
  hosts: string[];
  binaries: string[];
  touchesCredentials: boolean;
  escapesWorkspace: boolean;
}

export interface PolicyDecision {
  allowed: boolean;
  analysis: CommandAnalysis;
  violations: PolicyViolationDetail[];
}

const NETWORK_BINARIES = new Set([
  "curl", "wget", "nc", "ncat", "netcat", "telnet", "ssh", "scp", "sftp",
  "rsync", "ftp", "socat", "dig", "nslookup", "host", "ping",
]);
const PRIVILEGE_BINARIES = new Set(["sudo", "su", "doas", "setcap", "chroot", "mount", "insmod", "modprobe"]);
const READ_BINARIES = new Set([
  "ls", "cat", "head", "tail", "grep", "rg", "find", "wc", "file", "stat",
  "pwd", "echo", "sed", "awk", "sort", "uniq", "diff", "cut", "tr", "basename", "dirname", "which",
]);
const WRITE_BINARIES = new Set(["touch", "mkdir", "cp", "mv", "rm", "rmdir", "tee", "ln", "chmod", "chown", "truncate"]);
const BUILD_BINARIES = new Set([
  "npm", "npx", "pnpm", "yarn", "node", "tsc", "make", "python", "python3",
  "pip", "pip3", "cargo", "go", "javac", "java", "gcc", "g++", "bash", "sh", "jest", "vitest",
]);
const VCS_BINARIES = new Set(["git", "gh"]);
/**
 * Shell plumbing that carries no capability of its own. Without this they fall through to
 * the "unrecognised means code execution" default, and `cd /workspace && ls` would be
 * denied under a read-only budget.
 */
const NEUTRAL_BINARIES = new Set(["cd", "true", "false", ":", "test", "[", "[[", "then", "do", "fi", "done", "else"]);
const PROCESS_BINARIES = new Set(["ps", "kill", "pkill", "top", "jobs", "sleep", "timeout", "env", "printenv", "export", "set"]);

/** Interpreter one-liners that reach the network without invoking a network binary. */
const INLINE_NETWORK_PATTERNS = [
  /\bfetch\s*\(/i,
  /\bXMLHttpRequest\b/i,
  /\brequire\s*\(\s*['"](?:https?|net|dgram|tls)['"]\s*\)/i,
  /\bimport\s+.*\bfrom\s+['"]node:(?:https?|net|dgram|tls)['"]/i,
  /\burllib(?:\.request)?\b/i,
  /\brequests\s*\.\s*(?:get|post|put|patch|delete)\b/i,
  /\bhttp\.client\b/i,
  /\bsocket\s*\.\s*socket\s*\(/i,
  /\bnew\s+WebSocket\b/i,
];

/** Patterns that read a credential out of the environment or a well-known secret store. */
const CREDENTIAL_PATTERNS = [
  /\bARK_API_KEY\b/,
  // The provider-neutral name the broker token is injected under; must stay in step with
  // MODEL_API_KEY_ENV in config.ts or a credential read stops being detected.
  /\bMODEL_API_KEY\b/,
  /\bGLM_API_KEY\b/,
  /\bZAI_API_KEY\b/,
  /\bAPP_AUTH_TOKEN\b/,
  /\bprintenv\b(?!\s+(?:PATH|HOME|PWD|LANG|TERM|USER|SHELL)\b)/,
  /\benv\b\s*(?:\||>|$)/,
  /process\.env(?!\s*\.\s*(?:PATH|HOME|PWD|NODE_ENV)\b)/,
  /\bos\.environ\b/,
  /\.aws\/credentials\b/,
  /\.ssh\/id_/,
  /\bauth\.json\b/,
  /\bconfig\.toml\b/,
];

/**
 * Remove here-document bodies before analysis.
 *
 * `cat > f <<'EOF' ... EOF` carries file CONTENT, not commands. Scanning it produces
 * false positives that abort legitimate turns: a TypeScript file containing
 * `from './hello'` reads as a reference to an absolute path `/hello`, which looks like a
 * workspace escape. The delimiter line and everything up to it is data.
 */
export function stripHeredocs(command: string): string {
  const lines = command.split("\n");
  const output: string[] = [];
  let index = 0;
  while (index < lines.length) {
    const line = lines[index]!;
    output.push(line);
    index += 1;
    const opener = /<<-?\s*(?:(['"])([A-Za-z_][A-Za-z0-9_]*)\1|([A-Za-z_][A-Za-z0-9_]*))/.exec(line);
    if (!opener) continue;
    const delimiter = opener[2] ?? opener[3];
    if (!delimiter) continue;
    while (index < lines.length && lines[index]!.trim() !== delimiter) index += 1;
    // Skip the delimiter line itself; it is not a command either.
    if (index < lines.length) index += 1;
  }
  return output.join("\n");
}

/** Split a shell line into command segments, respecting quotes. */
export function splitSegments(command: string): string[] {
  const segments: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  for (let index = 0; index < command.length; index += 1) {
    const char = command[index]!;
    const next = command[index + 1];
    if (quote) {
      current += char;
      if (char === quote && command[index - 1] !== "\\") quote = null;
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      current += char;
      continue;
    }
    if (char === "\n" || char === ";") {
      segments.push(current);
      current = "";
      continue;
    }
    if ((char === "&" && next === "&") || (char === "|" && next === "|")) {
      segments.push(current);
      current = "";
      index += 1;
      continue;
    }
    if (char === "|") {
      segments.push(current);
      current = "";
      continue;
    }
    current += char;
  }
  segments.push(current);
  return segments.map((segment) => segment.trim()).filter((segment) => segment.length > 0);
}

/**
 * Strip the `bash -lc ...` wrapper Codex puts around every command.
 *
 * Codex emits both quoted (`bash -lc 'ls -la'`) and bare (`bash -lc mount`) forms. Missing
 * the bare form is not cosmetic: the whole string then classifies as the wrapper binary
 * `bash`, so `bash -lc curl` would read as a build step rather than a network one.
 */
export function unwrapShell(command: string): string {
  const quoted = command.match(
    /^\s*(?:\/[\w./-]*\/)?(?:ba|z|da)?sh\s+(?:-[a-z]+\s+)*-[a-z]*c\s+(['"])([\s\S]*)\1\s*$/,
  );
  if (quoted) return quoted[2]!;
  const bare = command.match(
    /^\s*(?:\/[\w./-]*\/)?(?:ba|z|da)?sh\s+(?:-[a-z]+\s+)*-[a-z]*c\s+([\s\S]+?)\s*$/,
  );
  return bare ? bare[1]! : command;
}

function binaryOf(segment: string): string {
  const tokens = segment.split(/\s+/).filter(Boolean);
  for (const token of tokens) {
    // Skip leading VAR=value assignments and redirections.
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token)) continue;
    if (/^[<>]/.test(token)) continue;
    return token.replace(/^.*\//, "").replace(/^['"]|['"]$/g, "");
  }
  return "";
}

export function extractHosts(command: string): string[] {
  const hosts = new Set<string>();
  for (const match of command.matchAll(/\bhttps?:\/\/([^\s/'"`)\\]+)/gi)) {
    hosts.add(normalizeHost(match[1]!));
  }
  // Bare host:port or host arguments to network binaries (e.g. `nc evil.tld 443`).
  for (const match of command.matchAll(
    /\b(?:nc|ncat|netcat|telnet|ssh|ping|dig|nslookup|host)\s+(?:-\S+\s+)*([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})\b/gi,
  )) {
    hosts.add(normalizeHost(match[1]!));
  }
  return [...hosts];
}

export function analyzeCommand(rawCommand: string, workspaceMount: string): CommandAnalysis {
  const command = stripHeredocs(unwrapShell(rawCommand));
  const classes = new Set<CommandClass>();
  const binaries: string[] = [];

  for (const segment of splitSegments(command)) {
    const binary = binaryOf(segment);
    if (!binary) continue;
    binaries.push(binary);
    if (NEUTRAL_BINARIES.has(binary)) {
      // Still count a redirection on this segment; `cd x > y` writes.
      if (/(?:^|\s)>>?\s*\S/.test(segment)) classes.add("write");
      continue;
    }
    if (PRIVILEGE_BINARIES.has(binary)) classes.add("privilege");
    else if (NETWORK_BINARIES.has(binary)) classes.add("network");
    else if (VCS_BINARIES.has(binary)) classes.add("vcs");
    else if (BUILD_BINARIES.has(binary)) classes.add("build");
    else if (WRITE_BINARIES.has(binary)) classes.add("write");
    else if (PROCESS_BINARIES.has(binary)) classes.add("process");
    else if (READ_BINARIES.has(binary)) classes.add("read");
    else classes.add("build"); // Unrecognised executables are treated as code execution.

    // Output redirection is a write regardless of the binary.
    if (/(?:^|\s)>>?\s*\S/.test(segment)) classes.add("write");
  }

  if (INLINE_NETWORK_PATTERNS.some((pattern) => pattern.test(command))) classes.add("network");
  if (/\bchmod\s+[+]?s|\bsetuid\b/.test(command)) classes.add("privilege");

  const hosts = extractHosts(command);
  const touchesCredentials = CREDENTIAL_PATTERNS.some((pattern) => pattern.test(command));
  const escapesWorkspace = detectWorkspaceEscape(command, workspaceMount);

  return {
    classes: [...classes].sort(),
    hosts,
    binaries,
    touchesCredentials,
    escapesWorkspace,
  };
}

function detectWorkspaceEscape(command: string, workspaceMount: string): boolean {
  const mount = workspaceMount.replace(/\/+$/, "");
  // A path must begin at a token boundary. Without this, the `/hello` inside a relative
  // import such as `from './hello'` reads as an absolute path and aborts a valid turn.
  for (const match of command.matchAll(/(?:^|[\s'"=(,;|&`])(\/[A-Za-z0-9_.\-/]{2,})/g)) {
    const candidate = match[1]!;
    if (mount && (candidate === mount || candidate.startsWith(mount + "/"))) continue;
    // Paths that are always fine to touch: temp space and the shell itself.
    if (/^\/(?:tmp|dev\/null|dev\/urandom|usr|bin|sbin|lib|lib64|etc\/ssl|proc\/self)\b/.test(candidate)) {
      continue;
    }
    return true;
  }
  return /(?:^|[\s'"=])\.\.\/(?:\.\.\/)*/.test(command);
}

export function evaluateCommand(
  budget: CapabilityBudget,
  rawCommand: string,
  options: { workspaceMount: string; stepIndex: number },
): PolicyDecision {
  const analysis = analyzeCommand(rawCommand, options.workspaceMount);
  const violations: PolicyViolationDetail[] = [];

  if (options.stepIndex >= budget.maxSteps) {
    violations.push({
      kind: "max-steps",
      detail: "step " + (options.stepIndex + 1) + " exceeds the budget of " + budget.maxSteps,
    });
  }

  for (const item of analysis.classes) {
    if (!budget.commandClasses.includes(item)) {
      violations.push({
        kind: item === "privilege" ? "privilege" : "command-class",
        detail: "command class '" + item + "' is not in the frozen budget",
      });
    }
  }

  const allowedHosts = budget.egressAllowlist.map(normalizeHost);
  for (const host of analysis.hosts) {
    if (!allowedHosts.includes(host)) {
      violations.push({ kind: "egress", detail: "egress to '" + host + "' is not allowed" });
    }
  }

  if (analysis.touchesCredentials) {
    violations.push({
      kind: "credential-access",
      detail: "command reads a credential or a secret store",
    });
  }

  if (analysis.escapesWorkspace && !budget.allowOutsideWorkspace) {
    violations.push({
      kind: "outside-workspace",
      detail: "command references a path outside the Agent workspace",
    });
  }

  return { allowed: violations.length === 0, analysis, violations };
}
