/**
 * L4 - Egress redaction.
 *
 * Last line of defence: even when every other layer has been bypassed, a credential must
 * not reach the transcript, the trace store, or the browser. Redaction is applied to
 * Agent output, to command strings, and to captured command output before any of them is
 * persisted or returned.
 */

/** Values registered here are matched literally, so a leaked key is caught verbatim. */
export class SecretRegistry {
  private readonly secrets = new Set<string>();

  register(value: string | undefined | null): void {
    const trimmed = value?.trim();
    // Very short values would match everywhere and destroy the transcript.
    if (trimmed && trimmed.length >= 8) this.secrets.add(trimmed);
  }

  values(): string[] {
    return [...this.secrets];
  }
}

/** Shapes that look like credentials even when we do not hold the literal value. */
const PATTERNS: Array<{ label: string; pattern: RegExp }> = [
  { label: "ark-key", pattern: /\bark-[A-Za-z0-9_-]{16,}\b/g },
  { label: "openai-key", pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { label: "aws-key", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { label: "github-token", pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g },
  { label: "bearer", pattern: /\b[Bb]earer\s+[A-Za-z0-9._~+/-]{20,}={0,2}/g },
  { label: "jwt", pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { label: "private-key", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
];

export interface RedactionResult {
  text: string;
  redactions: string[];
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function redact(text: string, registry?: SecretRegistry): RedactionResult {
  if (!text) return { text, redactions: [] };
  const redactions: string[] = [];
  let output = text;

  for (const secret of registry?.values() ?? []) {
    const pattern = new RegExp(escapeRegExp(secret), "g");
    if (pattern.test(output)) {
      output = output.replace(pattern, "[REDACTED:registered-secret]");
      redactions.push("registered-secret");
    }
  }

  for (const { label, pattern } of PATTERNS) {
    // A fresh RegExp per call keeps lastIndex from leaking between invocations.
    const scoped = new RegExp(pattern.source, pattern.flags);
    if (scoped.test(output)) {
      output = output.replace(new RegExp(pattern.source, pattern.flags), "[REDACTED:" + label + "]");
      redactions.push(label);
    }
  }

  return { text: output, redactions: [...new Set(redactions)] };
}
