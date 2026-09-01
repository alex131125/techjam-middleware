/**
 * L3 - Trace recording.
 *
 * Events are buffered in memory while a Run is in flight, so the Playground can watch a
 * turn unfold without a disk write per event, and flushed to the JSON store when the Run
 * settles. Reads merge the persisted rows with the in-flight buffer, so a caller always
 * sees the whole timeline.
 *
 * Everything written here has already passed through redaction: a trace that leaks the
 * credential it was added to protect would be worse than no trace at all.
 */

import { randomUUID } from "node:crypto";
import type { TraceEvent, TraceEventType } from "../types.js";
import { redact, type SecretRegistry } from "./redact.js";

const MAX_DETAIL_CHARS = 4_000;

export class TraceRecorder {
  private readonly buffers = new Map<string, TraceEvent[]>();
  private readonly counters = new Map<string, number>();

  constructor(private readonly secrets: SecretRegistry) {}

  record(
    agentId: string,
    runId: string,
    type: TraceEventType,
    summary: string,
    detail?: Record<string, unknown>,
  ): TraceEvent {
    const sequence = (this.counters.get(runId) ?? 0) + 1;
    this.counters.set(runId, sequence);
    const event: TraceEvent = {
      id: randomUUID(),
      runId,
      agentId,
      sequence,
      type,
      at: new Date().toISOString(),
      summary: redact(summary, this.secrets).text.slice(0, 500),
      detail: detail ? this.sanitizeDetail(detail) : null,
    };
    const buffer = this.buffers.get(runId);
    if (buffer) buffer.push(event);
    else this.buffers.set(runId, [event]);
    return event;
  }

  /** Events recorded so far for a Run that has not been flushed yet. */
  pending(runId: string): TraceEvent[] {
    return this.buffers.get(runId) ?? [];
  }

  /** Hand over the buffered events and stop tracking the Run. */
  drain(runId: string): TraceEvent[] {
    const events = this.buffers.get(runId) ?? [];
    this.buffers.delete(runId);
    this.counters.delete(runId);
    return events;
  }

  private sanitizeDetail(detail: Record<string, unknown>): Record<string, unknown> {
    const output: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(detail)) {
      if (typeof value === "string") {
        output[key] = redact(value, this.secrets).text.slice(0, MAX_DETAIL_CHARS);
      } else if (
        typeof value === "number" ||
        typeof value === "boolean" ||
        value === null ||
        Array.isArray(value)
      ) {
        output[key] = value;
      } else if (value !== undefined) {
        output[key] = redact(JSON.stringify(value), this.secrets).text.slice(0, MAX_DETAIL_CHARS);
      }
    }
    return output;
  }
}
