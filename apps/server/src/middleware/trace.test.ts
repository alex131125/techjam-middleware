import { describe, expect, it } from "vitest";
import { SecretRegistry } from "./redact.js";
import { TraceRecorder } from "./trace.js";

describe("trace recording", () => {
  it("redacts secrets recursively inside nested arrays and objects", () => {
    const secret = "registered-secret-value-1234";
    const registry = new SecretRegistry();
    registry.register(secret);
    const recorder = new TraceRecorder(registry);

    const event = recorder.record("agent", "run", "file.change", "changed files", {
      changes: [
        { path: "notes.txt", metadata: ["token=" + secret] },
        [secret, { nested: secret }],
      ],
    });
    const serialised = JSON.stringify(event.detail);

    expect(serialised).not.toContain(secret);
    expect(serialised).toContain("[REDACTED:registered-secret]");
  });
});
