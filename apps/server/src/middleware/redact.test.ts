import { describe, expect, it } from "vitest";
import { redact, SecretRegistry } from "./redact.js";

describe("egress redaction", () => {
  it("removes a registered secret verbatim", () => {
    const registry = new SecretRegistry();
    registry.register("ark-super-secret-value-1234");
    const result = redact("the key is ark-super-secret-value-1234 ok", registry);
    expect(result.text).not.toContain("ark-super-secret-value-1234");
    expect(result.redactions).toContain("registered-secret");
  });

  it("removes credential-shaped values it was never told about", () => {
    const result = redact("token: ark-9f8e7d6c5b4a39281706abcdef012345");
    expect(result.text).toContain("[REDACTED:ark-key]");
  });

  it("removes every occurrence, not just the first", () => {
    const registry = new SecretRegistry();
    registry.register("ark-super-secret-value-1234");
    const result = redact(
      "ark-super-secret-value-1234 and again ark-super-secret-value-1234",
      registry,
    );
    expect(result.text).not.toContain("ark-super-secret-value-1234");
  });

  it("ignores values too short to redact safely", () => {
    const registry = new SecretRegistry();
    registry.register("abc");
    expect(redact("abc is fine here", registry).text).toBe("abc is fine here");
  });

  it("leaves ordinary output untouched", () => {
    const result = redact("Created hello.txt with the expected contents.");
    expect(result.text).toBe("Created hello.txt with the expected contents.");
    expect(result.redactions).toEqual([]);
  });
});

// Taint is a signal an operator reads, so it has to stay informative. A rule broad enough
// to fire on an Agent reading back its own output would make every turn look tainted.
import { detectTaint } from "./spotlight.js";

describe("taint detection", () => {
  it("flags third-party directories and remote fetches", () => {
    expect(detectTaint("/bin/bash -lc 'cat vendor/README.md'").tainted).toBe(true);
    expect(detectTaint("/bin/bash -lc 'cat node_modules/x/readme.md'").tainted).toBe(true);
    expect(detectTaint("/bin/bash -lc 'curl https://example.com/x'").tainted).toBe(true);
  });

  it("does not flag an Agent reading back its own workspace output", () => {
    expect(detectTaint("/bin/bash -lc 'cd /workspace && cat hello.txt'").tainted).toBe(false);
    expect(detectTaint("/bin/bash -lc 'ls -la'").tainted).toBe(false);
    expect(detectTaint("/bin/bash -lc 'npm test'").tainted).toBe(false);
  });
});
