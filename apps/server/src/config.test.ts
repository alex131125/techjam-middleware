import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  isModelConfigured,
  loadConfig,
  writeCodexConfig,
} from "./config.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

describe("Model provider configuration", () => {
  it("defaults to GLM and writes a secret-free Codex configuration", async () => {
    const codexHome = await mkdtemp(path.join(tmpdir(), "launchpad-config-"));
    temporaryDirectories.push(codexHome);
    const config = loadConfig({
      NODE_ENV: "test",
      CODEX_HOME: codexHome,
      GLM_API_KEY: "glm-secret",
    });

    expect(config.modelProvider).toMatchObject({
      id: "glm",
      codexId: "zhipu_glm",
      model: "glm-5.3",
      baseUrl: "https://open.bigmodel.cn/api/v1",
    });
    expect(isModelConfigured(config)).toBe(true);

    await writeCodexConfig(config);
    const toml = await readFile(path.join(codexHome, "config.toml"), "utf8");
    expect(toml).toContain('model_provider = "zhipu_glm"');
    expect(toml).toContain('env_key = "MODEL_API_KEY"');
    expect(toml).toContain('wire_api = "responses"');
    expect(toml).not.toContain("glm-secret");
  });

  it("auto-selects Ark for legacy ARK environment variables", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      ARK_API_KEY: "ark-secret",
      ARK_MODEL: "ep-test",
    });

    expect(config.modelProvider).toMatchObject({
      id: "ark",
      codexId: "volcengine_ark",
      model: "ep-test",
    });
    expect(isModelConfigured(config)).toBe(true);
  });

  it("does not fall back when the provider is selected explicitly", () => {
    const config = loadConfig({
      NODE_ENV: "test",
      MODEL_PROVIDER: "glm",
      ARK_API_KEY: "ark-secret",
      ARK_MODEL: "ep-test",
    });

    expect(config.modelProvider.id).toBe("glm");
    expect(isModelConfigured(config)).toBe(false);
  });
});
