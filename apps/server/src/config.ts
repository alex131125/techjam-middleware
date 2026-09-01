import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";

export const MODEL_API_KEY_ENV = "MODEL_API_KEY";

export type ModelProviderId = "glm" | "ark";

export interface ResolvedModelProvider {
  id: ModelProviderId;
  codexId: "zhipu_glm" | "volcengine_ark";
  name: string;
  apiKey: string;
  model: string;
  baseUrl: string;
}

const envSchema = z.object({
  HOST: z.string().default("0.0.0.0"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  LOG_LEVEL: z.string().default("info"),
  APP_DATA_DIR: z.string().default(path.resolve(".data")),
  AGENT_WORKSPACE_ROOT: z.string().default(path.resolve("workspaces")),
  CODEX_HOME: z.string().default(path.resolve("codex-home")),
  CODEX_BIN: z.string().default("codex"),
  CODEX_SANDBOX_MODE: z
    .enum(["read-only", "workspace-write", "danger-full-access"])
    .default("workspace-write"),
  CODEX_TIMEOUT_MS: z.coerce.number().int().min(1_000).default(600_000),
  CODEX_MAX_OUTPUT_BYTES: z.coerce
    .number()
    .int()
    .min(65_536)
    .default(2_097_152),
  RUNTIME_PROVIDER: z
    .enum(["local-process", "container"])
    .default("local-process"),
  CONTAINER_ENGINE: z.string().min(1).default("docker"),
  CONTAINER_RUNTIME_IMAGE: z
    .string()
    .min(1)
    .default("volc-agent-runtime:local"),
  CONTAINER_CPU_LIMIT: z.coerce.number().positive().default(2),
  CONTAINER_MEMORY_LIMIT: z
    .string()
    .regex(/^\d+(?:\.\d+)?[bkmg]$/i)
    .default("2g"),
  CONTAINER_PIDS_LIMIT: z.coerce.number().int().positive().default(256),
  CONTAINER_USER: z.string().optional(),
  BROKER_HOST: z.string().default("0.0.0.0"),
  BROKER_PORT: z.coerce.number().int().min(0).max(65535).default(3001),
  RUNTIME_NETWORK: z
    .string()
    .trim()
    .min(1)
    .max(64)
    .regex(/^[a-zA-Z0-9_.-]+$/)
    .default("launchpad-runtime"),
  // When the control plane itself runs in a container and launches sibling Runtime
  // containers, bind-mount sources must be HOST paths. These map the in-container roots
  // back to the host so `docker run --mount` resolves correctly.
  // Address the Runtime should use to reach the broker. Normally auto-detected; set it
  // when the control plane's own network placement cannot be discovered.
  BROKER_ADVERTISE_HOST: z.string().optional(),
  RUNTIME_HOST_WORKSPACE_ROOT: z.string().optional(),
  RUNTIME_HOST_CODEX_HOME: z.string().optional(),
  MAX_STEPS_PER_RUN: z.coerce.number().int().min(1).max(1000).default(40),
  MAX_MODEL_CALLS_PER_RUN: z.coerce.number().int().min(1).max(1000).default(80),
  POLICY_ENFORCEMENT: z.enum(["enforce", "monitor"]).default("enforce"),
  // The L1 spotlight preamble tells a cooperative model what the frozen budget is. Turn
  // it off to observe the deterministic layers on their own — which is what an adaptive
  // attacker's model would do anyway, since it simply ignores the preamble.
  SPOTLIGHT_PREAMBLE: z.enum(["on", "off"]).default("on"),
  RUNTIME_INSTANCE_ID: z
    .string()
    .trim()
    .min(1)
    .max(48)
    .regex(/^[a-zA-Z0-9_.-]+$/)
    .default("default"),
  APP_AUTH_TOKEN: z
    .string()
    .trim()
    .max(128)
    .regex(/^[A-Za-z0-9._~-]*$/, "APP_AUTH_TOKEN must use URL-safe characters")
    .optional(),
  MODEL_PROVIDER: z.enum(["glm", "ark"]).optional(),
  GLM_API_KEY: z.string().optional(),
  ZAI_API_KEY: z.string().optional(),
  GLM_MODEL: z.string().optional(),
  GLM_BASE_URL: z.string().url().default("https://open.bigmodel.cn/api/v1"),
  ARK_API_KEY: z.string().optional(),
  ARK_MODEL: z.string().optional(),
  ARK_BASE_URL: z
    .string()
    .url()
    .default("https://ark.cn-beijing.volces.com/api/v3"),
  NODE_ENV: z
    .enum(["development", "test", "production"])
    .default("development"),
});

export type AppConfig = ReturnType<typeof loadConfig>;

function isConfiguredValue(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  return (
    normalized.length > 0 &&
    !normalized.startsWith("replace-") &&
    !normalized.includes("your-") &&
    !normalized.includes("not-configured")
  );
}

export function loadConfig(environment: NodeJS.ProcessEnv = process.env) {
  const env = envSchema.parse(environment);
  const authToken = env.APP_AUTH_TOKEN?.trim() ?? "";
  const loopbackHosts = new Set(["127.0.0.1", "::1", "localhost"]);
  if (env.NODE_ENV === "production" && !loopbackHosts.has(env.HOST)) {
    if (authToken.length < 24 || authToken.startsWith("replace-")) {
      throw new Error(
        "APP_AUTH_TOKEN must contain at least 24 characters for a non-loopback production server",
      );
    }
  }
  const defaultContainerUser =
    typeof process.getuid === "function" && typeof process.getgid === "function"
      ? process.getuid() + ":" + process.getgid()
      : "1000:1000";
  const glmApiKey = env.GLM_API_KEY?.trim() || env.ZAI_API_KEY?.trim() || "";
  const arkApiKey = env.ARK_API_KEY?.trim() ?? "";
  const providerId: ModelProviderId =
    env.MODEL_PROVIDER ??
    (isConfiguredValue(glmApiKey)
      ? "glm"
      : isConfiguredValue(arkApiKey) || isConfiguredValue(env.ARK_MODEL ?? "")
        ? "ark"
        : "glm");
  const modelProvider: ResolvedModelProvider =
    providerId === "glm"
      ? {
          id: "glm",
          codexId: "zhipu_glm",
          name: "Zhipu GLM",
          apiKey: glmApiKey,
          model: env.GLM_MODEL?.trim() || "glm-5.3",
          baseUrl: env.GLM_BASE_URL.replace(/\/+$/, ""),
        }
      : {
          id: "ark",
          codexId: "volcengine_ark",
          name: "Volcengine Ark",
          apiKey: arkApiKey,
          model: env.ARK_MODEL?.trim() ?? "",
          baseUrl: env.ARK_BASE_URL.replace(/\/+$/, ""),
        };
  return {
    host: env.HOST,
    port: env.PORT,
    logLevel: env.LOG_LEVEL,
    dataDirectory: path.resolve(env.APP_DATA_DIR),
    workspaceRoot: path.resolve(env.AGENT_WORKSPACE_ROOT),
    codexHome: path.resolve(env.CODEX_HOME),
    codexBin: env.CODEX_BIN,
    codexSandboxMode: env.CODEX_SANDBOX_MODE,
    codexTimeoutMs: env.CODEX_TIMEOUT_MS,
    codexMaxOutputBytes: env.CODEX_MAX_OUTPUT_BYTES,
    runtimeProvider: env.RUNTIME_PROVIDER,
    containerEngine: env.CONTAINER_ENGINE,
    containerRuntimeImage: env.CONTAINER_RUNTIME_IMAGE,
    containerCpuLimit: env.CONTAINER_CPU_LIMIT,
    containerMemoryLimit: env.CONTAINER_MEMORY_LIMIT,
    containerPidsLimit: env.CONTAINER_PIDS_LIMIT,
    containerUser: env.CONTAINER_USER?.trim() || defaultContainerUser,
    runtimeInstanceId: env.RUNTIME_INSTANCE_ID,
    brokerHost: env.BROKER_HOST,
    brokerPort: env.BROKER_PORT,
    runtimeNetwork: env.RUNTIME_NETWORK,
    brokerAdvertiseHost: env.BROKER_ADVERTISE_HOST?.trim() || null,
    runtimeHostWorkspaceRoot: env.RUNTIME_HOST_WORKSPACE_ROOT?.trim() || null,
    runtimeHostCodexHome: env.RUNTIME_HOST_CODEX_HOME?.trim() || null,
    maxStepsPerRun: env.MAX_STEPS_PER_RUN,
    maxModelCallsPerRun: env.MAX_MODEL_CALLS_PER_RUN,
    policyEnforcement: env.POLICY_ENFORCEMENT,
    spotlightPreamble: env.SPOTLIGHT_PREAMBLE,
    authToken,
    modelProvider,
    nodeEnv: env.NODE_ENV,
  };
}

export function isModelConfigured(config: AppConfig): boolean {
  return (
    isConfiguredValue(config.modelProvider.apiKey) &&
    isConfiguredValue(config.modelProvider.model)
  );
}

export function modelProviderSetupHint(config: AppConfig): string {
  return config.modelProvider.id === "glm"
    ? "Set GLM_API_KEY (or ZAI_API_KEY) and optionally GLM_MODEL, then restart."
    : "Set ARK_API_KEY and ARK_MODEL, then restart.";
}

/**
 * Write a Codex config.toml into ONE Agent's private Codex home.
 *
 * `base_url` points at the credential broker rather than at the provider directly, and `env_key`
 * resolves to a run-scoped token rather than the real key, so the Runtime holds no
 * durable credential. See middleware/broker.ts.
 */
export async function writeCodexConfig(
  config: AppConfig,
  codexHome = config.codexHome,
  baseUrl = config.modelProvider.baseUrl,
): Promise<void> {
  await mkdir(codexHome, { recursive: true });
  const provider = config.modelProvider;
  const toml = [
    "# Generated by Volc Agent Launchpad. Edit environment variables, not this file.",
    "model = " + JSON.stringify(provider.model || "model-not-configured"),
    "model_provider = " + JSON.stringify(provider.codexId),
    "",
    "[model_providers." + provider.codexId + "]",
    "name = " +
      JSON.stringify(provider.name + " (via Launchpad credential broker)"),
    "base_url = " + JSON.stringify(baseUrl),
    "env_key = " + JSON.stringify(MODEL_API_KEY_ENV),
    'wire_api = "responses"',
    "requires_openai_auth = false",
    "",
  ].join("\n");
  await writeFile(path.join(codexHome, "config.toml"), toml, {
    encoding: "utf8",
    mode: 0o600,
  });
}

/** Per-Agent Codex home. Isolating these is the IsolateGPT-style control for V3. */
export function agentCodexHome(config: AppConfig, agentId: string): string {
  return path.join(config.codexHome, "agents", agentId);
}
