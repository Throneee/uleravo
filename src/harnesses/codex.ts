import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { parse as parseToml } from "smol-toml";
import { compareCodeUnits } from "../order.js";
import { boundedRedactedEvidence } from "../redact.js";
import { HARNESS_ANALYZER_VERSION, PRODUCT_NAME } from "../version.js";
import {
  CODEX_HARNESS_ADAPTER_VERSION,
  CODEX_HARNESS_SCHEMA_VERSION,
  type CodexAppInventory,
  type CodexCommandIdentity,
  type CodexDeclaredValue,
  type CodexHarnessApplicability,
  type CodexHarnessCoverage,
  type CodexHarnessDiagnostic,
  type CodexHarnessEvidence,
  type CodexHarnessInventory,
  type CodexHarnessLayer,
  type CodexHarnessLayerKind,
  type CodexHarnessSnapshot,
  type CodexHarnessSnapshotOptions,
  type CodexHookInventory,
  type CodexInventoryValue,
  type CodexMcpIdentity,
  type CodexMcpServerInventory,
  type CodexPluginInventory,
  type CodexSemanticFact,
  type CodexSkillInventory,
  type CodexToolInventory,
  MAX_HARNESS_CONFIG_BYTES,
  MAX_HARNESS_FACTS,
  MAX_HARNESS_REPORT_BYTES,
} from "./domain.js";

const utf8Decoder = new TextDecoder("utf-8", { fatal: true });
const HARD_MAX_CONFIG_BYTES = 10_000_000;
const MAX_INVENTORY_ENTRIES = 10_000;
const MAX_DISPLAY_CHARACTERS = 1_000;
const FEATURE_KEYS = [
  "apps",
  "browser_use",
  "browser_use_external",
  "browser_use_full_cdp_access",
  "computer_use",
  "hooks",
  "in_app_browser",
  "multi_agent",
  "plugins",
  "remote_plugin",
  "shell_tool",
  "skill_mcp_dependency_install",
  "unified_exec",
  "workspace_dependencies",
] as const;
const GRANULAR_APPROVAL_KEYS = [
  "mcp_elicitations",
  "request_permissions",
  "rules",
  "sandbox_approval",
  "skill_approval",
] as const;

type TomlObject = Record<string, unknown>;

interface LoadedLayer {
  readonly data?: TomlObject;
  readonly layer: CodexHarnessLayer;
}

interface LayerRequest {
  readonly disabled?: boolean;
  readonly explicit: boolean;
  readonly kind: CodexHarnessLayerKind;
  readonly label: string;
  readonly path?: string;
  readonly projectRoot?: string;
}

interface NormalizationContext {
  readonly diagnostics: CodexHarnessDiagnostic[];
  readonly facts: Map<string, CodexSemanticFact>;
  inventoryCount: number;
  normalizationLimitReported: boolean;
}

interface ParsedLayer {
  readonly applicability: CodexHarnessApplicability;
  readonly data: TomlObject;
  readonly kind: CodexHarnessLayerKind;
}

/**
 * Captures declared local Codex configuration without starting Codex, hooks, MCP servers,
 * commands, package managers, or network clients. The result is a deterministic declaration
 * snapshot, not a claim about complete effective runtime state.
 */
export async function snapshotCodexHarness(
  requestedProject: string,
  options: CodexHarnessSnapshotOptions = {},
): Promise<CodexHarnessSnapshot> {
  const maxConfigBytes = normalizeConfigLimit(options.maxConfigBytes);
  const projectRoot = await canonicalProjectDirectory(requestedProject);
  const diagnostics: CodexHarnessDiagnostic[] = [];

  const userRequest = resolveUserConfigRequest(options);
  const projectRequest = resolveProjectConfigRequest(projectRoot, options);
  const requirementsRequest = resolveRequirementsRequest(options);
  const [user, project, requirements] = await Promise.all([
    loadLayer(userRequest, maxConfigBytes, diagnostics),
    loadLayer(projectRequest, maxConfigBytes, diagnostics),
    loadLayer(requirementsRequest, maxConfigBytes, diagnostics),
  ]);

  const trust = resolveProjectTrust(user.data, projectRoot);
  const projectConfigApplicability = resolveProjectConfigApplicability(project, trust);
  const userApplicability: CodexHarnessApplicability =
    user.layer.status === "parsed" ? "applied" : "unknown";
  const requirementApplicability: CodexHarnessApplicability = "constraints";
  const layers: CodexHarnessLayer[] = [
    { ...user.layer, applicability: userApplicability },
    {
      ...project.layer,
      applicability:
        projectConfigApplicability === "not-present" ? "ignored" : projectConfigApplicability,
    },
    { ...requirements.layer, applicability: requirementApplicability },
  ];

  const context: NormalizationContext = {
    diagnostics,
    facts: new Map(),
    inventoryCount: 0,
    normalizationLimitReported: false,
  };
  const parsedLayers: ParsedLayer[] = [];
  if (user.data !== undefined) {
    parsedLayers.push({ applicability: userApplicability, data: user.data, kind: "user-config" });
  }
  if (project.data !== undefined) {
    parsedLayers.push({
      applicability:
        projectConfigApplicability === "not-present" ? "ignored" : projectConfigApplicability,
      data: project.data,
      kind: "project-config",
    });
  }
  if (requirements.data !== undefined) {
    parsedLayers.push({
      applicability: requirementApplicability,
      data: requirements.data,
      kind: "requirements",
    });
  }

  for (const parsedLayer of parsedLayers) {
    if (parsedLayer.applicability === "applied") {
      normalizeLocalSettings(parsedLayer, context);
    } else if (parsedLayer.applicability === "constraints") {
      normalizeRequirements(parsedLayer, context);
    }
  }
  if (trust.state === "declared") {
    addFact(context, {
      effect: "posture",
      evidence: [trust.evidence],
      key: "project.trust",
      rank: trust.value === "trusted" ? 1 : 0,
      value: trust.value,
    });
  }

  const inventory = normalizeInventory(parsedLayers, context);
  const codexVersion = normalizeCodexVersion(options.codexVersion);
  const semanticFacts = [...context.facts.values()].sort(compareFacts);
  const coverage = buildCoverage(
    user,
    project,
    requirements,
    trust,
    projectConfigApplicability,
    codexVersion,
  );
  diagnostics.sort(compareDiagnostics);
  const inputSha256 = digestInput(layers, codexVersion);
  const capture = { complete: diagnostics.length === 0, inputSha256 } as const;
  const reportWithoutId = {
    capture,
    codexVersion,
    coverage,
    diagnostics,
    documentType: "uleravo.harness-snapshot" as const,
    inventory,
    layers,
    project: {
      configApplicability: projectConfigApplicability,
      trust,
    },
    schemaVersion: CODEX_HARNESS_SCHEMA_VERSION,
    semanticFacts,
  };
  const id = createHash("sha256")
    .update("uleravo:codex-harness-snapshot:v1\0")
    .update(stableJson(reportWithoutId))
    .digest("hex")
    .slice(0, 24);
  const snapshot: CodexHarnessSnapshot = {
    ...reportWithoutId,
    harness: {
      adapter: { name: "openai-codex-local", version: CODEX_HARNESS_ADAPTER_VERSION },
      analyzer: { name: PRODUCT_NAME, version: HARNESS_ANALYZER_VERSION },
      id,
    },
  };
  enforceGeneratedReportSize(snapshot);
  return snapshot;
}

function enforceGeneratedReportSize(snapshot: CodexHarnessSnapshot): void {
  const serializedBytes = Buffer.byteLength(`${JSON.stringify(snapshot, null, 2)}\n`, "utf8");
  if (serializedBytes > MAX_HARNESS_REPORT_BYTES) {
    throw new Error(
      `Codex harness snapshot exceeds the ${MAX_HARNESS_REPORT_BYTES.toString()}-byte report limit.`,
    );
  }
}

function resolveUserConfigRequest(options: CodexHarnessSnapshotOptions): LayerRequest {
  if (options.userConfig === null) {
    return { disabled: true, explicit: false, kind: "user-config", label: "user/config.toml" };
  }
  if (options.userConfig !== undefined) {
    return {
      explicit: true,
      kind: "user-config",
      label: "user/config.toml",
      path: path.resolve(options.userConfig),
    };
  }
  const codexHome = process.env.CODEX_HOME?.trim();
  return {
    explicit: false,
    kind: "user-config",
    label: "user/config.toml",
    path: path.join(
      codexHome === undefined || codexHome.length === 0
        ? path.join(homedir(), ".codex")
        : codexHome,
      "config.toml",
    ),
  };
}

function resolveProjectConfigRequest(
  projectRoot: string,
  options: CodexHarnessSnapshotOptions,
): LayerRequest {
  if (options.projectConfig === null) {
    return {
      disabled: true,
      explicit: false,
      kind: "project-config",
      label: ".codex/config.toml",
      projectRoot,
    };
  }
  return {
    explicit: options.projectConfig !== undefined,
    kind: "project-config",
    label: ".codex/config.toml",
    path:
      options.projectConfig === undefined
        ? path.join(projectRoot, ".codex", "config.toml")
        : path.resolve(options.projectConfig),
    projectRoot,
  };
}

function resolveRequirementsRequest(options: CodexHarnessSnapshotOptions): LayerRequest {
  if (options.requirements === null) {
    return {
      disabled: true,
      explicit: false,
      kind: "requirements",
      label: "system/requirements.toml",
    };
  }
  if (options.requirements !== undefined) {
    return {
      explicit: true,
      kind: "requirements",
      label: "system/requirements.toml",
      path: path.resolve(options.requirements),
    };
  }
  const requirementsPath =
    process.platform === "win32"
      ? path.join(
          process.env.ProgramData ?? "C:\\ProgramData",
          "OpenAI",
          "Codex",
          "requirements.toml",
        )
      : "/etc/codex/requirements.toml";
  return {
    explicit: false,
    kind: "requirements",
    label: "system/requirements.toml",
    path: requirementsPath,
  };
}

async function canonicalProjectDirectory(requested: string): Promise<string> {
  const resolved = path.resolve(requested);
  const metadata = await lstat(resolved);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error("Codex harness target must be a regular project directory.");
  }
  return await realpath(resolved);
}

async function loadLayer(
  request: LayerRequest,
  maximumBytes: number,
  diagnostics: CodexHarnessDiagnostic[],
): Promise<LoadedLayer> {
  const base = {
    applicability: request.kind === "requirements" ? "constraints" : "unknown",
    kind: request.kind,
    label: request.label,
    pathSource: request.disabled ? "disabled" : request.explicit ? "user-supplied" : "detected",
  } as const;
  if (request.path === undefined) {
    return { layer: { ...base, status: "absent" } };
  }

  let metadata: Awaited<ReturnType<typeof lstat>>;
  try {
    metadata = await lstat(request.path);
  } catch (error) {
    if (hasErrorCode(error, "ENOENT")) {
      if (request.explicit) {
        diagnostics.push({
          code: "HARNESS_CONFIG_MISSING",
          layer: request.kind,
          message: `${request.label} was explicitly supplied but is missing.`,
          type: "error",
        });
      }
      return { layer: { ...base, status: "absent" } };
    }
    diagnostics.push({
      code: "HARNESS_CONFIG_UNSAFE",
      layer: request.kind,
      message: `${request.label} could not be inspected safely.`,
      type: "error",
    });
    return { layer: { ...base, status: "unsafe" } };
  }

  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    diagnostics.push({
      code: "HARNESS_CONFIG_UNSAFE",
      layer: request.kind,
      message: `${request.label} must be a regular, non-linked file.`,
      type: "error",
    });
    return { layer: { ...base, status: "unsafe" } };
  }
  if (metadata.size > maximumBytes) {
    diagnostics.push({
      code: "HARNESS_CONFIG_SIZE_LIMIT",
      layer: request.kind,
      message: `${request.label} exceeds the configured byte limit.`,
      type: "error",
    });
    return { layer: { ...base, bytes: metadata.size, status: "invalid" } };
  }

  if (request.projectRoot !== undefined) {
    const canonical = await realpath(request.path);
    const expected = path.join(request.projectRoot, ".codex", "config.toml");
    if (
      pathIdentity(canonical) !== pathIdentity(expected) ||
      !isWithin(request.projectRoot, canonical)
    ) {
      diagnostics.push({
        code: "HARNESS_CONFIG_UNSAFE",
        layer: request.kind,
        message: `${request.label} must be the regular project-local .codex/config.toml file.`,
        type: "error",
      });
      return { layer: { ...base, status: "unsafe" } };
    }
  }

  try {
    const bytes = await readStableFile(request.path, metadata, maximumBytes);
    const digest = sha256(bytes);
    let decoded: string;
    try {
      decoded = utf8Decoder.decode(bytes);
    } catch {
      diagnostics.push({
        code: "HARNESS_CONFIG_INVALID",
        layer: request.kind,
        message: `${request.label} is not valid UTF-8.`,
        type: "error",
      });
      return {
        layer: { ...base, bytes: bytes.byteLength, sha256: digest, status: "invalid" },
      };
    }
    let parsed: unknown;
    try {
      parsed = parseToml(decoded);
    } catch {
      diagnostics.push({
        code: "HARNESS_CONFIG_INVALID",
        layer: request.kind,
        message: `${request.label} is not valid TOML.`,
        type: "error",
      });
      return {
        layer: { ...base, bytes: bytes.byteLength, sha256: digest, status: "invalid" },
      };
    }
    const data = asObject(parsed);
    if (data === undefined) {
      diagnostics.push({
        code: "HARNESS_CONFIG_INVALID",
        layer: request.kind,
        message: `${request.label} must contain a TOML table.`,
        type: "error",
      });
      return {
        layer: { ...base, bytes: bytes.byteLength, sha256: digest, status: "invalid" },
      };
    }
    return {
      data,
      layer: { ...base, bytes: bytes.byteLength, sha256: digest, status: "parsed" },
    };
  } catch (error) {
    const changed = error instanceof ConfigChangedError;
    diagnostics.push({
      code: changed ? "HARNESS_CONFIG_CHANGED" : "HARNESS_CONFIG_UNSAFE",
      layer: request.kind,
      message: changed
        ? `${request.label} changed while it was being read.`
        : `${request.label} could not be read safely.`,
      type: "error",
    });
    return { layer: { ...base, status: "unsafe" } };
  }
}

class ConfigChangedError extends Error {}

async function readStableFile(
  file: string,
  listed: Awaited<ReturnType<typeof lstat>>,
  maximumBytes: number,
): Promise<Uint8Array> {
  const noFollow = constants.O_NOFOLLOW ?? 0;
  const handle = await open(file, constants.O_RDONLY | noFollow);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || !sameFileSnapshot(listed, opened)) {
      throw new ConfigChangedError();
    }
    const chunks: Buffer[] = [];
    let offset = 0;
    while (offset <= maximumBytes) {
      const buffer = Buffer.allocUnsafe(Math.min(64 * 1_024, maximumBytes + 1 - offset));
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, offset);
      if (bytesRead === 0) break;
      chunks.push(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    if (offset > maximumBytes) {
      throw new ConfigChangedError();
    }
    const [after, pathAfter] = await Promise.all([handle.stat(), lstat(file)]);
    if (
      !after.isFile() ||
      !pathAfter.isFile() ||
      pathAfter.isSymbolicLink() ||
      !sameFileSnapshot(opened, after) ||
      !sameFileSnapshot(opened, pathAfter) ||
      offset !== opened.size
    ) {
      throw new ConfigChangedError();
    }
    return Buffer.concat(chunks, offset);
  } finally {
    await handle.close();
  }
}

function resolveProjectTrust(
  userConfig: TomlObject | undefined,
  projectRoot: string,
): CodexInventoryValue<"trusted" | "untrusted"> {
  const projects = asObject(userConfig?.projects);
  if (projects === undefined) {
    return unavailable("No matching user-config project trust declaration was observed.");
  }
  const matches: Array<CodexDeclaredValue<"trusted" | "untrusted">> = [];
  for (const [declaredPath, value] of sortedEntries(projects)) {
    const project = asObject(value);
    const trustLevel = project?.trust_level;
    if (trustLevel !== "trusted" && trustLevel !== "untrusted") continue;
    if (!sameConfiguredPath(declaredPath, projectRoot)) continue;
    matches.push({
      evidence: { key: `projects.${keyLabel(declaredPath)}.trust_level`, layer: "user-config" },
      state: "declared",
      value: trustLevel,
    });
  }
  if (matches.length !== 1) {
    return unavailable(
      matches.length === 0
        ? "No matching user-config project trust declaration was observed."
        : "Multiple matching project trust declarations were observed.",
    );
  }
  return matches[0] ?? unavailable("Project trust could not be resolved.");
}

function resolveProjectConfigApplicability(
  project: LoadedLayer,
  trust: CodexInventoryValue<"trusted" | "untrusted">,
): "applied" | "ignored" | "not-present" | "unknown" {
  if (project.layer.status === "absent") return "not-present";
  if (project.layer.status !== "parsed") return "unknown";
  if (trust.state === "unavailable") return "unknown";
  return trust.value === "trusted" ? "applied" : "ignored";
}

function normalizeLocalSettings(layer: ParsedLayer, context: NormalizationContext): void {
  const source = (key: string): CodexHarnessEvidence => ({ key, layer: layer.kind });
  const approvalPolicy = layer.data.approval_policy;
  if (typeof approvalPolicy === "string") {
    const rank = approvalRank(approvalPolicy);
    addFact(context, {
      effect: "posture",
      evidence: [source("approval_policy")],
      key: "approval.policy",
      ...(rank === undefined ? {} : { rank }),
      value: safeText(approvalPolicy),
    });
  } else {
    const approval = asObject(approvalPolicy);
    const granular = asObject(approval?.granular);
    if (granular !== undefined) {
      for (const key of GRANULAR_APPROVAL_KEYS) {
        const value = granular[key];
        if (typeof value === "boolean") {
          addFact(context, {
            effect: "posture",
            evidence: [source(`approval_policy.granular.${key}`)],
            key: `approval.granular.${key.replaceAll("_", "-")}`,
            rank: value ? 1 : 0,
            value,
          });
        }
      }
    }
  }

  addRankedStringSetting(layer, context, "sandbox_mode", "filesystem.sandbox-mode", sandboxRank);
  addRankedStringSetting(
    layer,
    context,
    "default_permissions",
    "filesystem.default-permissions",
    permissionProfileRank,
  );
  addRankedStringSetting(layer, context, "web_search", "network.web-search", webSearchRank);
  normalizeLegacyWebSearch(layer, context, "network.web-search");
  addRankedStringSetting(
    layer,
    context,
    "approvals_reviewer",
    "approval.reviewer",
    approvalReviewerRank,
  );
  addBooleanAt(
    layer,
    context,
    layer.data,
    "allow_login_shell",
    "allow_login_shell",
    "shell.login-enabled",
    "exposure",
  );

  const workspace = asObject(layer.data.sandbox_workspace_write);
  if (workspace !== undefined) {
    addBooleanAt(
      layer,
      context,
      workspace,
      "network_access",
      "sandbox_workspace_write.network_access",
      "network.workspace-command-access",
      "exposure",
    );
    addBooleanAt(
      layer,
      context,
      workspace,
      "exclude_tmpdir_env_var",
      "sandbox_workspace_write.exclude_tmpdir_env_var",
      "filesystem.workspace.exclude-tmpdir-env-root",
      "guard",
    );
    addBooleanAt(
      layer,
      context,
      workspace,
      "exclude_slash_tmp",
      "sandbox_workspace_write.exclude_slash_tmp",
      "filesystem.workspace.exclude-slash-tmp-root",
      "guard",
    );
    for (const root of stringArray(workspace.writable_roots)) {
      addFact(context, {
        effect: "exposure",
        evidence: [source("sandbox_workspace_write.writable_roots")],
        key: `filesystem.writable-root.${keyPart(root)}`,
        value: safeText(root),
      });
    }
  }

  const features = asObject(layer.data.features);
  if (features !== undefined) {
    for (const key of FEATURE_KEYS) {
      addBooleanAt(
        layer,
        context,
        features,
        key,
        `features.${key}`,
        `feature.${key.replaceAll("_", "-")}`,
        "exposure",
      );
    }
    normalizeHookFeatureAlias(layer, context, features, "feature.hooks");
    normalizeNetworkProxyFeature(layer, context, features, "network.proxy-feature");
  }
  const agents = asObject(layer.data.agents);
  if (agents !== undefined) {
    addBooleanAt(
      layer,
      context,
      agents,
      "enabled",
      "agents.enabled",
      "feature.multi-agent",
      "exposure",
    );
  }
  const windows = asObject(layer.data.windows);
  if (windows !== undefined) {
    addStringAt(
      layer,
      context,
      windows,
      "sandbox",
      "windows.sandbox",
      "filesystem.windows-sandbox",
      "posture",
    );
    addBooleanAt(
      layer,
      context,
      windows,
      "sandbox_private_desktop",
      "windows.sandbox_private_desktop",
      "filesystem.windows-private-desktop",
      "guard",
    );
  }
  normalizePermissionProfiles(layer, context);
}

function normalizeRequirements(layer: ParsedLayer, context: NormalizationContext): void {
  const source = (key: string): CodexHarnessEvidence => ({ key, layer: "requirements" });
  for (const [configKey, factPrefix] of [
    ["allowed_approval_policies", "requirement.approval.allowed"],
    ["allowed_approvals_reviewers", "requirement.approval-reviewer.allowed"],
    ["allowed_sandbox_modes", "requirement.sandbox.allowed"],
    ["allowed_web_search_modes", "requirement.web-search.allowed"],
  ] as const) {
    const configured = layer.data[configKey];
    if (configured !== undefined) {
      const values =
        configKey === "allowed_web_search_modes" && Array.isArray(configured)
          ? [...new Set([...stringArray(configured), "disabled"])]
          : stringArray(configured);
      if (Array.isArray(configured)) {
        addFact(context, {
          effect: "guard",
          evidence: [source(configKey)],
          key: `${factPrefix}.allowlist-present`,
          rank: 1,
          value: true,
        });
      }
      for (const value of values) {
        addFact(context, {
          effect: "exposure",
          evidence: [source(configKey)],
          key: `${factPrefix}.${keyPart(value)}`,
          value: safeText(value),
        });
      }
    }
  }
  addRankedStringSetting(
    layer,
    context,
    "default_permissions",
    "requirement.default-permissions",
    permissionProfileRank,
  );
  for (const [key, effect] of [
    ["allow_login_shell", "exposure"],
    ["allow_managed_hooks_only", "guard"],
    ["allow_remote_control", "exposure"],
  ] as const) {
    addBooleanAt(
      layer,
      context,
      layer.data,
      key,
      key,
      `requirement.${key.replaceAll("_", "-")}`,
      effect,
    );
  }

  const allowedPermissionProfiles = asObject(layer.data.allowed_permission_profiles);
  if (allowedPermissionProfiles !== undefined) {
    addFact(context, {
      effect: "guard",
      evidence: [source("allowed_permission_profiles")],
      key: "requirement.permission-profile.allowlist-present",
      rank: 1,
      value: true,
    });
    for (const [name, value] of sortedEntries(allowedPermissionProfiles)) {
      if (typeof value !== "boolean") continue;
      addFact(context, {
        effect: "exposure",
        evidence: [source(`allowed_permission_profiles.${keyLabel(name)}`)],
        key: `requirement.permission-profile.${keyPart(name)}.allowed`,
        rank: value ? 1 : 0,
        value,
      });
    }
  }

  const windows = asObject(layer.data.windows);
  if (windows !== undefined) {
    addStringAllowlistFacts(
      context,
      stringArray(windows.allowed_sandbox_implementations),
      source("windows.allowed_sandbox_implementations"),
      "requirement.windows-sandbox.allowed",
      Array.isArray(windows.allowed_sandbox_implementations),
    );
    addBooleanAt(
      layer,
      context,
      windows,
      "sandbox_private_desktop",
      "windows.sandbox_private_desktop",
      "requirement.windows-private-desktop",
      "guard",
    );
  }
  normalizeRemoteSandboxRequirements(layer, context);

  const features = asObject(layer.data.features);
  if (features !== undefined) {
    for (const [key, value] of sortedEntries(features)) {
      if (
        key === "codex_hooks" ||
        key === "network_proxy" ||
        key === "web_search" ||
        key === "web_search_cached" ||
        key === "web_search_request"
      ) {
        continue;
      }
      if (typeof value !== "boolean") continue;
      addFact(context, {
        effect: "exposure",
        evidence: [source(`features.${keyLabel(key)}`)],
        key: `requirement.feature.${keyPart(key)}`,
        rank: value ? 1 : 0,
        value,
      });
    }
    normalizeHookFeatureAlias(layer, context, features, "requirement.feature.hooks");
    normalizeLegacyWebSearch(layer, context, "requirement.network.web-search");
    normalizeNetworkProxyFeature(layer, context, features, "requirement.network.proxy-feature");
  }

  const filesystem = asObject(asObject(layer.data.permissions)?.filesystem);
  for (const denied of stringArray(filesystem?.deny_read)) {
    addFact(context, {
      effect: "guard",
      evidence: [source("permissions.filesystem.deny_read")],
      key: `requirement.filesystem.deny-read.${keyPart(denied)}`,
      value: safeText(denied),
    });
  }
  normalizePermissionProfiles(layer, context);

  const network = asObject(layer.data.experimental_network);
  if (network !== undefined) {
    addBooleanAt(
      layer,
      context,
      network,
      "enabled",
      "experimental_network.enabled",
      "requirement.network.proxy-enabled",
      "exposure",
    );
    for (const [key, effect] of [
      ["allow_upstream_proxy", "exposure"],
      ["dangerously_allow_non_loopback_proxy", "exposure"],
      ["dangerously_allow_all_unix_sockets", "exposure"],
      ["managed_allowed_domains_only", "guard"],
      ["allow_local_binding", "exposure"],
    ] as const) {
      addBooleanAt(
        layer,
        context,
        network,
        key,
        `experimental_network.${key}`,
        `requirement.network.${key.replaceAll("_", "-")}`,
        effect,
      );
    }
    for (const domain of stringArray(network.allowed_domains)) {
      addFact(context, {
        effect: "exposure",
        evidence: [source("experimental_network.allowed_domains")],
        key: `requirement.network.domain.${keyPart(domain)}`,
        value: `allow:${safeText(domain)}`,
      });
    }
    for (const domain of stringArray(network.denied_domains)) {
      addFact(context, {
        effect: "guard",
        evidence: [source("experimental_network.denied_domains")],
        key: `requirement.network.domain.${keyPart(domain)}`,
        value: `deny:${safeText(domain)}`,
      });
    }
    const domains = asObject(network.domains);
    if (domains !== undefined) {
      for (const [domain, decision] of sortedEntries(domains)) {
        if (decision !== "allow" && decision !== "deny") continue;
        addFact(context, {
          effect: decision === "allow" ? "exposure" : "guard",
          evidence: [source(`experimental_network.domains.${keyLabel(domain)}`)],
          key: `requirement.network.domain.${keyPart(domain)}`,
          value: `${decision}:${safeText(domain)}`,
        });
      }
    }
    normalizeDecisionTable(
      asObject(network.unix_sockets),
      layer,
      context,
      "experimental_network.unix_sockets",
      "requirement.network.unix-socket",
    );
  }
  normalizeRequirementMcpAllowlist(layer, context);
  normalizeRequirementPluginAllowlist(layer, context);
  normalizeRequirementApps(layer, context);
}

function normalizePermissionProfiles(layer: ParsedLayer, context: NormalizationContext): void {
  const permissions = asObject(layer.data.permissions);
  if (permissions === undefined) return;
  for (const [name, rawProfile] of sortedEntries(permissions)) {
    if (name === "filesystem") continue;
    const profile = asObject(rawProfile);
    if (profile === undefined) continue;
    const profileKey = `${
      layer.kind === "requirements" ? "requirement.permission-profile" : "permission-profile"
    }.${keyPart(name)}`;
    addFact(context, {
      effect: "exposure",
      evidence: [{ key: `permissions.${keyLabel(name)}`, layer: layer.kind }],
      key: `${profileKey}.declared`,
      value: true,
    });
    if (typeof profile.extends === "string") {
      addFact(context, {
        effect: "posture",
        evidence: [{ key: `permissions.${keyLabel(name)}.extends`, layer: layer.kind }],
        key: `${profileKey}.extends`,
        value: safeText(profile.extends),
      });
    }
    const workspaceRoots = asObject(profile.workspace_roots);
    if (workspaceRoots !== undefined) {
      for (const [root, enabled] of sortedEntries(workspaceRoots)) {
        if (typeof enabled !== "boolean") continue;
        addFact(context, {
          effect: "exposure",
          evidence: [
            {
              key: `permissions.${keyLabel(name)}.workspace_roots.${keyLabel(root)}`,
              layer: layer.kind,
            },
          ],
          key: `${profileKey}.workspace-root.${keyPart(root)}`,
          rank: enabled ? 1 : 0,
          value: enabled,
        });
      }
    }
    const filesystem = asObject(profile.filesystem);
    if (filesystem !== undefined) {
      flattenFilesystemRules(filesystem, [], name, profileKey, layer, context);
    }
    const network = asObject(profile.network);
    if (network !== undefined) {
      addBooleanAt(
        layer,
        context,
        network,
        "enabled",
        `permissions.${keyLabel(name)}.network.enabled`,
        `${profileKey}.network.enabled`,
        "exposure",
      );
      for (const key of [
        "enable_socks5",
        "enable_socks5_udp",
        "allow_upstream_proxy",
        "dangerously_allow_non_loopback_proxy",
        "dangerously_allow_all_unix_sockets",
        "allow_local_binding",
      ] as const) {
        addBooleanAt(
          layer,
          context,
          network,
          key,
          `permissions.${keyLabel(name)}.network.${key}`,
          `${profileKey}.network.${key.replaceAll("_", "-")}`,
          "exposure",
        );
      }
      if (typeof network.mode === "string") {
        const rank = network.mode === "limited" ? 0 : network.mode === "full" ? 1 : undefined;
        addFact(context, {
          effect: "exposure",
          evidence: [{ key: `permissions.${keyLabel(name)}.network.mode`, layer: layer.kind }],
          key: `${profileKey}.network.mode`,
          ...(rank === undefined ? {} : { rank }),
          value: safeText(network.mode),
        });
      }
      const domains = asObject(network.domains);
      if (domains !== undefined) {
        for (const [domain, decision] of sortedEntries(domains)) {
          if (decision !== "allow" && decision !== "deny") continue;
          addFact(context, {
            effect: decision === "allow" ? "exposure" : "guard",
            evidence: [
              {
                key: `permissions.${keyLabel(name)}.network.domains.${keyLabel(domain)}`,
                layer: layer.kind,
              },
            ],
            key: `${profileKey}.network.domain.${keyPart(domain)}`,
            value: `${decision}:${safeText(domain)}`,
          });
        }
      }
      normalizeDecisionTable(
        asObject(network.unix_sockets),
        layer,
        context,
        `permissions.${keyLabel(name)}.network.unix_sockets`,
        `${profileKey}.network.unix-socket`,
      );
      addUrlSettingIdentity(
        layer,
        context,
        network,
        "proxy_url",
        `permissions.${keyLabel(name)}.network.proxy_url`,
        `${profileKey}.network.proxy-url-identity`,
      );
      addUrlSettingIdentity(
        layer,
        context,
        network,
        "socks_url",
        `permissions.${keyLabel(name)}.network.socks_url`,
        `${profileKey}.network.socks-url-identity`,
      );
    }
  }
}

function flattenFilesystemRules(
  table: TomlObject,
  segments: readonly string[],
  profileName: string,
  profileKey: string,
  layer: ParsedLayer,
  context: NormalizationContext,
): void {
  for (const [key, value] of sortedEntries(table)) {
    if (key === "glob_scan_max_depth") continue;
    const next = [...segments, key];
    if (value === "read" || value === "write" || value === "deny") {
      const scope = next.join("/");
      addFact(context, {
        effect: value === "deny" ? "guard" : "exposure",
        evidence: [
          {
            key: `permissions.${keyLabel(profileName)}.filesystem.${next.map(keyLabel).join(".")}`,
            layer: layer.kind,
          },
        ],
        key: `${profileKey}.filesystem.${keyPart(scope)}`,
        rank: value === "deny" ? 0 : value === "read" ? 1 : 2,
        value,
      });
      continue;
    }
    const child = asObject(value);
    if (child !== undefined && next.length < 8) {
      flattenFilesystemRules(child, next, profileName, profileKey, layer, context);
    }
  }
}

function normalizeRequirementMcpAllowlist(layer: ParsedLayer, context: NormalizationContext): void {
  const mcpServers = asObject(layer.data.mcp_servers);
  if (mcpServers === undefined) return;
  addFact(context, {
    effect: "guard",
    evidence: [{ key: "mcp_servers", layer: "requirements" }],
    key: "requirement.mcp.allowlist-present",
    rank: 1,
    value: true,
  });
  for (const [id, raw] of sortedEntries(mcpServers)) {
    const identity = normalizeMcpIdentity(asObject(raw), true);
    addFact(context, {
      effect: "exposure",
      evidence: [{ key: `mcp_servers.${keyLabel(id)}.identity`, layer: "requirements" }],
      key: `requirement.mcp.server.${keyPart(id)}.allowed`,
      value: identityDigest(identity),
    });
  }
}

function normalizeRequirementPluginAllowlist(
  layer: ParsedLayer,
  context: NormalizationContext,
): void {
  const plugins = asObject(layer.data.plugins);
  if (plugins === undefined) return;
  addFact(context, {
    effect: "guard",
    evidence: [{ key: "plugins", layer: "requirements" }],
    key: "requirement.plugin-mcp.allowlist-present",
    rank: 1,
    value: true,
  });
  for (const [pluginId, rawPlugin] of sortedEntries(plugins)) {
    const servers = asObject(asObject(rawPlugin)?.mcp_servers);
    if (servers === undefined) continue;
    addFact(context, {
      effect: "guard",
      evidence: [{ key: `plugins.${keyLabel(pluginId)}.mcp_servers`, layer: "requirements" }],
      key: `requirement.plugin.${keyPart(pluginId)}.mcp.allowlist-present`,
      rank: 1,
      value: true,
    });
    for (const [serverId, rawServer] of sortedEntries(servers)) {
      const identity = normalizeMcpIdentity(asObject(rawServer), true);
      addFact(context, {
        effect: "exposure",
        evidence: [
          {
            key: `plugins.${keyLabel(pluginId)}.mcp_servers.${keyLabel(serverId)}.identity`,
            layer: "requirements",
          },
        ],
        key: `requirement.plugin.${keyPart(pluginId)}.mcp.${keyPart(serverId)}.allowed`,
        value: identityDigest(identity),
      });
    }
  }
}

function normalizeRequirementApps(layer: ParsedLayer, context: NormalizationContext): void {
  const apps = asObject(layer.data.apps);
  if (apps === undefined) return;
  for (const [id, rawApp] of sortedEntries(apps)) {
    const app = asObject(rawApp);
    if (app === undefined) continue;
    const base = `requirement.app.${keyPart(id)}`;
    addBooleanAt(
      layer,
      context,
      app,
      "enabled",
      `apps.${keyLabel(id)}.enabled`,
      `${base}.enabled`,
      "exposure",
    );
    const tools = asObject(app.tools);
    if (tools === undefined) continue;
    for (const [toolName, rawTool] of sortedEntries(tools)) {
      const approvalMode = asObject(rawTool)?.approval_mode;
      if (typeof approvalMode !== "string") continue;
      addFact(context, {
        effect: "posture",
        evidence: [
          {
            key: `apps.${keyLabel(id)}.tools.${keyLabel(toolName)}.approval_mode`,
            layer: "requirements",
          },
        ],
        key: `${base}.tool.${keyPart(toolName)}.approval-mode`,
        value: safeText(approvalMode),
      });
    }
  }
}

function normalizeRemoteSandboxRequirements(
  layer: ParsedLayer,
  context: NormalizationContext,
): void {
  const entries = layer.data.remote_sandbox_config;
  if (!Array.isArray(entries)) return;
  for (const [index, raw] of entries.entries()) {
    const entry = asObject(raw);
    if (entry === undefined) continue;
    const base = `requirement.remote-sandbox.${index.toString()}`;
    for (const pattern of stringArray(entry.hostname_patterns)) {
      addFact(context, {
        effect: "identity",
        evidence: [
          {
            key: `remote_sandbox_config.${index.toString()}.hostname_patterns`,
            layer: "requirements",
          },
        ],
        key: `${base}.hostname-pattern.${keyPart(pattern)}`,
        value: safeText(pattern),
      });
    }
    addStringAllowlistFacts(
      context,
      stringArray(entry.allowed_sandbox_modes),
      {
        key: `remote_sandbox_config.${index.toString()}.allowed_sandbox_modes`,
        layer: "requirements",
      },
      `${base}.sandbox.allowed`,
      Array.isArray(entry.allowed_sandbox_modes),
    );
  }
}

function addStringAllowlistFacts(
  context: NormalizationContext,
  values: readonly string[],
  evidence: CodexHarnessEvidence,
  factPrefix: string,
  present: boolean,
): void {
  if (present) {
    addFact(context, {
      effect: "guard",
      evidence: [evidence],
      key: `${factPrefix}.allowlist-present`,
      rank: 1,
      value: true,
    });
  }
  for (const value of values) {
    addFact(context, {
      effect: "exposure",
      evidence: [evidence],
      key: `${factPrefix}.${keyPart(value)}`,
      value: safeText(value),
    });
  }
}

function normalizeInventory(
  layers: readonly ParsedLayer[],
  context: NormalizationContext,
): CodexHarnessInventory {
  const apps: CodexAppInventory[] = [];
  const hooks: CodexHookInventory[] = [];
  const mcpServers: CodexMcpServerInventory[] = [];
  const plugins: CodexPluginInventory[] = [];
  const skills: CodexSkillInventory[] = [];
  for (const layer of layers) {
    if (layer.kind !== "requirements") normalizeSkills(layer, context, skills);
    normalizeApps(layer, context, apps);
    normalizePlugins(layer, context, plugins, mcpServers);
    normalizeMcpTable(layer, context, mcpServers, undefined, layer.kind === "requirements");
    normalizeHooks(layer, context, hooks);
  }
  return {
    apps: apps.sort(compareInventory),
    hooks: hooks.sort(compareInventory),
    mcpServers: mcpServers.sort(compareInventory),
    plugins: plugins.sort(compareInventory),
    skills: skills.sort(compareInventory),
  };
}

function normalizeSkills(
  layer: ParsedLayer,
  context: NormalizationContext,
  output: CodexSkillInventory[],
): void {
  const config = asObject(layer.data.skills)?.config;
  if (!Array.isArray(config)) return;
  for (const [index, raw] of config.entries()) {
    if (!reserveInventory(context)) break;
    const entry = asObject(raw);
    if (entry === undefined || typeof entry.path !== "string") continue;
    const configuredPath = nonEmptySafeText(entry.path);
    const source = { key: `skills.config.${index.toString()}`, layer: layer.kind } as const;
    const skill: CodexSkillInventory = {
      applicability: layer.applicability,
      enabled: declaredBoolean(entry.enabled, `${source.key}.enabled`, layer.kind),
      path: configuredPath,
      pathSha256: sha256(Buffer.from(entry.path, "utf8")),
      source,
    };
    output.push(skill);
    if (layer.applicability === "applied") {
      addFact(context, {
        effect: "identity",
        evidence: [source],
        key: `skill.${skill.pathSha256.slice(0, 24)}.configured`,
        value: configuredPath,
      });
      if (skill.enabled.state === "declared") {
        addFact(context, {
          effect: "exposure",
          evidence: [skill.enabled.evidence],
          key: `skill.${skill.pathSha256.slice(0, 24)}.enabled`,
          rank: skill.enabled.value ? 1 : 0,
          value: skill.enabled.value,
        });
      }
    }
  }
}

function normalizeApps(
  layer: ParsedLayer,
  context: NormalizationContext,
  output: CodexAppInventory[],
): void {
  const apps = asObject(layer.data.apps);
  if (apps === undefined) return;
  for (const [id, raw] of sortedEntries(apps)) {
    if (!reserveInventory(context)) break;
    const app = asObject(raw);
    if (app === undefined) continue;
    const prefix = `apps.${keyLabel(id)}`;
    const inventory: CodexAppInventory = {
      applicability: layer.applicability,
      approvalsReviewer: declaredString(
        app.approvals_reviewer,
        `${prefix}.approvals_reviewer`,
        layer.kind,
      ),
      defaultToolsApprovalMode: declaredString(
        app.default_tools_approval_mode,
        `${prefix}.default_tools_approval_mode`,
        layer.kind,
      ),
      defaultToolsEnabled: declaredBoolean(
        app.default_tools_enabled,
        `${prefix}.default_tools_enabled`,
        layer.kind,
      ),
      destructiveEnabled: declaredBoolean(
        app.destructive_enabled,
        `${prefix}.destructive_enabled`,
        layer.kind,
      ),
      enabled: declaredBoolean(app.enabled, `${prefix}.enabled`, layer.kind),
      id: nonEmptySafeText(id),
      openWorldEnabled: declaredBoolean(
        app.open_world_enabled,
        `${prefix}.open_world_enabled`,
        layer.kind,
      ),
      source: { key: prefix, layer: layer.kind },
      tools: normalizeTools(asObject(app.tools), prefix, layer.kind, context),
    };
    output.push(inventory);
    if (layer.applicability === "applied") {
      const base = `app.${keyPart(id)}`;
      addFact(context, {
        effect: "identity",
        evidence: [inventory.source],
        key: `${base}.configured`,
        value: true,
      });
      addInventoryBooleanFacts(context, base, inventory, [
        ["enabled", inventory.enabled, "exposure"],
        ["default-tools-enabled", inventory.defaultToolsEnabled, "exposure"],
        ["destructive-enabled", inventory.destructiveEnabled, "exposure"],
        ["open-world-enabled", inventory.openWorldEnabled, "exposure"],
      ]);
      addInventoryStringFact(
        context,
        `${base}.default-tools-approval-mode`,
        inventory.defaultToolsApprovalMode,
      );
      addInventoryRankedStringFact(
        context,
        `${base}.approvals-reviewer`,
        inventory.approvalsReviewer,
        approvalReviewerRank,
      );
      for (const tool of inventory.tools) {
        if (tool.enabled.state === "declared") {
          addFact(context, {
            effect: "exposure",
            evidence: [tool.enabled.evidence],
            key: `${base}.tool.${keyPart(tool.name)}.enabled`,
            rank: tool.enabled.value ? 1 : 0,
            value: tool.enabled.value,
          });
        }
        addInventoryStringFact(
          context,
          `${base}.tool.${keyPart(tool.name)}.approval-mode`,
          tool.approvalMode,
        );
      }
    }
  }
}

function normalizePlugins(
  layer: ParsedLayer,
  context: NormalizationContext,
  output: CodexPluginInventory[],
  mcpOutput: CodexMcpServerInventory[],
): void {
  const plugins = asObject(layer.data.plugins);
  if (plugins === undefined) return;
  for (const [id, raw] of sortedEntries(plugins)) {
    if (!reserveInventory(context)) break;
    const plugin = asObject(raw);
    if (plugin === undefined) continue;
    const servers = asObject(plugin.mcp_servers);
    const source = { key: `plugins.${keyLabel(id)}`, layer: layer.kind } as const;
    if (layer.applicability === "applied") {
      addFact(context, {
        effect: "identity",
        evidence: [source],
        key: `plugin.${keyPart(id)}.configured`,
        value: true,
      });
    }
    const firstServer = mcpOutput.length;
    normalizeMcpTable(layer, context, mcpOutput, id, layer.kind === "requirements", servers);
    const serverIds = [...new Set(mcpOutput.slice(firstServer).map((server) => server.id))].sort(
      compareCodeUnits,
    );
    output.push({
      applicability: layer.applicability,
      id: nonEmptySafeText(id),
      mcpServerIds: serverIds,
      source,
    });
  }
}

function normalizeMcpTable(
  layer: ParsedLayer,
  context: NormalizationContext,
  output: CodexMcpServerInventory[],
  plugin: string | undefined,
  requirementIdentity: boolean,
  provided?: TomlObject,
): void {
  const servers = provided ?? asObject(layer.data.mcp_servers);
  if (servers === undefined) return;
  for (const [id, raw] of sortedEntries(servers)) {
    if (!reserveInventory(context)) break;
    const server = asObject(raw);
    if (server === undefined) continue;
    const configPrefix =
      plugin === undefined
        ? `mcp_servers.${keyLabel(id)}`
        : `plugins.${keyLabel(plugin)}.mcp_servers.${keyLabel(id)}`;
    const environmentNames = new Set<string>(Object.keys(asObject(server.env) ?? {}));
    for (const entry of Array.isArray(server.env_vars) ? server.env_vars : []) {
      if (typeof entry === "string") environmentNames.add(entry);
      else {
        const object = asObject(entry);
        if (typeof object?.name === "string") environmentNames.add(object.name);
      }
    }
    if (typeof server.bearer_token_env_var === "string") {
      environmentNames.add(server.bearer_token_env_var);
    }
    const headerNames = new Set([
      ...Object.keys(asObject(server.http_headers) ?? {}),
      ...Object.keys(asObject(server.env_http_headers) ?? {}),
    ]);
    const identity = normalizeMcpIdentity(server, requirementIdentity);
    const tools = normalizeTools(asObject(server.tools), configPrefix, layer.kind, context);
    const inventory: CodexMcpServerInventory = {
      applicability: layer.applicability,
      defaultToolsApprovalMode: declaredString(
        server.default_tools_approval_mode,
        `${configPrefix}.default_tools_approval_mode`,
        layer.kind,
      ),
      disabledTools: boundedInventoryStrings(sortedSafeStrings(server.disabled_tools), context),
      enabled: declaredBoolean(server.enabled, `${configPrefix}.enabled`, layer.kind),
      enabledTools: boundedInventoryStrings(sortedSafeStrings(server.enabled_tools), context),
      enabledToolsAllowlistPresent: Array.isArray(server.enabled_tools),
      environmentNames: boundedInventoryStrings(sortedSafeStrings([...environmentNames]), context),
      executionEnvironment: declaredString(
        server.experimental_environment,
        `${configPrefix}.experimental_environment`,
        layer.kind,
      ),
      headerNames: boundedInventoryStrings(sortedSafeStrings([...headerNames]), context),
      httpHeadersHelper: declaredCommandIdentity(
        server.http_headers_helper,
        `${configPrefix}.http_headers_helper`,
        layer.kind,
      ),
      id: nonEmptySafeText(id),
      identity,
      oauthScopes: boundedInventoryStrings(sortedSafeStrings(server.scopes), context),
      ...(plugin === undefined ? {} : { plugin: nonEmptySafeText(plugin) }),
      required: declaredBoolean(server.required, `${configPrefix}.required`, layer.kind),
      source: { key: configPrefix, layer: layer.kind },
      tools,
    };
    output.push(inventory);
    if (layer.applicability === "applied") {
      addMcpFacts(context, inventory, id, plugin);
    }
  }
}

function addMcpFacts(
  context: NormalizationContext,
  inventory: CodexMcpServerInventory,
  rawId: string,
  rawPlugin: string | undefined,
): void {
  const base =
    rawPlugin === undefined
      ? `mcp.${keyPart(rawId)}`
      : `plugin.${keyPart(rawPlugin)}.mcp.${keyPart(rawId)}`;
  addFact(context, {
    effect: "identity",
    evidence: [inventory.source],
    key: `${base}.configured`,
    value: true,
  });
  if (inventory.identity.kind !== "unavailable") {
    addFact(context, {
      effect: "identity",
      evidence: [inventory.source],
      key: `${base}.identity`,
      value: identityDigest(inventory.identity),
    });
  }
  addInventoryBooleanFacts(context, base, inventory, [
    ["enabled", inventory.enabled, "exposure"],
    ["required", inventory.required, "guard"],
  ]);
  addInventoryStringFact(
    context,
    `${base}.default-tools-approval-mode`,
    inventory.defaultToolsApprovalMode,
  );
  addInventoryStringFact(context, `${base}.execution-environment`, inventory.executionEnvironment);
  if (inventory.httpHeadersHelper.state === "declared") {
    addFact(context, {
      effect: "identity",
      evidence: [inventory.httpHeadersHelper.evidence],
      key: `${base}.http-headers-helper-identity`,
      value: digestOpaque(inventory.httpHeadersHelper.value),
    });
  }
  if (inventory.enabledToolsAllowlistPresent) {
    addFact(context, {
      effect: "guard",
      evidence: [inventory.source],
      key: `${base}.tool-allowlist-present`,
      rank: 1,
      value: true,
    });
  }
  for (const tool of inventory.enabledTools) {
    addFact(context, {
      effect: "exposure",
      evidence: [inventory.source],
      key: `${base}.tool.${keyPart(tool)}.enabled`,
      value: tool,
    });
  }
  for (const tool of inventory.disabledTools) {
    addFact(context, {
      effect: "guard",
      evidence: [inventory.source],
      key: `${base}.tool.${keyPart(tool)}.disabled`,
      value: tool,
    });
  }
  for (const scope of inventory.oauthScopes) {
    addFact(context, {
      effect: "exposure",
      evidence: [inventory.source],
      key: `${base}.oauth-scope.${keyPart(scope)}`,
      value: scope,
    });
  }
  for (const name of inventory.environmentNames) {
    addFact(context, {
      effect: "exposure",
      evidence: [inventory.source],
      key: `${base}.environment-name.${keyPart(name)}`,
      value: name,
    });
  }
  for (const name of inventory.headerNames) {
    addFact(context, {
      effect: "exposure",
      evidence: [inventory.source],
      key: `${base}.header-name.${keyPart(name)}`,
      value: name,
    });
  }
  for (const tool of inventory.tools) {
    if (tool.enabled.state === "declared") {
      addFact(context, {
        effect: "exposure",
        evidence: [tool.enabled.evidence],
        key: `${base}.tool.${keyPart(tool.name)}.enabled`,
        rank: tool.enabled.value ? 1 : 0,
        value: tool.enabled.value,
      });
    }
    if (tool.approvalMode.state === "declared") {
      addFact(context, {
        effect: "posture",
        evidence: [tool.approvalMode.evidence],
        key: `${base}.tool.${keyPart(tool.name)}.approval-mode`,
        value: tool.approvalMode.value,
      });
    }
  }
}

function normalizeMcpIdentity(
  server: TomlObject | undefined,
  requirement: boolean,
): CodexMcpIdentity {
  if (server === undefined)
    return { kind: "unavailable", reason: "No supported identity was declared." };
  const identity = requirement ? asObject(server.identity) : server;
  if (identity === undefined)
    return { kind: "unavailable", reason: "No supported identity was declared." };
  const commandValue = identity.command;
  if (typeof commandValue === "string") {
    const executable = requirement
      ? firstExecutable(commandValue)
      : explicitExecutable(commandValue);
    if (executable === undefined) {
      return { kind: "unavailable", reason: "No non-empty stdio executable was declared." };
    }
    const args = requirement ? [] : Array.isArray(server.args) ? server.args : [];
    return {
      argumentCount: args.length,
      argumentIdentitySha256: digestOpaque(requirement ? commandValue : args),
      commandIdentitySha256: sha256(Buffer.from(commandValue, "utf8")),
      executable,
      kind: "stdio",
    };
  }
  const command = asObject(commandValue);
  if (command !== undefined && typeof command.executable === "string") {
    const executable = explicitExecutable(command.executable);
    if (executable === undefined) {
      return { kind: "unavailable", reason: "No non-empty stdio executable was declared." };
    }
    const args = Array.isArray(command.args) ? command.args : [];
    return {
      argumentCount: args.length,
      argumentIdentitySha256: digestOpaque(args),
      commandIdentitySha256: sha256(Buffer.from(command.executable, "utf8")),
      executable,
      kind: "stdio",
    };
  }

  const urlValue = identity.url;
  if (typeof urlValue === "string") return normalizeUrlIdentity(urlValue);
  const urlMatcher = asObject(urlValue);
  if (urlMatcher !== undefined) {
    const matcherValue =
      typeof urlMatcher.value === "string"
        ? urlMatcher.value
        : typeof urlMatcher.expression === "string"
          ? urlMatcher.expression
          : undefined;
    if (matcherValue !== undefined) {
      const mode = typeof urlMatcher.match === "string" ? safeText(urlMatcher.match) : "matcher";
      return {
        credentialsPresent: /\/\/[^/\s]*@/u.test(matcherValue),
        kind: "http",
        queryParameterNames: [],
        url: `${mode}:sha256:${sha256(Buffer.from(matcherValue, "utf8"))}`,
        urlIdentitySha256: sha256(Buffer.from(matcherValue, "utf8")),
      };
    }
  }
  return { kind: "unavailable", reason: "No supported stdio or HTTP identity was declared." };
}

function normalizeUrlIdentity(raw: string): CodexMcpIdentity {
  try {
    const parsed = new URL(raw);
    const queryParameterNames = sortedSafeStrings([...parsed.searchParams.keys()]);
    const host = parsed.port.length === 0 ? parsed.hostname : `${parsed.hostname}:${parsed.port}`;
    return {
      credentialsPresent: parsed.username.length > 0 || parsed.password.length > 0,
      kind: "http",
      queryParameterNames,
      url: safeText(`${parsed.protocol}//${host}${parsed.pathname}`),
      urlIdentitySha256: sha256(Buffer.from(raw, "utf8")),
    };
  } catch {
    return {
      credentialsPresent: /\/\/[^/\s]*@/u.test(raw),
      kind: "http",
      queryParameterNames: [],
      url: `unparseable:sha256:${sha256(Buffer.from(raw, "utf8"))}`,
      urlIdentitySha256: sha256(Buffer.from(raw, "utf8")),
    };
  }
}

function normalizeTools(
  tools: TomlObject | undefined,
  prefix: string,
  layer: CodexHarnessLayerKind,
  context: NormalizationContext,
): CodexToolInventory[] {
  if (tools === undefined) return [];
  const output: CodexToolInventory[] = [];
  for (const [name, raw] of sortedEntries(tools)) {
    if (!reserveInventory(context)) break;
    const tool = asObject(raw);
    const key = `${prefix}.tools.${keyLabel(name)}`;
    output.push({
      approvalMode: declaredString(tool?.approval_mode, `${key}.approval_mode`, layer),
      enabled: declaredBoolean(tool?.enabled, `${key}.enabled`, layer),
      name: nonEmptySafeText(name),
    });
  }
  return output.sort((left, right) => compareCodeUnits(left.name, right.name));
}

function normalizeHooks(
  layer: ParsedLayer,
  context: NormalizationContext,
  output: CodexHookInventory[],
): void {
  const hooks = asObject(layer.data.hooks);
  if (hooks === undefined) return;
  for (const directoryKey of ["managed_dir", "windows_managed_dir"] as const) {
    const directory = hooks[directoryKey];
    if (typeof directory !== "string") continue;
    addFact(context, {
      effect: "identity",
      evidence: [{ key: `hooks.${directoryKey}`, layer: layer.kind }],
      key: `${layer.kind === "requirements" ? "requirement." : ""}hook.${directoryKey.replaceAll("_", "-")}`,
      value: `sha256:${sha256(Buffer.from(directory, "utf8"))}`,
    });
  }
  for (const [event, rawGroups] of sortedEntries(hooks)) {
    if (!Array.isArray(rawGroups)) continue;
    for (const [groupIndex, rawGroup] of rawGroups.entries()) {
      const group = asObject(rawGroup);
      const handlers = Array.isArray(group?.hooks) ? group.hooks : [];
      const matcher = typeof group?.matcher === "string" ? group.matcher : "";
      for (const [handlerIndex, rawHandler] of handlers.entries()) {
        if (!reserveInventory(context)) return;
        const handler = asObject(rawHandler);
        if (handler === undefined) continue;
        const type =
          typeof handler.type === "string" ? nonEmptySafeText(handler.type) : "unavailable";
        const handlerIdentity = normalizeHookHandlerIdentity(handler);
        const source: CodexHarnessEvidence = {
          key: `hooks.${keyLabel(event)}.${groupIndex.toString()}.hooks.${handlerIndex.toString()}`,
          layer: layer.kind,
        };
        const inventory: CodexHookInventory = {
          applicability: layer.applicability,
          asynchronous: declaredBoolean(handler.async, `${source.key}.async`, layer.kind),
          event: nonEmptySafeText(event),
          handler: handlerIdentity,
          handlerIdentitySha256: digestOpaque(handler),
          handlerIndex,
          matcherIdentitySha256: sha256(Buffer.from(matcher, "utf8")),
          matcherPresent: matcher.length > 0,
          source,
          type,
        };
        output.push(inventory);
        if (layer.applicability === "applied" || layer.applicability === "constraints") {
          addFact(context, {
            effect: "identity",
            evidence: [source],
            key: `${layer.kind === "requirements" ? "requirement." : ""}hook.${keyPart(event)}.${groupIndex.toString()}.${handlerIndex.toString()}`,
            value: digestOpaque({ handler, matcher, type }),
          });
        }
      }
    }
  }
}

function normalizeHookHandlerIdentity(handler: TomlObject): string {
  for (const key of ["tool", "mcp_tool", "mcpTool"] as const) {
    if (typeof handler[key] !== "string") continue;
    const tool = nonEmptySafeText(handler[key]);
    return typeof handler.server === "string"
      ? `${nonEmptySafeText(handler.server)}/${tool}`
      : tool;
  }
  const command =
    typeof handler.command === "string" ? firstExecutable(handler.command) : undefined;
  const windowsCommand =
    typeof handler.commandWindows === "string"
      ? firstExecutable(handler.commandWindows)
      : typeof handler.command_windows === "string"
        ? firstExecutable(handler.command_windows)
        : undefined;
  if (command !== undefined && windowsCommand !== undefined) {
    return `default:${command}|windows:${windowsCommand}`;
  }
  if (command !== undefined) return command;
  if (windowsCommand !== undefined) return `windows:${windowsCommand}`;
  return "unavailable";
}

function firstExecutable(command: string): string | undefined {
  const trimmed = command.trim();
  if (trimmed.length === 0) return undefined;
  const quote = trimmed[0];
  if (quote === '"' || quote === "'") {
    const end = trimmed.indexOf(quote, 1);
    return explicitExecutable(end === -1 ? trimmed.slice(1) : trimmed.slice(1, end));
  }
  return explicitExecutable(trimmed.split(/\s+/u)[0] ?? "");
}

function explicitExecutable(executable: string): string | undefined {
  let candidate = executable.trim();
  const quote = candidate[0];
  if (
    candidate.length >= 2 &&
    (quote === '"' || quote === "'") &&
    candidate[candidate.length - 1] === quote
  ) {
    candidate = candidate.slice(1, -1).trim();
  }
  if (candidate.length === 0) return undefined;
  const display = safeText(candidate);
  return display.length === 0 ? undefined : display;
}

function buildCoverage(
  user: LoadedLayer,
  project: LoadedLayer,
  requirements: LoadedLayer,
  trust: CodexInventoryValue<"trusted" | "untrusted">,
  projectApplicability: "applied" | "ignored" | "not-present" | "unknown",
  codexVersion: CodexInventoryValue<string>,
): CodexHarnessCoverage[] {
  const coverage: CodexHarnessCoverage[] = [
    {
      area: "cloud-requirements",
      reason:
        "Cloud-fetched requirements, signed cache state, legacy managed config, and MDM preferences were not supplied to this local-file adapter.",
      state: "unavailable",
    },
    codexVersion.state === "declared"
      ? {
          area: "codex-version",
          reason: "Bound to the caller-supplied Codex version without launching Codex.",
          state: "resolved",
        }
      : {
          area: "codex-version",
          reason: codexVersion.reason,
          state: "unavailable",
        },
    {
      area: "effective-runtime-state",
      reason:
        "This is a declaration snapshot; runtime defaults, live session overrides, cloud layers, and initialization outcomes were not observed.",
      state: "unavailable",
    },
    {
      area: "profile-and-session-overrides",
      reason:
        "Profile files, dedicated CLI flags, --config overrides, and current-session changes were not supplied.",
      state: "unavailable",
    },
    layerCoverage("project-config", project, projectApplicability, trust),
    {
      area: "runtime-defaults",
      reason: "Version-specific defaults were not synthesized for omitted fields.",
      state: "unavailable",
    },
    {
      area: "runtime-discovered-artifacts",
      reason:
        "Installed Skill and Plugin directories, runtime tool discovery, and MCP initialization were not inspected.",
      state: "unavailable",
    },
    layerCoverage("system-requirements", requirements, "constraints", trust),
    layerCoverage("user-config", user, "applied", trust),
  ];
  return coverage.sort((left, right) => compareCodeUnits(left.area, right.area));
}

function layerCoverage(
  area: "project-config" | "system-requirements" | "user-config",
  loaded: LoadedLayer,
  applicability: "applied" | "constraints" | "ignored" | "not-present" | "unknown",
  trust: CodexInventoryValue<"trusted" | "untrusted">,
): CodexHarnessCoverage {
  if (loaded.layer.status === "absent") {
    return {
      area,
      reason:
        loaded.layer.pathSource === "disabled"
          ? `${loaded.layer.label} detection was explicitly disabled.`
          : `${loaded.layer.label} was not present at the detected location.`,
      state: "unavailable",
    };
  }
  if (loaded.layer.status !== "parsed") {
    return {
      area,
      reason: `${loaded.layer.label} could not be parsed safely.`,
      state: "partial",
    };
  }
  if (area === "project-config" && applicability === "ignored") {
    return {
      area,
      reason:
        "The project config was parsed as data but excluded from the local composite because the project is declared untrusted.",
      state: "ignored",
    };
  }
  if (area === "project-config" && applicability === "unknown") {
    return {
      area,
      reason:
        trust.state === "unavailable"
          ? "The project config was parsed, but project trust was unavailable so its runtime applicability is unknown."
          : "The project config applicability is unknown.",
      state: "partial",
    };
  }
  return {
    area,
    reason: `${loaded.layer.label} was parsed as bounded TOML data.`,
    state: "resolved",
  };
}

function normalizeCodexVersion(value: string | undefined): CodexInventoryValue<string> {
  if (value === undefined) {
    return unavailable(
      "No Codex version was supplied; Uleravo does not invoke Codex to discover it.",
    );
  }
  const normalized = safeText(value.trim());
  if (normalized.length === 0 || normalized.length > 200) {
    throw new Error("--codex-version must be a non-empty value of at most 200 characters.");
  }
  return {
    evidence: { key: "--codex-version", layer: "invocation" },
    state: "declared",
    value: normalized,
  };
}

function addStringAt(
  layer: ParsedLayer,
  context: NormalizationContext,
  table: TomlObject,
  property: string,
  evidenceKey: string,
  factKey: string,
  effect: "identity" | "posture",
): void {
  const value = table[property];
  if (typeof value !== "string") return;
  addFact(context, {
    effect,
    evidence: [{ key: evidenceKey, layer: layer.kind }],
    key: factKey,
    value: safeText(value),
  });
}

function addRankedStringSetting(
  layer: ParsedLayer,
  context: NormalizationContext,
  configKey: string,
  factKey: string,
  ranker: (value: string) => number | undefined,
): void {
  const value = layer.data[configKey];
  if (typeof value !== "string") return;
  const rank = ranker(value);
  addFact(context, {
    effect: "posture",
    evidence: [{ key: configKey, layer: layer.kind }],
    key: factKey,
    ...(rank === undefined ? {} : { rank }),
    value: safeText(value),
  });
}

function addBooleanAt(
  layer: ParsedLayer,
  context: NormalizationContext,
  table: TomlObject,
  property: string,
  evidenceKey: string,
  factKey: string,
  effect: "exposure" | "guard",
): void {
  const value = table[property];
  if (typeof value !== "boolean") return;
  addFact(context, {
    effect,
    evidence: [{ key: evidenceKey, layer: layer.kind }],
    key: factKey,
    rank: value ? 1 : 0,
    value,
  });
}

function addInventoryBooleanFacts<T extends object>(
  context: NormalizationContext,
  base: string,
  _inventory: T,
  entries: readonly [string, CodexInventoryValue<boolean>, "exposure" | "guard"][],
): void {
  for (const [name, claim, effect] of entries) {
    if (claim.state !== "declared") continue;
    addFact(context, {
      effect,
      evidence: [claim.evidence],
      key: `${base}.${name}`,
      rank: claim.value ? 1 : 0,
      value: claim.value,
    });
  }
}

function addInventoryStringFact(
  context: NormalizationContext,
  key: string,
  claim: CodexInventoryValue<string>,
): void {
  if (claim.state !== "declared") return;
  addFact(context, {
    effect: "posture",
    evidence: [claim.evidence],
    key,
    value: claim.value,
  });
}

function addInventoryRankedStringFact(
  context: NormalizationContext,
  key: string,
  claim: CodexInventoryValue<string>,
  ranker: (value: string) => number | undefined,
): void {
  if (claim.state !== "declared") return;
  const rank = ranker(claim.value);
  addFact(context, {
    effect: "posture",
    evidence: [claim.evidence],
    key,
    ...(rank === undefined ? {} : { rank }),
    value: claim.value,
  });
}

function normalizeDecisionTable(
  table: TomlObject | undefined,
  layer: ParsedLayer,
  context: NormalizationContext,
  evidencePrefix: string,
  factPrefix: string,
): void {
  if (table === undefined) return;
  for (const [target, decision] of sortedEntries(table)) {
    if (decision !== "allow" && decision !== "deny") continue;
    addFact(context, {
      effect: decision === "allow" ? "exposure" : "guard",
      evidence: [{ key: `${evidencePrefix}.${keyLabel(target)}`, layer: layer.kind }],
      key: `${factPrefix}.${keyPart(target)}`,
      value: `${decision}:${safeText(target)}`,
    });
  }
}

function normalizeNetworkPolicyTable(
  table: TomlObject | undefined,
  layer: ParsedLayer,
  context: NormalizationContext,
  evidencePrefix: string,
  factPrefix: string,
): void {
  if (table === undefined) return;
  for (const key of [
    "enabled",
    "enable_socks5",
    "enable_socks5_udp",
    "allow_upstream_proxy",
    "dangerously_allow_non_loopback_proxy",
    "dangerously_allow_all_unix_sockets",
    "allow_local_binding",
  ] as const) {
    addBooleanAt(
      layer,
      context,
      table,
      key,
      `${evidencePrefix}.${key}`,
      `${factPrefix}.${key.replaceAll("_", "-")}`,
      "exposure",
    );
  }
  normalizeDecisionTable(
    asObject(table.domains),
    layer,
    context,
    `${evidencePrefix}.domains`,
    `${factPrefix}.domain`,
  );
  normalizeDecisionTable(
    asObject(table.unix_sockets),
    layer,
    context,
    `${evidencePrefix}.unix_sockets`,
    `${factPrefix}.unix-socket`,
  );
  addUrlSettingIdentity(
    layer,
    context,
    table,
    "proxy_url",
    `${evidencePrefix}.proxy_url`,
    `${factPrefix}.proxy-url-identity`,
  );
  addUrlSettingIdentity(
    layer,
    context,
    table,
    "socks_url",
    `${evidencePrefix}.socks_url`,
    `${factPrefix}.socks-url-identity`,
  );
}

function normalizeNetworkProxyFeature(
  layer: ParsedLayer,
  context: NormalizationContext,
  features: TomlObject,
  factPrefix: string,
): void {
  const configured = features.network_proxy;
  if (typeof configured === "boolean") {
    addFact(context, {
      effect: "exposure",
      evidence: [{ key: "features.network_proxy", layer: layer.kind }],
      key: `${factPrefix}.enabled`,
      rank: configured ? 1 : 0,
      value: configured,
    });
    return;
  }
  normalizeNetworkPolicyTable(
    asObject(configured),
    layer,
    context,
    "features.network_proxy",
    factPrefix,
  );
}

function normalizeHookFeatureAlias(
  layer: ParsedLayer,
  context: NormalizationContext,
  features: TomlObject,
  factKey: string,
): void {
  if (typeof features.hooks === "boolean" || typeof features.codex_hooks !== "boolean") return;
  addFact(context, {
    effect: "exposure",
    evidence: [{ key: "features.codex_hooks", layer: layer.kind }],
    key: factKey,
    rank: features.codex_hooks ? 1 : 0,
    value: features.codex_hooks,
  });
}

function normalizeLegacyWebSearch(
  layer: ParsedLayer,
  context: NormalizationContext,
  factKey: string,
): void {
  if (typeof layer.data.web_search === "string") return;
  const features = asObject(layer.data.features);
  if (features === undefined) return;
  const selected =
    features.web_search_request === true
      ? { key: "web_search_request", mode: "live" }
      : features.web_search_cached === true
        ? { key: "web_search_cached", mode: "cached" }
        : undefined;
  if (selected === undefined) return;
  addFact(context, {
    effect: "posture",
    evidence: [{ key: `features.${selected.key}`, layer: layer.kind }],
    key: factKey,
    rank: selected.mode === "live" ? 3 : 1,
    value: selected.mode,
  });
}

function addUrlSettingIdentity(
  layer: ParsedLayer,
  context: NormalizationContext,
  table: TomlObject,
  property: string,
  evidenceKey: string,
  factKey: string,
): void {
  const value = table[property];
  if (typeof value !== "string") return;
  addFact(context, {
    effect: "identity",
    evidence: [{ key: evidenceKey, layer: layer.kind }],
    key: factKey,
    value: identityDigest(normalizeUrlIdentity(value)),
  });
}

function addFact(context: NormalizationContext, fact: CodexSemanticFact): void {
  if (!context.facts.has(fact.key) && context.facts.size >= MAX_HARNESS_FACTS) {
    reportNormalizationLimit(context);
    return;
  }
  context.facts.set(fact.key, fact);
}

function reserveInventory(context: NormalizationContext): boolean {
  if (context.inventoryCount >= MAX_INVENTORY_ENTRIES) {
    reportNormalizationLimit(context);
    return false;
  }
  context.inventoryCount += 1;
  return true;
}

function reportNormalizationLimit(context: NormalizationContext): void {
  if (context.normalizationLimitReported) return;
  context.normalizationLimitReported = true;
  context.diagnostics.push({
    code: "HARNESS_NORMALIZATION_LIMIT",
    message: "Codex configuration normalization exceeded the bounded entry limit.",
    type: "error",
  });
}

function declaredBoolean(
  value: unknown,
  key: string,
  layer: CodexHarnessLayerKind,
): CodexInventoryValue<boolean> {
  return typeof value === "boolean"
    ? { evidence: { key, layer }, state: "declared", value }
    : unavailable("No explicit boolean value was declared; runtime defaults were not assumed.");
}

function declaredString(
  value: unknown,
  key: string,
  layer: CodexHarnessLayerKind,
): CodexInventoryValue<string> {
  return typeof value === "string"
    ? { evidence: { key, layer }, state: "declared", value: safeText(value) }
    : unavailable("No explicit value was declared; runtime defaults were not assumed.");
}

function declaredCommandIdentity(
  value: unknown,
  key: string,
  layer: CodexHarnessLayerKind,
): CodexInventoryValue<CodexCommandIdentity> {
  if (typeof value !== "string") {
    return unavailable("No HTTP-header helper command was declared.");
  }
  const executable = firstExecutable(value);
  if (executable === undefined) {
    return unavailable("No non-empty HTTP-header helper executable was declared.");
  }
  return {
    evidence: { key, layer },
    state: "declared",
    value: {
      commandIdentitySha256: sha256(Buffer.from(value, "utf8")),
      executable,
    },
  };
}

function unavailable(reason: string): CodexInventoryValue<never> {
  return { reason, state: "unavailable" };
}

function normalizeConfigLimit(value: number | undefined): number {
  const candidate = value ?? MAX_HARNESS_CONFIG_BYTES;
  if (!Number.isSafeInteger(candidate) || candidate < 1 || candidate > HARD_MAX_CONFIG_BYTES) {
    throw new Error(
      `Codex harness maxConfigBytes must be a positive integer no greater than ${HARD_MAX_CONFIG_BYTES.toString()}.`,
    );
  }
  return candidate;
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === "string");
}

function sortedSafeStrings(value: unknown): string[] {
  return [
    ...new Set(
      stringArray(value)
        .map(safeText)
        .filter((entry) => entry.length > 0),
    ),
  ].sort();
}

function boundedInventoryStrings(
  values: readonly string[],
  context: NormalizationContext,
): string[] {
  const output: string[] = [];
  for (const value of values) {
    if (!reserveInventory(context)) break;
    output.push(value);
  }
  return output;
}

function asObject(value: unknown): TomlObject | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as TomlObject)
    : undefined;
}

function sortedEntries(object: TomlObject): Array<[string, unknown]> {
  return Object.keys(object)
    .sort()
    .map((key) => [key, object[key]]);
}

function safeText(value: string): string {
  return boundedRedactedEvidence(value.normalize("NFC"), MAX_DISPLAY_CHARACTERS, "...");
}

function nonEmptySafeText(value: string): string {
  const safe = safeText(value);
  return safe.length === 0 ? "<empty>" : safe;
}

function keyLabel(value: string): string {
  const safe = safeText(value);
  return safe === value && /^[A-Za-z0-9_-]{1,100}$/u.test(safe) ? safe : `[${keyPart(value)}]`;
}

function keyPart(value: string): string {
  const safe = safeText(value);
  return /^[A-Za-z0-9_-]{1,128}$/u.test(safe)
    ? safe
    : `sha256-${sha256(Buffer.from(value, "utf8")).slice(0, 24)}`;
}

function digestInput(
  layers: readonly CodexHarnessLayer[],
  version: CodexInventoryValue<string>,
): string {
  const identity = layers.map((layer) => ({
    bytes: layer.bytes ?? null,
    kind: layer.kind,
    pathSource: layer.pathSource,
    sha256: layer.sha256 ?? null,
    status: layer.status,
  }));
  return createHash("sha256")
    .update("uleravo:codex-harness-input:v1\0")
    .update(stableJson({ identity, version: version.state === "declared" ? version.value : null }))
    .digest("hex");
}

function digestOpaque(value: unknown): string {
  return sha256(Buffer.from(stableJson(value), "utf8"));
}

function identityDigest(identity: CodexMcpIdentity): string {
  return digestOpaque(identity);
}

function stableJson(value: unknown): string {
  return JSON.stringify(sortJsonValue(value));
}

function sortJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJsonValue);
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Date) return value.toISOString();
  const object = asObject(value);
  if (object === undefined) return value;
  return Object.fromEntries(
    sortedEntries(object).map(([key, entry]) => [key, sortJsonValue(entry)]),
  );
}

function approvalRank(value: string): number | undefined {
  if (value === "untrusted") return 0;
  if (value === "on-request" || value === "on-failure") return 1;
  if (value === "never") return 2;
  return undefined;
}

function approvalReviewerRank(value: string): number | undefined {
  if (value === "user") return 0;
  if (value === "auto_review") return 1;
  return undefined;
}

function sandboxRank(value: string): number | undefined {
  if (value === "read-only") return 0;
  if (value === "workspace-write") return 1;
  if (value === "danger-full-access") return 2;
  return undefined;
}

function permissionProfileRank(value: string): number | undefined {
  if (value === ":read-only") return 0;
  if (value === ":workspace") return 1;
  if (value === ":danger-full-access") return 2;
  return undefined;
}

function webSearchRank(value: string): number | undefined {
  if (value === "disabled") return 0;
  if (value === "cached") return 1;
  if (value === "indexed") return 2;
  if (value === "live") return 3;
  return undefined;
}

function compareFacts(left: CodexSemanticFact, right: CodexSemanticFact): number {
  return compareCodeUnits(left.key, right.key);
}

function compareDiagnostics(left: CodexHarnessDiagnostic, right: CodexHarnessDiagnostic): number {
  return compareCodeUnits(
    `${left.layer ?? ""}\0${left.code}\0${left.message}`,
    `${right.layer ?? ""}\0${right.code}\0${right.message}`,
  );
}

function compareInventory(
  left: { readonly source: CodexHarnessEvidence },
  right: { readonly source: CodexHarnessEvidence },
): number {
  return compareCodeUnits(
    `${left.source.layer}\0${left.source.key}`,
    `${right.source.layer}\0${right.source.key}`,
  );
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function sameConfiguredPath(configured: string, projectRoot: string): boolean {
  try {
    return pathIdentity(path.resolve(configured)) === pathIdentity(projectRoot);
  } catch {
    return false;
  }
}

function pathIdentity(value: string): string {
  const normalized = path.resolve(value).normalize("NFC");
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return (
    relative.length > 0 &&
    relative !== ".." &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

function sameFileSnapshot(
  left: Awaited<ReturnType<typeof lstat>>,
  right: Awaited<ReturnType<typeof lstat>>,
): boolean {
  const sameDevice =
    left.dev === right.dev ||
    (process.platform === "win32" &&
      (left.dev === 0 || right.dev === 0) &&
      left.ino !== 0 &&
      right.ino !== 0);
  return (
    sameDevice &&
    left.ino === right.ino &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.ctimeMs === right.ctimeMs
  );
}

function hasErrorCode(error: unknown, code: string): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { readonly code?: unknown }).code === code
  );
}
