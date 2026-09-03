import { createHash } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { lstat, open } from "node:fs/promises";
import path from "node:path";
import { boundedRedactedEvidence } from "../redact.js";
import type {
  CodexAppInventory,
  CodexCommandIdentity,
  CodexHarnessApplicability,
  CodexHarnessCoverage,
  CodexHarnessDiagnostic,
  CodexHarnessEvidence,
  CodexHarnessInventory,
  CodexHarnessLayer,
  CodexHarnessLayerKind,
  CodexHarnessSnapshot,
  CodexHookInventory,
  CodexInventoryValue,
  CodexMcpIdentity,
  CodexMcpServerInventory,
  CodexPluginInventory,
  CodexSemanticFact,
  CodexSkillInventory,
  CodexToolInventory,
} from "./domain.js";
import {
  CODEX_HARNESS_ADAPTER_VERSION,
  CODEX_HARNESS_SCHEMA_VERSION,
  MAX_HARNESS_FACTS,
  MAX_HARNESS_REPORT_BYTES,
} from "./domain.js";

const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

export async function readCodexHarnessSnapshot(source: string): Promise<CodexHarnessSnapshot> {
  const bytes = await readBoundedStableSnapshot(path.resolve(source));
  let serialized: string;
  try {
    serialized = utf8Decoder.decode(bytes);
  } catch {
    throw new Error("Codex harness snapshot is not valid UTF-8.");
  }
  return parseCodexHarnessSnapshot(serialized, source);
}

async function readBoundedStableSnapshot(source: string): Promise<Buffer> {
  const listed = await lstat(source);
  assertSnapshotFile(listed);
  const handle = await open(source, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat();
    assertSnapshotFile(opened);
    if (!sameSnapshotFile(listed, opened)) {
      throw new Error("Codex harness snapshot changed before it could be read safely.");
    }
    const allocation = Buffer.allocUnsafe(opened.size + 1);
    let used = 0;
    while (used < allocation.byteLength) {
      const { bytesRead } = await handle.read(allocation, used, allocation.byteLength - used, used);
      if (bytesRead === 0) break;
      used += bytesRead;
    }
    if (used > MAX_HARNESS_REPORT_BYTES) {
      throw new Error("Codex harness snapshot exceeds the report byte limit.");
    }
    const [after, pathAfter] = await Promise.all([handle.stat(), lstat(source)]);
    assertSnapshotFile(after);
    assertSnapshotFile(pathAfter);
    if (
      used !== after.size ||
      !sameSnapshotFile(opened, after) ||
      !sameSnapshotFile(opened, pathAfter)
    ) {
      throw new Error("Codex harness snapshot changed while it was being read.");
    }
    return Buffer.from(allocation.subarray(0, used));
  } finally {
    await handle.close();
  }
}

function assertSnapshotFile(metadata: Stats): void {
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error("Codex harness snapshot must be a regular, non-linked file.");
  }
  if (
    !Number.isSafeInteger(metadata.size) ||
    metadata.size < 0 ||
    metadata.size > MAX_HARNESS_REPORT_BYTES
  ) {
    throw new Error("Codex harness snapshot exceeds the report byte limit.");
  }
}

function sameSnapshotFile(left: Stats, right: Stats): boolean {
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

export function parseCodexHarnessSnapshot(
  serialized: string,
  label = "Codex harness snapshot",
): CodexHarnessSnapshot {
  if (Buffer.byteLength(serialized, "utf8") > MAX_HARNESS_REPORT_BYTES) {
    throw new Error(`${label} exceeds the report byte limit.`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new Error(`${label} is not valid JSON.`);
  }
  const root = exactObject(parsed, label, [
    "capture",
    "codexVersion",
    "coverage",
    "diagnostics",
    "documentType",
    "harness",
    "inventory",
    "layers",
    "project",
    "schemaVersion",
    "semanticFacts",
  ]);
  if (root.documentType !== "uleravo.harness-snapshot") {
    invalid(label, "has an unsupported documentType");
  }
  if (root.schemaVersion !== CODEX_HARNESS_SCHEMA_VERSION) {
    invalid(label, "has an unsupported schemaVersion");
  }

  const harness = parseHarness(root.harness, `${label}.harness`);
  const capture = parseCapture(root.capture, `${label}.capture`);
  const coverage = parseCoverage(root.coverage, `${label}.coverage`);
  const diagnostics = parseDiagnostics(root.diagnostics, `${label}.diagnostics`);
  const inventory = parseInventory(root.inventory, `${label}.inventory`);
  const layers = parseLayers(root.layers, `${label}.layers`);
  const project = parseProject(root.project, `${label}.project`);
  const codexVersion = parseInventoryString(root.codexVersion, `${label}.codexVersion`);
  const semanticFacts = parseFacts(root.semanticFacts, `${label}.semanticFacts`);
  if (capture.complete !== (diagnostics.length === 0)) {
    invalid(`${label}.capture.complete`, "does not match diagnostic completeness");
  }
  const expectedInputSha256 = inputDigest(layers, codexVersion);
  if (capture.inputSha256 !== expectedInputSha256) {
    invalid(`${label}.capture.inputSha256`, "does not match the selected layer identities");
  }
  const reportWithoutHarness = {
    capture,
    codexVersion,
    coverage,
    diagnostics,
    documentType: "uleravo.harness-snapshot",
    inventory,
    layers,
    project,
    schemaVersion: CODEX_HARNESS_SCHEMA_VERSION,
    semanticFacts,
  } as const;
  const expectedHarnessId = createHash("sha256")
    .update("uleravo:codex-harness-snapshot:v1\0")
    .update(stableJson(reportWithoutHarness))
    .digest("hex")
    .slice(0, 24);
  if (harness.id !== expectedHarnessId) {
    invalid(`${label}.harness.id`, "does not match the snapshot contents");
  }
  return { ...reportWithoutHarness, harness };
}

function parseHarness(value: unknown, label: string): CodexHarnessSnapshot["harness"] {
  const harness = exactObject(value, label, ["adapter", "analyzer", "id"]);
  const adapter = exactObject(harness.adapter, `${label}.adapter`, ["name", "version"]);
  if (adapter.name !== "openai-codex-local" || adapter.version !== CODEX_HARNESS_ADAPTER_VERSION) {
    invalid(`${label}.adapter`, "is unsupported");
  }
  const analyzer = exactObject(harness.analyzer, `${label}.analyzer`, ["name", "version"]);
  const name = boundedString(analyzer.name, `${label}.analyzer.name`);
  const version = boundedString(analyzer.version, `${label}.analyzer.version`);
  const id = digest(harness.id, `${label}.id`, 24);
  return {
    adapter: { name: "openai-codex-local", version: CODEX_HARNESS_ADAPTER_VERSION },
    analyzer: { name, version },
    id,
  };
}

function parseCapture(value: unknown, label: string): CodexHarnessSnapshot["capture"] {
  const capture = exactObject(value, label, ["complete", "inputSha256"]);
  if (typeof capture.complete !== "boolean") invalid(`${label}.complete`, "must be boolean");
  return {
    complete: capture.complete,
    inputSha256: digest(capture.inputSha256, `${label}.inputSha256`, 64),
  };
}

function parseCoverage(value: unknown, label: string): CodexHarnessCoverage[] {
  const expectedAreas: readonly CodexHarnessCoverage["area"][] = [
    "cloud-requirements",
    "codex-version",
    "effective-runtime-state",
    "profile-and-session-overrides",
    "project-config",
    "runtime-defaults",
    "runtime-discovered-artifacts",
    "system-requirements",
    "user-config",
  ];
  const entries = requireArray(value, label, expectedAreas.length);
  if (entries.length !== expectedAreas.length) invalid(label, "must contain every coverage area");
  return entries.map((raw, index) => {
    const location = `${label}[${index.toString()}]`;
    const entry = exactObject(raw, location, ["area", "reason", "state"]);
    const area = expectedAreas[index];
    if (entry.area !== area) invalid(`${location}.area`, "is missing or out of order");
    if (area === undefined) invalid(`${location}.area`, "is unsupported");
    const state = entry.state;
    if (
      state !== "ignored" &&
      state !== "partial" &&
      state !== "resolved" &&
      state !== "unavailable"
    ) {
      invalid(`${location}.state`, "is unsupported");
    }
    return {
      area,
      reason: boundedString(entry.reason, `${location}.reason`),
      state,
    };
  });
}

function parseDiagnostics(value: unknown, label: string): CodexHarnessDiagnostic[] {
  return requireArray(value, label, 1_000).map((raw, index) => {
    const location = `${label}[${index.toString()}]`;
    const object = exactObject(raw, location, ["code", "message", "type"], ["layer"]);
    const code = object.code;
    if (
      code !== "HARNESS_CONFIG_CHANGED" &&
      code !== "HARNESS_CONFIG_INVALID" &&
      code !== "HARNESS_CONFIG_MISSING" &&
      code !== "HARNESS_CONFIG_SIZE_LIMIT" &&
      code !== "HARNESS_CONFIG_UNSAFE" &&
      code !== "HARNESS_NORMALIZATION_LIMIT"
    ) {
      invalid(`${location}.code`, "is unsupported");
    }
    if (object.type !== "error") invalid(`${location}.type`, "must be error");
    const layer =
      object.layer === undefined ? undefined : parseLayerKind(object.layer, `${location}.layer`);
    return {
      code,
      ...(layer === undefined ? {} : { layer }),
      message: boundedString(object.message, `${location}.message`),
      type: "error",
    };
  });
}

function parseLayers(value: unknown, label: string): CodexHarnessLayer[] {
  const expectedKinds: readonly CodexHarnessLayerKind[] = [
    "user-config",
    "project-config",
    "requirements",
  ];
  const layers = requireArray(value, label, expectedKinds.length);
  if (layers.length !== expectedKinds.length) invalid(label, "must contain three config layers");
  return layers.map((raw, index) => {
    const location = `${label}[${index.toString()}]`;
    const object = exactObject(
      raw,
      location,
      ["applicability", "kind", "label", "pathSource", "status"],
      ["bytes", "sha256"],
    );
    const kind = parseLayerKind(object.kind, `${location}.kind`);
    if (kind !== expectedKinds[index]) invalid(`${location}.kind`, "is out of order");
    const pathSource = object.pathSource;
    if (pathSource !== "detected" && pathSource !== "disabled" && pathSource !== "user-supplied") {
      invalid(`${location}.pathSource`, "is unsupported");
    }
    const status = object.status;
    if (status !== "absent" && status !== "invalid" && status !== "parsed" && status !== "unsafe") {
      invalid(`${location}.status`, "is unsupported");
    }
    const bytes =
      object.bytes === undefined
        ? undefined
        : nonNegativeInteger(object.bytes, `${location}.bytes`);
    const sha256 =
      object.sha256 === undefined ? undefined : digest(object.sha256, `${location}.sha256`, 64);
    return {
      applicability: parseApplicability(object.applicability, `${location}.applicability`),
      ...(bytes === undefined ? {} : { bytes }),
      kind,
      label: boundedString(object.label, `${location}.label`),
      pathSource,
      ...(sha256 === undefined ? {} : { sha256 }),
      status,
    };
  });
}

function parseProject(value: unknown, label: string): CodexHarnessSnapshot["project"] {
  const project = exactObject(value, label, ["configApplicability", "trust"]);
  const configApplicability = project.configApplicability;
  if (
    configApplicability !== "applied" &&
    configApplicability !== "ignored" &&
    configApplicability !== "not-present" &&
    configApplicability !== "unknown"
  ) {
    invalid(`${label}.configApplicability`, "is unsupported");
  }
  return {
    configApplicability,
    trust: parseInventoryValue(project.trust, `${label}.trust`, (entry, entryLabel) => {
      if (entry !== "trusted" && entry !== "untrusted") {
        invalid(entryLabel, "must be trusted or untrusted");
      }
      return entry;
    }),
  };
}

function parseInventory(value: unknown, label: string): CodexHarnessInventory {
  const inventory = exactObject(value, label, ["apps", "hooks", "mcpServers", "plugins", "skills"]);
  return {
    apps: parseInventoryArray(inventory.apps, `${label}.apps`, parseApp),
    hooks: parseInventoryArray(inventory.hooks, `${label}.hooks`, parseHook),
    mcpServers: parseInventoryArray(inventory.mcpServers, `${label}.mcpServers`, parseMcpServer),
    plugins: parseInventoryArray(inventory.plugins, `${label}.plugins`, parsePlugin),
    skills: parseInventoryArray(inventory.skills, `${label}.skills`, parseSkill),
  };
}

function parseInventoryArray<T extends { readonly source: CodexHarnessEvidence }>(
  value: unknown,
  label: string,
  parser: (value: unknown, label: string) => T,
): T[] {
  const output = requireArray(value, label, MAX_HARNESS_FACTS).map((raw, index) =>
    parser(raw, `${label}[${index.toString()}]`),
  );
  assertStrictlySorted(
    output.map((entry) => `${entry.source.layer}\0${entry.source.key}`),
    label,
  );
  return output;
}

function parseSkill(value: unknown, label: string): CodexSkillInventory {
  const skill = exactObject(value, label, [
    "applicability",
    "enabled",
    "path",
    "pathSha256",
    "source",
  ]);
  return {
    applicability: parseApplicability(skill.applicability, `${label}.applicability`),
    enabled: parseInventoryBoolean(skill.enabled, `${label}.enabled`),
    path: boundedString(skill.path, `${label}.path`),
    pathSha256: digest(skill.pathSha256, `${label}.pathSha256`, 64),
    source: parseEvidenceEntry(skill.source, `${label}.source`),
  };
}

function parsePlugin(value: unknown, label: string): CodexPluginInventory {
  const plugin = exactObject(value, label, ["applicability", "id", "mcpServerIds", "source"]);
  return {
    applicability: parseApplicability(plugin.applicability, `${label}.applicability`),
    id: boundedString(plugin.id, `${label}.id`),
    mcpServerIds: parseStringArray(plugin.mcpServerIds, `${label}.mcpServerIds`),
    source: parseEvidenceEntry(plugin.source, `${label}.source`),
  };
}

function parseApp(value: unknown, label: string): CodexAppInventory {
  const app = exactObject(value, label, [
    "applicability",
    "approvalsReviewer",
    "defaultToolsApprovalMode",
    "defaultToolsEnabled",
    "destructiveEnabled",
    "enabled",
    "id",
    "openWorldEnabled",
    "source",
    "tools",
  ]);
  return {
    applicability: parseApplicability(app.applicability, `${label}.applicability`),
    approvalsReviewer: parseInventoryString(app.approvalsReviewer, `${label}.approvalsReviewer`),
    defaultToolsApprovalMode: parseInventoryString(
      app.defaultToolsApprovalMode,
      `${label}.defaultToolsApprovalMode`,
    ),
    defaultToolsEnabled: parseInventoryBoolean(
      app.defaultToolsEnabled,
      `${label}.defaultToolsEnabled`,
    ),
    destructiveEnabled: parseInventoryBoolean(
      app.destructiveEnabled,
      `${label}.destructiveEnabled`,
    ),
    enabled: parseInventoryBoolean(app.enabled, `${label}.enabled`),
    id: boundedString(app.id, `${label}.id`),
    openWorldEnabled: parseInventoryBoolean(app.openWorldEnabled, `${label}.openWorldEnabled`),
    source: parseEvidenceEntry(app.source, `${label}.source`),
    tools: parseTools(app.tools, `${label}.tools`),
  };
}

function parseTools(value: unknown, label: string): CodexToolInventory[] {
  const tools = requireArray(value, label, MAX_HARNESS_FACTS).map((raw, index) => {
    const location = `${label}[${index.toString()}]`;
    const tool = exactObject(raw, location, ["approvalMode", "enabled", "name"]);
    return {
      approvalMode: parseInventoryString(tool.approvalMode, `${location}.approvalMode`),
      enabled: parseInventoryBoolean(tool.enabled, `${location}.enabled`),
      name: boundedString(tool.name, `${location}.name`),
    };
  });
  assertSorted(
    tools.map((tool) => tool.name),
    label,
  );
  return tools;
}

function parseMcpServer(value: unknown, label: string): CodexMcpServerInventory {
  const server = exactObject(
    value,
    label,
    [
      "applicability",
      "defaultToolsApprovalMode",
      "disabledTools",
      "enabled",
      "enabledTools",
      "enabledToolsAllowlistPresent",
      "environmentNames",
      "executionEnvironment",
      "headerNames",
      "httpHeadersHelper",
      "id",
      "identity",
      "oauthScopes",
      "required",
      "source",
      "tools",
    ],
    ["plugin"],
  );
  if (typeof server.enabledToolsAllowlistPresent !== "boolean") {
    invalid(`${label}.enabledToolsAllowlistPresent`, "must be boolean");
  }
  const plugin =
    server.plugin === undefined ? undefined : boundedString(server.plugin, `${label}.plugin`);
  return {
    applicability: parseApplicability(server.applicability, `${label}.applicability`),
    defaultToolsApprovalMode: parseInventoryString(
      server.defaultToolsApprovalMode,
      `${label}.defaultToolsApprovalMode`,
    ),
    disabledTools: parseStringArray(server.disabledTools, `${label}.disabledTools`),
    enabled: parseInventoryBoolean(server.enabled, `${label}.enabled`),
    enabledTools: parseStringArray(server.enabledTools, `${label}.enabledTools`),
    enabledToolsAllowlistPresent: server.enabledToolsAllowlistPresent,
    environmentNames: parseStringArray(server.environmentNames, `${label}.environmentNames`),
    executionEnvironment: parseInventoryString(
      server.executionEnvironment,
      `${label}.executionEnvironment`,
    ),
    headerNames: parseStringArray(server.headerNames, `${label}.headerNames`),
    httpHeadersHelper: parseInventoryValue(
      server.httpHeadersHelper,
      `${label}.httpHeadersHelper`,
      parseCommandIdentity,
    ),
    id: boundedString(server.id, `${label}.id`),
    identity: parseMcpIdentity(server.identity, `${label}.identity`),
    oauthScopes: parseStringArray(server.oauthScopes, `${label}.oauthScopes`),
    ...(plugin === undefined ? {} : { plugin }),
    required: parseInventoryBoolean(server.required, `${label}.required`),
    source: parseEvidenceEntry(server.source, `${label}.source`),
    tools: parseTools(server.tools, `${label}.tools`),
  };
}

function parseMcpIdentity(value: unknown, label: string): CodexMcpIdentity {
  const object = objectValue(value, label);
  if (object.kind === "stdio") {
    const stdio = exactObject(value, label, [
      "argumentCount",
      "argumentIdentitySha256",
      "commandIdentitySha256",
      "executable",
      "kind",
    ]);
    return {
      argumentCount: nonNegativeInteger(stdio.argumentCount, `${label}.argumentCount`),
      argumentIdentitySha256: digest(
        stdio.argumentIdentitySha256,
        `${label}.argumentIdentitySha256`,
        64,
      ),
      commandIdentitySha256: digest(
        stdio.commandIdentitySha256,
        `${label}.commandIdentitySha256`,
        64,
      ),
      executable: boundedString(stdio.executable, `${label}.executable`),
      kind: "stdio",
    };
  }
  if (object.kind === "http") {
    const http = exactObject(value, label, [
      "credentialsPresent",
      "kind",
      "queryParameterNames",
      "url",
      "urlIdentitySha256",
    ]);
    if (typeof http.credentialsPresent !== "boolean") {
      invalid(`${label}.credentialsPresent`, "must be boolean");
    }
    return {
      credentialsPresent: http.credentialsPresent,
      kind: "http",
      queryParameterNames: parseStringArray(
        http.queryParameterNames,
        `${label}.queryParameterNames`,
      ),
      url: boundedString(http.url, `${label}.url`),
      urlIdentitySha256: digest(http.urlIdentitySha256, `${label}.urlIdentitySha256`, 64),
    };
  }
  if (object.kind === "unavailable") {
    const unavailable = exactObject(value, label, ["kind", "reason"]);
    return {
      kind: "unavailable",
      reason: boundedString(unavailable.reason, `${label}.reason`),
    };
  }
  return invalid(`${label}.kind`, "is unsupported");
}

function parseCommandIdentity(value: unknown, label: string): CodexCommandIdentity {
  const command = exactObject(value, label, ["commandIdentitySha256", "executable"]);
  return {
    commandIdentitySha256: digest(
      command.commandIdentitySha256,
      `${label}.commandIdentitySha256`,
      64,
    ),
    executable: boundedString(command.executable, `${label}.executable`),
  };
}

function parseHook(value: unknown, label: string): CodexHookInventory {
  const hook = exactObject(value, label, [
    "applicability",
    "asynchronous",
    "event",
    "handler",
    "handlerIdentitySha256",
    "handlerIndex",
    "matcherIdentitySha256",
    "matcherPresent",
    "source",
    "type",
  ]);
  if (typeof hook.matcherPresent !== "boolean") {
    invalid(`${label}.matcherPresent`, "must be boolean");
  }
  return {
    applicability: parseApplicability(hook.applicability, `${label}.applicability`),
    asynchronous: parseInventoryBoolean(hook.asynchronous, `${label}.asynchronous`),
    event: boundedString(hook.event, `${label}.event`),
    handler: boundedString(hook.handler, `${label}.handler`),
    handlerIdentitySha256: digest(hook.handlerIdentitySha256, `${label}.handlerIdentitySha256`, 64),
    handlerIndex: nonNegativeInteger(hook.handlerIndex, `${label}.handlerIndex`),
    matcherIdentitySha256: digest(hook.matcherIdentitySha256, `${label}.matcherIdentitySha256`, 64),
    matcherPresent: hook.matcherPresent,
    source: parseEvidenceEntry(hook.source, `${label}.source`),
    type: boundedString(hook.type, `${label}.type`),
  };
}

function parseInventoryBoolean(value: unknown, label: string): CodexInventoryValue<boolean> {
  return parseInventoryValue(value, label, (entry, entryLabel) => {
    if (typeof entry !== "boolean") invalid(entryLabel, "must be boolean");
    return entry;
  });
}

function parseInventoryString(value: unknown, label: string): CodexInventoryValue<string> {
  return parseInventoryValue(value, label, boundedDisplayString);
}

function parseInventoryValue<T>(
  value: unknown,
  label: string,
  parseValue: (value: unknown, label: string) => T,
): CodexInventoryValue<T> {
  const object = objectValue(value, label);
  if (object.state === "unavailable") {
    const unavailable = exactObject(value, label, ["reason", "state"]);
    return {
      reason: boundedString(unavailable.reason, `${label}.reason`),
      state: "unavailable",
    };
  }
  if (object.state === "declared") {
    const declared = exactObject(value, label, ["evidence", "state", "value"]);
    return {
      evidence: parseEvidenceEntry(declared.evidence, `${label}.evidence`),
      state: "declared",
      value: parseValue(declared.value, `${label}.value`),
    };
  }
  return invalid(`${label}.state`, "is unsupported");
}

function parseStringArray(value: unknown, label: string): string[] {
  const output = requireArray(value, label, MAX_HARNESS_FACTS).map((entry, index) =>
    boundedString(entry, `${label}[${index.toString()}]`),
  );
  assertStrictlySorted(output, label);
  return output;
}

function parseApplicability(value: unknown, label: string): CodexHarnessApplicability {
  if (
    value === "applied" ||
    value === "constraints" ||
    value === "ignored" ||
    value === "unknown"
  ) {
    return value;
  }
  return invalid(label, "is unsupported");
}

function parseLayerKind(value: unknown, label: string): CodexHarnessLayerKind {
  if (value === "user-config" || value === "project-config" || value === "requirements") {
    return value;
  }
  return invalid(label, "is unsupported");
}

function nonNegativeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    return invalid(label, "must be a non-negative safe integer");
  }
  return value as number;
}

function assertStrictlySorted(values: readonly string[], label: string): void {
  for (let index = 1; index < values.length; index += 1) {
    if ((values[index] ?? "") <= (values[index - 1] ?? "")) {
      invalid(label, "must be sorted with unique values");
    }
  }
}

function assertSorted(values: readonly string[], label: string): void {
  for (let index = 1; index < values.length; index += 1) {
    if ((values[index] ?? "") < (values[index - 1] ?? "")) {
      invalid(label, "must be sorted");
    }
  }
}

function inputDigest(
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

function stableJson(value: unknown): string {
  return JSON.stringify(sortJsonValue(value));
}

function sortJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJsonValue);
  if (typeof value !== "object" || value === null) return value;
  const object = value as Record<string, unknown>;
  return Object.fromEntries(
    Object.keys(object)
      .sort()
      .map((key) => [key, sortJsonValue(object[key])]),
  );
}

function parseFacts(value: unknown, label: string): CodexSemanticFact[] {
  const facts = requireArray(value, label, MAX_HARNESS_FACTS);
  const output: CodexSemanticFact[] = [];
  let previous = "";
  for (const [index, raw] of facts.entries()) {
    const location = `${label}[${index.toString()}]`;
    const fact = parseFact(raw, location);
    if (fact.key <= previous) invalid(label, "must be sorted with unique fact keys");
    previous = fact.key;
    output.push(fact);
  }
  return output;
}

function parseFact(value: unknown, location: string): CodexSemanticFact {
  const object = objectValue(value, location);
  const expected =
    object.rank === undefined
      ? ["effect", "evidence", "key", "value"]
      : ["effect", "evidence", "key", "rank", "value"];
  if (!sameStrings(Object.keys(object).sort(), expected)) {
    invalid(location, "has unknown or missing fields");
  }
  const effect = parseEffect(object.effect, `${location}.effect`);
  const key = boundedString(object.key, `${location}.key`);
  const semanticValue = parseSemanticValue(object.value, `${location}.value`);
  const rank = parseRank(object.rank, `${location}.rank`);
  return {
    effect,
    evidence: parseEvidence(object.evidence, `${location}.evidence`),
    key,
    ...(rank === undefined ? {} : { rank }),
    value: semanticValue,
  };
}

function parseEffect(value: unknown, label: string): CodexSemanticFact["effect"] {
  if (value === "exposure" || value === "guard" || value === "identity" || value === "posture") {
    return value;
  }
  return invalid(label, "is unsupported");
}

function boundedString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2_000) {
    return invalid(label, "must be a bounded non-empty string");
  }
  if (boundedRedactedEvidence(value, 2_000) !== value) {
    return invalid(label, "must already be redacted and display-safe");
  }
  return value;
}

function boundedDisplayString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length > 2_000) {
    return invalid(label, "must be a bounded string");
  }
  if (boundedRedactedEvidence(value, 2_000) !== value) {
    return invalid(label, "must already be redacted and display-safe");
  }
  return value;
}

function parseSemanticValue(value: unknown, label: string): boolean | number | string {
  if (typeof value !== "boolean" && typeof value !== "number" && typeof value !== "string") {
    return invalid(label, "must be a primitive semantic value");
  }
  if (typeof value === "string" && value.length > 2_000) {
    return invalid(label, "exceeds the semantic value limit");
  }
  if (typeof value === "string" && boundedRedactedEvidence(value, 2_000) !== value) {
    return invalid(label, "must already be redacted and display-safe");
  }
  if (typeof value === "number" && !Number.isFinite(value)) {
    return invalid(label, "must be a finite semantic value");
  }
  return value;
}

function parseRank(value: unknown, label: string): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    return invalid(label, "must be a non-negative safe integer");
  }
  return value as number;
}

function parseEvidence(value: unknown, label: string): CodexHarnessEvidence[] {
  return requireArray(value, label, 16).map((raw, index) =>
    parseEvidenceEntry(raw, `${label}[${index.toString()}]`),
  );
}

function parseEvidenceEntry(value: unknown, label: string): CodexHarnessEvidence {
  const object = exactObject(value, label, ["key", "layer"]);
  const key = boundedString(object.key, `${label}.key`);
  if (
    object.layer !== "user-config" &&
    object.layer !== "project-config" &&
    object.layer !== "requirements" &&
    object.layer !== "invocation"
  ) {
    invalid(`${label}.layer`, "is unsupported");
  }
  return { key, layer: object.layer };
}

function requireArray(value: unknown, label: string, maximum: number): unknown[] {
  if (!Array.isArray(value) || value.length > maximum) {
    invalid(label, `must be an array with at most ${maximum.toString()} items`);
  }
  return value;
}

function exactObject(
  value: unknown,
  label: string,
  keys: readonly string[],
  optionalKeys: readonly string[] = [],
): Record<string, unknown> {
  const object = objectValue(value, label);
  const actual = Object.keys(object);
  const allowed = new Set([...keys, ...optionalKeys]);
  if (keys.some((key) => !Object.hasOwn(object, key)) || actual.some((key) => !allowed.has(key))) {
    invalid(label, "has unknown or missing fields");
  }
  return object;
}

function objectValue(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    invalid(label, "must be an object");
  }
  return value as Record<string, unknown>;
}

function digest(value: unknown, label: string, length: number): string {
  if (
    typeof value !== "string" ||
    !new RegExp(`^[a-f0-9]{${length.toString()}}$`, "u").test(value)
  ) {
    invalid(label, `must be a ${length.toString()}-character lowercase hexadecimal digest`);
  }
  return value;
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((entry, index) => entry === right[index]);
}

function invalid(label: string, reason: string): never {
  throw new Error(`${label} ${reason}.`);
}
