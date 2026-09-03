import { redactEvidenceToFixedPoint } from "../../redact.js";
import type { ArtifactDiscoveryResult, DiscoveredArtifactFile } from "../discovery.js";
import type {
  ArtifactAbsentClaim,
  ArtifactClaim,
  ArtifactCoverage,
  ArtifactDiagnostic,
  ArtifactValueClaim,
  PluginManifestClaims,
} from "../domain.js";
import { MAX_ARTIFACT_CLAIM_CHARACTERS } from "../domain.js";
import { isPortableArtifactPath, isWellFormedUnicode } from "../path.js";
import { validateJsonStructure } from "../read.js";
import type { PluginAdapter, PluginAdapterAnalysis } from "./types.js";

const MANIFEST_PATH = ".codex-plugin/plugin.json";
const MAX_MANIFEST_BYTES = 256_000;
const MAX_NAME_CHARACTERS = 256;
const MAX_DESCRIPTION_CHARACTERS = 8_000;
const MAX_VERSION_CHARACTERS = 256;
const MAX_DECLARED_PATHS = 1_000;
const PLUGIN_NAME_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

type JsonObject = Record<string, unknown>;
interface ObservedPathIndex {
  readonly directories: ReadonlySet<string>;
  readonly files: ReadonlySet<string>;
}
type ParsedValue<T> =
  | { readonly error?: never; readonly value: T }
  | { readonly error: string; readonly value?: never };

interface ParsedManifest {
  readonly description: ArtifactClaim<string>;
  readonly diagnostics: readonly ArtifactDiagnostic[];
  readonly name: ArtifactClaim<string>;
  readonly valid: boolean;
  readonly version: ArtifactClaim<string>;
}

export const openAiPluginAdapter: PluginAdapter = {
  analyze(discovery: ArtifactDiscoveryResult<"plugin">): PluginAdapterAnalysis {
    return analyzeOpenAiPlugin(discovery);
  },
  kind: "plugin",
  name: "openai-plugin",
  version: "1.0.0",
};

function analyzeOpenAiPlugin(discovery: ArtifactDiscoveryResult<"plugin">): PluginAdapterAnalysis {
  const manifestFile = discovery.files.find((file) => file.relativePath === MANIFEST_PATH);
  const parsed =
    manifestFile === undefined ? missingManifest() : parsePluginManifest(manifestFile, discovery);
  const pathClaim: ArtifactValueClaim<".codex-plugin/plugin.json"> = {
    evidence: manifestFile === undefined ? [] : [{ path: MANIFEST_PATH }],
    source: "observed",
    state: manifestFile === undefined ? "unresolved" : "resolved",
    value: MANIFEST_PATH,
  };
  const manifest: PluginManifestClaims = {
    description: parsed.description,
    name: parsed.name,
    path: pathClaim,
    version: parsed.version,
  };
  const coverage: ArtifactCoverage[] = [
    {
      area: "manifest-metadata",
      claim: parsed.valid
        ? resolvedTextClaim(
            "The required plugin name and supported optional manifest declarations were parsed; component contents remain opaque.",
            "declared",
          )
        : unavailableTextClaim("Required plugin manifest metadata is unavailable."),
    },
    {
      area: "capability-normalization",
      claim: {
        evidence: [],
        reason:
          "Declared install-surface capabilities are not treated as observed behavior; normalization is deferred.",
        source: "inferred",
        state: "unsupported",
      },
    },
    {
      area: "harness-permissions",
      claim: {
        evidence: [],
        reason:
          "Bundled hooks and MCP configuration were not executed; effective permissions cannot be inferred.",
        source: "inferred",
        state: "unavailable",
      },
    },
  ];
  return {
    complete: parsed.valid,
    coverage,
    diagnostics: parsed.diagnostics,
    manifest,
  };
}

function missingManifest(): ParsedManifest {
  const reason = "Plugin root does not contain a regular .codex-plugin/plugin.json manifest.";
  return {
    description: unavailableTextClaim(reason),
    diagnostics: [
      { code: "PLUGIN_MANIFEST_MISSING", file: MANIFEST_PATH, message: reason, type: "error" },
    ],
    name: unavailableTextClaim(reason),
    valid: false,
    version: unavailableTextClaim(reason),
  };
}

function parsePluginManifest(
  file: DiscoveredArtifactFile,
  discovery: ArtifactDiscoveryResult<"plugin">,
): ParsedManifest {
  if (file.bytes.byteLength > MAX_MANIFEST_BYTES) {
    return invalidManifest(
      `Plugin manifest exceeds the ${MAX_MANIFEST_BYTES.toString()}-byte metadata limit.`,
    );
  }
  const decoded = decodeManifest(file);
  if (decoded.error !== undefined) {
    return invalidManifest(decoded.error);
  }
  try {
    validateJsonStructure(decoded.value, "plugin manifest");
  } catch {
    return invalidManifest(
      "Plugin manifest must be strict JSON without duplicate keys or excessive nesting.",
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(decoded.value) as unknown;
  } catch {
    return invalidManifest("Plugin manifest must be valid JSON.");
  }
  if (!isJsonObject(parsed)) {
    return invalidManifest("Plugin manifest must contain one JSON object.");
  }

  const fields = readManifestFields(parsed);
  if (fields.error !== undefined) {
    return invalidManifest(fields.error);
  }
  const declarationError = validateComponentDeclarations(parsed, discovery);
  if (declarationError !== undefined) {
    return invalidManifest(declarationError);
  }
  const fieldError = validateManifestFields(fields.value);
  if (fieldError !== undefined) {
    return invalidManifest(fieldError);
  }

  return {
    description: declaredTextClaim(fields.value.description ?? ""),
    diagnostics: [],
    name: declaredTextClaim(fields.value.name ?? ""),
    valid: true,
    version: declaredTextClaim(fields.value.version ?? ""),
  };
}

function decodeManifest(file: DiscoveredArtifactFile): ParsedValue<string> {
  try {
    const text = utf8Decoder.decode(file.bytes);
    return { value: text.startsWith("\uFEFF") ? text.slice(1) : text };
  } catch {
    return { error: "Plugin manifest is not valid UTF-8." };
  }
}

function readManifestFields(object: JsonObject): ParsedValue<{
  readonly description?: string;
  readonly name?: string;
  readonly version?: string;
}> {
  const fields: { description?: string; name?: string; version?: string } = {};
  for (const key of ["name", "description", "version"] as const) {
    const value = object[key];
    if (value === undefined) {
      continue;
    }
    if (typeof value !== "string") {
      return { error: `Plugin manifest ${key} must be a string when declared.` };
    }
    fields[key] = value;
  }
  return { value: fields };
}

function validateManifestFields(fields: {
  readonly description?: string;
  readonly name?: string;
  readonly version?: string;
}): string | undefined {
  if (fields.name === undefined || fields.name.trim().length === 0) {
    return "Plugin manifest must declare a non-empty name.";
  }
  if (fields.description === undefined || fields.description.trim().length === 0) {
    return "Plugin manifest must declare a non-empty description for a complete Uleravo snapshot.";
  }
  if (fields.version === undefined || fields.version.trim().length === 0) {
    return "Plugin manifest must declare a non-empty version for a complete Uleravo snapshot.";
  }
  if (!PLUGIN_NAME_PATTERN.test(fields.name) || fields.name.length > MAX_NAME_CHARACTERS) {
    return "Plugin manifest name must be a bounded kebab-case identifier.";
  }
  if (redactEvidenceToFixedPoint(fields.name) !== fields.name) {
    return "Plugin manifest name must not contain sensitive data.";
  }
  for (const [label, value, maximum] of [
    ["name", fields.name, MAX_NAME_CHARACTERS],
    ["description", fields.description, MAX_DESCRIPTION_CHARACTERS],
    ["version", fields.version, MAX_VERSION_CHARACTERS],
  ] as const) {
    const error = validateManifestText(label, value, maximum);
    if (error !== undefined) {
      return error;
    }
  }
  return undefined;
}

function validateManifestText(
  label: "description" | "name" | "version",
  value: string,
  maximum: number,
): string | undefined {
  if (
    value.trim().length === 0 ||
    value !== value.trim() ||
    value.length > maximum ||
    !isWellFormedUnicode(value)
  ) {
    return `Plugin manifest ${label} must be a non-empty, trimmed, bounded Unicode string.`;
  }
  if (redactEvidenceToFixedPoint(value).length > MAX_ARTIFACT_CLAIM_CHARACTERS) {
    return `Plugin manifest ${label} exceeds the artifact claim limit after safe display escaping.`;
  }
  return undefined;
}

function validateComponentDeclarations(
  object: JsonObject,
  discovery: ArtifactDiscoveryResult<"plugin">,
): string | undefined {
  const pathIndex: ObservedPathIndex = {
    directories: new Set(discovery.directories),
    files: new Set(discovery.files.map((file) => file.relativePath)),
  };
  return (
    validateCoreComponentDeclarations(object, pathIndex) ??
    validateInterfaceDeclarations(object.interface, pathIndex)
  );
}

function validateCoreComponentDeclarations(
  object: JsonObject,
  pathIndex: ObservedPathIndex,
): string | undefined {
  const skills = object.skills;
  if (skills !== undefined && !validPathOrPathArray(skills, "directory", pathIndex)) {
    return "Plugin manifest skills must resolve to an observed safe ./-relative directory or non-empty directory array.";
  }

  const mcpServers = object.mcpServers;
  if (
    mcpServers !== undefined &&
    !isJsonObject(mcpServers) &&
    (typeof mcpServers !== "string" ||
      resolveDeclaredPath(mcpServers, "file", pathIndex) === undefined)
  ) {
    return "Plugin manifest mcpServers must be an opaque inline object or resolve to one observed safe ./-relative file.";
  }

  const apps = object.apps;
  if (
    apps !== undefined &&
    (typeof apps !== "string" || resolveDeclaredPath(apps, "file", pathIndex) === undefined)
  ) {
    return "Plugin manifest apps must resolve to one observed safe ./-relative file.";
  }

  const hooks = object.hooks;
  if (hooks !== undefined && !validHookDeclaration(hooks, pathIndex)) {
    return "Plugin manifest hooks must be an observed safe path, homogeneous paths, an inline object, or homogeneous inline objects.";
  }

  return undefined;
}

function validateInterfaceDeclarations(
  interfaceValue: unknown,
  pathIndex: ObservedPathIndex,
): string | undefined {
  if (interfaceValue === undefined) {
    return undefined;
  }
  if (!isJsonObject(interfaceValue)) {
    return "Plugin manifest interface must be an object when declared.";
  }
  for (const key of ["composerIcon", "logo", "logoDark"] as const) {
    const value = interfaceValue[key];
    if (
      value !== undefined &&
      (typeof value !== "string" || resolveDeclaredPath(value, "file", pathIndex) === undefined)
    ) {
      return `Plugin manifest interface.${key} must resolve to one observed safe ./-relative file.`;
    }
  }
  const screenshots = interfaceValue.screenshots;
  if (
    screenshots !== undefined &&
    (!Array.isArray(screenshots) ||
      screenshots.length > MAX_DECLARED_PATHS ||
      !screenshots.every(
        (candidate) =>
          typeof candidate === "string" &&
          resolveDeclaredPath(candidate, "file", pathIndex) !== undefined,
      ))
  ) {
    return "Plugin manifest interface.screenshots must contain only observed safe ./-relative files.";
  }
  return undefined;
}

function validPathOrPathArray(
  value: unknown,
  expectedKind: "directory" | "file",
  pathIndex: ObservedPathIndex,
): boolean {
  if (typeof value === "string") {
    return resolveDeclaredPath(value, expectedKind, pathIndex) !== undefined;
  }
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.length <= MAX_DECLARED_PATHS &&
    value.every(
      (candidate) =>
        typeof candidate === "string" &&
        resolveDeclaredPath(candidate, expectedKind, pathIndex) !== undefined,
    )
  );
}

function validHookDeclaration(value: unknown, pathIndex: ObservedPathIndex): boolean {
  if (typeof value === "string") {
    return resolveDeclaredPath(value, "file", pathIndex) !== undefined;
  }
  if (isJsonObject(value)) {
    return true;
  }
  if (!Array.isArray(value)) {
    return false;
  }
  if (value.length > MAX_DECLARED_PATHS) {
    return false;
  }
  return (
    value.every(
      (candidate) =>
        typeof candidate === "string" &&
        resolveDeclaredPath(candidate, "file", pathIndex) !== undefined,
    ) || value.every((candidate) => isJsonObject(candidate))
  );
}

function resolveDeclaredPath(
  value: string,
  expectedKind: "directory" | "file",
  pathIndex: ObservedPathIndex,
): string | undefined {
  const normalized = normalizePluginRelativePath(value);
  if (normalized === undefined) {
    return undefined;
  }
  const observed =
    expectedKind === "file"
      ? pathIndex.files.has(normalized)
      : pathIndex.directories.has(normalized);
  return observed ? normalized : undefined;
}

function normalizePluginRelativePath(value: string): string | undefined {
  if (!value.startsWith("./") || value.length <= 2 || value.includes("\\")) {
    return undefined;
  }
  const withoutPrefix = value.slice(2);
  const normalized = withoutPrefix.endsWith("/") ? withoutPrefix.slice(0, -1) : withoutPrefix;
  return normalized.length > 0 && isPortableArtifactPath(normalized) ? normalized : undefined;
}

function invalidManifest(message: string): ParsedManifest {
  return {
    description: unavailableTextClaim(message),
    diagnostics: [{ code: "PLUGIN_MANIFEST_INVALID", file: MANIFEST_PATH, message, type: "error" }],
    name: unavailableTextClaim(message),
    valid: false,
    version: unavailableTextClaim(message),
  };
}

function declaredTextClaim(value: string): ArtifactValueClaim<string> {
  const redacted = redactEvidenceToFixedPoint(value);
  return {
    evidence: [{ path: MANIFEST_PATH }],
    ...(redacted === value ? {} : { redacted: true as const }),
    source: "declared",
    state: "resolved",
    value: redacted,
  };
}

function resolvedTextClaim(
  value: string,
  source: ArtifactValueClaim<string>["source"],
): ArtifactValueClaim<string> {
  return { evidence: [{ path: MANIFEST_PATH }], source, state: "resolved", value };
}

function unavailableTextClaim(reason: string): ArtifactAbsentClaim {
  return { evidence: [], reason, source: "observed", state: "unavailable" };
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
