import type { YAMLMap } from "yaml";
import { isAlias, isMap, isScalar, parseDocument, visit } from "yaml";
import { redactEvidenceToFixedPoint } from "../../redact.js";
import type { ArtifactDiscoveryResult, DiscoveredArtifactFile } from "../discovery.js";
import type {
  ArtifactAbsentClaim,
  ArtifactClaim,
  ArtifactCoverage,
  ArtifactDiagnostic,
  ArtifactValueClaim,
  SkillManifestClaims,
} from "../domain.js";
import { MAX_ARTIFACT_CLAIM_CHARACTERS } from "../domain.js";
import { isWellFormedUnicode } from "../path.js";
import type { SkillAdapter, SkillAdapterAnalysis } from "./types.js";

const MANIFEST_PATH = "SKILL.md";
const MAX_FRONT_MATTER_BYTES = 256_000;
const MAX_NAME_CHARACTERS = 256;
const MAX_DESCRIPTION_CHARACTERS = 8_000;
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

interface ParsedManifest {
  readonly description: ArtifactClaim<string>;
  readonly diagnostics: readonly ArtifactDiagnostic[];
  readonly name: ArtifactClaim<string>;
  readonly valid: boolean;
}

type ParsedValue<T> =
  | { readonly error?: never; readonly value: T }
  | { readonly error: string; readonly value?: never };

export const openAiSkillAdapter: SkillAdapter = {
  analyze(discovery: ArtifactDiscoveryResult): SkillAdapterAnalysis {
    return analyzeOpenAiSkill(discovery);
  },
  kind: "skill",
  name: "openai-skill",
  unavailableVersionClaim,
  version: "1.0.0",
};

function analyzeOpenAiSkill(discovery: ArtifactDiscoveryResult): SkillAdapterAnalysis {
  const manifestFile = discovery.files.find((file) => file.relativePath === MANIFEST_PATH);
  const parsed = manifestFile === undefined ? missingManifest() : parseSkillManifest(manifestFile);
  const pathClaim: ArtifactValueClaim<"SKILL.md"> = {
    evidence: manifestFile === undefined ? [] : [{ path: MANIFEST_PATH }],
    source: "observed",
    state: manifestFile === undefined ? "unresolved" : "resolved",
    value: MANIFEST_PATH,
  };
  const manifest: SkillManifestClaims = {
    description: parsed.description,
    name: parsed.name,
    path: pathClaim,
    version: unavailableVersionClaim(),
  };
  const coverage: ArtifactCoverage[] = [
    {
      area: "manifest-metadata",
      claim: parsed.valid
        ? resolvedTextClaim("Required SKILL.md metadata and instructions were parsed.", "declared")
        : unavailableTextClaim("Required SKILL.md metadata or instructions are unavailable."),
    },
    {
      area: "capability-normalization",
      claim: {
        evidence: [],
        reason: "Capability normalization is intentionally deferred from this foundation slice.",
        source: "inferred",
        state: "unsupported",
      },
    },
    {
      area: "harness-permissions",
      claim: {
        evidence: [],
        reason: "No harness was selected or inspected; effective permissions cannot be inferred.",
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
  const reason = "Skill root does not contain a regular SKILL.md manifest.";
  return {
    description: unavailableTextClaim(reason),
    diagnostics: [
      { code: "SKILL_MANIFEST_MISSING", file: MANIFEST_PATH, message: reason, type: "error" },
    ],
    name: unavailableTextClaim(reason),
    valid: false,
  };
}

function parseSkillManifest(file: DiscoveredArtifactFile): ParsedManifest {
  const decoded = decodeManifest(file);
  if (decoded.error !== undefined) {
    return invalidManifest(decoded.error);
  }
  const extracted = extractFrontMatter(decoded.value);
  if (extracted.error !== undefined) {
    return invalidManifest(extracted.error);
  }
  const structureError = validateManifestStructure(extracted);
  if (structureError !== undefined) {
    return invalidManifest(structureError);
  }
  const parsedMap = parseFrontMatterMap(extracted.yaml);
  if (parsedMap.error !== undefined) {
    return invalidManifest(parsedMap.error);
  }
  const fields = readManifestFields(parsedMap.value);
  if (fields.error !== undefined) {
    return invalidManifest(fields.error);
  }
  const fieldError = validateRequiredFields(fields.value.name, fields.value.description);
  if (fieldError !== undefined) {
    return invalidManifest(fieldError);
  }
  return {
    description: declaredTextClaim(fields.value.description ?? ""),
    diagnostics: [],
    name: declaredTextClaim(fields.value.name ?? ""),
    valid: true,
  };
}

function decodeManifest(file: DiscoveredArtifactFile): ParsedValue<string> {
  try {
    const text = utf8Decoder.decode(file.bytes);
    return { value: text.startsWith("\uFEFF") ? text.slice(1) : text };
  } catch {
    return { error: "SKILL.md is not valid UTF-8." };
  }
}

function validateManifestStructure(extracted: {
  readonly body: string;
  readonly yaml: string;
}): string | undefined {
  if (Buffer.byteLength(extracted.yaml, "utf8") > MAX_FRONT_MATTER_BYTES) {
    return `SKILL.md front matter exceeds the ${MAX_FRONT_MATTER_BYTES.toString()}-byte limit.`;
  }
  return extracted.body.trim().length === 0
    ? "SKILL.md must contain instructions after its front matter."
    : undefined;
}

function parseFrontMatterMap(yaml: string): ParsedValue<YAMLMap> {
  const document = parseDocument(yaml, {
    customTags: [],
    prettyErrors: false,
    schema: "failsafe",
    strict: true,
    stringKeys: true,
    uniqueKeys: true,
  });
  if (document.errors.length > 0 || document.warnings.length > 0 || !isMap(document.contents)) {
    return { error: "SKILL.md front matter must be one valid YAML mapping." };
  }
  if (hasForbiddenYamlFeature(document)) {
    return {
      error: "SKILL.md front matter must not use aliases, anchors, or custom tags.",
    };
  }
  return { value: document.contents };
}

function hasForbiddenYamlFeature(document: ReturnType<typeof parseDocument>): boolean {
  let forbidden = false;
  visit(document, {
    Node(_key, node) {
      if (
        isAlias(node) ||
        node.tag !== undefined ||
        ("anchor" in node && typeof node.anchor === "string")
      ) {
        forbidden = true;
        return visit.BREAK;
      }
      return undefined;
    },
  });
  return forbidden;
}

function readManifestFields(
  map: YAMLMap,
): ParsedValue<{ readonly description?: string; readonly name?: string }> {
  const fields: { description?: string; name?: string } = {};
  for (const pair of map.items) {
    if (!isScalar(pair.key) || typeof pair.key.value !== "string") {
      return { error: "SKILL.md front matter keys must be strings." };
    }
    const key = pair.key.value;
    if (key !== "name" && key !== "description") {
      continue;
    }
    if (!isScalar(pair.value) || typeof pair.value.value !== "string") {
      return { error: `SKILL.md ${key} must be a string scalar.` };
    }
    fields[key] = pair.value.value;
  }
  return { value: fields };
}

function extractFrontMatter(
  text: string,
):
  | { readonly body: string; readonly error?: never; readonly yaml: string }
  | { readonly body?: never; readonly error: string; readonly yaml?: never } {
  const lines = text.split(/\r?\n/);
  if (lines[0] !== "---") {
    return { error: "SKILL.md must begin with YAML front matter." };
  }
  const closingIndex = lines.findIndex((line, index) => index > 0 && line === "---");
  if (closingIndex < 0) {
    return { error: "SKILL.md YAML front matter is not closed." };
  }
  return {
    body: lines.slice(closingIndex + 1).join("\n"),
    yaml: lines.slice(1, closingIndex).join("\n"),
  };
}

function validateRequiredFields(
  name: string | undefined,
  description: string | undefined,
): string | undefined {
  if (name === undefined || name.trim().length === 0) {
    return "SKILL.md must declare a non-empty name.";
  }
  if (name.length > MAX_NAME_CHARACTERS) {
    return `SKILL.md name exceeds ${MAX_NAME_CHARACTERS.toString()} characters.`;
  }
  if (description === undefined || description.trim().length === 0) {
    return "SKILL.md must declare a non-empty description.";
  }
  if (description.length > MAX_DESCRIPTION_CHARACTERS) {
    return `SKILL.md description exceeds ${MAX_DESCRIPTION_CHARACTERS.toString()} characters.`;
  }
  for (const [label, value] of [
    ["name", name],
    ["description", description],
  ] as const) {
    if (!isWellFormedUnicode(value)) {
      return `SKILL.md ${label} must contain well-formed Unicode.`;
    }
    if (redactEvidenceToFixedPoint(value.trim()).length > MAX_ARTIFACT_CLAIM_CHARACTERS) {
      return `SKILL.md ${label} exceeds the ${MAX_ARTIFACT_CLAIM_CHARACTERS.toString()}-character artifact claim limit after safe display escaping.`;
    }
  }
  return undefined;
}

function invalidManifest(message: string): ParsedManifest {
  return {
    description: unavailableTextClaim(message),
    diagnostics: [{ code: "SKILL_MANIFEST_INVALID", file: MANIFEST_PATH, message, type: "error" }],
    name: unavailableTextClaim(message),
    valid: false,
  };
}

function declaredTextClaim(value: string): ArtifactValueClaim<string> {
  const normalized = value.trim();
  const redacted = redactEvidenceToFixedPoint(normalized);
  return {
    evidence: [{ path: MANIFEST_PATH }],
    ...(redacted === normalized ? {} : { redacted: true as const }),
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

function unavailableVersionClaim(): ArtifactAbsentClaim {
  return {
    evidence: [],
    reason: "The supported SKILL.md contract does not declare an artifact version.",
    source: "inferred",
    state: "unavailable",
  };
}
