import { Buffer } from "node:buffer";
import type { RepositoryProvenance } from "../domain.js";
import { compareCodeUnits } from "../order.js";
import { redactEvidence } from "../redact.js";
import { normalizeRepositoryIdentity } from "../scanner/provenance.js";
import { ARTIFACT_ANALYZER_VERSION, PRODUCT_NAME } from "../version.js";
import { openAiPluginAdapter } from "./adapters/openai-plugin.js";
import { openAiSkillAdapter } from "./adapters/openai-skill.js";
import type { PluginAdapterAnalysis, SkillAdapterAnalysis } from "./adapters/types.js";
import { artifactSnapshotId } from "./digest.js";
import {
  type ArtifactDiscoveryResult,
  discoverPluginArtifact,
  discoverSkillArtifact,
} from "./discovery.js";
import type {
  ArtifactAbsentClaim,
  ArtifactClosureFile,
  ArtifactCoverage,
  ArtifactDiagnostic,
  ArtifactKind,
  ArtifactRepositoryClaims,
  ArtifactSnapshot,
  ArtifactSnapshotOptions,
  ArtifactValueClaim,
  PluginArtifactSnapshot,
  SkillArtifactSnapshot,
} from "./domain.js";
import {
  MAX_ARTIFACT_CLAIM_CHARACTERS,
  MAX_ARTIFACT_DIAGNOSTICS,
  MAX_ARTIFACT_REPORT_BYTES,
} from "./domain.js";

export async function snapshotSkill(
  requestedTarget: string,
  options: ArtifactSnapshotOptions = {},
): Promise<SkillArtifactSnapshot> {
  return (await snapshotArtifact(requestedTarget, options, "skill")).snapshot;
}

export async function snapshotPlugin(
  requestedTarget: string,
  options: ArtifactSnapshotOptions = {},
): Promise<PluginArtifactSnapshot> {
  return (await snapshotArtifact(requestedTarget, options, "plugin")).snapshot;
}

export async function snapshotSkillWithRoot(
  requestedTarget: string,
  options: ArtifactSnapshotOptions = {},
): Promise<{ readonly root: string; readonly snapshot: SkillArtifactSnapshot }> {
  return snapshotArtifact(requestedTarget, options, "skill");
}

export async function snapshotPluginWithRoot(
  requestedTarget: string,
  options: ArtifactSnapshotOptions = {},
): Promise<{ readonly root: string; readonly snapshot: PluginArtifactSnapshot }> {
  return snapshotArtifact(requestedTarget, options, "plugin");
}

type ArtifactCapture =
  | {
      readonly adapter: typeof openAiPluginAdapter;
      readonly analysis: PluginAdapterAnalysis;
      readonly discovery: ArtifactDiscoveryResult<"plugin">;
      readonly kind: "plugin";
    }
  | {
      readonly adapter: typeof openAiSkillAdapter;
      readonly analysis: SkillAdapterAnalysis;
      readonly discovery: ArtifactDiscoveryResult<"skill">;
      readonly kind: "skill";
    };

async function snapshotArtifact(
  requestedTarget: string,
  options: ArtifactSnapshotOptions,
  kind: "skill",
): Promise<{ readonly root: string; readonly snapshot: SkillArtifactSnapshot }>;
async function snapshotArtifact(
  requestedTarget: string,
  options: ArtifactSnapshotOptions,
  kind: "plugin",
): Promise<{ readonly root: string; readonly snapshot: PluginArtifactSnapshot }>;
async function snapshotArtifact(
  requestedTarget: string,
  options: ArtifactSnapshotOptions,
  kind: ArtifactKind,
): Promise<{ readonly root: string; readonly snapshot: ArtifactSnapshot }> {
  const startedAt = Date.now();
  const capture = await captureArtifact(requestedTarget, options, kind);
  const { adapter, analysis, discovery } = capture;
  const diagnostics = limitDiagnostics(
    deduplicateDiagnostics(
      [...discovery.diagnostics, ...analysis.diagnostics].sort(compareDiagnostics),
    ),
  );
  const complete = discovery.complete && analysis.complete && !hasErrors(diagnostics);
  const files: ArtifactClosureFile[] = discovery.files.map((file) => ({
    bytes: observedValueClaim(file.bytes.byteLength, file.relativePath),
    path: observedValueClaim(file.relativePath, file.relativePath),
    sha256: observedValueClaim(file.sha256, file.relativePath),
  }));
  const coverage: ArtifactCoverage[] = [
    {
      area: "artifact-closure",
      claim: discovery.complete
        ? {
            evidence: files.map((file) => ({ path: file.path.value })),
            source: "observed",
            state: "resolved",
            value:
              "Every admitted regular file was safely hashed; VCS control directories are outside the closure definition.",
          }
        : {
            evidence: files.map((file) => ({ path: file.path.value })),
            source: "observed",
            state: "unresolved",
            value:
              "Only the safely observed subset was hashed; the full artifact closure is unresolved.",
          },
    },
    ...analysis.coverage,
  ];
  const repository =
    options.repository === undefined ? undefined : repositoryClaims(options.repository);
  const id = artifactSnapshotId({
    adapterVersion: adapter.version,
    analyzerVersion: ARTIFACT_ANALYZER_VERSION,
    context: repository === undefined ? "" : `${repository.url.value}\0${repository.commit.value}`,
    diagnostics,
    observationSha256: discovery.observedSha256,
  });

  const identity = {
    contentSha256:
      discovery.contentSha256 === undefined
        ? unavailableContentIdentity()
        : {
            evidence: files.map((file) => ({ path: file.path.value })),
            source: "observed" as const,
            state: "resolved" as const,
            value: discovery.contentSha256,
          },
    mutable: {
      evidence: [],
      source: "inferred" as const,
      state: "mutable" as const,
      value: true as const,
    },
  };
  const envelope = {
    closure: {
      files,
      observedSha256: {
        evidence: files.map((file) => ({ path: file.path.value })),
        source: "observed",
        state: "resolved",
        value: discovery.observedSha256,
      },
      totalBytes: {
        evidence: files.map((file) => ({ path: file.path.value })),
        source: "observed",
        state: discovery.complete ? "resolved" : "unresolved",
        value: discovery.totalBytes,
      },
    },
    complete,
    coverage,
    diagnostics,
    documentType: "uleravo.artifact-snapshot",
    schemaVersion: "1.0.0",
    snapshot: {
      analyzer: { name: PRODUCT_NAME, version: ARTIFACT_ANALYZER_VERSION },
      consistency: "best-effort",
      durationMs: Math.max(0, Date.now() - startedAt),
      generatedAt: new Date().toISOString(),
      id,
      target: discovery.target,
    },
  } as const;
  const snapshot: ArtifactSnapshot =
    capture.kind === "skill"
      ? {
          artifact: {
            adapter: { name: "openai-skill", version: "1.0.0" },
            identity,
            kind: "skill",
            manifest: capture.analysis.manifest,
            ...(repository === undefined ? {} : { repository }),
          },
          ...envelope,
        }
      : {
          artifact: {
            adapter: { name: "openai-plugin", version: "1.0.0" },
            identity,
            kind: "plugin",
            manifest: capture.analysis.manifest,
            ...(repository === undefined ? {} : { repository }),
          },
          ...envelope,
        };
  const reportBytes = Buffer.byteLength(JSON.stringify(snapshot, null, 2), "utf8") + 1;
  if (reportBytes > MAX_ARTIFACT_REPORT_BYTES) {
    throw new Error(
      `Artifact snapshot exceeds the ${MAX_ARTIFACT_REPORT_BYTES.toString()}-byte report limit; lower the file limits or shorten artifact paths.`,
    );
  }
  return { root: discovery.root, snapshot };
}

async function captureArtifact(
  requestedTarget: string,
  options: ArtifactSnapshotOptions,
  kind: ArtifactKind,
): Promise<ArtifactCapture> {
  if (kind === "skill") {
    const discovery = await discoverSkillArtifact(requestedTarget, options);
    return {
      adapter: openAiSkillAdapter,
      analysis: openAiSkillAdapter.analyze(discovery),
      discovery,
      kind,
    };
  }
  const discovery = await discoverPluginArtifact(requestedTarget, options);
  return {
    adapter: openAiPluginAdapter,
    analysis: openAiPluginAdapter.analyze(discovery),
    discovery,
    kind,
  };
}

function observedValueClaim<T>(value: T, evidencePath: string): ArtifactValueClaim<T> {
  return {
    evidence: [{ path: evidencePath }],
    source: "observed",
    state: "resolved",
    value,
  };
}

function unavailableContentIdentity(): ArtifactAbsentClaim {
  return {
    evidence: [],
    reason: "A content identity is unavailable until the full artifact closure is resolved.",
    source: "observed",
    state: "unavailable",
  };
}

function repositoryClaims(repository: RepositoryProvenance): ArtifactRepositoryClaims {
  const normalized = normalizeRepositoryIdentity(repository);
  if (normalized.url.length > MAX_ARTIFACT_CLAIM_CHARACTERS) {
    throw new Error(
      `Repository URL exceeds the ${MAX_ARTIFACT_CLAIM_CHARACTERS.toString()}-character artifact claim limit.`,
    );
  }
  if (redactEvidence(normalized.url) !== normalized.url) {
    throw new Error("Repository URL must not contain sensitive data.");
  }
  return {
    commit: {
      evidence: [],
      source: "user-supplied",
      state: "endpoint-unverified",
      value: normalized.commit,
    },
    url: {
      evidence: [],
      source: "user-supplied",
      state: "endpoint-unverified",
      value: normalized.url,
    },
  };
}

function hasErrors(diagnostics: readonly ArtifactDiagnostic[]): boolean {
  return diagnostics.some((diagnostic) => diagnostic.type === "error");
}

function compareDiagnostics(left: ArtifactDiagnostic, right: ArtifactDiagnostic): number {
  return (
    compareCodeUnits(left.file ?? "", right.file ?? "") ||
    compareCodeUnits(left.code, right.code) ||
    compareCodeUnits(left.type, right.type) ||
    compareCodeUnits(left.message, right.message)
  );
}

function deduplicateDiagnostics(
  diagnostics: readonly ArtifactDiagnostic[],
): readonly ArtifactDiagnostic[] {
  return diagnostics.filter(
    (diagnostic, index) =>
      index === 0 ||
      compareDiagnostics(diagnostic, diagnostics[index - 1] as ArtifactDiagnostic) !== 0,
  );
}

function limitDiagnostics(
  diagnostics: readonly ArtifactDiagnostic[],
): readonly ArtifactDiagnostic[] {
  if (diagnostics.length <= MAX_ARTIFACT_DIAGNOSTICS) {
    return diagnostics;
  }
  const preservedDiagnostics = diagnostics.filter(
    (diagnostic) =>
      diagnostic.code === "ARTIFACT_DIAGNOSTIC_LIMIT" ||
      diagnostic.code === "PLUGIN_MANIFEST_INVALID" ||
      diagnostic.code === "PLUGIN_MANIFEST_MISSING" ||
      diagnostic.code === "SKILL_MANIFEST_INVALID" ||
      diagnostic.code === "SKILL_MANIFEST_MISSING",
  );
  const otherDiagnostics = diagnostics.filter(
    (diagnostic) =>
      diagnostic.code !== "ARTIFACT_DIAGNOSTIC_LIMIT" &&
      diagnostic.code !== "PLUGIN_MANIFEST_INVALID" &&
      diagnostic.code !== "PLUGIN_MANIFEST_MISSING" &&
      diagnostic.code !== "SKILL_MANIFEST_INVALID" &&
      diagnostic.code !== "SKILL_MANIFEST_MISSING",
  );
  const marker: ArtifactDiagnostic = {
    code: "ARTIFACT_DIAGNOSTIC_LIMIT",
    message: `Artifact diagnostics were truncated at ${MAX_ARTIFACT_DIAGNOSTICS.toString()} entries.`,
    type: "error",
  };
  const retainedDiagnostics = preservedDiagnostics.slice(0, MAX_ARTIFACT_DIAGNOSTICS - 1);
  const hasMarker = retainedDiagnostics.some(
    (diagnostic) => diagnostic.code === "ARTIFACT_DIAGNOSTIC_LIMIT",
  );
  const markerCapacity = hasMarker ? 0 : 1;
  const remainingCapacity = MAX_ARTIFACT_DIAGNOSTICS - retainedDiagnostics.length - markerCapacity;
  return [
    ...retainedDiagnostics,
    ...otherDiagnostics.slice(0, remainingCapacity),
    ...(hasMarker ? [] : [marker]),
  ].sort(compareDiagnostics);
}
