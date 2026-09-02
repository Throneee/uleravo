import { Buffer } from "node:buffer";
import type { RepositoryProvenance } from "../domain.js";
import { compareCodeUnits } from "../order.js";
import { redactEvidence } from "../redact.js";
import { normalizeRepositoryIdentity } from "../scanner/provenance.js";
import { ARTIFACT_ANALYZER_VERSION, PRODUCT_NAME } from "../version.js";
import { openAiSkillAdapter } from "./adapters/openai-skill.js";
import { artifactSnapshotId } from "./digest.js";
import { discoverSkillArtifact } from "./discovery.js";
import type {
  ArtifactAbsentClaim,
  ArtifactClosureFile,
  ArtifactCoverage,
  ArtifactDiagnostic,
  ArtifactRepositoryClaims,
  ArtifactSnapshot,
  ArtifactSnapshotOptions,
  ArtifactValueClaim,
} from "./domain.js";
import {
  MAX_ARTIFACT_CLAIM_CHARACTERS,
  MAX_ARTIFACT_DIAGNOSTICS,
  MAX_ARTIFACT_REPORT_BYTES,
} from "./domain.js";

export async function snapshotSkill(
  requestedTarget: string,
  options: ArtifactSnapshotOptions = {},
): Promise<ArtifactSnapshot> {
  const startedAt = Date.now();
  const discovery = await discoverSkillArtifact(requestedTarget, options);
  const analysis = openAiSkillAdapter.analyze(discovery);
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
    adapterVersion: openAiSkillAdapter.version,
    analyzerVersion: ARTIFACT_ANALYZER_VERSION,
    context: repository === undefined ? "" : `${repository.url.value}\0${repository.commit.value}`,
    diagnostics,
    observationSha256: discovery.observedSha256,
  });

  const snapshot: ArtifactSnapshot = {
    artifact: {
      adapter: { name: openAiSkillAdapter.name, version: openAiSkillAdapter.version },
      identity: {
        contentSha256:
          discovery.contentSha256 === undefined
            ? unavailableContentIdentity()
            : {
                evidence: files.map((file) => ({ path: file.path.value })),
                source: "observed",
                state: "resolved",
                value: discovery.contentSha256,
              },
        mutable: {
          evidence: [],
          source: "inferred",
          state: "mutable",
          value: true,
        },
      },
      kind: "skill",
      manifest: analysis.manifest,
      ...(repository === undefined ? {} : { repository }),
    },
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
  };
  const reportBytes = Buffer.byteLength(JSON.stringify(snapshot, null, 2), "utf8") + 1;
  if (reportBytes > MAX_ARTIFACT_REPORT_BYTES) {
    throw new Error(
      `Artifact snapshot exceeds the ${MAX_ARTIFACT_REPORT_BYTES.toString()}-byte report limit; lower the file limits or shorten artifact paths.`,
    );
  }
  return snapshot;
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
      diagnostic.code === "SKILL_MANIFEST_INVALID" ||
      diagnostic.code === "SKILL_MANIFEST_MISSING",
  );
  const otherDiagnostics = diagnostics.filter(
    (diagnostic) =>
      diagnostic.code !== "ARTIFACT_DIAGNOSTIC_LIMIT" &&
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
