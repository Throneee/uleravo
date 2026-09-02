import type { RepositoryProvenance } from "../domain.js";

export const ARTIFACT_DIAGNOSTIC_CODES = [
  "ARTIFACT_DIRECTORY_CHANGED",
  "ARTIFACT_DIRECTORY_DEPTH_LIMIT",
  "ARTIFACT_DIRECTORY_ENUMERATION_FAILED",
  "ARTIFACT_DIAGNOSTIC_LIMIT",
  "ARTIFACT_DIRECTORY_LIMIT",
  "ARTIFACT_ENTRY_LIMIT",
  "ARTIFACT_FILE_READ_FAILED",
  "ARTIFACT_FILE_SIZE_LIMIT",
  "ARTIFACT_LFS_POINTER_UNRESOLVED",
  "ARTIFACT_NON_PORTABLE_PATH",
  "ARTIFACT_NON_REGULAR_ENTRY",
  "ARTIFACT_SENSITIVE_PATH",
  "ARTIFACT_SYMLINK_UNSUPPORTED",
  "ARTIFACT_TOTAL_SIZE_LIMIT",
  "PLUGIN_MANIFEST_INVALID",
  "PLUGIN_MANIFEST_MISSING",
  "SKILL_MANIFEST_INVALID",
  "SKILL_MANIFEST_MISSING",
] as const;
export type ArtifactDiagnosticCode = (typeof ARTIFACT_DIAGNOSTIC_CODES)[number];
export const MAX_ARTIFACT_CLAIM_CHARACTERS = 10_000;
export const MAX_ARTIFACT_DIAGNOSTICS = 1_000;
export const MAX_ARTIFACT_REPORT_BYTES = 10_000_000;
export const MAX_ARTIFACT_TARGET_CHARACTERS = 1_000;

export interface ArtifactDiagnostic {
  readonly code: ArtifactDiagnosticCode;
  readonly file?: string;
  readonly message: string;
  readonly type: "error";
}

export const ARTIFACT_EVIDENCE_SOURCES = [
  "declared",
  "inferred",
  "observed",
  "user-supplied",
] as const;
export type ArtifactEvidenceSource = (typeof ARTIFACT_EVIDENCE_SOURCES)[number];

export const ARTIFACT_EVIDENCE_STATES = [
  "endpoint-unverified",
  "mutable",
  "resolved",
  "unavailable",
  "unresolved",
  "unsupported",
] as const;
export type ArtifactEvidenceState = (typeof ARTIFACT_EVIDENCE_STATES)[number];

export interface ArtifactEvidenceReference {
  readonly path: string;
}

export interface ArtifactValueClaim<T> {
  readonly evidence: readonly ArtifactEvidenceReference[];
  readonly redacted?: true;
  readonly source: ArtifactEvidenceSource;
  readonly state: "endpoint-unverified" | "mutable" | "resolved" | "unresolved";
  readonly value: T;
}

export interface ArtifactAbsentClaim {
  readonly evidence: readonly ArtifactEvidenceReference[];
  readonly reason: string;
  readonly source: ArtifactEvidenceSource;
  readonly state: "unavailable" | "unsupported";
}

export type ArtifactClaim<T> = ArtifactAbsentClaim | ArtifactValueClaim<T>;

export interface ArtifactClosureFile {
  readonly bytes: ArtifactValueClaim<number>;
  readonly path: ArtifactValueClaim<string>;
  readonly sha256: ArtifactValueClaim<string>;
}

export interface ArtifactCoverage {
  readonly area:
    | "artifact-closure"
    | "capability-normalization"
    | "harness-permissions"
    | "manifest-metadata";
  readonly claim: ArtifactClaim<string>;
}

export interface SkillManifestClaims {
  readonly description: ArtifactClaim<string>;
  readonly name: ArtifactClaim<string>;
  readonly path: ArtifactValueClaim<"SKILL.md">;
  readonly version: ArtifactAbsentClaim;
}

export interface PluginManifestClaims {
  readonly description: ArtifactClaim<string>;
  readonly name: ArtifactClaim<string>;
  readonly path: ArtifactValueClaim<".codex-plugin/plugin.json">;
  readonly version: ArtifactClaim<string>;
}

export type ArtifactKind = "plugin" | "skill";
export type ArtifactManifestClaims = PluginManifestClaims | SkillManifestClaims;

export interface ArtifactRepositoryClaims {
  readonly commit: ArtifactValueClaim<string>;
  readonly url: ArtifactValueClaim<string>;
}

interface ArtifactDescriptorBase {
  readonly identity: {
    readonly contentSha256: ArtifactClaim<string>;
    readonly mutable: ArtifactValueClaim<true>;
  };
  readonly repository?: ArtifactRepositoryClaims;
}

export interface SkillArtifactDescriptor extends ArtifactDescriptorBase {
  readonly adapter: {
    readonly name: "openai-skill";
    readonly version: "1.0.0";
  };
  readonly kind: "skill";
  readonly manifest: SkillManifestClaims;
}

export interface PluginArtifactDescriptor extends ArtifactDescriptorBase {
  readonly adapter: {
    readonly name: "openai-plugin";
    readonly version: "1.0.0";
  };
  readonly kind: "plugin";
  readonly manifest: PluginManifestClaims;
}

interface ArtifactSnapshotBase {
  readonly closure: {
    readonly files: readonly ArtifactClosureFile[];
    readonly observedSha256: ArtifactValueClaim<string>;
    readonly totalBytes: ArtifactValueClaim<number>;
  };
  readonly complete: boolean;
  readonly coverage: readonly ArtifactCoverage[];
  readonly diagnostics: readonly ArtifactDiagnostic[];
  readonly documentType: "uleravo.artifact-snapshot";
  readonly schemaVersion: "1.0.0";
  readonly snapshot: {
    readonly analyzer: {
      readonly name: string;
      readonly version: string;
    };
    readonly consistency: "best-effort";
    readonly durationMs: number;
    readonly generatedAt: string;
    readonly id: string;
    readonly target: string;
  };
}

export interface SkillArtifactSnapshot extends ArtifactSnapshotBase {
  readonly artifact: SkillArtifactDescriptor;
}

export interface PluginArtifactSnapshot extends ArtifactSnapshotBase {
  readonly artifact: PluginArtifactDescriptor;
}

export type ArtifactSnapshot = PluginArtifactSnapshot | SkillArtifactSnapshot;

export interface ArtifactSnapshotOptions {
  readonly maxFileBytes?: number;
  readonly maxFiles?: number;
  readonly maxTotalBytes?: number;
  readonly repository?: RepositoryProvenance;
}
