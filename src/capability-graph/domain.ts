import type { ArtifactSnapshotOptions } from "../artifacts/domain.js";
import type {
  CodexHarnessApplicability,
  CodexHarnessLayerKind,
  CodexHarnessSnapshotOptions,
} from "../harnesses/domain.js";

export const CAPABILITY_GRAPH_SCHEMA_VERSION = "1.0.0" as const;
export const SKILL_CORRELATION_ADAPTER_VERSION = "1.0.0" as const;
export const MAX_CAPABILITY_GRAPH_REPORT_BYTES = 2_000_000;

export const SKILL_CORRELATION_STATES = [
  "declared-disabled",
  "declared-enabled",
  "not-declared",
  "unknown",
] as const;
export type SkillCorrelationState = (typeof SKILL_CORRELATION_STATES)[number];

export const CAPABILITY_GRAPH_DIAGNOSTIC_CODES = [
  "DECLARATION_AMBIGUOUS",
  "DECLARATION_APPLICABILITY_UNKNOWN",
  "DECLARATION_CONTEXT_CHANGED",
  "DECLARATION_CONTEXT_UNAVAILABLE",
  "DECLARATION_ENABLEMENT_UNKNOWN",
  "DECLARATION_IDENTITY_MISMATCH",
  "DECLARATION_LAYER_DISABLED",
  "DECLARATION_NOT_APPLIED",
  "DECLARATION_PATH_UNSAFE",
  "HARNESS_CAPTURE_CHANGED",
  "HARNESS_CAPTURE_INCOMPLETE",
  "SKILL_CAPTURE_CHANGED",
] as const;
export type CapabilityGraphDiagnosticCode = (typeof CAPABILITY_GRAPH_DIAGNOSTIC_CODES)[number];

export interface CapabilityGraphDiagnostic {
  readonly code: CapabilityGraphDiagnosticCode;
  readonly layer?: "project-config" | "user-config";
  readonly message: string;
  readonly type: "error";
}

export type SkillDeclarationEnablement = "disabled" | "enabled" | "unspecified";
export type SkillDeclarationIdentity = "exact-content" | "mismatch";

export interface SkillDeclarationEdge {
  readonly applicability: Exclude<CodexHarnessApplicability, "constraints">;
  readonly count: number;
  readonly enablement: SkillDeclarationEnablement;
  readonly from: string;
  readonly id: string;
  readonly identity: SkillDeclarationIdentity;
  readonly kind: "declares-skill";
  readonly layer: Exclude<CodexHarnessLayerKind, "requirements">;
  readonly to: string;
}

export interface CapabilityGraphNode {
  readonly id: string;
  readonly kind: "codex-harness" | "skill";
}

export interface SkillCapabilityGraph {
  readonly adapter: {
    readonly name: "openai-skill-codex-correlation";
    readonly version: typeof SKILL_CORRELATION_ADAPTER_VERSION;
  };
  readonly complete: boolean;
  readonly correlation: {
    readonly id: string;
    readonly reason: string;
    readonly state: SkillCorrelationState;
  };
  readonly diagnostics: readonly CapabilityGraphDiagnostic[];
  readonly documentType: "uleravo.skill-capability-graph";
  readonly edges: readonly SkillDeclarationEdge[];
  readonly graph: {
    readonly id: string;
  };
  readonly inputs: {
    readonly harness: {
      readonly adapter: {
        readonly name: "openai-codex-local";
        readonly version: string;
      };
      readonly analyzerVersion: string;
      readonly inputSha256: string;
      readonly schemaVersion: string;
      readonly snapshotId: string;
    };
    readonly skill: {
      readonly adapter: {
        readonly name: "openai-skill";
        readonly version: string;
      };
      readonly analyzerVersion: string;
      readonly contentSha256: string;
      readonly schemaVersion: string;
      readonly snapshotId: string;
    };
  };
  readonly nodes: readonly [CapabilityGraphNode, CapabilityGraphNode];
  readonly schemaVersion: typeof CAPABILITY_GRAPH_SCHEMA_VERSION;
  readonly scope: {
    readonly assertion: "declared-exposure-only";
    readonly effectAuthority: "not-established";
    readonly runtimeReachability: "not-observed";
  };
}

export interface SkillCapabilityGraphOptions extends CodexHarnessSnapshotOptions {
  readonly maxSkillFileBytes?: ArtifactSnapshotOptions["maxFileBytes"];
  readonly maxSkillFiles?: ArtifactSnapshotOptions["maxFiles"];
  readonly maxSkillTotalBytes?: ArtifactSnapshotOptions["maxTotalBytes"];
}
