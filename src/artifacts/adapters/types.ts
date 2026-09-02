import type { ArtifactDiscoveryResult } from "../discovery.js";
import type {
  ArtifactClaim,
  ArtifactCoverage,
  ArtifactDiagnostic,
  SkillManifestClaims,
} from "../domain.js";

export interface SkillAdapterAnalysis {
  readonly complete: boolean;
  readonly coverage: readonly ArtifactCoverage[];
  readonly diagnostics: readonly ArtifactDiagnostic[];
  readonly manifest: SkillManifestClaims;
}

export interface SkillAdapter {
  readonly kind: "skill";
  readonly name: "openai-skill";
  readonly version: "1.0.0";
  analyze(discovery: ArtifactDiscoveryResult): SkillAdapterAnalysis;
  unavailableVersionClaim(): ArtifactClaim<string>;
}
