import type { ArtifactDiscoveryResult } from "../discovery.js";
import type {
  ArtifactClaim,
  ArtifactCoverage,
  ArtifactDiagnostic,
  ArtifactManifestClaims,
  PluginManifestClaims,
  SkillManifestClaims,
} from "../domain.js";

export interface ArtifactAdapterAnalysis<
  Manifest extends ArtifactManifestClaims = ArtifactManifestClaims,
> {
  readonly complete: boolean;
  readonly coverage: readonly ArtifactCoverage[];
  readonly diagnostics: readonly ArtifactDiagnostic[];
  readonly manifest: Manifest;
}

export type SkillAdapterAnalysis = ArtifactAdapterAnalysis<SkillManifestClaims>;
export type PluginAdapterAnalysis = ArtifactAdapterAnalysis<PluginManifestClaims>;

export interface SkillAdapter {
  readonly kind: "skill";
  readonly name: "openai-skill";
  readonly version: "1.0.0";
  analyze(discovery: ArtifactDiscoveryResult<"skill">): SkillAdapterAnalysis;
  unavailableVersionClaim(): ArtifactClaim<string>;
}

export interface PluginAdapter {
  readonly kind: "plugin";
  readonly name: "openai-plugin";
  readonly version: "1.0.0";
  analyze(discovery: ArtifactDiscoveryResult<"plugin">): PluginAdapterAnalysis;
}
