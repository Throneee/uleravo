import type { ArtifactClaim, ArtifactSnapshot } from "../artifacts/domain.js";

export function formatArtifactSnapshotJson(snapshot: ArtifactSnapshot): string {
  return `${JSON.stringify(snapshot, null, 2)}\n`;
}

export function formatArtifactSnapshotText(snapshot: ArtifactSnapshot): string {
  const identityLines =
    snapshot.artifact.kind === "skill"
      ? [`Skill: ${claimValue(snapshot.artifact.manifest.name)}`]
      : [
          `Plugin: ${claimValue(snapshot.artifact.manifest.name)}`,
          `Version: ${claimValue(snapshot.artifact.manifest.version)}`,
        ];
  const lines = [
    `Uleravo artifact snapshot ${snapshot.snapshot.id}`,
    `Target: ${snapshot.snapshot.target}`,
    `Kind: ${snapshot.artifact.kind}`,
    `Complete: ${snapshot.complete ? "yes" : "no"}`,
    ...identityLines,
    `Description: ${claimValue(snapshot.artifact.manifest.description)}`,
    `Content SHA-256: ${claimValue(snapshot.artifact.identity.contentSha256)}`,
    `Observed files: ${snapshot.closure.files.length.toString()}`,
    `Observed bytes: ${snapshot.closure.totalBytes.value.toString()}`,
    "Coverage:",
    ...snapshot.coverage.map(
      (coverage) => `  ${coverage.area}: ${coverage.claim.state} (${claimDetail(coverage.claim)})`,
    ),
  ];

  if (snapshot.diagnostics.length > 0) {
    lines.push(
      "Diagnostics:",
      ...snapshot.diagnostics.map(
        (diagnostic) =>
          `  ${diagnostic.type.toUpperCase()}${diagnostic.file === undefined ? "" : ` ${diagnostic.file}`}: ${diagnostic.message}`,
      ),
    );
  }
  return `${lines.join("\n")}\n`;
}

function claimValue(claim: ArtifactClaim<unknown>): string {
  if ("value" in claim) {
    return String(claim.value);
  }
  return `${claim.state}: ${claim.reason}`;
}

function claimDetail(claim: ArtifactClaim<string>): string {
  return "value" in claim ? claim.value : claim.reason;
}
