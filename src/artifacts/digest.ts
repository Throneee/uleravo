import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { compareCodeUnits } from "../order.js";
import type { ArtifactDiagnostic, ArtifactKind } from "./domain.js";

export interface DigestibleArtifactFile {
  readonly bytes: Buffer;
  readonly relativePath: string;
  readonly sha256: string;
}

const CONTENT_DOMAIN = Buffer.from("uleravo-artifact-content-v1\0", "utf8");
const OBSERVATION_DOMAIN = Buffer.from("uleravo-artifact-observation-v1\0", "utf8");
const SNAPSHOT_DOMAIN = Buffer.from("uleravo-artifact-snapshot-v1\0", "utf8");

export function artifactContentSha256(
  kind: ArtifactKind,
  files: readonly DigestibleArtifactFile[],
): string {
  const hash = createHash("sha256").update(CONTENT_DOMAIN);
  updateLengthPrefixed(hash, kind);
  for (const file of sortedFiles(files)) {
    updateLengthPrefixed(hash, file.relativePath);
    updateUnsignedLength(hash, file.bytes.byteLength);
    hash.update(Buffer.from(file.sha256, "hex"));
  }
  return hash.digest("hex");
}

export function artifactObservationSha256(
  kind: ArtifactKind,
  files: readonly DigestibleArtifactFile[],
): string {
  const hash = createHash("sha256").update(OBSERVATION_DOMAIN);
  updateLengthPrefixed(hash, kind);
  for (const file of sortedFiles(files)) {
    updateLengthPrefixed(hash, file.relativePath);
    updateUnsignedLength(hash, file.bytes.byteLength);
    hash.update(Buffer.from(file.sha256, "hex"));
  }
  return hash.digest("hex");
}

export function artifactSnapshotId(input: {
  readonly adapterVersion: string;
  readonly analyzerVersion: string;
  readonly context: string;
  readonly diagnostics: readonly ArtifactDiagnostic[];
  readonly observationSha256: string;
}): string {
  const hash = createHash("sha256").update(SNAPSHOT_DOMAIN);
  updateLengthPrefixed(hash, input.adapterVersion);
  updateLengthPrefixed(hash, input.analyzerVersion);
  updateLengthPrefixed(hash, input.context);
  updateLengthPrefixed(hash, input.observationSha256);
  updateLengthPrefixed(
    hash,
    JSON.stringify(
      input.diagnostics.map(({ code, file, type }) => ({
        code,
        ...(file === undefined ? {} : { file }),
        type,
      })),
    ),
  );
  return hash.digest("hex").slice(0, 24);
}

function sortedFiles(files: readonly DigestibleArtifactFile[]): readonly DigestibleArtifactFile[] {
  return [...files].sort((left, right) => compareCodeUnits(left.relativePath, right.relativePath));
}

function updateLengthPrefixed(hash: ReturnType<typeof createHash>, value: string): void {
  const bytes = Buffer.from(value, "utf8");
  updateUnsignedLength(hash, bytes.byteLength);
  hash.update(bytes);
}

function updateUnsignedLength(hash: ReturnType<typeof createHash>, value: number): void {
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(value));
  hash.update(length);
}
