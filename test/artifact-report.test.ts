import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import type { ArtifactSnapshot } from "../src/artifacts/domain.js";
import { parseArtifactSnapshot, readArtifactSnapshot } from "../src/artifacts/read.js";
import { snapshotSkill } from "../src/artifacts/snapshot.js";
import { redactEvidence } from "../src/redact.js";

const minimalSkill = fileURLToPath(new URL("./fixtures/skills/minimal", import.meta.url));
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("artifact snapshot report reader", () => {
  it("round-trips complete, incomplete, and repository-bound producer reports", async () => {
    const complete = await snapshotSkill(minimalSkill);
    const emptySkill = await makeTemporaryDirectory();
    const incomplete = await snapshotSkill(emptySkill);
    const repositoryBound = await snapshotSkill(minimalSkill, {
      repository: {
        commit: "0123456789abcdef0123456789abcdef01234567",
        url: "https://github.com/Throneee/uleravo",
      },
    });

    expect(parseArtifactSnapshot(JSON.stringify(complete))).toEqual(complete);
    expect(parseArtifactSnapshot(JSON.stringify(incomplete))).toEqual(incomplete);
    expect(parseArtifactSnapshot(JSON.stringify(repositoryBound))).toEqual(repositoryBound);
  });

  it("does not impose path normalization rules on safe manifest prose", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(
      path.join(directory, "SKILL.md"),
      [
        "---",
        "name: decomposed-prose",
        "description: A safe decomposed cafe\u0301 description.",
        "---",
        "Instructions.",
      ].join("\n"),
    );
    const snapshot = await snapshotSkill(directory);

    expect(parseArtifactSnapshot(JSON.stringify(snapshot))).toEqual(snapshot);
  });

  it("reads a bounded stable regular UTF-8 report", async () => {
    const directory = await makeTemporaryDirectory();
    const reportPath = path.join(directory, "snapshot.json");
    const snapshot = await snapshotSkill(minimalSkill);
    await writeFile(reportPath, JSON.stringify(snapshot));

    await expect(readArtifactSnapshot(reportPath)).resolves.toEqual(snapshot);
  });

  it("fully redacts bounded parse labels and filesystem errors", async () => {
    const credential = `AKIA${"A".repeat(16)}`;
    const crafted = `${credential}SECRETVALUE password=SECRETVALUE`;

    const parseMessage = capturedErrorMessage(() => parseArtifactSnapshot("{", crafted));
    const readMessage = await capturedAsyncErrorMessage(
      readArtifactSnapshot(path.join(tmpdir(), crafted)),
    );
    for (const message of [parseMessage, readMessage]) {
      expect(message.length).toBeLessThanOrEqual(1_100);
      expect(message).not.toContain(credential);
      expect(redactEvidence(message)).toBe(message);
    }
  });

  it("rejects directories, oversized files, and invalid UTF-8", async () => {
    const directory = await makeTemporaryDirectory();
    const invalidUtf8 = path.join(directory, "invalid.json");
    const oversized = path.join(directory, "oversized.json");
    const nestedDirectory = path.join(directory, "directory.json");
    await writeFile(invalidUtf8, Buffer.from([0xff, 0xfe, 0xfd]));
    await writeFile(oversized, Buffer.alloc(10_000_001));
    await mkdir(nestedDirectory);

    await expect(readArtifactSnapshot(invalidUtf8)).rejects.toThrow(/UTF-8/u);
    await expect(readArtifactSnapshot(oversized)).rejects.toThrow(/10000000-byte/u);
    await expect(readArtifactSnapshot(nestedDirectory)).rejects.toThrow(/regular report file/u);
  });

  it.runIf(process.platform !== "win32")("rejects a symbolic-link report", async () => {
    const directory = await makeTemporaryDirectory();
    const target = path.join(directory, "target.json");
    const linked = path.join(directory, "linked.json");
    await writeFile(target, JSON.stringify(await snapshotSkill(minimalSkill)));
    await symlink(target, linked, "file");

    await expect(readArtifactSnapshot(linked)).rejects.toThrow(/regular report file/u);
  });

  it("rejects duplicate JSON keys at nested object depths", async () => {
    const serialized = JSON.stringify(await snapshotSkill(minimalSkill));
    const duplicated = serialized.replace(
      '"adapter":{"name":"openai-skill","version":"1.0.0"}',
      '"adapter":{"name":"openai-skill","name":"openai-skill","version":"1.0.0"}',
    );
    expect(duplicated).not.toBe(serialized);

    expect(() => parseArtifactSnapshot(duplicated)).toThrow(/duplicate JSON object key/u);

    const escapedDuplicate = serialized.replace(
      '"name":"openai-skill"',
      '"name":"openai-skill","\\u006eame":"openai-skill"',
    );
    expect(escapedDuplicate).not.toBe(serialized);
    expect(() => parseArtifactSnapshot(escapedDuplicate)).toThrow(/duplicate JSON object key/u);
  });

  it("bounds JSON nesting before native parsing", () => {
    const overlyNested = `${"[".repeat(130)}null${"]".repeat(130)}`;

    expect(() => parseArtifactSnapshot(overlyNested)).toThrow(/JSON nesting limit/u);
  });

  it("rejects unknown fields at every validated object boundary", async () => {
    const root = mutableClone(await snapshotSkill(minimalSkill));
    objectValue(objectValue(root, "artifact"), "adapter").futureField = true;

    expect(() => parseArtifactSnapshot(JSON.stringify(root))).toThrow(/unknown field/u);
  });

  it.each([
    [
      "manifest text",
      (root: JsonObject, credential: string) => {
        objectValue(objectValue(objectValue(root, "artifact"), "manifest"), "name").value =
          credential;
      },
    ],
    [
      "snapshot target",
      (root: JsonObject, credential: string) => {
        objectValue(root, "snapshot").target = credential;
      },
    ],
    [
      "coverage reason",
      (root: JsonObject, credential: string) => {
        const coverage = arrayValue(root, "coverage");
        const deferred = coverage.find(
          (entry) => objectValue(entry).area === "capability-normalization",
        );
        objectValue(objectValue(deferred), "claim").reason = credential;
      },
    ],
  ])("rejects unredacted credential-shaped %s", async (_label, mutate) => {
    const root = mutableClone(await snapshotSkill(minimalSkill));
    mutate(root, `sk-${"Z".repeat(24)}`);

    expect(() => parseArtifactSnapshot(JSON.stringify(root))).toThrow(/safe redacted string/u);
  });

  it.each([
    ["traversal", "../escape"],
    ["backslash", "assets\\escape.txt"],
    ["non-NFC", "assets/e\u0301.txt"],
    ["display control", "assets/unsafe\u007f.txt"],
    ["bidirectional control", "assets/unsafe\u202e.txt"],
    ["unpaired surrogate", "assets/unsafe\ud800.txt"],
    ["sensitive credential", `assets/sk-${"A".repeat(24)}.txt`],
  ])("rejects a %s closure path", async (_label, invalidPath) => {
    const root = mutableClone(await snapshotSkill(minimalSkill));
    const firstFile = objectValue(arrayValue(objectValue(root, "closure"), "files")[0]);
    objectValue(firstFile, "path").value = invalidPath;

    expect(() => parseArtifactSnapshot(JSON.stringify(root))).toThrow(/normalized portable/u);
  });

  it("enforces string, array, and safe-integer bounds", async () => {
    const snapshot = await snapshotSkill(minimalSkill);

    const longString = mutableClone(snapshot);
    objectValue(objectValue(longString, "snapshot"), "analyzer").name = "a".repeat(201);
    expect(() => parseArtifactSnapshot(JSON.stringify(longString))).toThrow(/1 and 200/u);

    const tooManyDiagnostics = mutableClone(snapshot);
    tooManyDiagnostics.diagnostics = Array.from({ length: 1_001 }, () => ({
      code: "SKILL_MANIFEST_INVALID",
      message: "Invalid.",
      type: "error",
    }));
    expect(() => parseArtifactSnapshot(JSON.stringify(tooManyDiagnostics))).toThrow(
      /0 to 1000 entries/u,
    );

    const unsafeInteger = mutableClone(snapshot);
    objectValue(unsafeInteger, "snapshot").durationMs = Number.MAX_SAFE_INTEGER + 1;
    expect(() => parseArtifactSnapshot(JSON.stringify(unsafeInteger))).toThrow(/safe integer/u);
  });

  it("requires sorted unique closure files and evidence", async () => {
    const snapshot = await snapshotSkill(minimalSkill);

    const unsortedFiles = mutableClone(snapshot);
    const files = arrayValue(objectValue(unsortedFiles, "closure"), "files");
    [files[0], files[1]] = [files[1], files[0]];
    expect(() => parseArtifactSnapshot(JSON.stringify(unsortedFiles))).toThrow(
      /strictly sorted by unique path/u,
    );

    const duplicateEvidence = mutableClone(snapshot);
    const observed = objectValue(objectValue(duplicateEvidence, "closure"), "observedSha256");
    const evidence = arrayValue(observed, "evidence");
    evidence.splice(1, 0, structuredClone(evidence[0]));
    expect(() => parseArtifactSnapshot(JSON.stringify(duplicateEvidence))).toThrow(
      /strictly sorted and contain no duplicate paths/u,
    );
  });

  it("requires each coverage area exactly once", async () => {
    const root = mutableClone(await snapshotSkill(minimalSkill));
    const coverage = arrayValue(root, "coverage");
    objectValue(coverage[1]).area = objectValue(coverage[0]).area;

    expect(() => parseArtifactSnapshot(JSON.stringify(root))).toThrow(/exactly-once coverage/u);
  });

  it("requires known, canonically ordered diagnostic codes", async () => {
    const unknownCode = mutableClone(await snapshotSkill(minimalSkill));
    unknownCode.diagnostics = [
      { code: "ARTIFACT_FUTURE_CODE", message: "Unknown.", type: "error" },
    ];
    expect(() => parseArtifactSnapshot(JSON.stringify(unknownCode))).toThrow(
      /recognized artifact diagnostic code/u,
    );

    const unsorted = mutableClone(await snapshotSkill(minimalSkill));
    unsorted.diagnostics = [
      {
        code: "SKILL_MANIFEST_INVALID",
        file: "z.txt",
        message: "Later.",
        type: "error",
      },
      {
        code: "SKILL_MANIFEST_INVALID",
        file: "a.txt",
        message: "Earlier.",
        type: "error",
      },
    ];
    expect(() => parseArtifactSnapshot(JSON.stringify(unsorted))).toThrow(
      /strictly sorted and contain no duplicate diagnostics/u,
    );
  });

  it("rejects field-specific claim-state and evidence mismatches", async () => {
    const wrongMutable = mutableClone(await snapshotSkill(minimalSkill));
    objectValue(objectValue(objectValue(wrongMutable, "artifact"), "identity"), "mutable").value =
      false;
    expect(() => parseArtifactSnapshot(JSON.stringify(wrongMutable))).toThrow(/must be true/u);

    const wrongEvidence = mutableClone(await snapshotSkill(minimalSkill));
    const firstFile = objectValue(arrayValue(objectValue(wrongEvidence, "closure"), "files")[0]);
    objectValue(firstFile, "bytes").evidence = [{ path: "different.txt" }];
    expect(() => parseArtifactSnapshot(JSON.stringify(wrongEvidence))).toThrow(
      /inconsistent with its field/u,
    );

    const wrongVersion = mutableClone(await snapshotSkill(minimalSkill));
    objectValue(objectValue(objectValue(wrongVersion, "artifact"), "manifest"), "version").value =
      "1.0.0";
    expect(() => parseArtifactSnapshot(JSON.stringify(wrongVersion))).toThrow(/unknown field/u);
  });

  it("keeps closure and repository schema fields value-claim-only", async () => {
    const schema = JSON.parse(
      await readFile(path.join(repositoryRoot, "schemas/artifact-snapshot.schema.json"), "utf8"),
    ) as JsonObject;
    const rootProperties = objectValue(schema, "properties");
    const artifactProperties = objectValue(objectValue(rootProperties, "artifact"), "properties");
    const repositoryProperties = objectValue(
      objectValue(artifactProperties, "repository"),
      "properties",
    );
    const closureProperties = objectValue(objectValue(rootProperties, "closure"), "properties");
    const fileItems = objectValue(objectValue(closureProperties, "files"), "items");
    const fileProperties = objectValue(fileItems, "properties");

    expect(objectValue(fileProperties, "bytes").$ref).toBe("#/$defs/observedResolvedIntegerClaim");
    expect(objectValue(fileProperties, "sha256").$ref).toBe("#/$defs/observedResolvedDigestClaim");
    expect(objectValue(closureProperties, "totalBytes").$ref).toBe(
      "#/$defs/observedTotalBytesClaim",
    );
    expect(objectValue(repositoryProperties, "commit").$ref).toBe("#/$defs/repositoryCommitClaim");
    expect(objectValue(repositoryProperties, "url").$ref).toBe("#/$defs/repositoryUrlClaim");

    const absentBytes = mutableClone(await snapshotSkill(minimalSkill));
    const firstFile = objectValue(arrayValue(objectValue(absentBytes, "closure"), "files")[0]);
    firstFile.bytes = {
      evidence: [],
      reason: "withheld",
      source: "observed",
      state: "unavailable",
    };
    expect(() => parseArtifactSnapshot(JSON.stringify(absentBytes))).toThrow();
  });

  it.each([
    [
      "total bytes",
      (root: JsonObject) => {
        const claim = objectValue(objectValue(root, "closure"), "totalBytes");
        claim.value = numberValue(claim, "value") + 1;
      },
      /closure file total/u,
    ],
    [
      "observation digest",
      (root: JsonObject) => {
        objectValue(objectValue(root, "closure"), "observedSha256").value = "0".repeat(64);
      },
      /closure observation/u,
    ],
    [
      "content digest",
      (root: JsonObject) => {
        objectValue(objectValue(objectValue(root, "artifact"), "identity"), "contentSha256").value =
          "0".repeat(64);
      },
      /complete-closure digest/u,
    ],
    [
      "snapshot ID",
      (root: JsonObject) => {
        objectValue(root, "snapshot").id = "0".repeat(24);
      },
      /recomputed snapshot identity/u,
    ],
    [
      "completeness",
      (root: JsonObject) => {
        root.complete = false;
      },
      /does not match closure, manifest, and diagnostic state/u,
    ],
  ])("rejects a mismatched recomputed %s", async (_label, mutate, expected) => {
    const root = mutableClone(await snapshotSkill(minimalSkill));
    mutate(root);

    expect(() => parseArtifactSnapshot(JSON.stringify(root))).toThrow(expected);
  });
});

type JsonObject = Record<string, unknown>;

function mutableClone(snapshot: ArtifactSnapshot): JsonObject {
  return JSON.parse(JSON.stringify(snapshot)) as JsonObject;
}

function objectValue(value: unknown, key?: string): JsonObject {
  const candidate = key === undefined ? value : asObject(value)[key];
  return asObject(candidate);
}

function asObject(value: unknown): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Expected an object in test fixture.");
  }
  return value as JsonObject;
}

function arrayValue(value: unknown, key: string): unknown[] {
  const candidate = asObject(value)[key];
  if (!Array.isArray(candidate)) {
    throw new Error("Expected an array in test fixture.");
  }
  return candidate;
}

function numberValue(value: unknown, key: string): number {
  const candidate = asObject(value)[key];
  if (typeof candidate !== "number") {
    throw new Error("Expected a number in test fixture.");
  }
  return candidate;
}

function capturedErrorMessage(operation: () => unknown): string {
  try {
    operation();
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error("Expected operation to throw.");
}

async function capturedAsyncErrorMessage(operation: Promise<unknown>): Promise<string> {
  try {
    await operation;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error("Expected operation to reject.");
}

async function makeTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "uleravo-artifact-report-"));
  temporaryDirectories.push(directory);
  return directory;
}
