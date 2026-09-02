import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { access, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const publicExportScript = path.join(repositoryRoot, "scripts/public-export.mjs");
const legacyBrand = ["mir", "sad"].join("");
const legacyBrandTitle = `${legacyBrand.slice(0, 1).toUpperCase()}${legacyBrand.slice(1)}`;
const rejectedDraftBrand = ["lim", "intra"].join("");
const rejectedDraftBrandTitle = `${rejectedDraftBrand.slice(0, 1).toUpperCase()}${rejectedDraftBrand.slice(1)}`;
const previousDraftBrand = ["jepo", "rano"].join("");
const previousDraftBrandTitle = `${previousDraftBrand.slice(0, 1).toUpperCase()}${previousDraftBrand.slice(1)}`;
const temporaryDirectories: string[] = [];

interface FileSnapshot {
  readonly ctimeMs: number;
  readonly dev: number;
  readonly ino: number;
  readonly mtimeMs: number;
  readonly size: number;
}

interface PublicExportIdentityPredicates {
  readonly sameOpenedFileSnapshot: (left: FileSnapshot, right: FileSnapshot) => boolean;
  readonly samePathAndOpenedFileSnapshot: (
    pathSnapshot: FileSnapshot,
    openedSnapshot: FileSnapshot,
    platform?: string,
  ) => boolean;
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("public release export", () => {
  it("keeps the Windows path-device exception narrow and rejects replacement snapshots", async () => {
    const { sameOpenedFileSnapshot, samePathAndOpenedFileSnapshot } =
      await loadIdentityPredicates();
    const openedSnapshot = {
      ctimeMs: 300,
      dev: 9,
      ino: 42,
      mtimeMs: 200,
      size: 100,
    };
    const windowsPathSnapshot = { ...openedSnapshot, dev: 0 };

    expect(samePathAndOpenedFileSnapshot(windowsPathSnapshot, openedSnapshot, "win32")).toBe(true);
    expect(samePathAndOpenedFileSnapshot(windowsPathSnapshot, openedSnapshot, "linux")).toBe(false);
    expect(
      samePathAndOpenedFileSnapshot(
        { ...windowsPathSnapshot, ino: openedSnapshot.ino + 1 },
        openedSnapshot,
        "win32",
      ),
    ).toBe(false);
    expect(
      sameOpenedFileSnapshot(openedSnapshot, {
        ...openedSnapshot,
        ctimeMs: openedSnapshot.ctimeMs + 1,
      }),
    ).toBe(false);
  });

  it("validates the exact source allowlist without writing an export", async () => {
    const { stdout } = await runPublicExport("--check");

    expect(stdout).toMatch(/Public export allowlist validated: [1-9][0-9]* regular files\./);
  });

  it("copies only reviewed public files into a new empty tree", async () => {
    const temporary = await makeTemporaryDirectory();
    const destination = path.join(temporary, "public");

    await runPublicExport("--export", destination);

    const manifest = JSON.parse(
      await readFile(path.join(destination, "release/public-export.json"), "utf8"),
    ) as { files: string[] };
    await Promise.all(
      manifest.files.map((relativePath) => access(path.join(destination, relativePath))),
    );
    await expect(access(path.join(destination, ".github/corpus-review.json"))).rejects.toThrow();
    await expect(
      access(path.join(destination, ".github/corpus-expectations.json")),
    ).rejects.toThrow();
    await expect(
      access(path.join(destination, ".github/workflows/corpus-validation.yml")),
    ).rejects.toThrow();
    await expect(access(path.join(destination, "AGENTS.md"))).rejects.toThrow();
    await expect(access(path.join(destination, "docs/corpus-methodology.md"))).rejects.toThrow();
    await expect(access(path.join(destination, "docs/product-direction.md"))).rejects.toThrow();
    await expect(
      access(path.join(destination, "docs/responsible-disclosure.md")),
    ).rejects.toThrow();
    await expect(access(path.join(destination, "docs/roadmap.md"))).rejects.toThrow();
    await expect(
      access(path.join(destination, "scripts/check-corpus-report.mjs")),
    ).rejects.toThrow();
  });

  it("refuses non-empty and symlink destinations without replacing existing data", async () => {
    const temporary = await makeTemporaryDirectory();
    const nonEmpty = path.join(temporary, "non-empty");
    const sentinel = path.join(nonEmpty, "sentinel.txt");
    await mkdir(nonEmpty);
    await writeFile(sentinel, "keep me\n");

    await expect(runPublicExport("--export", nonEmpty)).rejects.toThrow(/must not already exist/);
    expect(await readFile(sentinel, "utf8")).toBe("keep me\n");

    const empty = path.join(temporary, "empty");
    await mkdir(empty);
    await expect(runPublicExport("--export", empty)).rejects.toThrow(/must not already exist/);

    if (process.platform !== "win32") {
      const symlinkTarget = path.join(temporary, "symlink-target");
      const symlinkDestination = path.join(temporary, "symlink-destination");
      await mkdir(symlinkTarget);
      await symlink(symlinkTarget, symlinkDestination, "dir");
      await expect(runPublicExport("--export", symlinkDestination)).rejects.toThrow(/symlink/);
    }
  });

  it.each([legacyBrand, rejectedDraftBrand, previousDraftBrand])(
    "rejects blocked branding in allowlisted paths: %s",
    async (blockedBrand) => {
      const repository = await makeTemporaryDirectory();
      await mkdir(path.join(repository, "docs"));
      await mkdir(path.join(repository, "release"));
      const brandedPath = `docs/${blockedBrand}-guide.md`;
      await writeFile(path.join(repository, brandedPath), "legacy path\n");
      await writePublicManifest(repository, {
        brandingCompatibility: {},
        files: [brandedPath, "release/public-export.json"],
        schemaVersion: 1,
      });

      await expect(runPublicExportCheck(repository)).rejects.toThrow(
        /blocked branding in a public file path/,
      );
    },
  );

  it.each([[legacyBrand, legacyBrandTitle]])(
    "rejects blocked branding in compatibility reasons: %s",
    async (blockedBrand, title) => {
      const repository = await makeTemporaryDirectory();
      await mkdir(path.join(repository, "src"));
      await mkdir(path.join(repository, "release"));
      const signatureContext = `${blockedBrand}:signed-report:v1`;
      await writeFile(path.join(repository, "src/signatures.ts"), `${signatureContext}\n`);
      await writePublicManifest(repository, {
        brandingCompatibility: {
          "src/signatures.ts": [
            {
              literal: signatureContext,
              occurrences: 1,
              reason: `Keep the ${title} signature context for compatibility.`,
            },
          ],
        },
        files: ["release/public-export.json", "src/signatures.ts"],
        schemaVersion: 1,
      });

      await expect(runPublicExportCheck(repository)).rejects.toThrow(
        /reason cannot repeat blocked branding/,
      );
    },
  );

  it("allows only an exact approved frozen compatibility literal", async () => {
    const repository = await makeTemporaryDirectory();
    await mkdir(path.join(repository, "src"));
    await mkdir(path.join(repository, "release"));
    const signatureContext = `${legacyBrand}:signed-report:v1`;
    await writeFile(path.join(repository, "src/signatures.ts"), `${signatureContext}\n`);
    await writePublicManifest(repository, {
      brandingCompatibility: {
        "src/signatures.ts": [
          {
            literal: signatureContext,
            occurrences: 1,
            reason: "Keep the frozen signature context so existing reports remain verifiable.",
          },
        ],
      },
      files: ["release/public-export.json", "src/signatures.ts"],
      schemaVersion: 1,
    });

    await runPublicExportCheck(repository);
  });

  it("rejects a broad compatibility literal that hides human-facing branding", async () => {
    const repository = await makeTemporaryDirectory();
    await mkdir(path.join(repository, "release"));
    const brandedSentence = `${rejectedDraftBrandTitle} is still the current product name.`;
    await writeFile(path.join(repository, "README.md"), `${brandedSentence}\n`);
    await writePublicManifest(repository, {
      brandingCompatibility: {
        "README.md": [
          {
            literal: brandedSentence,
            occurrences: 1,
            reason: "Keep an earlier statement for compatibility with an old document.",
          },
        ],
      },
      files: ["README.md", "release/public-export.json"],
      schemaVersion: 1,
    });

    await expect(runPublicExportCheck(repository)).rejects.toThrow(
      /not an approved frozen compatibility identifier/,
    );
  });

  it("rejects non-canonical manifests with duplicate JSON keys", async () => {
    const repository = await makeTemporaryDirectory();
    await mkdir(path.join(repository, "release"));
    const manifest = [
      "{",
      `  "schemaVersion": "${rejectedDraftBrand} private note",`,
      '  "schemaVersion": 1,',
      '  "files": ["release/public-export.json"],',
      '  "brandingCompatibility": {},',
      '  "reviewedSha256": {}',
      "}",
      "",
    ].join("\n");
    await writeFile(path.join(repository, "release/public-export.json"), manifest);

    await expect(runPublicExportCheck(repository)).rejects.toThrow(
      /canonical two-space JSON with no duplicate keys/,
    );
  });

  it.each([rejectedDraftBrandTitle, previousDraftBrandTitle])(
    "rejects rejected-draft branding in allowlisted content: %s",
    async (title) => {
      const repository = await makeTemporaryDirectory();
      await mkdir(path.join(repository, "release"));
      await writeFile(path.join(repository, "README.md"), `${title} scanner\n`);
      await writePublicManifest(repository, {
        brandingCompatibility: {},
        files: ["README.md", "release/public-export.json"],
        schemaVersion: 1,
      });

      await expect(runPublicExportCheck(repository)).rejects.toThrow(
        /blocked human-facing product branding/,
      );
    },
  );

  it("binds allowlisted files to their release-reviewed digests", async () => {
    const repository = await makeTemporaryDirectory();
    await mkdir(path.join(repository, "release"));
    await writeFile(path.join(repository, "README.md"), "reviewed bytes\n");
    await writePublicManifest(repository, {
      brandingCompatibility: {},
      files: ["README.md", "release/public-export.json"],
      schemaVersion: 1,
    });

    await runPublicExportCheck(repository);
    await writeFile(path.join(repository, "README.md"), "changed after review\n");

    await expect(runPublicExportCheck(repository)).rejects.toThrow(/release-reviewed SHA-256/);
  });
});

async function runPublicExport(...arguments_: string[]) {
  return execFileAsync(process.execPath, [publicExportScript, ...arguments_], {
    cwd: repositoryRoot,
    encoding: "utf8",
  });
}

async function loadIdentityPredicates(): Promise<PublicExportIdentityPredicates> {
  return (await import(pathToFileURL(publicExportScript).href)) as PublicExportIdentityPredicates;
}

async function runPublicExportCheck(root: string) {
  const evaluate = [
    "const { checkPublicSurface } = await import(process.argv[1]);",
    "await checkPublicSurface(process.argv[2]);",
  ].join("\n");
  return execFileAsync(
    process.execPath,
    ["--input-type=module", "--eval", evaluate, pathToFileURL(publicExportScript).href, root],
    { encoding: "utf8" },
  );
}

async function writePublicManifest(
  root: string,
  manifest: { files: string[]; [key: string]: unknown },
): Promise<void> {
  const reviewedSha256 = Object.fromEntries(
    await Promise.all(
      manifest.files
        .filter((relativePath) => relativePath !== "release/public-export.json")
        .map(async (relativePath) => {
          const content = await readFile(path.join(root, relativePath));
          const digest = createHash("sha256").update(content).digest("hex");
          return [relativePath, digest] as const;
        }),
    ),
  );
  await writeFile(
    path.join(root, "release/public-export.json"),
    `${JSON.stringify({ ...manifest, reviewedSha256 }, null, 2)}\n`,
  );
}

async function makeTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "uleravo-public-export-test-"));
  temporaryDirectories.push(directory);
  return directory;
}
