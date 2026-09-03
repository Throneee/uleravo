import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const publicationScript = path.join(repositoryRoot, "scripts/check-publication-ready.mjs");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("final publication gate", () => {
  it("accepts exactly three full-SHA Action pins including Uleravo", async () => {
    const productSha = "2".repeat(40);
    const result = await runPublicationCheck(
      [
        `        uses: actions/checkout@${"1".repeat(40)}`,
        `        uses: Throneee/uleravo@${productSha}`,
        `        uses: actions/upload-artifact@${"3".repeat(40)}`,
      ],
      productSha,
    );

    expect(result.stdout).toContain("Final publication Action pins validated.");
  });

  it("rejects a product pin that is not the reviewed release commit", async () => {
    await expect(
      runPublicationCheck(
        [
          `        uses: actions/checkout@${"1".repeat(40)}`,
          `        uses: Throneee/uleravo@${"2".repeat(40)}`,
          `        uses: actions/upload-artifact@${"3".repeat(40)}`,
        ],
        "4".repeat(40),
      ),
    ).rejects.toThrow(/must pin the reviewed Uleravo commit/);
  });

  it("rejects the staged Commit A placeholder", async () => {
    await expect(
      runPublicationCheck([
        `        uses: actions/checkout@${"1".repeat(40)}`,
        "        uses: OWNER/REPOSITORY@PUBLIC_COMMIT_A",
        `        uses: actions/upload-artifact@${"3".repeat(40)}`,
      ]),
    ).rejects.toThrow(/Commit B must replace the staged Commit A placeholder/);
  });

  it("rejects tags, branches, short SHAs, and a missing product pin", async () => {
    await expect(
      runPublicationCheck([
        `        uses: actions/checkout@${"1".repeat(40)}`,
        "        uses: Throneee/uleravo@v0.7.0",
        `        uses: actions/upload-artifact@${"3".repeat(40)}`,
      ]),
    ).rejects.toThrow(/full 40-hex commit SHA/);

    await expect(
      runPublicationCheck([
        `        uses: actions/checkout@${"1".repeat(40)}`,
        `        uses: actions/cache@${"2".repeat(40)}`,
        `        uses: actions/upload-artifact@${"3".repeat(40)}`,
      ]),
    ).rejects.toThrow(/pin exactly one Throneee\/uleravo Action/);
  });
});

async function runPublicationCheck(referenceLines: readonly string[], expectedProductSha?: string) {
  const directory = await mkdtemp(path.join(tmpdir(), "uleravo-publication-test-"));
  temporaryDirectories.push(directory);
  await mkdir(path.join(directory, "scripts"));
  await mkdir(path.join(directory, "examples", "github-actions"), { recursive: true });
  await writeFile(
    path.join(directory, "scripts", "check-publication-ready.mjs"),
    await readFile(publicationScript),
  );
  await writeFile(
    path.join(directory, "examples", "github-actions", "uleravo-observe.yml"),
    `${["name: test", "jobs:", "  scan:", "    steps:", ...referenceLines].join("\n")}\n`,
  );
  return execFileAsync(
    process.execPath,
    [
      path.join(directory, "scripts", "check-publication-ready.mjs"),
      ...(expectedProductSha === undefined ? [] : ["--expected-product-sha", expectedProductSha]),
    ],
    {
      encoding: "utf8",
    },
  );
}
