import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { scan } from "../src/scanner/scan.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("scan provenance", () => {
  it("records source, package, lockfile, and explicit repository identity", async () => {
    const directory = await makeTemporaryDirectory();
    const lockfile = "lockfileVersion: '9.0'\n";
    await writeFile(
      path.join(directory, "package.json"),
      JSON.stringify({ name: "example-mcp", version: "1.2.3" }),
    );
    await writeFile(path.join(directory, "pnpm-lock.yaml"), lockfile);
    await writeFile(path.join(directory, "server.ts"), "export const safe = true;\n");

    const report = await scan(directory, {
      repository: {
        commit: "A".repeat(40),
        url: "https://github.com/example/example-mcp/",
      },
    });

    expect(report.provenance).toEqual({
      lockfiles: [
        {
          path: "pnpm-lock.yaml",
          sha256: createHash("sha256").update(lockfile).digest("hex"),
          state: "hashed",
        },
      ],
      package: { name: "example-mcp", version: "1.2.3" },
      repository: {
        commit: "a".repeat(40),
        url: "https://github.com/example/example-mcp",
      },
      scanInputSha256: expect.stringMatching(/^[a-f0-9]{64}$/),
    });
  });

  it("recognizes a binary Bun lockfile without decoding or scanning it", async () => {
    const directory = await makeTemporaryDirectory();
    const bytes = new Uint8Array([0, 255, 10, 128]);
    await writeFile(
      path.join(directory, "package.json"),
      JSON.stringify({ dependencies: { "@modelcontextprotocol/sdk": "latest" } }),
    );
    const withoutLockfile = await scan(directory);
    await writeFile(path.join(directory, "bun.lockb"), bytes);

    const report = await scan(directory);

    expect(report.provenance?.lockfiles).toEqual([
      {
        path: "bun.lockb",
        sha256: createHash("sha256").update(bytes).digest("hex"),
        state: "hashed",
      },
    ]);
    expect(report.findings.map((finding) => finding.ruleId)).not.toContain("MCP010");
    expect(report.scan.id).not.toBe(withoutLockfile.scan.id);
    expect(report.scan.filesSkipped).toBe(1);
  });

  it("records lockfiles omitted by the safety limit", async () => {
    const directory = await makeTemporaryDirectory();
    const lockfilePath = path.join(directory, "pnpm-lock.yaml");
    await writeFile(lockfilePath, "lockfileVersion: '9.0'\n");

    const report = await scan(lockfilePath, { maxFileBytes: 4 });

    expect(report.provenance?.lockfiles).toEqual([{ path: "pnpm-lock.yaml", state: "size-limit" }]);
    expect(report.diagnostics).toContainEqual({
      file: "pnpm-lock.yaml",
      message: expect.stringContaining("scan evidence is incomplete"),
      type: "error",
    });
  });

  it("binds incomplete-scan diagnostics into scan identity", async () => {
    const cleanDirectory = await makeTemporaryDirectory();
    const incompleteDirectory = await makeTemporaryDirectory();
    for (const directory of [cleanDirectory, incompleteDirectory]) {
      await writeFile(path.join(directory, "server.ts"), "export const safe = true;\n");
    }
    await writeFile(path.join(incompleteDirectory, "oversized.ts"), "x".repeat(100));

    const clean = await scan(cleanDirectory, { maxFileBytes: 50 });
    const incomplete = await scan(incompleteDirectory, { maxFileBytes: 50 });

    expect(clean.provenance?.scanInputSha256).toBe(incomplete.provenance?.scanInputSha256);
    expect(incomplete.diagnostics.some((diagnostic) => diagnostic.type === "error")).toBe(true);
    expect(incomplete.scan.id).not.toBe(clean.scan.id);
  });

  it("frames paths and contents so embedded NUL bytes cannot collide", async () => {
    const combinedDirectory = await makeTemporaryDirectory();
    const splitDirectory = await makeTemporaryDirectory();
    await writeFile(path.join(combinedDirectory, "a.ts"), "X\0b.ts\0Y");
    await writeFile(path.join(splitDirectory, "a.ts"), "X");
    await writeFile(path.join(splitDirectory, "b.ts"), "Y");

    const combined = await scan(combinedDirectory);
    const split = await scan(splitDirectory);

    expect(combined.provenance?.scanInputSha256).not.toBe(split.provenance?.scanInputSha256);
    expect(combined.scan.id).not.toBe(split.scan.id);
  });

  it("does not depend on the host locale when ordering non-ASCII paths", async () => {
    const directory = await makeTemporaryDirectory();
    for (const segment of ["z", "ä"]) {
      await mkdir(path.join(directory, segment));
      await writeFile(
        path.join(directory, segment, "server.ts"),
        'const endpoint = "http://example.com";\n',
      );
      await writeFile(path.join(directory, segment, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    }
    const baseline = await scan(directory);
    const localeCompare = vi
      .spyOn(String.prototype, "localeCompare")
      .mockImplementation(function reverseCodeUnits(this: string, other: string): number {
        return this < other ? 1 : this > other ? -1 : 0;
      });
    let adversarialLocale: Awaited<ReturnType<typeof scan>>;
    try {
      adversarialLocale = await scan(directory);
    } finally {
      localeCompare.mockRestore();
    }

    expect(adversarialLocale.provenance?.scanInputSha256).toBe(
      baseline.provenance?.scanInputSha256,
    );
    expect(adversarialLocale.scan.id).toBe(baseline.scan.id);
    expect(adversarialLocale.findings.map((finding) => finding.file)).toEqual(
      baseline.findings.map((finding) => finding.file),
    );
    expect(adversarialLocale.provenance?.lockfiles.map((lockfile) => lockfile.path)).toEqual(
      baseline.provenance?.lockfiles.map((lockfile) => lockfile.path),
    );
  });

  it.skipIf(process.platform === "win32")(
    "keeps literal POSIX backslashes distinct from directory separators",
    async () => {
      const directory = await makeTemporaryDirectory();
      await mkdir(path.join(directory, "reports"));
      await writeFile(
        path.join(directory, "reports\\uleravo.json"),
        JSON.stringify({ endpoint: "http://literal.example.com" }),
      );
      await writeFile(
        path.join(directory, "reports", "uleravo.json"),
        JSON.stringify({ endpoint: "http://nested.example.com" }),
      );

      const report = await scan(directory);

      expect(report.scan.filesScanned).toBe(2);
      expect(report.findings.map((finding) => finding.file).sort()).toEqual([
        "reports/uleravo.json",
        "reports\\uleravo.json",
      ]);
    },
  );

  it("rejects incomplete hashes and repository URLs that could carry credentials", async () => {
    const directory = await makeTemporaryDirectory();
    await writeFile(path.join(directory, "server.ts"), "export const safe = true;\n");

    await expect(
      scan(directory, {
        repository: { commit: "abc", url: "https://github.com/example/project" },
      }),
    ).rejects.toThrow("complete 40- or 64-character Git hash");
    await expect(
      scan(directory, {
        repository: {
          commit: "a".repeat(40),
          url: "https://token@example.com/project",
        },
      }),
    ).rejects.toThrow("must not contain credentials");
  });
});

async function makeTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "uleravo-provenance-"));
  temporaryDirectories.push(directory);
  return directory;
}
