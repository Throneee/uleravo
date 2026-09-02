import { chmod, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { isMainEntrypoint, main } from "../src/cli.js";
import { formatJson } from "../src/formatters/json.js";
import { readScanReport } from "../src/reports/read.js";
import { scan } from "../src/scanner/scan.js";

const fixture = path.join(fileURLToPath(new URL("./fixtures/safe-server", import.meta.url)));
const temporaryDirectories: string[] = [];

beforeEach(() => {
  vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  vi.spyOn(process.stderr, "write").mockImplementation(() => true);
});

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe("signing CLI", () => {
  it("renders clean help for every command", async () => {
    expect(await main(["--help"])).toBe(0);
    const output = vi.mocked(process.stdout.write).mock.calls.join(" ");

    expect(output).toContain("uleravo sign");
    expect(output).toContain("uleravo verify");
    expect(output).not.toContain("\n+");
  });

  it("generates keys, signs a report, and recovers it after verification", async () => {
    const directory = await makeTemporaryDirectory();
    const privateKey = path.join(directory, "private.pem");
    const publicKey = path.join(directory, "public.pem");
    const reportPath = path.join(directory, "report.json");
    const envelopePath = path.join(directory, "report.signed.json");
    const recoveredPath = path.join(directory, "verified.json");
    const report = await scan(fixture);
    await writeFile(reportPath, formatJson(report));

    expect(await main(["keygen", "--private-key", privateKey, "--public-key", publicKey])).toBe(0);
    if (process.platform !== "win32") {
      expect((await stat(privateKey)).mode & 0o077).toBe(0);
    }
    expect(await main(["sign", reportPath, "--private-key", privateKey, "-o", envelopePath])).toBe(
      0,
    );
    expect(
      await main(["verify", envelopePath, "--public-key", publicKey, "-o", recoveredPath]),
    ).toBe(0);
    expect(await readScanReport(recoveredPath)).toEqual(report);
    expect((await readFile(envelopePath, "utf8")).toString()).toContain('"algorithm": "Ed25519"');
  });

  it("never overwrites existing signing keys", async () => {
    const directory = await makeTemporaryDirectory();
    const privateKey = path.join(directory, "private.pem");
    const publicKey = path.join(directory, "public.pem");
    await writeFile(privateKey, "existing", { mode: 0o600 });

    expect(await main(["keygen", "--private-key", privateKey, "--public-key", publicKey])).toBe(2);
    expect(await readFile(privateKey, "utf8")).toBe("existing");
    expect(vi.mocked(process.stderr.write).mock.calls.join(" ")).toContain("Refusing to overwrite");
  });

  it.runIf(process.platform !== "win32")(
    "rejects a private key readable by other users",
    async () => {
      const directory = await makeTemporaryDirectory();
      const privateKey = path.join(directory, "private.pem");
      const publicKey = path.join(directory, "public.pem");
      const reportPath = path.join(directory, "report.json");
      await writeFile(reportPath, formatJson(await scan(fixture)));
      expect(await main(["keygen", "--private-key", privateKey, "--public-key", publicKey])).toBe(
        0,
      );
      await chmod(privateKey, 0o644);

      expect(await main(["sign", reportPath, "--private-key", privateKey])).toBe(2);
      expect(vi.mocked(process.stderr.write).mock.calls.join(" ")).toContain(
        "permissions are too broad",
      );
    },
  );
});

describe("CLI entrypoint", () => {
  it.runIf(process.platform !== "win32")(
    "recognizes the symlink created by package managers",
    async () => {
      const directory = await makeTemporaryDirectory();
      const moduleUrl = new URL("../src/cli.ts", import.meta.url);
      const executable = path.join(directory, "uleravo");
      await symlink(fileURLToPath(moduleUrl), executable);

      expect(await isMainEntrypoint(executable, moduleUrl.href)).toBe(true);
      expect(await isMainEntrypoint(undefined, moduleUrl.href)).toBe(false);
    },
  );
});

async function makeTemporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "uleravo-cli-"));
  temporaryDirectories.push(directory);
  return directory;
}
