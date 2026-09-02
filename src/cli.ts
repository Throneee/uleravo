#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import { lstat, readFile, realpath, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { compareReports, type ReportComparison } from "./comparison.js";
import {
  type Finding,
  type ScanReport,
  SEVERITIES,
  type Severity,
  severityRank,
} from "./domain.js";
import { formatComparisonJson, formatComparisonText } from "./formatters/comparison.js";
import { formatJson } from "./formatters/json.js";
import { formatSarif } from "./formatters/sarif.js";
import { formatText } from "./formatters/text.js";
import { redactEvidence } from "./redact.js";
import { readScanReport } from "./reports/read.js";
import { scan } from "./scanner/scan.js";
import {
  formatSignedReportEnvelope,
  generateSigningKeyPair,
  parseSignedReportEnvelope,
  SIGNED_REPORT_MAX_ENVELOPE_BYTES,
  signReport,
  verifySignedReport,
} from "./signatures.js";
import { PRODUCT_NAME, PRODUCT_SLUG, VERSION } from "./version.js";

type ScanOutputFormat = "json" | "sarif" | "text";
type ComparisonOutputFormat = "json" | "text";
type FailureThreshold = Severity | "none";
const MAX_KEY_BYTES = 64_000;
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

export async function main(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  try {
    const parsed = parseCli(argv);
    if (parsed.action === "help") {
      process.stdout.write(helpText());
      return 0;
    }
    if (parsed.action === "version") {
      process.stdout.write(`${VERSION}\n`);
      return 0;
    }
    if (parsed.action === "compare") {
      return await runComparison(parsed);
    }
    if (parsed.action === "keygen") {
      return await runKeyGeneration(parsed);
    }
    if (parsed.action === "sign") {
      return await runSigning(parsed);
    }
    if (parsed.action === "verify") {
      return await runVerification(parsed);
    }
    return await runScan(parsed);
  } catch (error) {
    process.stderr.write(`${PRODUCT_SLUG}: ${safeErrorMessage(error)}\n`);
    return 2;
  }
}

function safeErrorMessage(error: unknown): string {
  const message = redactEvidence(error instanceof Error ? error.message : String(error));
  return message.length <= 1_000 ? message : `${message.slice(0, 997)}...`;
}

interface ScanCommand {
  readonly action: "scan";
  readonly exclude: readonly string[];
  readonly failOn: FailureThreshold;
  readonly format: ScanOutputFormat;
  readonly maxFileBytes: number;
  readonly output?: string;
  readonly repository?: {
    readonly commit: string;
    readonly url: string;
  };
  readonly target: string;
}

interface CompareCommand {
  readonly action: "compare";
  readonly baseline: string;
  readonly current: string;
  readonly failOn: FailureThreshold;
  readonly format: ComparisonOutputFormat;
  readonly output?: string;
}

interface KeyGenerationCommand {
  readonly action: "keygen";
  readonly privateKey: string;
  readonly publicKey: string;
}

interface SignCommand {
  readonly action: "sign";
  readonly output?: string;
  readonly privateKey: string;
  readonly report: string;
}

interface VerifyCommand {
  readonly action: "verify";
  readonly envelope: string;
  readonly output?: string;
  readonly publicKey: string;
}

type ParsedCommand =
  | CompareCommand
  | KeyGenerationCommand
  | ScanCommand
  | SignCommand
  | VerifyCommand
  | { readonly action: "help" }
  | { readonly action: "version" };

async function runScan(command: ScanCommand): Promise<number> {
  const report = await scan(command.target, {
    excludePrefixes: command.exclude,
    maxFileBytes: command.maxFileBytes,
    ...(command.repository === undefined ? {} : { repository: command.repository }),
  });
  await emitOutput(renderScan(report, command.format), command.output, command.format);

  if (report.diagnostics.some((diagnostic) => diagnostic.type === "error")) {
    return 2;
  }
  return exceedsThreshold(report.findings, command.failOn) ? 1 : 0;
}

async function runComparison(command: CompareCommand): Promise<number> {
  const [baseline, current] = await Promise.all([
    readScanReport(command.baseline),
    readScanReport(command.current),
  ]);
  if (
    [...baseline.diagnostics, ...current.diagnostics].some(
      (diagnostic) => diagnostic.type === "error",
    )
  ) {
    throw new Error("Cannot compare reports that contain scan errors.");
  }

  const comparison = compareReports(baseline, current);
  await emitOutput(renderComparison(comparison, command.format), command.output, command.format);
  return exceedsThreshold(comparison.added, command.failOn) ? 1 : 0;
}

async function runKeyGeneration(command: KeyGenerationCommand): Promise<number> {
  const keyPair = generateSigningKeyPair();
  await writeKeyPair(command.privateKey, command.publicKey, keyPair);
  process.stdout.write(
    `Created Ed25519 signing keys.\nPrivate key: ${command.privateKey}\nPublic key: ${command.publicKey}\nKey ID: ${keyPair.keyId}\n`,
  );
  return 0;
}

async function runSigning(command: SignCommand): Promise<number> {
  const [report, privateKeyPem] = await Promise.all([
    readScanReport(command.report),
    readKeyFile(command.privateKey, true),
  ]);
  const serialized = formatSignedReportEnvelope(signReport(report, privateKeyPem));
  if (command.output === undefined) {
    process.stdout.write(serialized);
  } else {
    await writeAtomically(command.output, serialized);
    process.stdout.write(`Signed report written to ${command.output}\n`);
  }
  return 0;
}

async function runVerification(command: VerifyCommand): Promise<number> {
  const [serialized, publicKeyPem] = await Promise.all([
    readUtf8File(command.envelope, SIGNED_REPORT_MAX_ENVELOPE_BYTES, "signed report"),
    readKeyFile(command.publicKey, false),
  ]);
  const verified = verifySignedReport(
    parseSignedReportEnvelope(serialized, command.envelope),
    publicKeyPem,
  );
  if (command.output === undefined) {
    process.stdout.write(
      `Verified scan report ${verified.report.scan.id}.\nKey ID: ${verified.keyId}\nPayload SHA-256: ${verified.payloadSha256}\n`,
    );
  } else {
    await writeAtomically(command.output, formatJson(verified.report));
    process.stdout.write(`Verified report written to ${command.output}\n`);
  }
  return 0;
}

function parseCli(argv: readonly string[]): ParsedCommand {
  const command = argv[0];
  if (command === undefined || command === "--help" || command === "-h") {
    return { action: "help" };
  }
  if (command === "--version" || command === "-v") {
    return { action: "version" };
  }
  if (command === "scan") {
    return parseScanCommand(argv.slice(1));
  }
  if (command === "compare") {
    return parseCompareCommand(argv.slice(1));
  }
  if (command === "keygen") {
    return parseKeyGenerationCommand(argv.slice(1));
  }
  if (command === "sign") {
    return parseSignCommand(argv.slice(1));
  }
  if (command === "verify") {
    return parseVerifyCommand(argv.slice(1));
  }
  throw new Error(`Unknown command ${command}. Run ${PRODUCT_SLUG} --help.`);
}

function parseScanCommand(args: readonly string[]): ScanCommand | { readonly action: "help" } {
  const parsed = parseArgs({
    allowPositionals: true,
    args: [...args],
    options: {
      "commit-sha": { type: "string" },
      exclude: { multiple: true, type: "string" },
      "fail-on": { default: "none", type: "string" },
      format: { default: "text", short: "f", type: "string" },
      help: { short: "h", type: "boolean" },
      "max-file-bytes": { default: "1000000", type: "string" },
      output: { short: "o", type: "string" },
      "repository-url": { type: "string" },
    },
    strict: true,
  });
  if (parsed.values.help === true) {
    return { action: "help" };
  }
  if (parsed.positionals.length > 1) {
    throw new Error("The scan command accepts at most one target.");
  }

  const maxFileBytes = Number.parseInt(parsed.values["max-file-bytes"], 10);
  if (!Number.isSafeInteger(maxFileBytes) || maxFileBytes < 1) {
    throw new Error("--max-file-bytes must be a positive integer.");
  }
  const repository = parseRepositoryOptions(
    parsed.values["repository-url"],
    parsed.values["commit-sha"],
  );

  return {
    action: "scan",
    exclude: parsed.values.exclude ?? [],
    failOn: parseFailureThreshold(parsed.values["fail-on"]),
    format: parseScanFormat(parsed.values.format),
    maxFileBytes,
    ...(parsed.values.output === undefined ? {} : { output: parsed.values.output }),
    ...(repository === undefined ? {} : { repository }),
    target: parsed.positionals[0] ?? ".",
  };
}

function parseCompareCommand(
  args: readonly string[],
): CompareCommand | { readonly action: "help" } {
  const parsed = parseArgs({
    allowPositionals: true,
    args: [...args],
    options: {
      "fail-on": { default: "none", type: "string" },
      format: { default: "text", short: "f", type: "string" },
      help: { short: "h", type: "boolean" },
      output: { short: "o", type: "string" },
    },
    strict: true,
  });
  if (parsed.values.help === true) {
    return { action: "help" };
  }
  if (parsed.positionals.length !== 2) {
    throw new Error("The compare command requires baseline and current JSON reports.");
  }

  return {
    action: "compare",
    baseline: parsed.positionals[0] ?? "",
    current: parsed.positionals[1] ?? "",
    failOn: parseFailureThreshold(parsed.values["fail-on"]),
    format: parseComparisonFormat(parsed.values.format),
    ...(parsed.values.output === undefined ? {} : { output: parsed.values.output }),
  };
}

function parseKeyGenerationCommand(
  args: readonly string[],
): KeyGenerationCommand | { readonly action: "help" } {
  const parsed = parseArgs({
    allowPositionals: false,
    args: [...args],
    options: {
      help: { short: "h", type: "boolean" },
      "private-key": { type: "string" },
      "public-key": { type: "string" },
    },
    strict: true,
  });
  if (parsed.values.help === true) {
    return { action: "help" };
  }
  if (parsed.values["private-key"] === undefined || parsed.values["public-key"] === undefined) {
    throw new Error("The keygen command requires --private-key and --public-key paths.");
  }
  return {
    action: "keygen",
    privateKey: parsed.values["private-key"],
    publicKey: parsed.values["public-key"],
  };
}

function parseSignCommand(args: readonly string[]): SignCommand | { readonly action: "help" } {
  const parsed = parseArgs({
    allowPositionals: true,
    args: [...args],
    options: {
      help: { short: "h", type: "boolean" },
      output: { short: "o", type: "string" },
      "private-key": { type: "string" },
    },
    strict: true,
  });
  if (parsed.values.help === true) {
    return { action: "help" };
  }
  if (parsed.positionals.length !== 1 || parsed.values["private-key"] === undefined) {
    throw new Error("The sign command requires one report and --private-key.");
  }
  return {
    action: "sign",
    ...(parsed.values.output === undefined ? {} : { output: parsed.values.output }),
    privateKey: parsed.values["private-key"],
    report: parsed.positionals[0] ?? "",
  };
}

function parseVerifyCommand(args: readonly string[]): VerifyCommand | { readonly action: "help" } {
  const parsed = parseArgs({
    allowPositionals: true,
    args: [...args],
    options: {
      help: { short: "h", type: "boolean" },
      output: { short: "o", type: "string" },
      "public-key": { type: "string" },
    },
    strict: true,
  });
  if (parsed.values.help === true) {
    return { action: "help" };
  }
  if (parsed.positionals.length !== 1 || parsed.values["public-key"] === undefined) {
    throw new Error("The verify command requires one signed report and --public-key.");
  }
  return {
    action: "verify",
    envelope: parsed.positionals[0] ?? "",
    ...(parsed.values.output === undefined ? {} : { output: parsed.values.output }),
    publicKey: parsed.values["public-key"],
  };
}

function parseRepositoryOptions(
  url: string | undefined,
  commit: string | undefined,
): ScanCommand["repository"] {
  if (url === undefined && commit === undefined) {
    return undefined;
  }
  if (url === undefined || commit === undefined) {
    throw new Error("--repository-url and --commit-sha must be provided together.");
  }
  return { commit, url };
}

function parseScanFormat(value: string): ScanOutputFormat {
  if (value === "json" || value === "sarif" || value === "text") {
    return value;
  }
  throw new Error("--format must be text, json, or sarif.");
}

function parseComparisonFormat(value: string): ComparisonOutputFormat {
  if (value === "json" || value === "text") {
    return value;
  }
  throw new Error("Comparison --format must be text or json.");
}

function parseFailureThreshold(value: string): FailureThreshold {
  if (value === "none" || (SEVERITIES as readonly string[]).includes(value)) {
    return value as FailureThreshold;
  }
  throw new Error("--fail-on must be none, info, low, medium, high, or critical.");
}

function renderScan(report: ScanReport, format: ScanOutputFormat): string {
  if (format === "json") {
    return formatJson(report);
  }
  if (format === "sarif") {
    return formatSarif(report);
  }
  return formatText(report, process.stdout.isTTY);
}

function renderComparison(comparison: ReportComparison, format: ComparisonOutputFormat): string {
  return format === "json" ? formatComparisonJson(comparison) : formatComparisonText(comparison);
}

function exceedsThreshold(findings: readonly Finding[], threshold: FailureThreshold): boolean {
  return (
    threshold !== "none" &&
    findings.some((finding) => severityRank(finding.severity) >= severityRank(threshold))
  );
}

async function emitOutput(
  content: string,
  destination: string | undefined,
  format: ScanOutputFormat,
): Promise<void> {
  if (destination === undefined) {
    process.stdout.write(content);
    return;
  }
  await writeAtomically(destination, content);
  if (format === "text") {
    process.stdout.write(`Report written to ${destination}\n`);
  }
}

async function writeAtomically(destination: string, content: string): Promise<void> {
  const resolved = path.resolve(destination);
  const temporary = `${resolved}.${process.pid.toString()}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, content, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await rename(temporary, resolved);
  } finally {
    await unlink(temporary).catch(() => undefined);
  }
}

async function readKeyFile(keyPath: string, privateKey: boolean): Promise<string> {
  const resolved = path.resolve(keyPath);
  const metadata = await lstat(resolved);
  if (!metadata.isFile()) {
    throw new Error(`${keyPath} is not a regular key file.`);
  }
  if (metadata.size > MAX_KEY_BYTES) {
    throw new Error(`${keyPath} exceeds the ${MAX_KEY_BYTES.toString()}-byte key limit.`);
  }
  if (privateKey && process.platform !== "win32" && (metadata.mode & 0o077) !== 0) {
    throw new Error(`Private key permissions are too broad for ${keyPath}; use chmod 600.`);
  }
  return await readUtf8File(keyPath, MAX_KEY_BYTES, "key");
}

async function readUtf8File(source: string, limit: number, label: string): Promise<string> {
  const resolved = path.resolve(source);
  const metadata = await lstat(resolved);
  if (!metadata.isFile()) {
    throw new Error(`${source} is not a regular ${label} file.`);
  }
  if (metadata.size > limit) {
    throw new Error(`${source} exceeds the ${limit.toString()}-byte ${label} limit.`);
  }
  const bytes = await readFile(resolved);
  if (bytes.byteLength > limit) {
    throw new Error(`${source} exceeds the ${limit.toString()}-byte ${label} limit.`);
  }
  try {
    return utf8Decoder.decode(bytes);
  } catch {
    throw new Error(`${source} is not valid UTF-8.`);
  }
}

async function writeKeyPair(
  privateKeyPath: string,
  publicKeyPath: string,
  keyPair: ReturnType<typeof generateSigningKeyPair>,
): Promise<void> {
  const privateDestination = path.resolve(privateKeyPath);
  const publicDestination = path.resolve(publicKeyPath);
  if (privateDestination === publicDestination) {
    throw new Error("Private and public key paths must be different.");
  }

  let privateKeyCreated = false;
  try {
    await writeFile(privateDestination, keyPair.privateKeyPem, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    privateKeyCreated = true;
    await writeFile(publicDestination, keyPair.publicKeyPem, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
  } catch (error) {
    if (privateKeyCreated) {
      await unlink(privateDestination).catch(() => undefined);
    }
    if (isAlreadyExistsError(error)) {
      throw new Error("Refusing to overwrite an existing signing key file.");
    }
    throw error;
  }
}

function isAlreadyExistsError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { readonly code?: unknown }).code === "EEXIST"
  );
}

function helpText(): string {
  return `${PRODUCT_NAME} ${VERSION}\n\nUsage:\n  ${PRODUCT_SLUG} scan [target] [options]\n  ${PRODUCT_SLUG} compare <baseline.json> <current.json> [options]\n  ${PRODUCT_SLUG} keygen --private-key <path> --public-key <path>\n  ${PRODUCT_SLUG} sign <report.json> --private-key <path> [-o <path>]\n  ${PRODUCT_SLUG} verify <signed-report.json> --public-key <path> [-o <report.json>]\n\nScan options:\n  -f, --format <text|json|sarif>  Output format (default: text)\n  -o, --output <path>             Write the report atomically\n      --fail-on <severity|none>    Exit 1 at or above a severity (default: none)\n      --exclude <path>             Exclude a relative path; repeatable\n      --max-file-bytes <bytes>     Per-file safety limit (default: 1000000)\n      --repository-url <https>     Repository source URL for provenance\n      --commit-sha <hash>          Complete Git commit for provenance\n\nCompare options:\n  -f, --format <text|json>         Output format (default: text)\n  -o, --output <path>              Write the comparison atomically\n      --fail-on <severity|none>     Exit 1 for newly added findings only\n\nSigning options:\n      --private-key <path>         Ed25519 PKCS#8 private key (sign)\n      --public-key <path>          Ed25519 SPKI public key (verify)\n  -o, --output <path>              Write the envelope or recovered report\n\nGeneral options:\n  -h, --help                       Show this help\n  -v, --version                    Show the version\n\nExit codes:\n  0  Operation completed and threshold passed\n  1  Findings met the configured threshold\n  2  Usage, scan, report, signature, or rule error\n`;
}

export async function isMainEntrypoint(
  entrypoint: string | undefined,
  moduleUrl = import.meta.url,
): Promise<boolean> {
  if (entrypoint === undefined) {
    return false;
  }

  try {
    const [entrypointPath, modulePath] = await Promise.all([
      realpath(entrypoint),
      realpath(fileURLToPath(moduleUrl)),
    ]);
    return entrypointPath === modulePath;
  } catch {
    return false;
  }
}

if (await isMainEntrypoint(process.argv[1])) {
  process.exitCode = await main();
}
