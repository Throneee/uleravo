#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import { lstat, readFile, realpath, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import type { ArtifactKind, ArtifactSnapshot } from "./artifacts/domain.js";
import { snapshotPluginWithRoot, snapshotSkillWithRoot } from "./artifacts/snapshot.js";
import { compareReports, type ReportComparison } from "./comparison.js";
import {
  type Finding,
  type ScanReport,
  SEVERITIES,
  type Severity,
  severityRank,
} from "./domain.js";
import {
  formatArtifactSnapshotJson,
  formatArtifactSnapshotText,
} from "./formatters/artifact-snapshot.js";
import {
  formatCodexHarnessDeltaJson,
  formatCodexHarnessDeltaText,
  formatCodexHarnessJson,
  formatCodexHarnessText,
} from "./formatters/codex-harness.js";
import { formatComparisonJson, formatComparisonText } from "./formatters/comparison.js";
import { formatJson } from "./formatters/json.js";
import { formatSarif } from "./formatters/sarif.js";
import { formatText } from "./formatters/text.js";
import { snapshotCodexHarness } from "./harnesses/codex.js";
import { compareCodexHarnessSnapshots } from "./harnesses/comparison.js";
import { readCodexHarnessSnapshot } from "./harnesses/read.js";
import { assertOutputOutsideRoot, writeNewFileAtomically } from "./output.js";
import { boundedRedactedEvidence } from "./redact.js";
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
type SnapshotOutputFormat = "json" | "text";
type HarnessOutputFormat = "json" | "text";
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
    if (parsed.action === "snapshot") {
      return await runSnapshot(parsed);
    }
    if (parsed.action === "harness") {
      return await runHarness(parsed);
    }
    if (parsed.action === "harness-delta") {
      return await runHarnessDelta(parsed);
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
  return boundedRedactedEvidence(error instanceof Error ? error.message : String(error), 1_000);
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

interface SnapshotCommand {
  readonly action: "snapshot";
  readonly format: SnapshotOutputFormat;
  readonly kind: ArtifactKind;
  readonly maxFileBytes: number;
  readonly maxFiles: number;
  readonly maxTotalBytes: number;
  readonly output?: string;
  readonly repository?: {
    readonly commit: string;
    readonly url: string;
  };
  readonly target: string;
}

interface HarnessCommand {
  readonly action: "harness";
  readonly codexVersion?: string;
  readonly format: HarnessOutputFormat;
  readonly maxConfigBytes: number;
  readonly output?: string;
  readonly projectConfig?: string | null;
  readonly requirements?: string | null;
  readonly target: string;
  readonly userConfig?: string | null;
}

interface HarnessDeltaCommand {
  readonly action: "harness-delta";
  readonly baseline: string;
  readonly current: string;
  readonly format: HarnessOutputFormat;
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
  | HarnessCommand
  | HarnessDeltaCommand
  | KeyGenerationCommand
  | ScanCommand
  | SignCommand
  | SnapshotCommand
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

async function runSnapshot(command: SnapshotCommand): Promise<number> {
  const options = {
    maxFileBytes: command.maxFileBytes,
    maxFiles: command.maxFiles,
    maxTotalBytes: command.maxTotalBytes,
    ...(command.repository === undefined ? {} : { repository: command.repository }),
  };
  const capture =
    command.kind === "skill"
      ? await snapshotSkillWithRoot(command.target, options)
      : await snapshotPluginWithRoot(command.target, options);
  if (command.output !== undefined) {
    await assertOutputOutsideRoot(command.output, capture.root);
  }
  const { snapshot } = capture;
  await emitSnapshotOutput(
    renderSnapshot(snapshot, command.format),
    command.output,
    command.format,
  );
  return snapshot.complete ? 0 : 2;
}

async function runHarness(command: HarnessCommand): Promise<number> {
  const snapshot = await snapshotCodexHarness(command.target, {
    ...(command.codexVersion === undefined ? {} : { codexVersion: command.codexVersion }),
    maxConfigBytes: command.maxConfigBytes,
    ...(command.projectConfig === undefined ? {} : { projectConfig: command.projectConfig }),
    ...(command.requirements === undefined ? {} : { requirements: command.requirements }),
    ...(command.userConfig === undefined ? {} : { userConfig: command.userConfig }),
  });
  const rendered =
    command.format === "json" ? formatCodexHarnessJson(snapshot) : formatCodexHarnessText(snapshot);
  await emitSnapshotOutput(rendered, command.output, command.format);
  return snapshot.capture.complete ? 0 : 2;
}

async function runHarnessDelta(command: HarnessDeltaCommand): Promise<number> {
  const [baseline, current] = await Promise.all([
    readCodexHarnessSnapshot(command.baseline),
    readCodexHarnessSnapshot(command.current),
  ]);
  const delta = compareCodexHarnessSnapshots(baseline, current);
  const rendered =
    command.format === "json"
      ? formatCodexHarnessDeltaJson(delta)
      : formatCodexHarnessDeltaText(delta);
  await emitSnapshotOutput(rendered, command.output, command.format);
  return 0;
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
  if (command === "snapshot") {
    return parseSnapshotCommand(argv.slice(1));
  }
  if (command === "harness") {
    return parseHarnessCommand(argv.slice(1));
  }
  if (command === "harness-delta") {
    return parseHarnessDeltaCommand(argv.slice(1));
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

function parseSnapshotCommand(
  args: readonly string[],
): SnapshotCommand | { readonly action: "help" } {
  const parsed = parseArgs({
    allowPositionals: true,
    args: [...args],
    options: {
      "commit-sha": { type: "string" },
      format: { default: "text", short: "f", type: "string" },
      help: { short: "h", type: "boolean" },
      kind: { type: "string" },
      "max-file-bytes": { default: "10000000", type: "string" },
      "max-files": { default: "1000", type: "string" },
      "max-total-bytes": { default: "50000000", type: "string" },
      output: { short: "o", type: "string" },
      "repository-url": { type: "string" },
    },
    strict: true,
  });
  if (parsed.values.help === true) {
    return { action: "help" };
  }
  if (parsed.positionals.length > 1) {
    throw new Error("The snapshot command accepts at most one target.");
  }
  if (parsed.values.kind !== "skill" && parsed.values.kind !== "plugin") {
    throw new Error("The snapshot command requires --kind skill or --kind plugin.");
  }
  const repository = parseRepositoryOptions(
    parsed.values["repository-url"],
    parsed.values["commit-sha"],
  );
  return {
    action: "snapshot",
    format: parseSnapshotFormat(parsed.values.format),
    kind: parsed.values.kind,
    maxFileBytes: parsePositiveInteger(parsed.values["max-file-bytes"], "--max-file-bytes"),
    maxFiles: parsePositiveInteger(parsed.values["max-files"], "--max-files"),
    maxTotalBytes: parsePositiveInteger(parsed.values["max-total-bytes"], "--max-total-bytes"),
    ...(parsed.values.output === undefined ? {} : { output: parsed.values.output }),
    ...(repository === undefined ? {} : { repository }),
    target: parsed.positionals[0] ?? ".",
  };
}

function parseHarnessCommand(
  args: readonly string[],
): HarnessCommand | { readonly action: "help" } {
  const parsed = parseArgs({
    allowPositionals: true,
    args: [...args],
    options: {
      "codex-version": { type: "string" },
      format: { default: "text", short: "f", type: "string" },
      help: { short: "h", type: "boolean" },
      "max-config-bytes": { default: "1000000", type: "string" },
      output: { short: "o", type: "string" },
      "project-config": { type: "string" },
      requirements: { type: "string" },
      "skip-project-config": { type: "boolean" },
      "skip-requirements": { type: "boolean" },
      "skip-user-config": { type: "boolean" },
      "user-config": { type: "string" },
    },
    strict: true,
  });
  if (parsed.values.help === true) return { action: "help" };
  if (parsed.positionals.length > 1) {
    throw new Error("The harness command accepts at most one project target.");
  }
  assertExclusiveHarnessPath(
    parsed.values["project-config"],
    parsed.values["skip-project-config"],
    "project config",
  );
  assertExclusiveHarnessPath(
    parsed.values.requirements,
    parsed.values["skip-requirements"],
    "requirements",
  );
  assertExclusiveHarnessPath(
    parsed.values["user-config"],
    parsed.values["skip-user-config"],
    "user config",
  );
  return {
    action: "harness",
    ...(parsed.values["codex-version"] === undefined
      ? {}
      : { codexVersion: parsed.values["codex-version"] }),
    format: parseHarnessFormat(parsed.values.format),
    maxConfigBytes: parsePositiveInteger(parsed.values["max-config-bytes"], "--max-config-bytes"),
    ...(parsed.values.output === undefined ? {} : { output: parsed.values.output }),
    ...(parsed.values["skip-project-config"] === true
      ? { projectConfig: null }
      : parsed.values["project-config"] === undefined
        ? {}
        : { projectConfig: parsed.values["project-config"] }),
    ...(parsed.values["skip-requirements"] === true
      ? { requirements: null }
      : parsed.values.requirements === undefined
        ? {}
        : { requirements: parsed.values.requirements }),
    target: parsed.positionals[0] ?? ".",
    ...(parsed.values["skip-user-config"] === true
      ? { userConfig: null }
      : parsed.values["user-config"] === undefined
        ? {}
        : { userConfig: parsed.values["user-config"] }),
  };
}

function parseHarnessDeltaCommand(
  args: readonly string[],
): HarnessDeltaCommand | { readonly action: "help" } {
  const parsed = parseArgs({
    allowPositionals: true,
    args: [...args],
    options: {
      format: { default: "text", short: "f", type: "string" },
      help: { short: "h", type: "boolean" },
      output: { short: "o", type: "string" },
    },
    strict: true,
  });
  if (parsed.values.help === true) return { action: "help" };
  if (parsed.positionals.length !== 2) {
    throw new Error("The harness-delta command requires baseline and current JSON snapshots.");
  }
  return {
    action: "harness-delta",
    baseline: parsed.positionals[0] ?? "",
    current: parsed.positionals[1] ?? "",
    format: parseHarnessFormat(parsed.values.format),
    ...(parsed.values.output === undefined ? {} : { output: parsed.values.output }),
  };
}

function assertExclusiveHarnessPath(
  pathValue: string | undefined,
  skipped: boolean | undefined,
  label: string,
): void {
  if (pathValue !== undefined && skipped === true) {
    throw new Error(`Cannot supply and skip ${label} at the same time.`);
  }
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

function parseSnapshotFormat(value: string): SnapshotOutputFormat {
  if (value === "json" || value === "text") {
    return value;
  }
  throw new Error("Snapshot --format must be text or json.");
}

function parseHarnessFormat(value: string): HarnessOutputFormat {
  if (value === "json" || value === "text") return value;
  throw new Error("Harness --format must be text or json.");
}

function parsePositiveInteger(value: string, label: string): number {
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`${label} must be a positive integer.`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${label} must be a positive safe integer.`);
  }
  return parsed;
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

function renderSnapshot(snapshot: ArtifactSnapshot, format: SnapshotOutputFormat): string {
  return format === "json"
    ? formatArtifactSnapshotJson(snapshot)
    : formatArtifactSnapshotText(snapshot);
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

async function emitSnapshotOutput(
  content: string,
  destination: string | undefined,
  format: SnapshotOutputFormat,
): Promise<void> {
  if (destination === undefined) {
    process.stdout.write(content);
    return;
  }
  await writeNewFileAtomically(destination, content);
  if (format === "text") {
    process.stdout.write(
      `Report written to ${boundedRedactedEvidence(destination, 1_000, "[path withheld]")}\n`,
    );
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
  return `${PRODUCT_NAME} ${VERSION}\n\nUsage:\n  ${PRODUCT_SLUG} scan [target] [options]\n  ${PRODUCT_SLUG} compare <baseline.json> <current.json> [options]\n  ${PRODUCT_SLUG} snapshot [target] --kind <skill|plugin> [options]\n  ${PRODUCT_SLUG} harness [project] [options]\n  ${PRODUCT_SLUG} harness-delta <baseline.json> <current.json> [options]\n  ${PRODUCT_SLUG} keygen --private-key <path> --public-key <path>\n  ${PRODUCT_SLUG} sign <report.json> --private-key <path> [-o <path>]\n  ${PRODUCT_SLUG} verify <signed-report.json> --public-key <path> [-o <report.json>]\n\nScan options:\n  -f, --format <text|json|sarif>  Output format (default: text)\n  -o, --output <path>             Write the report atomically\n      --fail-on <severity|none>    Exit 1 at or above a severity (default: none)\n      --exclude <path>             Exclude a relative path; repeatable\n      --max-file-bytes <bytes>     Per-file safety limit (default: 1000000)\n      --repository-url <https>     Repository source URL for provenance\n      --commit-sha <hash>          Complete Git commit for provenance\n\nSnapshot options:\n      --kind <skill|plugin>        Snapshot one local Skill or Plugin\n  -f, --format <text|json>         Output format (default: text)\n  -o, --output <path>              Write the snapshot atomically\n      --max-file-bytes <bytes>     Per-file safety limit (default: 10000000)\n      --max-files <count>          Artifact file limit (default: 1000)\n      --max-total-bytes <bytes>    Aggregate safety limit (default: 50000000)\n      --repository-url <https>     Optional, user-supplied repository URL\n      --commit-sha <hash>          Optional, user-supplied complete commit\n\nHarness options:\n  -f, --format <text|json>         Output format (default: text)\n  -o, --output <path>              Write a new snapshot or delta file\n      --user-config <path>         Supply the user config.toml\n      --project-config <path>      Supply the project .codex/config.toml\n      --requirements <path>        Supply system requirements.toml\n      --skip-<layer>               Disable detection for a config layer\n      --codex-version <version>    Bind a caller-observed Codex version\n      --max-config-bytes <bytes>   Per-config limit (default: 1000000)\n\nCompare options:\n  -f, --format <text|json>         Output format (default: text)\n  -o, --output <path>              Write the comparison atomically\n      --fail-on <severity|none>     Exit 1 for newly added findings only\n\nSigning options:\n      --private-key <path>         Ed25519 PKCS#8 private key (sign)\n      --public-key <path>          Ed25519 SPKI public key (verify)\n  -o, --output <path>              Write the envelope or recovered report\n\nGeneral options:\n  -h, --help                       Show this help\n  -v, --version                    Show the version\n\nExit codes:\n  0  Operation completed and threshold passed\n  1  Findings met the configured threshold\n  2  Usage, incomplete snapshot, scan, report, signature, or rule error\n`;
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
