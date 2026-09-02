import { randomUUID } from "node:crypto";
import { appendFile, lstat, mkdir, realpath, rename, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { SEVERITIES, type Severity, severityRank } from "./domain.js";
import { formatJson } from "./formatters/json.js";
import { formatSarif } from "./formatters/sarif.js";
import { redactEvidence } from "./redact.js";
import { normalizeRepositoryIdentity, type RepositoryIdentity } from "./scanner/provenance.js";
import { scan } from "./scanner/scan.js";
import { PRODUCT_NAME, PRODUCT_SLUG, VERSION } from "./version.js";

type FailureThreshold = Severity | "none";
type ActionEnvironment = Readonly<Record<string, string | undefined>>;

const MAX_ACTION_FILE_BYTES = 100_000_000;
const MAX_EXCLUDE_INPUT_LENGTH = 65_536;
const MAX_LOG_MESSAGE_LENGTH = 1_000;
const MAX_PATH_INPUT_LENGTH = 4_096;

export interface ActionRunOptions {
  readonly environment?: ActionEnvironment;
  readonly stderr?: (message: string) => void;
  readonly stdout?: (message: string) => void;
}

interface ActionConfig {
  readonly excludePrefixes: readonly string[];
  readonly failOn: FailureThreshold;
  readonly maxFileBytes: number;
  readonly reportOutput: string;
  readonly reportPath: string;
  readonly repository: RepositoryIdentity;
  readonly sarifOutput: string;
  readonly sarifPath: string;
  readonly targetPath: string;
  readonly workspace: string;
}

interface OutputPathPlan {
  readonly destination: string;
  readonly initialParent: string;
  readonly inputName: string;
  readonly leafName: string;
  readonly missingSegments: readonly string[];
  readonly workspace: string;
}

interface ExistingPathIdentity {
  readonly canonicalPath: string;
  readonly device: number;
  readonly inode: number;
}

export async function runAction(options: ActionRunOptions = {}): Promise<number> {
  const environment = options.environment ?? process.env;
  const stdout = options.stdout ?? ((message: string) => process.stdout.write(message));
  const stderr = options.stderr ?? ((message: string) => process.stderr.write(message));

  try {
    const config = await parseActionConfig(environment);
    const report = await scan(config.targetPath, {
      excludePrefixes: config.excludePrefixes,
      maxFileBytes: config.maxFileBytes,
      repository: config.repository,
    });

    await Promise.all([
      writeAtomically(config.reportPath, formatJson(report)),
      writeAtomically(config.sarifPath, formatSarif(report)),
    ]);

    const errorDiagnostics = report.diagnostics.filter(
      (diagnostic) => diagnostic.type === "error",
    ).length;
    const warningDiagnostics = report.diagnostics.length - errorDiagnostics;
    const hasScanErrors = errorDiagnostics > 0;
    const hasFindings = report.summary.total > 0;
    const thresholdFailed = exceedsThreshold(report.findings, config.failOn);
    const outcome = hasScanErrors ? "error" : thresholdFailed ? "findings" : "passed";
    const status = actionStatus(hasScanErrors, config.failOn, thresholdFailed);
    await publishSummary(environment, report.summary, {
      errorDiagnostics,
      status,
      thresholdExceeded: thresholdFailed,
      warningDiagnostics,
    });
    await publishOutputs(environment, {
      critical: report.summary.critical.toString(),
      "error-diagnostics": errorDiagnostics.toString(),
      findings: report.summary.total.toString(),
      "has-findings": hasFindings.toString(),
      high: report.summary.high.toString(),
      info: report.summary.info.toString(),
      low: report.summary.low.toString(),
      medium: report.summary.medium.toString(),
      outcome,
      report: config.reportOutput,
      sarif: config.sarifOutput,
      "scan-complete": (!hasScanErrors).toString(),
      "scan-id": report.scan.id,
      "threshold-exceeded": thresholdFailed.toString(),
      "warning-diagnostics": warningDiagnostics.toString(),
    });
    stdout(
      `${PRODUCT_NAME} ${VERSION}: ${status}; ${report.summary.total.toString()} findings (${report.summary.critical.toString()} critical, ${report.summary.high.toString()} high); ${errorDiagnostics.toString()} error diagnostics; ${warningDiagnostics.toString()} warning diagnostics.\n`,
    );
    if (hasScanErrors) {
      stderr(
        `${PRODUCT_SLUG} action: scan is incomplete and must not be treated as clean; evidence files were preserved.\n`,
      );
      return 2;
    }
    if (thresholdFailed) {
      stderr(`${PRODUCT_SLUG} action: scan meets the ${config.failOn} failure threshold.\n`);
      return 1;
    }
    return 0;
  } catch (error) {
    stderr(`${PRODUCT_SLUG} action: ${safeErrorMessage(error)}\n`);
    return 2;
  }
}

async function parseActionConfig(environment: ActionEnvironment): Promise<ActionConfig> {
  const workspace = await realpath(
    path.resolve(requireEnvironment(environment, "GITHUB_WORKSPACE")),
  );
  if (!(await lstat(workspace)).isDirectory()) {
    throw new Error("GITHUB_WORKSPACE must resolve to a directory.");
  }

  const targetInput = input(environment, "target", ".");
  validatePathInput(targetInput, "target");
  if (isAbsolutePathInput(targetInput)) {
    throw new Error("target must be a relative path inside GITHUB_WORKSPACE.");
  }
  const targetPath = await realpath(path.resolve(workspace, targetInput));
  if (!isWithin(workspace, targetPath)) {
    throw new Error("target must resolve inside GITHUB_WORKSPACE.");
  }
  const targetMetadata = await lstat(targetPath);
  if (!targetMetadata.isDirectory() && !targetMetadata.isFile()) {
    throw new Error("target must resolve to a regular file or directory.");
  }

  const excludePrefixes = new Set(parseExclusions(input(environment, "exclude", "")));
  const failOn = parseFailureThreshold(input(environment, "fail-on", "none"));
  const maxFileBytes = parsePositiveInteger(
    input(environment, "max-file-bytes", "1000000"),
    "max-file-bytes",
    MAX_ACTION_FILE_BYTES,
  );
  const repository = repositoryIdentity(environment);

  const reportPlan = await planOutputPath(
    workspace,
    input(environment, "output", `${PRODUCT_SLUG}.json`),
    "output",
  );
  const sarifPlan = await planOutputPath(
    workspace,
    input(environment, "sarif-output", `${PRODUCT_SLUG}.sarif`),
    "sarif-output",
  );
  validateOutputDestinations(
    targetPath,
    targetMetadata.isFile(),
    reportPlan.destination,
    sarifPlan.destination,
  );
  await validateExistingOutputAliases(
    targetPath,
    targetMetadata.isFile(),
    reportPlan.destination,
    sarifPlan.destination,
  );
  if (targetMetadata.isDirectory()) {
    await addOutputExclusions(
      targetPath,
      reportPlan.destination,
      sarifPlan.destination,
      excludePrefixes,
    );
  }
  const reportPath = await materializeOutputPath(reportPlan);
  const sarifPath = await materializeOutputPath(sarifPlan);

  return {
    excludePrefixes: [...excludePrefixes].sort(),
    failOn,
    maxFileBytes,
    reportOutput: toPosixPath(path.relative(workspace, reportPath)),
    reportPath,
    repository,
    sarifOutput: toPosixPath(path.relative(workspace, sarifPath)),
    sarifPath,
    targetPath,
    workspace,
  };
}

function validateOutputDestinations(
  targetPath: string,
  targetIsFile: boolean,
  reportPath: string,
  sarifPath: string,
): void {
  if (reportPath === sarifPath) {
    throw new Error("output and sarif-output must be different files.");
  }
  if (sameCaseFoldedPath(reportPath, sarifPath)) {
    throw new Error("output and sarif-output must not be case aliases of the same file.");
  }
  if (isStrictPathAncestor(reportPath, sarifPath) || isStrictPathAncestor(sarifPath, reportPath)) {
    throw new Error("output and sarif-output cannot be parent and child paths.");
  }
  if (
    targetIsFile &&
    [reportPath, sarifPath].some(
      (outputPath) => outputPath === targetPath || sameCaseFoldedPath(outputPath, targetPath),
    )
  ) {
    throw new Error("Action outputs cannot overwrite the scanned target file.");
  }
}

async function validateExistingOutputAliases(
  targetPath: string,
  targetIsFile: boolean,
  reportPath: string,
  sarifPath: string,
): Promise<void> {
  const [report, sarif, target] = await Promise.all([
    existingPathIdentity(reportPath),
    existingPathIdentity(sarifPath),
    targetIsFile ? existingPathIdentity(targetPath) : undefined,
  ]);
  if (report !== undefined && sarif !== undefined && samePathIdentity(report, sarif)) {
    throw new Error("output and sarif-output must not resolve to the same existing file.");
  }
  if (
    target !== undefined &&
    ((report !== undefined && samePathIdentity(target, report)) ||
      (sarif !== undefined && samePathIdentity(target, sarif)))
  ) {
    throw new Error("Action outputs cannot alias the scanned target file.");
  }
}

async function existingPathIdentity(candidate: string): Promise<ExistingPathIdentity | undefined> {
  try {
    const canonicalPath = await realpath(candidate);
    const metadata = await lstat(canonicalPath);
    return { canonicalPath, device: metadata.dev, inode: metadata.ino };
  } catch (error) {
    if (hasErrorCode(error, "ENOENT")) {
      return undefined;
    }
    throw error;
  }
}

function samePathIdentity(left: ExistingPathIdentity, right: ExistingPathIdentity): boolean {
  return (
    foldedPath(left.canonicalPath) === foldedPath(right.canonicalPath) ||
    (left.device === right.device && left.inode === right.inode)
  );
}

async function addOutputExclusions(
  targetPath: string,
  reportPath: string,
  sarifPath: string,
  excludePrefixes: Set<string>,
): Promise<void> {
  for (const [inputName, outputPath] of [
    ["output", reportPath],
    ["sarif-output", sarifPath],
  ] as const) {
    if (isWithin(targetPath, outputPath)) {
      if (await pathExists(outputPath)) {
        throw new Error(`${inputName} must not pre-exist inside the scan target.`);
      }
      excludePrefixes.add(toPosixPath(path.relative(targetPath, outputPath)));
    }
  }
}

async function planOutputPath(
  workspace: string,
  requestedPath: string,
  inputName: string,
): Promise<OutputPathPlan> {
  validatePathInput(requestedPath, inputName);
  validatePortableOutputPath(requestedPath, inputName);
  if (isAbsolutePathInput(requestedPath)) {
    throw new Error(`${inputName} must be a relative path inside GITHUB_WORKSPACE.`);
  }
  const lexicalDestination = path.resolve(workspace, requestedPath);
  if (!isWithin(workspace, lexicalDestination) || lexicalDestination === workspace) {
    throw new Error(`${inputName} must resolve to a file inside GITHUB_WORKSPACE.`);
  }

  const lexicalParent = path.dirname(lexicalDestination);
  const { missingSegments, resolvedParent } = await resolveOutputAncestor(lexicalParent);
  if (!isWithin(workspace, resolvedParent)) {
    throw new Error(`${inputName} cannot traverse a directory link outside GITHUB_WORKSPACE.`);
  }
  if (!(await lstat(resolvedParent)).isDirectory()) {
    throw new Error(`${inputName} parent must resolve to a directory inside GITHUB_WORKSPACE.`);
  }
  const leafName = path.basename(lexicalDestination);
  return {
    destination: path.join(resolvedParent, ...missingSegments, leafName),
    initialParent: resolvedParent,
    inputName,
    leafName,
    missingSegments,
    workspace,
  };
}

async function materializeOutputPath(plan: OutputPathPlan): Promise<string> {
  const parent = await createMissingOutputParents(
    plan.workspace,
    plan.initialParent,
    plan.missingSegments,
    plan.inputName,
  );
  return path.join(parent, plan.leafName);
}

async function resolveOutputAncestor(
  lexicalParent: string,
): Promise<{ readonly missingSegments: readonly string[]; readonly resolvedParent: string }> {
  const missingSegments: string[] = [];
  let existingAncestor = lexicalParent;

  while (true) {
    try {
      return {
        missingSegments,
        resolvedParent: await realpath(existingAncestor),
      };
    } catch (error) {
      if (!hasErrorCode(error, "ENOENT")) {
        throw error;
      }
      missingSegments.unshift(path.basename(existingAncestor));
      existingAncestor = path.dirname(existingAncestor);
    }
  }
}

async function createMissingOutputParents(
  workspace: string,
  initialParent: string,
  missingSegments: readonly string[],
  inputName: string,
): Promise<string> {
  let resolvedParent = initialParent;
  for (const segment of missingSegments) {
    const nextParent = path.join(resolvedParent, segment);
    try {
      await mkdir(nextParent, { mode: 0o700 });
    } catch (error) {
      if (!hasErrorCode(error, "EEXIST")) {
        throw error;
      }
    }
    const metadata = await lstat(nextParent);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new Error(`${inputName} parent cannot traverse a directory link.`);
    }
    const canonicalParent = await realpath(nextParent);
    if (!isWithin(workspace, canonicalParent)) {
      throw new Error(`${inputName} cannot traverse a directory link outside GITHUB_WORKSPACE.`);
    }
    resolvedParent = canonicalParent;
  }

  return resolvedParent;
}

function repositoryIdentity(environment: ActionEnvironment): RepositoryIdentity {
  const serverUrl = requireEnvironment(environment, "GITHUB_SERVER_URL").replace(/\/+$/, "");
  const repository = requireEnvironment(environment, "GITHUB_REPOSITORY");
  const commit = requireEnvironment(environment, "GITHUB_SHA");
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
    throw new Error("GITHUB_REPOSITORY has an invalid owner/name value.");
  }
  return normalizeRepositoryIdentity({ commit, url: `${serverUrl}/${repository}` });
}

function parseExclusions(value: string): readonly string[] {
  if (value.length > MAX_EXCLUDE_INPUT_LENGTH) {
    throw new Error(`exclude must be at most ${MAX_EXCLUDE_INPUT_LENGTH.toString()} characters.`);
  }
  const exclusions: string[] = [];
  for (const line of value.split(/\r?\n/)) {
    if (hasControlCharacter(line)) {
      throw new Error("exclude entries cannot contain control characters.");
    }
    const normalized = toPosixPath(line.trim()).replace(/^\.\//, "").replace(/\/$/, "");
    if (normalized.length === 0) {
      continue;
    }
    if (
      normalized.startsWith("/") ||
      /^[A-Za-z]:\//.test(normalized) ||
      normalized.split("/").some((segment) => segment === "." || segment === "..")
    ) {
      throw new Error("exclude entries must be normalized relative paths.");
    }
    exclusions.push(normalized);
  }
  return [...new Set(exclusions)];
}

function parseFailureThreshold(value: string): FailureThreshold {
  if (value === "none" || (SEVERITIES as readonly string[]).includes(value)) {
    return value as FailureThreshold;
  }
  throw new Error("fail-on must be none, info, low, medium, high, or critical.");
}

function parsePositiveInteger(value: string, inputName: string, maximum: number): number {
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`${inputName} must be a positive integer.`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${inputName} must be a safe positive integer.`);
  }
  if (parsed > maximum) {
    throw new Error(`${inputName} must not exceed ${maximum.toString()}.`);
  }
  return parsed;
}

function input(environment: ActionEnvironment, name: string, fallback: string): string {
  const value = environment[`INPUT_${name.toUpperCase()}`];
  return value === undefined || value.length === 0 ? fallback : value;
}

function requireEnvironment(environment: ActionEnvironment, name: string): string {
  const value = environment[name];
  if (value === undefined || value.length === 0) {
    throw new Error(`${name} is required.`);
  }
  return value;
}

function validatePathInput(value: string, name: string): void {
  if (value.length === 0) {
    throw new Error(`${name} must be a non-empty path.`);
  }
  if (value.length > MAX_PATH_INPUT_LENGTH) {
    throw new Error(`${name} must be at most ${MAX_PATH_INPUT_LENGTH.toString()} characters.`);
  }
  if (hasControlCharacter(value)) {
    throw new Error(`${name} cannot contain control characters.`);
  }
  if (value.split(/[\\/]/).some((segment) => segment === "..")) {
    throw new Error(`${name} cannot contain parent traversal segments.`);
  }
}

function validatePortableOutputPath(value: string, name: string): void {
  for (const segment of value.split(/[\\/]/)) {
    if (segment.length === 0 || segment === ".") {
      continue;
    }
    if (/[<>:"|?*]/.test(segment)) {
      throw new Error(`${name} cannot contain Windows-reserved path characters.`);
    }
    if (/[. ]$/.test(segment)) {
      throw new Error(`${name} cannot contain a segment ending in a dot or space.`);
    }
    if (/^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:[ .]|$)/iu.test(segment)) {
      throw new Error(`${name} cannot contain a Windows reserved device name.`);
    }
  }
}

function isAbsolutePathInput(value: string): boolean {
  return path.isAbsolute(value) || /^[A-Za-z]:[\\/]/.test(value);
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 31 || codeUnit === 127) {
      return true;
    }
  }
  return false;
}

function hasErrorCode(error: unknown, code: string): boolean {
  return error instanceof Error && "code" in error && error.code === code;
}

function exceedsThreshold(
  findings: readonly { readonly severity: Severity }[],
  threshold: FailureThreshold,
): boolean {
  return (
    threshold !== "none" &&
    findings.some((finding) => severityRank(finding.severity) >= severityRank(threshold))
  );
}

function actionStatus(
  hasScanErrors: boolean,
  threshold: FailureThreshold,
  thresholdExceeded: boolean,
):
  | "complete threshold exceeded"
  | "complete threshold passed"
  | "complete observation"
  | "incomplete scan" {
  if (hasScanErrors) {
    return "incomplete scan";
  }
  if (threshold === "none") {
    return "complete observation";
  }
  return thresholdExceeded ? "complete threshold exceeded" : "complete threshold passed";
}

async function writeAtomically(destination: string, content: string): Promise<void> {
  const temporary = `${destination}.${process.pid.toString()}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, content, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await rename(temporary, destination);
  } finally {
    await unlink(temporary).catch(() => undefined);
  }
}

async function publishOutputs(
  environment: ActionEnvironment,
  outputs: Readonly<Record<string, string>>,
): Promise<void> {
  const outputFile = environment.GITHUB_OUTPUT;
  if (outputFile === undefined || outputFile.length === 0) {
    return;
  }
  const records = Object.entries(outputs)
    .map(([name, value]) => {
      const delimiter = `${PRODUCT_SLUG}_${randomUUID()}`;
      return `${name}<<${delimiter}\n${value}\n${delimiter}\n`;
    })
    .join("");
  await appendFile(outputFile, records, "utf8");
}

async function publishSummary(
  environment: ActionEnvironment,
  summary: {
    readonly critical: number;
    readonly high: number;
    readonly info: number;
    readonly low: number;
    readonly medium: number;
    readonly total: number;
  },
  result: {
    readonly errorDiagnostics: number;
    readonly status:
      | "complete threshold exceeded"
      | "complete threshold passed"
      | "complete observation"
      | "incomplete scan";
    readonly thresholdExceeded: boolean;
    readonly warningDiagnostics: number;
  },
): Promise<void> {
  const summaryFile = environment.GITHUB_STEP_SUMMARY;
  if (summaryFile === undefined || summaryFile.length === 0) {
    return;
  }
  const markdown = `## ${PRODUCT_NAME} scan\n\n${summaryGuidance(result.status)}\n\n| Total | Critical | High | Medium | Low | Info |\n| ---: | ---: | ---: | ---: | ---: | ---: |\n| ${summary.total.toString()} | ${summary.critical.toString()} | ${summary.high.toString()} | ${summary.medium.toString()} | ${summary.low.toString()} | ${summary.info.toString()} |\n\n| Error diagnostics | Warning diagnostics | Threshold exceeded |\n| ---: | ---: | :---: |\n| ${result.errorDiagnostics.toString()} | ${result.warningDiagnostics.toString()} | ${result.thresholdExceeded ? "yes" : "no"} |\n`;
  await appendFile(summaryFile, markdown, "utf8");
}

function summaryGuidance(
  status:
    | "complete threshold exceeded"
    | "complete threshold passed"
    | "complete observation"
    | "incomplete scan",
): string {
  switch (status) {
    case "complete observation":
      return "> **Complete observation.** Findings are reported but do not fail this step.";
    case "complete threshold exceeded":
      return "> **Complete.** Findings meet the configured failure threshold.";
    case "complete threshold passed":
      return "> **Complete.** No findings meet the configured failure threshold.";
    case "incomplete scan":
      return "> **Incomplete.** Do not interpret the finding count as a clean result.";
  }
}

function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return (
    relative === "" ||
    (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
  );
}

function toPosixPath(value: string): string {
  return path.sep === "\\" ? value.replaceAll("\\", "/") : value;
}

function safeErrorMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const sanitized = redactEvidence(message);
  if (sanitized.length <= MAX_LOG_MESSAGE_LENGTH) {
    return sanitized;
  }
  return `${sanitized.slice(0, MAX_LOG_MESSAGE_LENGTH - 3)}...`;
}

async function pathExists(candidate: string): Promise<boolean> {
  try {
    await lstat(candidate);
    return true;
  } catch (error) {
    if (hasErrorCode(error, "ENOENT")) {
      return false;
    }
    throw error;
  }
}

function sameCaseFoldedPath(left: string, right: string): boolean {
  return left !== right && foldedPath(left) === foldedPath(right);
}

function isStrictPathAncestor(parent: string, child: string): boolean {
  if (parent !== child && isWithin(parent, child)) {
    return true;
  }
  const foldedParent = foldedPath(parent);
  const foldedChild = foldedPath(child);
  return foldedParent !== foldedChild && isWithin(foldedParent, foldedChild);
}

function foldedPath(value: string): string {
  return value.normalize("NFC").toLowerCase();
}
