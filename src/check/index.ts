import { lstat } from "node:fs/promises";
import path from "node:path";
import { capture, type LocalObservation } from "../monitor/capture.js";
import { parseOptions } from "../monitor/options.js";
import type { Harness, RuleId, Snapshot } from "../monitor/types.js";

// Local presentation only. Detection, filtering, identity and safe selectors are
// the same capture/observation pipeline used by monitor --explain. Never wire data.
const rules: Record<
  RuleId,
  { title: string; severity: "HIGH" | "MEDIUM"; why: string; next: string }
> = {
  CFG001: {
    title: "Permission prompts bypassed",
    severity: "HIGH",
    why: "The settings declare bypassed permission prompts. The installed harness may not honor this declaration.",
    next: "Restore permission prompts and narrowly scoped approvals unless independently reviewed external isolation justifies bypassing them.",
  },
  CFG002: {
    title: "Unrestricted sandbox declared",
    severity: "HIGH",
    why: "The configuration declares full access rather than a restricted sandbox; effective runtime permissions are unobserved.",
    next: "Restrict sandbox access to the minimum required workspace or read-only scope; review any external isolation separately.",
  },
  CFG003: {
    title: "Unpinned package launcher",
    severity: "MEDIUM",
    why: "The direct package launcher has no recognized exact version, so a later launch may select different code.",
    next: "Pin a reviewed exact package version. A pin does not verify artifact identity or dependencies.",
  },
  CFG004: {
    title: "Unencrypted remote MCP connection",
    severity: "MEDIUM",
    why: "The declared non-loopback MCP URL uses HTTP, which does not encrypt transport.",
    next: "Use encrypted transport for the remote MCP connection. Review the destination before trusting it.",
  },
  CFG005: {
    title: "Literal credential in configuration",
    severity: "HIGH",
    why: "An inspected credential field contains a literal value rather than a recognized reference; sharing the file may expose it.",
    next: "Replace literal credentials with harness-supported references or credential storage; rotate exposed credentials. No reference is resolved by this report.",
  },
  CFG006: {
    title: "Broad automatic shell approval",
    severity: "HIGH",
    why: "The allow list declares broad shell approval instead of narrowly scoped operations.",
    next: "Narrow automatic shell approvals to reviewed operations. Approval rules are not an operating-system isolation boundary.",
  },
};

const header = "Declaration review, not runtime protection — LOCAL-ONLY (not telemetry)";
const files: Record<Harness, string> = {
  "claude-code": ".claude/settings.json, .claude/settings.local.json, .mcp.json",
  cursor: ".cursor/mcp.json",
  codex: ".codex/config.toml",
};

// Lexical syntax policy only, before even lstat. This cannot identify mapped
// drives, network mounts or redirects in ancestors; use stable local storage.
function unsupportedLocalSyntax(value: string): boolean {
  return (
    !value ||
    /[\p{Cc}\p{Cf}]/u.test(value) ||
    /^(?:\\|\/[\\/])/.test(value) ||
    /^\/(?:\?\?|Device|GLOBAL\?\?|DosDevices)(?:[\\/]|$)/i.test(value) ||
    (/^[^\\/]*:/.test(value) && !/^[a-z]:[\\/]/i.test(value))
  );
}

async function inspectTarget(project: string): Promise<string | undefined> {
  try {
    const stat = await lstat(project);
    if (stat.isSymbolicLink())
      return "Target is a symbolic link or junction; review not performed.";
    if (!stat.isDirectory()) return "Target is not a directory; review not performed.";
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT"
      ? "Target does not exist; review not performed."
      : "Target could not be inspected; review not performed.";
  }
  return undefined;
}

export async function runCheck(argv: string[]): Promise<number> {
  if (argv.length === 1 && ["--help", "-h"].includes(argv[0] ?? "")) {
    process.stdout.write(`uleravo check [project]
Review supported local project configuration declarations; default: current directory.
UNC/device and drive-relative paths are unsupported, including the current directory.
Use stable local storage; this is not OS network isolation.
Mapped drives, network mounts and ancestor redirects are not identified by the syntax check.
Prints prioritized titles, severity, local file/field, why and manual next steps.
Project files only: ${Object.values(files).join("; ")}.
Coverage is reported by harness/project group, not effective settings or runtime protection.
No account, credential lookup, upload, watch, target execution or file edits.
No user-wide reads; use the existing monitor --include-user only with explicit consent.
Skill content is unsupported by check. No findings is not verification of security.
Exit 0 for covered complete review without findings; 1 for findings;
2 for invalid target, no coverage or incomplete review (also invalid arguments).
After a reviewed manual edit, repeat uleravo check with the same project.
`);
    return 0;
  }
  if (
    argv.length > 1 ||
    argv.some((arg) => !arg || arg.startsWith("-") || /[\p{Cc}\p{Cf}]/u.test(arg))
  ) {
    process.stderr.write(
      "Invalid check arguments. Use uleravo check [project] or uleravo check --help; no upload, watch or user-wide options.\n",
    );
    return 2;
  }
  const cwd = process.cwd();
  const target = argv[0] ?? cwd;
  if ([cwd, target].some(unsupportedLocalSyntax)) {
    process.stdout.write(
      `${header}\nCovered configuration groups: none\nUnsupported local target syntax; review not performed.\nManual next step: use an ordinary path to a stable project on local storage.\n`,
    );
    return 2;
  }
  const project = path.resolve(cwd, target);
  const targetProblem = await inspectTarget(project);
  if (targetProblem) {
    process.stdout.write(
      `${header}\nCovered configuration groups: none\n${targetProblem}\nManual next step: select an existing stable local project directory with uleravo check "PATH/TO/PROJECT".\n`,
    );
    return 2;
  }
  const observations: LocalObservation[] = [];
  const snapshot = await capture(parseOptions(["--project", project]), (item) =>
    observations.push(item),
  );
  return printReview(snapshot, observations);
}

function printReview(snapshot: Snapshot, observations: LocalObservation[]): number {
  const covered = snapshot.configurations.filter((item) => item.status === "read");
  const lines = [
    header,
    `Covered configuration groups: ${covered.map((item) => `${item.harness}/${item.scope}`).join(", ") || "none"}`,
    "Project declarations only; user-wide settings, Skills, source code and runtime behavior are not inspected.",
  ];
  const missing = snapshot.configurations.filter((item) => item.status === "missing");
  if (missing.length)
    lines.push(
      `Not covered (missing): ${missing.map((item) => `${item.harness}/${item.scope}`).join(", ")}`,
    );
  if (!snapshot.complete) {
    lines.push(
      "Incomplete review: local finding locations withheld; absence of findings is not evidence of security.",
    );
    for (const config of snapshot.configurations.filter((item) => item.status === "error")) {
      lines.push(
        `Malformed, unreadable, unsafe or over-limit configuration: ${config.harness}/${config.scope}.`,
      );
      lines.push(
        `Manual next step: inspect ${files[config.harness]} locally for syntax, inspected field types, size and regular-file access; then recheck. The collector does not identify which file failed within an aggregate group.`,
      );
    }
    process.stdout.write(`${lines.join("\n")}\n`);
    return 2;
  }
  if (!covered.length) {
    lines.push(
      "No coverage: no supported project configuration files were read. No security conclusion is available.",
      "Skill content is unsupported by check; a Skill-only directory is not a supported configuration review target.",
      `Manual next step: select the project containing its existing supported configuration (${Object.values(files).join("; ")}). Do not create settings merely to get a passing result.`,
    );
    process.stdout.write(`${lines.join("\n")}\n`);
    return 2;
  }
  lines.push(
    snapshot.findings.length
      ? `${snapshot.findings.length} ${snapshot.findings.length === 1 ? "declaration needs" : "declarations need"} review.`
      : "No supported declaration findings observed in the covered groups. This is not verification of security or resolution.",
  );
  const findings = new Set(snapshot.findings.map((item) => item.id));
  const ranked = observations
    .filter((item) => findings.has(item.finding.id))
    .sort(
      (a, b) =>
        rules[a.finding.ruleId].severity.localeCompare(rules[b.finding.ruleId].severity) ||
        a.finding.ruleId.localeCompare(b.finding.ruleId) ||
        a.file.localeCompare(b.file) ||
        a.selector.localeCompare(b.selector),
    );
  const located = new Set(ranked.map((item) => item.finding.id));
  const unavailable = snapshot.findings.filter((item) => !located.has(item.id)).length;
  if (unavailable) {
    lines.push(
      `Incomplete local presentation: ${unavailable} finding location(s) unavailable; findings still need review. Inspect the supported project files locally, then recheck.`,
    );
  }
  for (const [index, item] of ranked.entries()) {
    const rule = rules[item.finding.ruleId];
    lines.push(
      "",
      `${index + 1}. [${rule.severity}] ${rule.title}`,
      `   Location: ${item.finding.scope} ${item.file} :: ${item.selector}`,
      `   Why: ${rule.why}`,
      `   Manual next step: ${rule.next}`,
    );
  }
  lines.push(
    "",
    "After a reviewed manual edit, run uleravo check again with the same project. No execution, edits or upload.",
  );
  process.stdout.write(`${lines.join("\n")}\n`);
  return snapshot.findings.length ? 1 : 0;
}
