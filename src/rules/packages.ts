import path from "node:path";
import type { FindingInput } from "../domain.js";
import { findingAtOffset } from "../scanner/source.js";
import { RULES } from "./catalog.js";
import type { Rule } from "./types.js";

type JsonObject = Record<string, unknown>;

export const unpinnedPackageRule: Rule = {
  metadata: RULES.unpinnedPackage,
  scan({ file, hasLockfile }): readonly FindingInput[] {
    if (file.kind !== "json") {
      return [];
    }

    let document: unknown;
    try {
      document = JSON.parse(file.text) as unknown;
    } catch {
      return [];
    }
    if (!isObject(document)) {
      return [];
    }

    const findings: FindingInput[] = [];
    if (path.posix.basename(file.relativePath) === "package.json" && !hasLockfile) {
      inspectPackageJson(document, file, findings);
    }
    inspectMcpConfiguration(document, file, findings);
    return findings;
  },
};

function inspectPackageJson(
  document: JsonObject,
  file: Parameters<typeof findingAtOffset>[0],
  findings: FindingInput[],
): void {
  for (const sectionName of ["dependencies", "devDependencies", "optionalDependencies"]) {
    const section = document[sectionName];
    if (!isObject(section)) {
      continue;
    }
    for (const [name, value] of Object.entries(section)) {
      if (typeof value !== "string" || !looksLikeMcpPackage(name) || isExactReference(value)) {
        continue;
      }
      findings.push(
        findingForValue(
          file,
          value,
          `MCP dependency ${name} uses mutable reference ${value} without a lockfile.`,
        ),
      );
    }
  }
}

function inspectMcpConfiguration(
  document: JsonObject,
  file: Parameters<typeof findingAtOffset>[0],
  findings: FindingInput[],
): void {
  const servers = document.mcpServers;
  if (!isObject(servers)) {
    return;
  }

  for (const [serverName, value] of Object.entries(servers)) {
    if (!isObject(value) || typeof value.command !== "string" || !Array.isArray(value.args)) {
      continue;
    }
    const command = path.win32.basename(value.command).toLowerCase();
    if (!new Set(["bunx", "npx", "pnpx", "uvx"]).has(command)) {
      continue;
    }
    const packageReference = value.args.find(
      (argument): argument is string => typeof argument === "string" && !argument.startsWith("-"),
    );
    if (packageReference === undefined || isExactRunnerReference(command, packageReference)) {
      continue;
    }
    findings.push(
      findingForValue(
        file,
        packageReference,
        `MCP server ${serverName} executes mutable package reference ${packageReference}.`,
      ),
    );
  }
}

function isExactRunnerReference(command: string, reference: string): boolean {
  return isExactReference(reference) || (command === "uvx" && isExactPythonRequirement(reference));
}

function isExactPythonRequirement(reference: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9._,-]+\])?==v?\d[0-9A-Za-z.!+_-]*$/u.test(
    reference,
  );
}

function findingForValue(
  file: Parameters<typeof findingAtOffset>[0],
  value: string,
  message: string,
): FindingInput {
  const quotedOffset = file.text.indexOf(`"${value}"`);
  const offset = quotedOffset === -1 ? Math.max(0, file.text.indexOf(value)) : quotedOffset + 1;
  return findingAtOffset(file, offset, value.length, RULES.unpinnedPackage, message);
}

function looksLikeMcpPackage(name: string): boolean {
  return (
    name === "@modelcontextprotocol/sdk" || /(?:^|[-_/])mcp(?:$|[-_/])/.test(name.toLowerCase())
  );
}

function isExactReference(reference: string): boolean {
  if (/^(?:file|link|workspace):/.test(reference)) {
    return true;
  }
  if (/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(reference)) {
    return true;
  }
  if (/#[0-9a-f]{40}$/i.test(reference)) {
    return true;
  }

  const scopedPackage = reference.startsWith("@");
  const versionSeparator = scopedPackage ? reference.indexOf("@", 1) : reference.lastIndexOf("@");
  if (versionSeparator > 0) {
    return isExactReference(reference.slice(versionSeparator + 1));
  }
  return false;
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
