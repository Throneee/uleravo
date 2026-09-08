import { createHash, randomUUID } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { parse as parseToml } from "smol-toml";
import type { MonitorOptions } from "./options.js";
import { isLoopback } from "./options.js";
import { checkDirectory, readConfig } from "./read.js";
import { literalCredential, mutableLauncher } from "./rules.js";
import type { Configuration, Finding, Harness, RuleId, Scope, Snapshot, Status } from "./types.js";

export function hash(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}
export function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

// Opt-in in-memory side channel only. Never attach local locations to Snapshot.
export interface LocalObservation {
  finding: Finding;
  file: string;
  selector: string;
}

export async function capture(
  options: MonitorOptions,
  observe?: (observation: LocalObservation) => void,
): Promise<Snapshot> {
  const configurations: Configuration[] = [];
  const findings: Finding[] = [];
  let projectId: string | undefined;
  for (const scope of (options.includeUser ? ["project", "user"] : ["project"]) as Scope[]) {
    let base = scope === "project" ? options.project : os.homedir();
    let safeProject = true;
    try {
      base = await checkDirectory(base);
      if (scope === "project") {
        projectId = hash(process.platform === "win32" ? base.toLowerCase() : base);
      }
    } catch {
      safeProject = false;
    }
    for (const harness of ["claude-code", "cursor", "codex"] as const) {
      const files =
        harness === "claude-code"
          ? scope === "project"
            ? [".claude/settings.json", ".claude/settings.local.json", ".mcp.json"]
            : [".claude/settings.json", ".claude.json"]
          : harness === "codex"
            ? [".codex/config.toml"]
            : [".cursor/mcp.json"];
      const states: Status[] = safeProject ? [] : ["error"];
      const groupFindings: Finding[] = [];
      let serverCount = 0;
      const disabled = new Set<string>();
      for (const file of files) {
        if (!safeProject) break;
        try {
          const text = await readConfig(path.resolve(base, file));
          const root: unknown = harness === "codex" ? parseToml(text) : JSON.parse(text);
          const config = object(root);
          if (!config) throw new Error("malformed");
          const isSettings = harness === "claude-code" && file.includes("settings");
          validate(config, harness, isSettings);
          const record = (ruleId: RuleId, identity: string[], selector: string): Finding => {
            const result = finding(ruleId, harness, scope, [path.resolve(base), file, ...identity]);
            observe?.({ finding: result, file, selector });
            return result;
          };
          states.push("read");
          if (harness === "claude-code" && strings(config.disabledMcpjsonServers)) {
            for (const name of config.disabledMcpjsonServers) disabled.add(name);
          }
          if (
            harness === "claude-code" &&
            file.includes("settings") &&
            literalCredential(config, harness)
          ) {
            groupFindings.push(
              record(
                "CFG005",
                ["settings"],
                'JSON Pointer "" (settings root; inspected credential fields)',
              ),
            );
          }
          const servers = isSettings
            ? undefined
            : object(config[harness === "codex" ? "mcp_servers" : "mcpServers"]);
          for (const { name, entry, ordinal } of Object.entries(servers ?? {})
            .map(([name, entry], index) => ({ name, entry, ordinal: index + 1 }))
            .sort((a, b) => a.name.localeCompare(b.name))) {
            const server = object(entry);
            if (
              !server ||
              server.disabled === true ||
              server.enabled === false ||
              (file === ".mcp.json" && disabled.has(name))
            )
              continue;
            serverCount++;
            const serverFinding = (ruleId: RuleId): Finding =>
              record(
                ruleId,
                ["server", name],
                `${harness === "codex" ? "mcp_servers" : "mcpServers"} entry #${ordinal} (parsed key order; label withheld)`,
              );
            if (literalCredential(server, harness)) {
              groupFindings.push(serverFinding("CFG005"));
            }
            if (mutableLauncher(server)) {
              groupFindings.push(serverFinding("CFG003"));
            }
            if (typeof server.url === "string") {
              const url = new URL(server.url);
              if (url.protocol === "http:" && !isLoopback(url.hostname)) {
                groupFindings.push(serverFinding("CFG004"));
              }
            }
          }
          if (harness === "codex" && config.sandbox_mode === "danger-full-access") {
            groupFindings.push(record("CFG002", ["sandbox"], "sandbox_mode"));
          }
          const permissions = isSettings ? object(config.permissions) : undefined;
          if (permissions?.defaultMode === "bypassPermissions") {
            groupFindings.push(record("CFG001", ["permissions"], "/permissions/defaultMode"));
          }
          if (
            Array.isArray(permissions?.allow) &&
            permissions.allow.some((rule) => ["Bash", "Bash(*)", "Bash(:*)"].includes(rule))
          ) {
            groupFindings.push(record("CFG006", ["permissions"], "/permissions/allow"));
          }
        } catch (error) {
          states.push((error as NodeJS.ErrnoException).code === "ENOENT" ? "missing" : "error");
        }
      }
      const status = states.includes("error")
        ? "error"
        : states.includes("read")
          ? "read"
          : "missing";
      configurations.push({
        harness,
        scope,
        status,
        serverCount,
        ...(status === "read" ? { digest: hash([states, serverCount, groupFindings]) } : {}),
      });
      // Findings need fully read harness/scope coverage on the wire. Preserve
      // the error status so the backend keeps earlier findings unresolved.
      if (status === "read") findings.push(...groupFindings);
    }
  }
  const snapshot: Snapshot = {
    schemaVersion: 1,
    ...(projectId ? { projectId } : {}),
    captureId: randomUUID(),
    capturedAt: new Date().toISOString(),
    complete: !configurations.some((c) => c.status === "error"),
    configurations,
    findings,
  };
  if (findings.length > 500 || Buffer.byteLength(JSON.stringify(snapshot)) > 128 * 1024) {
    snapshot.complete = false;
    for (const config of configurations) {
      if (config.status === "read") {
        config.status = "error";
        delete config.digest;
      }
    }
    // All read coverage above became error; do not attach findings to it.
    snapshot.findings = [];
  }
  return snapshot;
}
function finding(ruleId: RuleId, harness: Harness, scope: Scope, identity: unknown): Finding {
  const subjectId = hash([harness, scope, identity]);
  return { id: hash([ruleId, harness, scope, subjectId]), ruleId, harness, scope, subjectId };
}

function validate(config: Record<string, unknown>, harness: Harness, isSettings: boolean): void {
  if (
    harness === "claude-code" &&
    config.disabledMcpjsonServers !== undefined &&
    !strings(config.disabledMcpjsonServers)
  )
    throw new Error("malformed");
  if (
    harness === "codex" &&
    config.sandbox_mode !== undefined &&
    typeof config.sandbox_mode !== "string"
  )
    throw new Error("malformed");
  const permissions = isSettings ? config.permissions : undefined;
  if (
    permissions !== undefined &&
    (!object(permissions) ||
      (object(permissions)?.allow !== undefined && !strings(object(permissions)?.allow)) ||
      (object(permissions)?.defaultMode !== undefined &&
        typeof object(permissions)?.defaultMode !== "string"))
  )
    throw new Error("malformed");
  const servers = isSettings
    ? undefined
    : config[harness === "codex" ? "mcp_servers" : "mcpServers"];
  if (servers !== undefined && !object(servers)) throw new Error("malformed");
  if (Object.keys(object(servers) ?? {}).length > 500) throw new Error("too_many");
  for (const entry of Object.values(object(servers) ?? {})) {
    const server = object(entry);
    if (!server || (server.args !== undefined && !strings(server.args)))
      throw new Error("malformed");
    for (const field of ["command", "url"]) {
      if (server[field] !== undefined && typeof server[field] !== "string")
        throw new Error("malformed");
    }
    for (const field of ["enabled", "disabled"]) {
      if (server[field] !== undefined && typeof server[field] !== "boolean")
        throw new Error("malformed");
    }
    validateCredentials(server, harness);
  }
  if (isSettings) validateCredentials(config, harness);
}
function validateCredentials(config: Record<string, unknown>, harness: Harness): void {
  if (harness === "codex" && config.oauth !== undefined) {
    const oauth = object(config.oauth);
    if (!oauth || (oauth.client_secret !== undefined && typeof oauth.client_secret !== "string"))
      throw new Error("malformed");
  }
  if (config.auth !== undefined) {
    const auth = object(config.auth);
    // Only known scalar slots have a shape contract here. The credential
    // heuristic's substring matches do not define schemas for auth extensions.
    if (
      !auth ||
      Object.entries(auth).some(
        ([key, value]) =>
          /^(?:token|bearer_token|api_key|apiKey|password|client_secret|authorization)$/i.test(
            key,
          ) && typeof value !== "string",
      )
    )
      throw new Error("malformed");
  }
  for (const field of ["token", "bearer_token", "api_key", "apiKey", "password", "client_secret"]) {
    if (config[field] !== undefined && typeof config[field] !== "string")
      throw new Error("malformed");
  }
  for (const field of ["env", "headers", "http_headers"]) {
    if (
      config[field] !== undefined &&
      (!object(config[field]) ||
        !Object.values(object(config[field]) ?? {}).every((value) => typeof value === "string"))
    )
      throw new Error("malformed");
  }
}
function strings(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}
