import {
  type CodexHarnessDelta,
  type CodexHarnessSnapshot,
  MAX_HARNESS_REPORT_BYTES,
} from "../harnesses/domain.js";
import { boundedRedactedEvidence } from "../redact.js";

export function formatCodexHarnessJson(snapshot: CodexHarnessSnapshot): string {
  const serialized = `${JSON.stringify(snapshot, null, 2)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > MAX_HARNESS_REPORT_BYTES) {
    throw new Error(
      `Codex harness snapshot exceeds the ${MAX_HARNESS_REPORT_BYTES.toString()}-byte report limit.`,
    );
  }
  return serialized;
}

export function formatCodexHarnessText(snapshot: CodexHarnessSnapshot): string {
  const version =
    snapshot.codexVersion.state === "declared"
      ? snapshot.codexVersion.value
      : `unavailable: ${snapshot.codexVersion.reason}`;
  const lines = [
    `Uleravo Codex harness snapshot ${snapshot.harness.id}`,
    `Capture complete: ${snapshot.capture.complete ? "yes" : "no"}`,
    `Codex version: ${version}`,
    `Project trust: ${
      snapshot.project.trust.state === "declared"
        ? snapshot.project.trust.value
        : `unavailable: ${snapshot.project.trust.reason}`
    }`,
    `Project config: ${snapshot.project.configApplicability}`,
    `Semantic facts: ${snapshot.semanticFacts.length.toString()}`,
    `Skills: ${snapshot.inventory.skills.length.toString()}`,
    `Plugins: ${snapshot.inventory.plugins.length.toString()}`,
    `Apps: ${snapshot.inventory.apps.length.toString()}`,
    `MCP servers: ${snapshot.inventory.mcpServers.length.toString()}`,
    `Hooks: ${snapshot.inventory.hooks.length.toString()}`,
    "Layers:",
    ...snapshot.layers.map(
      (layer) => `  ${layer.kind}: ${layer.status} · ${layer.applicability} · ${layer.pathSource}`,
    ),
    "Coverage:",
    ...snapshot.coverage.map(
      (coverage) => `  ${coverage.area}: ${coverage.state} (${coverage.reason})`,
    ),
  ];
  if (snapshot.diagnostics.length > 0) {
    lines.push(
      "Diagnostics:",
      ...snapshot.diagnostics.map(
        (diagnostic) =>
          `  ERROR${diagnostic.layer === undefined ? "" : ` ${diagnostic.layer}`}: ${diagnostic.message}`,
      ),
    );
  }
  return `${lines.join("\n")}\n`;
}

export function formatCodexHarnessDeltaJson(delta: CodexHarnessDelta): string {
  return `${JSON.stringify(delta, null, 2)}\n`;
}

export function formatCodexHarnessDeltaText(delta: CodexHarnessDelta): string {
  const lines = [
    "Uleravo Codex semantic permission delta",
    `Baseline: ${delta.baseline.harnessId}`,
    `Current: ${delta.current.harnessId}`,
    `${delta.summary.expanded.toString()} expanded · ${delta.summary.reduced.toString()} reduced · ${delta.summary.changed.toString()} changed`,
  ];
  if (delta.changes.length > 0) {
    lines.push(
      "Changes:",
      ...delta.changes.map(
        (change) =>
          `  ${change.direction.toUpperCase()} ${boundedRedactedEvidence(change.key, 2_000)}: ${displayFactValue(change.before)} -> ${displayFactValue(change.after)}`,
      ),
    );
  }
  return `${lines.join("\n")}\n`;
}

function displayFactValue(
  fact: CodexHarnessDelta["changes"][number]["before"] | undefined,
): string {
  if (fact === undefined) return "absent";
  return JSON.stringify(
    typeof fact.value === "string" ? boundedRedactedEvidence(fact.value, 2_000) : fact.value,
  );
}
