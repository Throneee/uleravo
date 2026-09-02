import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { FindingInput } from "../src/domain.js";
import { RULES } from "../src/rules/catalog.js";
import type { FileRule, RepositoryRule } from "../src/rules/types.js";
import { scan } from "../src/scanner/scan.js";

const fixture = path.join(fileURLToPath(new URL("./fixtures", import.meta.url)), "safe-server");
const FINDING_LIMIT = 5_000;
const LIMIT_DIAGNOSTIC = {
  message: "Finding limit exceeded (5000 raw findings retained); scan evidence is incomplete.",
  type: "error",
} as const;

describe("global finding limit", () => {
  it("completes when a rule produces exactly the retained limit", async () => {
    const repositoryRule: RepositoryRule = {
      metadata: RULES.commandInjection,
      scanRepository() {
        return lazyFindings("repository-rule.ts", 0, FINDING_LIMIT, () => undefined);
      },
    };

    const report = await scan(fixture, { rules: [repositoryRule] });

    expect(report.findings).toHaveLength(FINDING_LIMIT);
    expect(report.summary.total).toBe(FINDING_LIMIT);
    expect(report.diagnostics).toEqual([]);
  });

  it("stops a lazy file rule and skips repository rules after the limit is exceeded", async () => {
    let iterations = 0;
    let repositoryCalls = 0;
    const fileRule: FileRule = {
      metadata: RULES.commandInjection,
      scan({ file }) {
        return lazyFindings(file.relativePath, 0, FINDING_LIMIT * 100, () => {
          iterations += 1;
        });
      },
    };
    const repositoryRule: RepositoryRule = {
      metadata: RULES.commandInjection,
      scanRepository() {
        repositoryCalls += 1;
        return [];
      },
    };

    const report = await scan(fixture, { rules: [fileRule, repositoryRule] });

    expect(report.findings).toHaveLength(FINDING_LIMIT);
    expect(report.summary.total).toBe(FINDING_LIMIT);
    expect(report.diagnostics).toEqual([LIMIT_DIAGNOSTIC]);
    expect(report.scan.filesScanned).toBe(0);
    expect(report.scan.filesSkipped).toBeGreaterThan(0);
    expect(iterations).toBe(FINDING_LIMIT + 1);
    expect(repositoryCalls).toBe(0);
  });

  it("shares the cap with repository rules and produces deterministic bounded evidence", async () => {
    let repositoryIterations = 0;
    const fileRule: FileRule = {
      metadata: RULES.commandInjection,
      scan({ file }) {
        return file.kind === "source"
          ? [syntheticFinding(file.relativePath, 0), syntheticFinding(file.relativePath, 1)]
          : [];
      },
    };
    const repositoryRule: RepositoryRule = {
      metadata: RULES.commandInjection,
      scanRepository() {
        return lazyFindings("repository-rule.ts", 2, FINDING_LIMIT * 100, () => {
          repositoryIterations += 1;
        });
      },
    };
    const rules = [fileRule, repositoryRule] as const;

    const first = await scan(fixture, { rules });
    const firstIterations = repositoryIterations;
    const second = await scan(fixture, { rules });
    const secondIterations = repositoryIterations - firstIterations;

    expect(first.findings).toHaveLength(FINDING_LIMIT);
    expect(first.diagnostics).toEqual([LIMIT_DIAGNOSTIC]);
    expect(firstIterations).toBe(FINDING_LIMIT - 2 + 1);
    expect(secondIterations).toBe(firstIterations);
    expect(second.findings).toEqual(first.findings);
    expect(second.diagnostics).toEqual(first.diagnostics);
    expect(second.summary).toEqual(first.summary);
    expect(second.scan.id).toBe(first.scan.id);
  });
});

function lazyFindings(
  file: string,
  start: number,
  count: number,
  onIteration: () => void,
): readonly FindingInput[] {
  return {
    *[Symbol.iterator]() {
      for (let index = 0; index < count; index += 1) {
        onIteration();
        yield syntheticFinding(file, start + index);
      }
    },
  } as unknown as readonly FindingInput[];
}

function syntheticFinding(file: string, index: number): FindingInput {
  return {
    column: 1,
    evidence: `synthetic-${index.toString()}`,
    file,
    line: index + 1,
    message: "Synthetic finding used to exercise the scanner-wide bound.",
    metadata: RULES.commandInjection,
  };
}
