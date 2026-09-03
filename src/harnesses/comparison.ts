import type {
  CodexHarnessDelta,
  CodexHarnessSnapshot,
  CodexPermissionChange,
  CodexPermissionChangeDirection,
  CodexSemanticFact,
} from "./domain.js";

export function compareCodexHarnessSnapshots(
  baseline: CodexHarnessSnapshot,
  current: CodexHarnessSnapshot,
): CodexHarnessDelta {
  assertComparableSnapshot(baseline, "baseline");
  assertComparableSnapshot(current, "current");
  const before = new Map(baseline.semanticFacts.map((fact) => [fact.key, fact]));
  const after = new Map(current.semanticFacts.map((fact) => [fact.key, fact]));
  const changes: CodexPermissionChange[] = [];
  for (const key of [...new Set([...before.keys(), ...after.keys()])].sort()) {
    const oldFact = before.get(key);
    const newFact = after.get(key);
    if (oldFact !== undefined && newFact !== undefined && sameFact(oldFact, newFact)) continue;
    changes.push({
      ...(newFact === undefined ? {} : { after: newFact }),
      ...(oldFact === undefined ? {} : { before: oldFact }),
      direction: classifyChange(oldFact, newFact),
      key,
    });
  }
  return {
    baseline: {
      harnessId: baseline.harness.id,
      inputSha256: baseline.capture.inputSha256,
    },
    changes,
    current: {
      harnessId: current.harness.id,
      inputSha256: current.capture.inputSha256,
    },
    documentType: "uleravo.harness-delta",
    schemaVersion: "1.0.0",
    summary: {
      changed: changes.filter((change) => change.direction === "changed").length,
      expanded: changes.filter((change) => change.direction === "expanded").length,
      reduced: changes.filter((change) => change.direction === "reduced").length,
    },
  };
}

function classifyChange(
  before: CodexSemanticFact | undefined,
  after: CodexSemanticFact | undefined,
): CodexPermissionChangeDirection {
  if (before === undefined) return after === undefined ? "changed" : classifyAddition(after);
  if (after === undefined) return reverse(classifyAddition(before));
  return classifyPresentChange(before, after);
}

function classifyPresentChange(
  before: CodexSemanticFact,
  after: CodexSemanticFact,
): CodexPermissionChangeDirection {
  if (before.effect !== after.effect) {
    return classifyEffectTransition(before.effect, after.effect);
  }
  if (before.rank !== undefined && after.rank !== undefined && before.rank !== after.rank) {
    const increased = after.rank > before.rank;
    if (before.effect === "guard") return increased ? "reduced" : "expanded";
    return increased ? "expanded" : "reduced";
  }
  return "changed";
}

function classifyEffectTransition(
  before: CodexSemanticFact["effect"],
  after: CodexSemanticFact["effect"],
): CodexPermissionChangeDirection {
  if (before === "exposure" && after === "guard") return "reduced";
  if (before === "guard" && after === "exposure") return "expanded";
  return "changed";
}

function classifyAddition(fact: CodexSemanticFact): CodexPermissionChangeDirection {
  if (fact.effect === "identity" || fact.effect === "posture") return "changed";
  const active = fact.rank === undefined || fact.rank > 0;
  if (fact.effect === "exposure") return active ? "expanded" : "reduced";
  return active ? "reduced" : "expanded";
}

function reverse(direction: CodexPermissionChangeDirection): CodexPermissionChangeDirection {
  if (direction === "expanded") return "reduced";
  if (direction === "reduced") return "expanded";
  return "changed";
}

function sameFact(left: CodexSemanticFact, right: CodexSemanticFact): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function assertComparableSnapshot(snapshot: CodexHarnessSnapshot, label: string): void {
  if (
    snapshot.documentType !== "uleravo.harness-snapshot" ||
    snapshot.schemaVersion !== "1.0.0" ||
    snapshot.harness.adapter.name !== "openai-codex-local"
  ) {
    throw new Error(`${label} is not a supported Codex harness snapshot.`);
  }
  if (!snapshot.capture.complete) {
    throw new Error(`${label} is incomplete and cannot produce a permission delta.`);
  }
  if (snapshot.project.configApplicability === "unknown") {
    throw new Error(`${label} has unknown project-config applicability.`);
  }
  let previous = "";
  for (const fact of snapshot.semanticFacts) {
    if (
      fact.key.length === 0 ||
      fact.key <= previous ||
      (fact.effect !== "exposure" &&
        fact.effect !== "guard" &&
        fact.effect !== "identity" &&
        fact.effect !== "posture")
    ) {
      throw new Error(`${label} has invalid or unsorted semantic facts.`);
    }
    previous = fact.key;
  }
}
