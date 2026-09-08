import { capture, type LocalObservation } from "./capture.js";
import type { MonitorOptions } from "./options.js";
import type { RuleId } from "./types.js";

const advice: Record<RuleId, string> = {
  CFG001:
    "Restore permission prompts and narrowly scoped approvals unless independently reviewed external isolation justifies bypassing them. The declaration may not be honored by the installed harness.",
  CFG002:
    "Restrict sandbox access to the minimum required workspace or read-only scope; review any external isolation separately.",
  CFG003:
    "Pin a reviewed exact package version. A pin does not verify artifact identity or dependencies.",
  CFG004:
    "Use encrypted transport for the remote MCP connection. Review the destination before trusting it.",
  CFG005:
    "Replace literal credentials with harness-supported references or credential storage; rotate exposed credentials. No reference is resolved by this report.",
  CFG006:
    "Narrow automatic shell approvals to reviewed operations. Approval rules are not an operating-system isolation boundary.",
};

export async function explain(options: MonitorOptions): Promise<number> {
  const matches: LocalObservation[] = [];
  const snapshot = await capture(options, (observation) => {
    if (observation.finding.subjectId === options.explain) matches.push(observation);
  });
  console.log("LOCAL-ONLY explanation (not telemetry)");
  if (!snapshot.complete) {
    console.log("Incomplete fresh capture; local locations withheld.");
    return 2;
  }
  if (matches.length === 0) {
    console.log(
      "Subject not observed in this fresh capture. This is not verification of security or resolution.",
    );
    return 0;
  }
  for (const { finding, file, selector } of matches) {
    console.log(`${finding.scope} ${file} :: ${selector}`);
    console.log(`${finding.ruleId}: ${advice[finding.ruleId]}`);
  }
  console.log("No execution, edits, upload or verification of effective permissions.");
  return 0;
}
