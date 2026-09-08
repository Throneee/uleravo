export type Harness = "claude-code" | "cursor" | "codex";
export type Scope = "project" | "user";
export type RuleId = "CFG001" | "CFG002" | "CFG003" | "CFG004" | "CFG005" | "CFG006";
export type Status = "read" | "missing" | "error";
export interface Configuration {
  harness: Harness;
  scope: Scope;
  status: Status;
  digest?: string;
  serverCount: number;
}
export interface Finding {
  id: string;
  ruleId: RuleId;
  harness: Harness;
  scope: Scope;
  subjectId: string;
}
export interface Snapshot {
  schemaVersion: 1;
  // Omitted only when the explicit project root cannot be safely canonicalized.
  projectId?: string;
  captureId: string;
  capturedAt: string;
  complete: boolean;
  configurations: Configuration[];
  findings: Finding[];
}
