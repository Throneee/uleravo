import type { FindingInput, RuleMetadata } from "../domain.js";
import type { ScannableFile } from "../scanner/files.js";

export interface RuleContext {
  readonly file: ScannableFile;
  readonly hasLockfile: boolean;
}

export interface RepositoryRuleContext {
  readonly files: readonly ScannableFile[];
}

export interface FileRule {
  readonly metadata: RuleMetadata;
  scan(context: RuleContext): readonly FindingInput[];
}

export interface RepositoryRule {
  readonly metadata: RuleMetadata;
  scanRepository(context: RepositoryRuleContext): readonly FindingInput[];
}

export type Rule = FileRule;
export type ScannerRule = FileRule | RepositoryRule;
