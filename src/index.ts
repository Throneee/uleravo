export type {
  ComparisonSummary,
  ReportComparison,
  ScanReference,
} from "./comparison.js";
export { compareReports } from "./comparison.js";
export type {
  Confidence,
  Diagnostic,
  Finding,
  LockfileProvenance,
  PackageProvenance,
  RepositoryProvenance,
  RuleMetadata,
  ScanProvenance,
  ScanReport,
  ScanSummary,
  Severity,
  StandardsMapping,
} from "./domain.js";
export { formatComparisonJson, formatComparisonText } from "./formatters/comparison.js";
export { formatJson } from "./formatters/json.js";
export { formatSarif } from "./formatters/sarif.js";
export { formatText } from "./formatters/text.js";
export { parseScanReport, readScanReport } from "./reports/read.js";
export type { ScanOptions } from "./scanner/scan.js";
export { scan } from "./scanner/scan.js";
export type {
  SignedReportEnvelope,
  SigningKeyPair,
  VerifiedSignedReport,
} from "./signatures.js";
export {
  formatSignedReportEnvelope,
  generateSigningKeyPair,
  parseSignedReportEnvelope,
  SIGNED_REPORT_MAX_ENVELOPE_BYTES,
  SIGNED_REPORT_MAX_PAYLOAD_BYTES,
  signReport,
  verifySignedReport,
} from "./signatures.js";
export { PRODUCT_NAME, PRODUCT_SLUG, PRODUCT_URL, VERSION } from "./version.js";
