export const CODEX_HARNESS_ADAPTER_VERSION = "1.0.0" as const;
export const CODEX_HARNESS_SCHEMA_VERSION = "1.0.0" as const;
export const MAX_HARNESS_CONFIG_BYTES = 1_000_000;
export const MAX_HARNESS_FACTS = 10_000;
export const MAX_HARNESS_REPORT_BYTES = 10_000_000;

export type CodexHarnessLayerKind = "project-config" | "requirements" | "user-config";
export type CodexHarnessEvidenceLayer = CodexHarnessLayerKind | "invocation";
export type CodexHarnessApplicability = "applied" | "constraints" | "ignored" | "unknown";

export interface CodexHarnessEvidence {
  readonly key: string;
  readonly layer: CodexHarnessEvidenceLayer;
}

export interface CodexHarnessLayer {
  readonly applicability: CodexHarnessApplicability;
  readonly bytes?: number;
  readonly kind: CodexHarnessLayerKind;
  readonly label: string;
  readonly pathSource: "detected" | "disabled" | "user-supplied";
  readonly sha256?: string;
  readonly status: "absent" | "invalid" | "parsed" | "unsafe";
}

export interface CodexHarnessDiagnostic {
  readonly code:
    | "HARNESS_CONFIG_CHANGED"
    | "HARNESS_CONFIG_INVALID"
    | "HARNESS_CONFIG_MISSING"
    | "HARNESS_CONFIG_SIZE_LIMIT"
    | "HARNESS_CONFIG_UNSAFE"
    | "HARNESS_NORMALIZATION_LIMIT";
  readonly layer?: CodexHarnessLayerKind;
  readonly message: string;
  readonly type: "error";
}

export interface CodexDeclaredValue<T> {
  readonly evidence: CodexHarnessEvidence;
  readonly state: "declared";
  readonly value: T;
}

export interface CodexUnavailableValue {
  readonly reason: string;
  readonly state: "unavailable";
}

export type CodexInventoryValue<T> = CodexDeclaredValue<T> | CodexUnavailableValue;

export interface CodexSkillInventory {
  readonly applicability: CodexHarnessApplicability;
  readonly enabled: CodexInventoryValue<boolean>;
  readonly path: string;
  readonly pathSha256: string;
  readonly source: CodexHarnessEvidence;
}

export interface CodexToolInventory {
  readonly approvalMode: CodexInventoryValue<string>;
  readonly enabled: CodexInventoryValue<boolean>;
  readonly name: string;
}

export interface CodexAppInventory {
  readonly applicability: CodexHarnessApplicability;
  readonly approvalsReviewer: CodexInventoryValue<string>;
  readonly defaultToolsApprovalMode: CodexInventoryValue<string>;
  readonly defaultToolsEnabled: CodexInventoryValue<boolean>;
  readonly destructiveEnabled: CodexInventoryValue<boolean>;
  readonly enabled: CodexInventoryValue<boolean>;
  readonly id: string;
  readonly openWorldEnabled: CodexInventoryValue<boolean>;
  readonly source: CodexHarnessEvidence;
  readonly tools: readonly CodexToolInventory[];
}

export interface CodexMcpIdentityStdio {
  readonly argumentCount: number;
  readonly argumentIdentitySha256: string;
  readonly commandIdentitySha256: string;
  readonly executable: string;
  readonly kind: "stdio";
}

export interface CodexCommandIdentity {
  readonly commandIdentitySha256: string;
  readonly executable: string;
}

export interface CodexMcpIdentityHttp {
  readonly credentialsPresent: boolean;
  readonly kind: "http";
  readonly queryParameterNames: readonly string[];
  readonly url: string;
  readonly urlIdentitySha256: string;
}

export interface CodexMcpIdentityUnavailable {
  readonly reason: string;
  readonly kind: "unavailable";
}

export type CodexMcpIdentity =
  | CodexMcpIdentityHttp
  | CodexMcpIdentityStdio
  | CodexMcpIdentityUnavailable;

export interface CodexMcpServerInventory {
  readonly applicability: CodexHarnessApplicability;
  readonly defaultToolsApprovalMode: CodexInventoryValue<string>;
  readonly disabledTools: readonly string[];
  readonly enabled: CodexInventoryValue<boolean>;
  readonly enabledTools: readonly string[];
  readonly enabledToolsAllowlistPresent: boolean;
  readonly environmentNames: readonly string[];
  readonly headerNames: readonly string[];
  readonly httpHeadersHelper: CodexInventoryValue<CodexCommandIdentity>;
  readonly id: string;
  readonly identity: CodexMcpIdentity;
  readonly oauthScopes: readonly string[];
  readonly plugin?: string;
  readonly required: CodexInventoryValue<boolean>;
  readonly executionEnvironment: CodexInventoryValue<string>;
  readonly source: CodexHarnessEvidence;
  readonly tools: readonly CodexToolInventory[];
}

export interface CodexHookInventory {
  readonly applicability: CodexHarnessApplicability;
  readonly asynchronous: CodexInventoryValue<boolean>;
  readonly event: string;
  readonly handler: string;
  readonly handlerIdentitySha256: string;
  readonly handlerIndex: number;
  readonly matcherIdentitySha256: string;
  readonly matcherPresent: boolean;
  readonly source: CodexHarnessEvidence;
  readonly type: string;
}

export interface CodexPluginInventory {
  readonly applicability: CodexHarnessApplicability;
  readonly id: string;
  readonly mcpServerIds: readonly string[];
  readonly source: CodexHarnessEvidence;
}

export interface CodexHarnessInventory {
  readonly apps: readonly CodexAppInventory[];
  readonly hooks: readonly CodexHookInventory[];
  readonly mcpServers: readonly CodexMcpServerInventory[];
  readonly plugins: readonly CodexPluginInventory[];
  readonly skills: readonly CodexSkillInventory[];
}

export interface CodexHarnessCoverage {
  readonly area:
    | "cloud-requirements"
    | "codex-version"
    | "effective-runtime-state"
    | "profile-and-session-overrides"
    | "project-config"
    | "runtime-defaults"
    | "runtime-discovered-artifacts"
    | "system-requirements"
    | "user-config";
  readonly reason: string;
  readonly state: "ignored" | "partial" | "resolved" | "unavailable";
}

export interface CodexSemanticFact {
  readonly effect: "exposure" | "guard" | "identity" | "posture";
  readonly evidence: readonly CodexHarnessEvidence[];
  readonly key: string;
  readonly rank?: number;
  readonly value: boolean | number | string;
}

export interface CodexHarnessSnapshot {
  readonly capture: {
    readonly complete: boolean;
    readonly inputSha256: string;
  };
  readonly codexVersion: CodexInventoryValue<string>;
  readonly coverage: readonly CodexHarnessCoverage[];
  readonly diagnostics: readonly CodexHarnessDiagnostic[];
  readonly documentType: "uleravo.harness-snapshot";
  readonly harness: {
    readonly adapter: {
      readonly name: "openai-codex-local";
      readonly version: typeof CODEX_HARNESS_ADAPTER_VERSION;
    };
    readonly analyzer: {
      readonly name: string;
      readonly version: string;
    };
    readonly id: string;
  };
  readonly inventory: CodexHarnessInventory;
  readonly layers: readonly CodexHarnessLayer[];
  readonly project: {
    readonly configApplicability: "applied" | "ignored" | "not-present" | "unknown";
    readonly trust: CodexInventoryValue<"trusted" | "untrusted">;
  };
  readonly schemaVersion: typeof CODEX_HARNESS_SCHEMA_VERSION;
  readonly semanticFacts: readonly CodexSemanticFact[];
}

export interface CodexHarnessSnapshotOptions {
  /** Explicitly binds this snapshot to a caller-observed Codex version. Uleravo never runs Codex. */
  readonly codexVersion?: string;
  /** `null` disables this layer; omission detects `<project>/.codex/config.toml`. */
  readonly projectConfig?: string | null;
  /** `null` disables this layer; omission detects the platform system requirements path. */
  readonly requirements?: string | null;
  /** `null` disables this layer; omission detects `$CODEX_HOME/config.toml` or `~/.codex/config.toml`. */
  readonly userConfig?: string | null;
  readonly maxConfigBytes?: number;
}

export type CodexPermissionChangeDirection = "changed" | "expanded" | "reduced";

export interface CodexPermissionChange {
  readonly after?: CodexSemanticFact;
  readonly before?: CodexSemanticFact;
  readonly direction: CodexPermissionChangeDirection;
  readonly key: string;
}

export interface CodexHarnessDelta {
  readonly baseline: {
    readonly harnessId: string;
    readonly inputSha256: string;
  };
  readonly changes: readonly CodexPermissionChange[];
  readonly current: {
    readonly harnessId: string;
    readonly inputSha256: string;
  };
  readonly documentType: "uleravo.harness-delta";
  readonly schemaVersion: "1.0.0";
  readonly summary: {
    readonly changed: number;
    readonly expanded: number;
    readonly reduced: number;
  };
}
