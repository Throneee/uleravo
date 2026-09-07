import { createHash } from "node:crypto";
import path from "node:path";
import { resolveSkillRoot } from "../artifacts/discovery.js";
import { snapshotSkillWithRoot } from "../artifacts/snapshot.js";
import {
  freezeCodexHarnessResolution,
  snapshotCodexHarnessWithResolution,
} from "../harnesses/codex.js";
import type { CodexHarnessLayerKind, CodexSkillInventory } from "../harnesses/domain.js";
import {
  captureSafeDirectory,
  hasNonLinkedDirectoryAncestors,
  type SafeDirectorySnapshot,
} from "../safe-directory.js";
import { sameOpenedFileSnapshot } from "../scanner/files.js";
import {
  CAPABILITY_GRAPH_SCHEMA_VERSION,
  type CapabilityGraphDiagnostic,
  MAX_CAPABILITY_GRAPH_REPORT_BYTES,
  SKILL_CORRELATION_ADAPTER_VERSION,
  type SkillCapabilityGraph,
  type SkillCapabilityGraphOptions,
  type SkillDeclarationEnablement,
} from "./domain.js";
import {
  buildCapabilityGraphIdentities,
  capabilityGraphDiagnostic,
  classificationDiagnostics,
  compareCapabilityGraphDiagnostics,
  correlationReason,
  deriveCorrelationState,
  type EdgeCore,
} from "./identity.js";

interface LayerContext {
  readonly base: SafeDirectorySnapshot;
  readonly kind: "project-config" | "user-config";
}

interface SkillAddressPair {
  readonly manifest: string;
  readonly root: string;
}

interface FrozenRequestedSkillAddresses {
  readonly asManifest: SkillAddressPair;
  readonly asRoot: SkillAddressPair;
  readonly target: string;
}

interface DeclarationPathPolicy {
  readonly canonicalProjectRoot: string;
  readonly selectedSkillAddresses: readonly string[];
}

interface MatchedDeclaration {
  readonly applicability: Exclude<CodexSkillInventory["applicability"], "constraints">;
  readonly enablement: SkillDeclarationEnablement;
  identity: "exact-content" | "mismatch";
  readonly layer: "project-config" | "user-config";
}

interface ResolvedDeclaration {
  readonly contextRoot: string;
  readonly declaration: CodexSkillInventory;
  readonly layer: "project-config" | "user-config";
  readonly root: string;
  readonly rootSnapshot: SafeDirectorySnapshot;
}

/**
 * Correlates exact local Skill bytes to declarations in one bounded Codex harness capture.
 * This reads configuration and artifact files as inert data. It does not claim runtime
 * reachability, effect authority, successful initialization, or complete runtime discovery.
 */
export async function captureSkillCapabilityGraph(
  requestedSkill: string,
  requestedProject: string,
  options: SkillCapabilityGraphOptions = {},
): Promise<SkillCapabilityGraph> {
  return (await captureSkillCapabilityGraphWithRoot(requestedSkill, requestedProject, options))
    .graph;
}

export async function captureSkillCapabilityGraphWithRoot(
  requestedSkill: string,
  requestedProject: string,
  options: SkillCapabilityGraphOptions = {},
): Promise<{ readonly graph: SkillCapabilityGraph; readonly root: string }> {
  const workingDirectory = process.cwd();
  const artifactOptions = {
    ...(options.maxSkillFileBytes === undefined ? {} : { maxFileBytes: options.maxSkillFileBytes }),
    ...(options.maxSkillFiles === undefined ? {} : { maxFiles: options.maxSkillFiles }),
    ...(options.maxSkillTotalBytes === undefined
      ? {}
      : { maxTotalBytes: options.maxSkillTotalBytes }),
  };
  const harnessOptions = {
    ...(options.codexVersion === undefined ? {} : { codexVersion: options.codexVersion }),
    ...(options.maxConfigBytes === undefined ? {} : { maxConfigBytes: options.maxConfigBytes }),
    ...(options.projectConfig === undefined ? {} : { projectConfig: options.projectConfig }),
    ...(options.requirements === undefined ? {} : { requirements: options.requirements }),
    ...(options.userConfig === undefined ? {} : { userConfig: options.userConfig }),
  };
  if (isUnsafeConfiguredSkillPath(requestedSkill)) {
    throw new Error("Capability graph Skill target must use a supported local filesystem path.");
  }
  const requestedSkillRoot = path.resolve(workingDirectory, requestedSkill);
  const requestedSkillAddresses = freezeRequestedSkillAddresses(requestedSkillRoot);
  const harnessResolution = freezeCodexHarnessResolution(
    requestedProject,
    harnessOptions,
    workingDirectory,
  );

  let skillCapture: Awaited<ReturnType<typeof snapshotSkillWithRoot>>;
  try {
    skillCapture = await snapshotSkillWithRoot(requestedSkillRoot, artifactOptions);
  } catch {
    throw new Error("Capability graph could not safely capture the supplied Skill root.");
  }
  const content = skillCapture.snapshot.artifact.identity.contentSha256;
  if (!skillCapture.snapshot.complete || !("value" in content)) {
    throw new Error("Capability graph requires a complete exact Skill byte identity.");
  }
  const skillRootBefore = await captureSafeDirectory(skillCapture.root);
  if (skillRootBefore === undefined) {
    throw new Error("Capability graph requires stable, non-linked Skill and project roots.");
  }
  const requestedSkillAlias = await selectRequestedSkillAddresses(
    requestedSkillAddresses,
    skillRootBefore,
  );
  const projectBefore = await captureSafeDirectory(harnessResolution.requestedProjectRoot);
  if (requestedSkillAlias === undefined || projectBefore === undefined) {
    throw new Error("Capability graph requires stable, non-linked Skill and project roots.");
  }
  const declarationPathPolicy = freezeDeclarationPathPolicy(
    projectBefore.canonicalPath,
    skillCapture.root,
    requestedSkillAlias,
  );

  let harness: Awaited<ReturnType<typeof snapshotCodexHarnessWithResolution>>;
  try {
    harness = await snapshotCodexHarnessWithResolution(harnessResolution);
  } catch {
    throw new Error("Capability graph could not safely capture the Codex harness evidence.");
  }

  const diagnostics: CapabilityGraphDiagnostic[] = [];
  if (!harness.capture.complete) {
    const incompleteDeclarationLayers = new Set(
      harness.diagnostics.flatMap((diagnostic) =>
        diagnostic.layer === "project-config" || diagnostic.layer === "user-config"
          ? [diagnostic.layer]
          : [],
      ),
    );
    if (incompleteDeclarationLayers.size === 0) {
      diagnostics.push(capabilityGraphDiagnostic("HARNESS_CAPTURE_INCOMPLETE"));
    } else {
      for (const layer of incompleteDeclarationLayers) {
        diagnostics.push(capabilityGraphDiagnostic("HARNESS_CAPTURE_INCOMPLETE", layer));
      }
    }
  }
  for (const layer of harness.layers) {
    if (
      (layer.kind === "user-config" || layer.kind === "project-config") &&
      layer.pathSource === "disabled"
    ) {
      diagnostics.push(capabilityGraphDiagnostic("DECLARATION_LAYER_DISABLED", layer.kind));
    }
  }

  const contexts = await captureLayerContexts(
    harness.layers.map((layer) => ({ kind: layer.kind, status: layer.status })),
    projectBefore,
    harnessResolution.userConfig.path,
    diagnostics,
  );
  const matches: MatchedDeclaration[] = [];
  const resolvedDeclarations: ResolvedDeclaration[] = [];
  if (harness.capture.complete) {
    for (const declaration of harness.inventory.skills) {
      const layer = declaration.source.layer;
      if (layer === "requirements" || layer === "invocation") continue;
      const context = contexts.get(layer);
      if (context === undefined) {
        diagnostics.push(capabilityGraphDiagnostic("DECLARATION_CONTEXT_UNAVAILABLE", layer));
        continue;
      }
      const resolved = await resolveDeclaredSkill(
        declaration,
        context.base.canonicalPath,
        declarationPathPolicy,
      );
      if (resolved === undefined) {
        diagnostics.push(capabilityGraphDiagnostic("DECLARATION_PATH_UNSAFE", layer));
        continue;
      }
      resolvedDeclarations.push({
        contextRoot: context.base.canonicalPath,
        declaration,
        layer,
        root: resolved.root,
        rootSnapshot: resolved.rootSnapshot,
      });
      if (samePath(resolved.root, skillCapture.root)) {
        if (declaration.applicability === "constraints") {
          diagnostics.push(capabilityGraphDiagnostic("DECLARATION_APPLICABILITY_UNKNOWN", layer));
          continue;
        }
        matches.push({
          applicability: declaration.applicability,
          enablement: declarationEnablement(declaration),
          identity: sameDirectorySnapshot(resolved.rootSnapshot, skillRootBefore)
            ? "exact-content"
            : "mismatch",
          layer,
        });
      }
    }
  }

  const skillStable = await skillCaptureStillMatches(
    skillCapture.root,
    skillRootBefore,
    content.value,
    artifactOptions,
  );
  if (!skillStable) {
    if (matches.length === 0) {
      diagnostics.push(capabilityGraphDiagnostic("SKILL_CAPTURE_CHANGED"));
    } else {
      for (const match of matches) match.identity = "mismatch";
      diagnostics.push(capabilityGraphDiagnostic("DECLARATION_IDENTITY_MISMATCH"));
    }
  }

  await addChangedContextDiagnostics(contexts, diagnostics);
  await addChangedDeclarationDiagnostics(resolvedDeclarations, declarationPathPolicy, diagnostics);
  const projectAfter = await captureSafeDirectory(projectBefore.canonicalPath);
  if (projectAfter === undefined || !sameDirectorySnapshot(projectBefore, projectAfter)) {
    diagnostics.push(capabilityGraphDiagnostic("DECLARATION_CONTEXT_CHANGED", "project-config"));
  }

  try {
    const harnessAfter = await snapshotCodexHarnessWithResolution(harnessResolution);
    if (
      harnessAfter.harness.id !== harness.harness.id ||
      harnessAfter.capture.inputSha256 !== harness.capture.inputSha256
    ) {
      diagnostics.push(capabilityGraphDiagnostic("HARNESS_CAPTURE_CHANGED"));
    }
  } catch {
    diagnostics.push(capabilityGraphDiagnostic("HARNESS_CAPTURE_CHANGED"));
  }

  const edgeCores = groupMatches(matches);
  diagnostics.push(...classificationDiagnostics(edgeCores));
  const canonicalDiagnostics = deduplicateDiagnostics(diagnostics);
  const state = deriveCorrelationState(edgeCores, canonicalDiagnostics);
  const inputs: SkillCapabilityGraph["inputs"] = {
    harness: {
      adapter: harness.harness.adapter,
      analyzerVersion: harness.harness.analyzer.version,
      inputSha256: harness.capture.inputSha256,
      schemaVersion: harness.schemaVersion,
      snapshotId: harness.harness.id,
    },
    skill: {
      adapter: skillCapture.snapshot.artifact.adapter,
      analyzerVersion: skillCapture.snapshot.snapshot.analyzer.version,
      contentSha256: content.value,
      schemaVersion: skillCapture.snapshot.schemaVersion,
      snapshotId: skillCapture.snapshot.snapshot.id,
    },
  };
  const identities = buildCapabilityGraphIdentities({
    diagnostics: canonicalDiagnostics,
    edges: edgeCores,
    inputs,
    state,
  });
  const graph: SkillCapabilityGraph = {
    adapter: {
      name: "openai-skill-codex-correlation",
      version: SKILL_CORRELATION_ADAPTER_VERSION,
    },
    complete: state !== "unknown",
    correlation: { id: identities.correlationId, reason: correlationReason(state), state },
    diagnostics: canonicalDiagnostics,
    documentType: "uleravo.skill-capability-graph",
    edges: identities.edges,
    graph: { id: identities.graphId },
    inputs,
    nodes: identities.nodes,
    schemaVersion: CAPABILITY_GRAPH_SCHEMA_VERSION,
    scope: {
      assertion: "declared-exposure-only",
      effectAuthority: "not-established",
      runtimeReachability: "not-observed",
    },
  };
  if (
    Buffer.byteLength(`${JSON.stringify(graph, null, 2)}\n`, "utf8") >
    MAX_CAPABILITY_GRAPH_REPORT_BYTES
  ) {
    throw new Error("Capability graph exceeds the bounded report size.");
  }
  return { graph, root: skillCapture.root };
}

async function captureLayerContexts(
  layers: readonly { readonly kind: CodexHarnessLayerKind; readonly status: string }[],
  project: SafeDirectorySnapshot,
  userConfigPath: string | undefined,
  diagnostics: CapabilityGraphDiagnostic[],
): Promise<Map<"project-config" | "user-config", LayerContext>> {
  const contexts = new Map<"project-config" | "user-config", LayerContext>();
  for (const layer of layers) {
    if (layer.status !== "parsed" || layer.kind === "requirements") continue;
    if (layer.kind === "project-config") {
      contexts.set(layer.kind, { base: project, kind: layer.kind });
      continue;
    }
    if (userConfigPath === undefined) {
      diagnostics.push(capabilityGraphDiagnostic("DECLARATION_CONTEXT_UNAVAILABLE", layer.kind));
      continue;
    }
    const basePath = path.dirname(userConfigPath);
    const base = await captureSafeDirectory(basePath);
    if (base === undefined) {
      diagnostics.push(capabilityGraphDiagnostic("DECLARATION_CONTEXT_UNAVAILABLE", layer.kind));
    } else {
      contexts.set(layer.kind, { base, kind: layer.kind });
    }
  }
  return contexts;
}

async function resolveDeclaredSkill(
  declaration: CodexSkillInventory,
  contextRoot: string,
  pathPolicy: DeclarationPathPolicy,
): Promise<{ readonly root: string; readonly rootSnapshot: SafeDirectorySnapshot } | undefined> {
  if (
    declaration.pathSha256 !== sha256(declaration.path) ||
    isUnsafeConfiguredSkillPath(declaration.path)
  ) {
    return undefined;
  }
  const absolute = path.isAbsolute(declaration.path);
  const candidate = absolute
    ? path.resolve(declaration.path)
    : path.resolve(contextRoot, declaration.path);
  if (!absolute && !isWithin(contextRoot, candidate)) return undefined;
  if (
    declaration.source.layer === "project-config" &&
    absolute &&
    !isWithin(pathPolicy.canonicalProjectRoot, candidate) &&
    !pathPolicy.selectedSkillAddresses.some((address) => samePath(address, candidate))
  ) {
    return undefined;
  }

  // All project-controlled path authorization above is path-only. No declaration
  // may reach filesystem discovery before that decision is complete.
  // Check ancestors before the root resolver inspects either a directory or manifest
  // leaf. Both initial resolution and lifecycle recapture use this same boundary.
  if (!(await hasNonLinkedDirectoryAncestors(candidate))) return undefined;
  try {
    const root = await resolveSkillRoot(candidate);
    const rootSnapshot = await captureSafeDirectory(root);
    return rootSnapshot === undefined ? undefined : { root, rootSnapshot };
  } catch {
    return undefined;
  }
}

async function addChangedDeclarationDiagnostics(
  declarations: readonly ResolvedDeclaration[],
  pathPolicy: DeclarationPathPolicy,
  diagnostics: CapabilityGraphDiagnostic[],
): Promise<void> {
  for (const captured of declarations) {
    const current = await resolveDeclaredSkill(
      captured.declaration,
      captured.contextRoot,
      pathPolicy,
    );
    if (
      current === undefined ||
      !samePath(captured.root, current.root) ||
      !sameDirectorySnapshot(captured.rootSnapshot, current.rootSnapshot)
    ) {
      diagnostics.push(capabilityGraphDiagnostic("DECLARATION_CONTEXT_CHANGED", captured.layer));
    }
  }
}

function freezeRequestedSkillAddresses(requestedTarget: string): FrozenRequestedSkillAddresses {
  const target = path.resolve(requestedTarget);
  return Object.freeze({
    asManifest: freezeSkillAddressPair(path.dirname(target), target),
    asRoot: freezeSkillAddressPair(target, path.join(target, "SKILL.md")),
    target,
  });
}

async function selectRequestedSkillAddresses(
  requested: FrozenRequestedSkillAddresses,
  canonicalRoot: SafeDirectorySnapshot,
): Promise<SkillAddressPair | undefined> {
  const requestedAsDirectory = await captureSafeDirectory(requested.target);
  if (
    requestedAsDirectory !== undefined &&
    sameDirectorySnapshot(requestedAsDirectory, canonicalRoot)
  ) {
    return requested.asRoot;
  }
  if (path.basename(requested.target) !== "SKILL.md") return undefined;

  const requestedParent = await captureSafeDirectory(requested.asManifest.root);
  return requestedParent !== undefined && sameDirectorySnapshot(requestedParent, canonicalRoot)
    ? requested.asManifest
    : undefined;
}

function freezeDeclarationPathPolicy(
  canonicalProjectRoot: string,
  canonicalSkillRoot: string,
  requestedSkill: SkillAddressPair,
): DeclarationPathPolicy {
  const canonicalSkill = freezeSkillAddressPair(
    canonicalSkillRoot,
    path.join(canonicalSkillRoot, "SKILL.md"),
  );
  return Object.freeze({
    canonicalProjectRoot,
    selectedSkillAddresses: Object.freeze([
      canonicalSkill.root,
      canonicalSkill.manifest,
      requestedSkill.root,
      requestedSkill.manifest,
    ]),
  });
}

function freezeSkillAddressPair(root: string, manifest: string): SkillAddressPair {
  return Object.freeze({ manifest: path.resolve(manifest), root: path.resolve(root) });
}

export function isUnsafeConfiguredSkillPath(value: string, platform = process.platform): boolean {
  return (
    value.length === 0 ||
    value.includes("\0") ||
    /^[\\/]{2}/u.test(value) ||
    (platform === "win32" && /^[\\/]/u.test(value)) ||
    (/^[A-Za-z]:/u.test(value) && !/^[A-Za-z]:[\\/]/u.test(value)) ||
    /^[A-Za-z][A-Za-z0-9+.-]*:\/\//u.test(value) ||
    /(^|[\\/])~(?:[\\/]|$)/u.test(value) ||
    /(^|[\\/])\.\.(?:[\\/]|$)/u.test(value) ||
    /\$\{|\$[A-Za-z_]|%[^%]+%/u.test(value)
  );
}

function declarationEnablement(declaration: CodexSkillInventory): SkillDeclarationEnablement {
  if (declaration.enabled.state === "unavailable") return "unspecified";
  return declaration.enabled.value ? "enabled" : "disabled";
}

async function skillCaptureStillMatches(
  root: string,
  before: SafeDirectorySnapshot,
  contentSha256: string,
  artifactOptions: Parameters<typeof snapshotSkillWithRoot>[1],
): Promise<boolean> {
  try {
    const second = await snapshotSkillWithRoot(root, artifactOptions);
    const identity = second.snapshot.artifact.identity.contentSha256;
    const after = await captureSafeDirectory(root);
    return (
      second.snapshot.complete &&
      "value" in identity &&
      identity.value === contentSha256 &&
      after !== undefined &&
      sameDirectorySnapshot(before, after)
    );
  } catch {
    return false;
  }
}

async function addChangedContextDiagnostics(
  contexts: ReadonlyMap<"project-config" | "user-config", LayerContext>,
  diagnostics: CapabilityGraphDiagnostic[],
): Promise<void> {
  for (const context of contexts.values()) {
    const current = await captureSafeDirectory(context.base.canonicalPath);
    if (current === undefined || !sameDirectorySnapshot(context.base, current)) {
      diagnostics.push(capabilityGraphDiagnostic("DECLARATION_CONTEXT_CHANGED", context.kind));
    }
  }
}

function sameDirectorySnapshot(left: SafeDirectorySnapshot, right: SafeDirectorySnapshot): boolean {
  return (
    samePath(left.canonicalPath, right.canonicalPath) &&
    sameOpenedFileSnapshot(left.metadata, right.metadata)
  );
}

function groupMatches(matches: readonly MatchedDeclaration[]): EdgeCore[] {
  const grouped = new Map<string, EdgeCore>();
  for (const match of matches) {
    const key = [match.layer, match.applicability, match.enablement, match.identity].join("\0");
    const current = grouped.get(key);
    grouped.set(key, {
      applicability: match.applicability,
      count: (current?.count ?? 0) + 1,
      enablement: match.enablement,
      identity: match.identity,
      kind: "declares-skill",
      layer: match.layer,
    });
  }
  return [...grouped.values()];
}

function deduplicateDiagnostics(
  diagnostics: readonly CapabilityGraphDiagnostic[],
): CapabilityGraphDiagnostic[] {
  const sorted = [...diagnostics].sort(compareCapabilityGraphDiagnostics);
  return sorted.filter(
    (entry, index) =>
      index === 0 ||
      compareCapabilityGraphDiagnostics(entry, sorted[index - 1] as CapabilityGraphDiagnostic) !==
        0,
  );
}

function samePath(left: string, right: string): boolean {
  return normalizedPath(left) === normalizedPath(right);
}

function isWithin(root: string, candidate: string): boolean {
  const relative = path.relative(normalizedPath(root), normalizedPath(candidate));
  return (
    relative.length === 0 ||
    (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
  );
}

function normalizedPath(value: string): string {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLocaleLowerCase("en-US") : resolved;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
