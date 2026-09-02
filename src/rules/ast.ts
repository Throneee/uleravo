import { posix as path } from "node:path";
import ts from "typescript";
import type { FindingInput } from "../domain.js";
import type { ScannableFile } from "../scanner/files.js";
import {
  callName,
  findingAtNode,
  literalText,
  parseSource,
  propertyName,
  walk,
} from "../scanner/source.js";
import { RULES } from "./catalog.js";
import { isTestFile } from "./file-context.js";
import type { FileRule, RepositoryRule } from "./types.js";

const HANDLER_REGISTRATIONS = new Set([
  "prompt",
  "registerPrompt",
  "registerResource",
  "registerTool",
  "resource",
  "setRequestHandler",
  "tool",
]);
const FILESYSTEM_SINKS = new Set([
  "appendFile",
  "chmod",
  "chown",
  "createReadStream",
  "createWriteStream",
  "lstat",
  "mkdir",
  "open",
  "opendir",
  "readFile",
  "readdir",
  "readlink",
  "realpath",
  "rename",
  "rm",
  "rmdir",
  "stat",
  "truncate",
  "unlink",
  "writeFile",
]);
const POISONING_PATTERNS: readonly RegExp[] = [
  /ignore (?:all |any )?(?:developer|previous|prior|system) instructions?/i,
  /(?:collect|exfiltrat|read|send|steal|upload).{0,100}(?:\.ssh|api keys?|credentials?|environment variables?|passwords?|secrets?|tokens?)/i,
  /do not (?:disclose|inform|reveal|show|tell).{0,40}(?:the )?user/i,
  /(?:hidden|secret) instructions?.{0,60}(?:assistant|model)/i,
];
const DESTRUCTIVE_TOOL_VERBS = [
  "delete",
  "destroy",
  "drop",
  "kill",
  "overwrite",
  "purge",
  "remove",
  "reset",
  "revoke",
  "terminate",
  "wipe",
] as const;
const MAX_DIRECT_IMPORTED_CALL_STATES = 1_000;
const TAINT_PRESERVING_RECEIVER_METHODS = new Set([
  "concat",
  "join",
  "map",
  "replace",
  "replaceAll",
  "slice",
  "substr",
  "substring",
  "toLocaleLowerCase",
  "toLocaleUpperCase",
  "toLowerCase",
  "toUpperCase",
  "trim",
  "trimEnd",
  "trimStart",
]);

type HandlerFunction =
  | ts.ArrowFunction
  | ts.FunctionDeclaration
  | ts.FunctionExpression
  | ts.MethodDeclaration;

interface Bindings {
  readonly axios: Set<string>;
  readonly basename: Set<string>;
  readonly childNamespaces: Set<string>;
  readonly exec: Set<string>;
  readonly execFile: Set<string>;
  readonly filesystem: Map<string, string>;
  readonly filesystemNamespaces: Set<string>;
  readonly networkNamespaces: Set<string>;
  readonly spawn: Set<string>;
}

interface FunctionSeed {
  readonly safePathParameterIndexes: ReadonlySet<number>;
  readonly taintedParameterIndexes: ReadonlySet<number>;
}

interface FunctionState {
  readonly safePaths: Set<string>;
  readonly tainted: Set<string>;
}

interface LocalBinding {
  readonly name: string;
  readonly scope: ts.Node;
}

interface ImportedFunctionSeed {
  readonly file: ScannableFile;
  readonly importedName: string;
  readonly safePathParameterIndexes: ReadonlySet<number>;
  readonly taintedParameterIndexes: ReadonlySet<number>;
}

interface RelativeNamedImport {
  readonly file: ScannableFile;
  readonly importedName: string;
}

export const astSecurityRule: FileRule = {
  metadata: RULES.commandInjection,
  scan({ file }): readonly FindingInput[] {
    if (file.kind !== "source" || isTestFile(file.relativePath)) {
      return [];
    }

    const sourceFile = parseSource(file);
    const bindings = collectBindings(sourceFile);
    const handlers = collectHandlers(sourceFile);
    const findings: FindingInput[] = [];

    for (const handler of handlers) {
      findings.push(...scanHandler(file, sourceFile, handler, bindings));
    }
    findings.push(...scanEnvironmentPassthrough(file, sourceFile, bindings));
    return deduplicate(findings);
  },
};

export const astImportSecurityRule: RepositoryRule = {
  metadata: RULES.commandInjection,
  scanRepository({ files }): readonly FindingInput[] {
    const sourceFiles = new Map(
      files
        .filter((file) => file.kind === "source" && !isTestFile(file.relativePath))
        .map((file) => [file.relativePath, file] as const),
    );
    const parsedFiles = new Map<string, ts.SourceFile>();
    const importedFunctions = new Map<string, ImportedFunctionSeed>();

    for (const file of sourceFiles.values()) {
      const sourceFile = cachedSourceFile(file, parsedFiles);
      const imports = collectRelativeNamedImports(file, sourceFile, sourceFiles);
      if (imports.size === 0) {
        continue;
      }
      const bindings = collectBindings(sourceFile);
      for (const handler of collectHandlers(sourceFile)) {
        collectImportedFunctionSeeds(handler, bindings, imports, importedFunctions);
      }
    }

    const findings: FindingInput[] = [];
    for (const seed of importedFunctions.values()) {
      const sourceFile = cachedSourceFile(seed.file, parsedFiles);
      const target = findExportedFunction(sourceFile, seed.importedName);
      if (target === undefined) {
        continue;
      }
      findings.push(
        ...scanFunction(seed.file, sourceFile, target, collectBindings(sourceFile), {
          safePathParameterIndexes: seed.safePathParameterIndexes,
          taintedParameterIndexes: seed.taintedParameterIndexes,
        }),
      );
    }
    return deduplicate(findings);
  },
};

export const toolMetadataRule: FileRule = {
  metadata: RULES.poisonedDescription,
  scan({ file }): readonly FindingInput[] {
    if (file.kind !== "source" || isTestFile(file.relativePath)) {
      return [];
    }

    const sourceFile = parseSource(file);
    const findings: FindingInput[] = [];
    walk(sourceFile, (node) => {
      if (!ts.isCallExpression(node)) {
        return;
      }
      const registration = callName(node.expression);
      if (registration !== "tool" && registration !== "registerTool") {
        return;
      }

      const toolName = literalText(node.arguments[0]);
      const description = findDescription(node.arguments.slice(1, 3));
      if (
        description !== undefined &&
        POISONING_PATTERNS.some((pattern) => pattern.test(description.text))
      ) {
        findings.push(
          findingAtNode(
            file,
            sourceFile,
            description.node,
            RULES.poisonedDescription,
            `Tool ${toolName ?? "<unknown>"} contains instructions that can redirect model behavior or solicit secrets.`,
          ),
        );
      }

      if (
        toolName !== undefined &&
        isDestructiveToolName(toolName) &&
        !hasDestructiveAnnotation(node.arguments.slice(1, 3))
      ) {
        findings.push(
          findingAtNode(
            file,
            sourceFile,
            node,
            RULES.destructiveAnnotation,
            `Tool ${toolName} appears destructive but does not declare annotations.destructiveHint=true.`,
          ),
        );
      }
    });
    return findings;
  },
};

function collectBindings(sourceFile: ts.SourceFile): Bindings {
  const bindings: Bindings = {
    axios: new Set(),
    basename: new Set(),
    childNamespaces: new Set(),
    exec: new Set(),
    execFile: new Set(),
    filesystem: new Map(),
    filesystemNamespaces: new Set(),
    networkNamespaces: new Set(),
    spawn: new Set(),
  };

  for (const statement of sourceFile.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier)) {
      collectImport(statement, normalizeModule(statement.moduleSpecifier.text), bindings);
    }
    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        collectRequire(declaration, bindings);
      }
    }
  }

  let changed = true;
  while (changed) {
    changed = false;
    walk(sourceFile, (node) => {
      if (
        !ts.isVariableDeclaration(node) ||
        !ts.isIdentifier(node.name) ||
        node.initializer === undefined ||
        !ts.isCallExpression(node.initializer)
      ) {
        return;
      }
      const firstArgument = node.initializer.arguments[0];
      if (
        firstArgument !== undefined &&
        ts.isIdentifier(firstArgument) &&
        bindings.exec.has(firstArgument.text) &&
        !bindings.exec.has(node.name.text)
      ) {
        bindings.exec.add(node.name.text);
        changed = true;
      }
    });
  }
  return bindings;
}

function collectImport(
  declaration: ts.ImportDeclaration,
  moduleName: string,
  bindings: Bindings,
): void {
  const clause = declaration.importClause;
  if (clause === undefined) {
    return;
  }

  if (moduleName === "axios" && clause.name !== undefined) {
    bindings.axios.add(clause.name.text);
  }
  const namedBindings = clause.namedBindings;
  if (namedBindings === undefined) {
    return;
  }
  if (ts.isNamespaceImport(namedBindings)) {
    addNamespaceBinding(moduleName, namedBindings.name.text, bindings);
    return;
  }
  for (const element of namedBindings.elements) {
    addNamedBinding(
      moduleName,
      element.propertyName?.text ?? element.name.text,
      element.name.text,
      bindings,
    );
  }
}

function collectRequire(declaration: ts.VariableDeclaration, bindings: Bindings): void {
  const moduleName = requiredModule(declaration.initializer);
  if (moduleName === undefined) {
    return;
  }
  if (ts.isIdentifier(declaration.name)) {
    addNamespaceBinding(moduleName, declaration.name.text, bindings);
    return;
  }
  for (const element of declaration.name.elements) {
    if (ts.isOmittedExpression(element) || !ts.isIdentifier(element.name)) {
      continue;
    }
    addNamedBinding(
      moduleName,
      propertyName(element.propertyName) ?? element.name.text,
      element.name.text,
      bindings,
    );
  }
}

function addNamespaceBinding(moduleName: string, localName: string, bindings: Bindings): void {
  if (moduleName === "child_process") {
    bindings.childNamespaces.add(localName);
  } else if (moduleName === "fs" || moduleName === "fs/promises") {
    bindings.filesystemNamespaces.add(localName);
  } else if (moduleName === "http" || moduleName === "https") {
    bindings.networkNamespaces.add(localName);
  } else if (moduleName === "axios") {
    bindings.axios.add(localName);
  } else if (moduleName === "path") {
    bindings.basename.add(`${localName}.basename`);
  }
}

function addNamedBinding(
  moduleName: string,
  importedName: string,
  localName: string,
  bindings: Bindings,
): void {
  if (moduleName === "child_process") {
    addChildProcessBinding(importedName, localName, bindings);
    return;
  }
  if ((moduleName === "fs" || moduleName === "fs/promises") && FILESYSTEM_SINKS.has(importedName)) {
    bindings.filesystem.set(localName, importedName);
    return;
  }
  if (moduleName === "path" && importedName === "basename") {
    bindings.basename.add(localName);
    return;
  }
  if (
    (moduleName === "http" || moduleName === "https") &&
    (importedName === "get" || importedName === "request")
  ) {
    bindings.networkNamespaces.add(localName);
  }
}

function addChildProcessBinding(importedName: string, localName: string, bindings: Bindings): void {
  if (importedName === "exec" || importedName === "execSync") {
    bindings.exec.add(localName);
  } else if (importedName === "execFile" || importedName === "execFileSync") {
    bindings.execFile.add(localName);
  } else if (importedName === "spawn" || importedName === "spawnSync") {
    bindings.spawn.add(localName);
  }
}

function collectHandlers(sourceFile: ts.SourceFile): readonly HandlerFunction[] {
  const handlers = new Set<HandlerFunction>();
  const namedHandlers = new Set<string>();

  walk(sourceFile, (node) => {
    if (!ts.isCallExpression(node) || !HANDLER_REGISTRATIONS.has(callName(node.expression) ?? "")) {
      return;
    }
    for (const argument of node.arguments) {
      if (ts.isArrowFunction(argument) || ts.isFunctionExpression(argument)) {
        handlers.add(argument);
      } else if (ts.isIdentifier(argument)) {
        namedHandlers.add(argument.text);
      }
    }
  });

  walk(sourceFile, (node) => {
    if (
      (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) &&
      node.name !== undefined &&
      namedHandlers.has(propertyName(node.name) ?? "")
    ) {
      handlers.add(node);
    }
  });
  return [...handlers];
}

function cachedSourceFile(
  file: ScannableFile,
  parsedFiles: Map<string, ts.SourceFile>,
): ts.SourceFile {
  const cached = parsedFiles.get(file.relativePath);
  if (cached !== undefined) {
    return cached;
  }
  const sourceFile = parseSource(file);
  parsedFiles.set(file.relativePath, sourceFile);
  return sourceFile;
}

function collectRelativeNamedImports(
  file: ScannableFile,
  sourceFile: ts.SourceFile,
  sourceFiles: ReadonlyMap<string, ScannableFile>,
): ReadonlyMap<string, RelativeNamedImport> {
  const imports = new Map<string, RelativeNamedImport>();
  const ambiguousLocalNames = new Set<string>();

  for (const statement of sourceFile.statements) {
    const imported = namedRelativeImport(statement, file, sourceFiles);
    if (imported === undefined) {
      continue;
    }
    for (const element of imported.elements) {
      addRelativeNamedImport(element, imported.file, imports, ambiguousLocalNames);
    }
  }
  return imports;
}

function namedRelativeImport(
  statement: ts.Statement,
  origin: ScannableFile,
  sourceFiles: ReadonlyMap<string, ScannableFile>,
): { readonly elements: readonly ts.ImportSpecifier[]; readonly file: ScannableFile } | undefined {
  if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) {
    return undefined;
  }
  const moduleSpecifier = statement.moduleSpecifier.text;
  if (!moduleSpecifier.startsWith("./") && !moduleSpecifier.startsWith("../")) {
    return undefined;
  }
  const clause = statement.importClause;
  if (
    clause === undefined ||
    clause.isTypeOnly ||
    clause.namedBindings === undefined ||
    !ts.isNamedImports(clause.namedBindings)
  ) {
    return undefined;
  }
  const file = resolveRelativeSource(origin, moduleSpecifier, sourceFiles);
  return file === undefined ? undefined : { elements: clause.namedBindings.elements, file };
}

function addRelativeNamedImport(
  element: ts.ImportSpecifier,
  file: ScannableFile,
  imports: Map<string, RelativeNamedImport>,
  ambiguousLocalNames: Set<string>,
): void {
  const localName = element.name.text;
  if (element.isTypeOnly || ambiguousLocalNames.has(localName)) {
    return;
  }
  if (imports.has(localName)) {
    imports.delete(localName);
    ambiguousLocalNames.add(localName);
    return;
  }
  imports.set(localName, {
    file,
    importedName: element.propertyName?.text ?? localName,
  });
}

function resolveRelativeSource(
  file: ScannableFile,
  moduleSpecifier: string,
  sourceFiles: ReadonlyMap<string, ScannableFile>,
): ScannableFile | undefined {
  const unresolved = path.normalize(path.join(path.dirname(file.relativePath), moduleSpecifier));
  if (path.isAbsolute(unresolved) || unresolved === ".." || unresolved.startsWith("../")) {
    return undefined;
  }

  const candidatePaths = new Set<string>([unresolved]);
  const extension = path.extname(unresolved);
  const stem = extension.length === 0 ? unresolved : unresolved.slice(0, -extension.length);
  if (extension === ".js") {
    candidatePaths.add(`${stem}.ts`);
    candidatePaths.add(`${stem}.tsx`);
  } else if (extension === ".jsx") {
    candidatePaths.add(`${stem}.tsx`);
  } else if (extension === ".mjs") {
    candidatePaths.add(`${stem}.mts`);
  } else if (extension === ".cjs") {
    candidatePaths.add(`${stem}.cts`);
  } else if (extension.length === 0) {
    for (const sourceExtension of [".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"]) {
      candidatePaths.add(`${unresolved}${sourceExtension}`);
      candidatePaths.add(`${unresolved}/index${sourceExtension}`);
    }
  }

  const candidates = [...candidatePaths]
    .map((candidate) => sourceFiles.get(candidate))
    .filter((candidate): candidate is ScannableFile => candidate !== undefined);
  return candidates.length === 1 ? candidates[0] : undefined;
}

function collectImportedFunctionSeeds(
  handler: HandlerFunction,
  bindings: Bindings,
  imports: ReadonlyMap<string, RelativeNamedImport>,
  destination: Map<string, ImportedFunctionSeed>,
): void {
  if (handler.body === undefined) {
    return;
  }
  const state = analyzeFunctionState(handler, bindings, {
    safePathParameterIndexes: new Set(),
    taintedParameterIndexes: new Set(handler.parameters.map((_, index) => index)),
  });
  const localBindings = collectHandlerLocalBindings(handler);

  walk(handler.body, (node) => {
    const seed = importedFunctionSeed(node, bindings, imports, localBindings, state);
    if (seed === undefined) {
      return;
    }
    if (!destination.has(seed.key) && destination.size >= MAX_DIRECT_IMPORTED_CALL_STATES) {
      throw new Error(
        `Direct imported-call analysis exceeded ${MAX_DIRECT_IMPORTED_CALL_STATES.toString()} unique call states.`,
      );
    }
    destination.set(seed.key, seed.value);
  });
}

function importedFunctionSeed(
  node: ts.Node,
  bindings: Bindings,
  imports: ReadonlyMap<string, RelativeNamedImport>,
  localBindings: readonly LocalBinding[],
  state: FunctionState,
): { readonly key: string; readonly value: ImportedFunctionSeed } | undefined {
  if (!ts.isCallExpression(node)) {
    return undefined;
  }
  const imported = importedCallTarget(node, imports, localBindings);
  if (imported === undefined) {
    return undefined;
  }
  const indexes = importedParameterIndexes(node, state, bindings);
  if (indexes.tainted.size === 0) {
    return undefined;
  }

  const taintedKey = [...indexes.tainted].sort((left, right) => left - right).join(",");
  const safePathKey = [...indexes.safePaths].sort((left, right) => left - right).join(",");
  return {
    key: `${imported.file.relativePath}\0${imported.importedName}\0t:${taintedKey}\0s:${safePathKey}`,
    value: {
      file: imported.file,
      importedName: imported.importedName,
      safePathParameterIndexes: indexes.safePaths,
      taintedParameterIndexes: indexes.tainted,
    },
  };
}

function importedCallTarget(
  call: ts.CallExpression,
  imports: ReadonlyMap<string, RelativeNamedImport>,
  localBindings: readonly LocalBinding[],
): RelativeNamedImport | undefined {
  if (
    !ts.isIdentifier(call.expression) ||
    isLocallyShadowed(call, call.expression.text, localBindings) ||
    call.arguments.some((argument) => ts.isSpreadElement(argument))
  ) {
    return undefined;
  }
  return imports.get(call.expression.text);
}

function importedParameterIndexes(
  call: ts.CallExpression,
  state: FunctionState,
  bindings: Bindings,
): { readonly safePaths: Set<number>; readonly tainted: Set<number> } {
  const safePaths = new Set<number>();
  const tainted = new Set<number>();
  for (const [index, argument] of call.arguments.entries()) {
    if (isTainted(argument, state.tainted)) {
      tainted.add(index);
    }
    if (isSafePath(argument, state.safePaths, bindings)) {
      safePaths.add(index);
    }
  }
  return { safePaths, tainted };
}

function collectHandlerLocalBindings(handler: HandlerFunction): readonly LocalBinding[] {
  const localBindings: LocalBinding[] = [];
  for (const parameter of handler.parameters) {
    addLocalBindings(parameter.name, handler, localBindings);
  }
  if (handler.body !== undefined) {
    walk(handler.body, (node) => {
      collectNodeLocalBindings(node, handler, localBindings);
    });
  }
  return localBindings;
}

function collectNodeLocalBindings(
  node: ts.Node,
  handler: HandlerFunction,
  destination: LocalBinding[],
): void {
  if (ts.isVariableDeclaration(node)) {
    addVariableLocalBindings(node, handler, destination);
    return;
  }
  if (ts.isParameter(node)) {
    addParameterLocalBindings(node, destination);
    return;
  }
  addNamedLocalBinding(node, handler, destination);
}

function addVariableLocalBindings(
  declaration: ts.VariableDeclaration,
  handler: HandlerFunction,
  destination: LocalBinding[],
): void {
  const scope = variableBindingScope(declaration, handler);
  if (scope !== undefined) {
    addLocalBindings(declaration.name, scope, destination);
  }
}

function addParameterLocalBindings(
  parameter: ts.ParameterDeclaration,
  destination: LocalBinding[],
): void {
  if (isFunctionScope(parameter.parent)) {
    addLocalBindings(parameter.name, parameter.parent, destination);
  }
}

function addNamedLocalBinding(
  node: ts.Node,
  handler: HandlerFunction,
  destination: LocalBinding[],
): void {
  if ((ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node)) && node.name !== undefined) {
    const scope = nearestLexicalScope(node, handler);
    if (scope !== undefined) {
      addLocalBindings(node.name, scope, destination);
    }
    return;
  }
  if ((ts.isFunctionExpression(node) || ts.isClassExpression(node)) && node.name !== undefined) {
    addLocalBindings(node.name, node, destination);
  }
}

function addLocalBindings(name: ts.BindingName, scope: ts.Node, destination: LocalBinding[]): void {
  const names = new Set<string>();
  collectBindingNames(name, names);
  for (const localName of names) {
    destination.push({ name: localName, scope });
  }
}

function variableBindingScope(
  declaration: ts.VariableDeclaration,
  handler: HandlerFunction,
): ts.Node | undefined {
  if (ts.isCatchClause(declaration.parent)) {
    return declaration.parent;
  }
  if (
    ts.isVariableDeclarationList(declaration.parent) &&
    (declaration.parent.flags & ts.NodeFlags.BlockScoped) === 0
  ) {
    return nearestFunctionScope(declaration, handler);
  }
  return nearestLexicalScope(declaration, handler);
}

function nearestFunctionScope(node: ts.Node, handler: HandlerFunction): ts.Node | undefined {
  for (let current = node.parent; current !== undefined; current = current.parent) {
    if (isFunctionScope(current)) {
      return current;
    }
    if (current === handler) {
      return handler;
    }
  }
  return undefined;
}

function nearestLexicalScope(node: ts.Node, handler: HandlerFunction): ts.Node | undefined {
  for (let current = node.parent; current !== undefined; current = current.parent) {
    if (
      ts.isBlock(current) ||
      ts.isCaseBlock(current) ||
      ts.isCatchClause(current) ||
      ts.isForStatement(current) ||
      ts.isForInStatement(current) ||
      ts.isForOfStatement(current) ||
      isFunctionScope(current)
    ) {
      return current;
    }
    if (current === handler) {
      return handler;
    }
  }
  return undefined;
}

function isFunctionScope(node: ts.Node): boolean {
  return (
    ts.isArrowFunction(node) ||
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node)
  );
}

function isLocallyShadowed(
  call: ts.CallExpression,
  name: string,
  localBindings: readonly LocalBinding[],
): boolean {
  return localBindings.some(
    (binding) => binding.name === name && isNodeWithin(call, binding.scope),
  );
}

function isNodeWithin(node: ts.Node, scope: ts.Node): boolean {
  for (let current: ts.Node | undefined = node; current !== undefined; current = current.parent) {
    if (current === scope) {
      return true;
    }
  }
  return false;
}

function findExportedFunction(
  sourceFile: ts.SourceFile,
  importedName: string,
): HandlerFunction | undefined {
  for (const statement of sourceFile.statements) {
    if (
      ts.isFunctionDeclaration(statement) &&
      statement.name?.text === importedName &&
      statement.body !== undefined &&
      hasModifier(statement, ts.SyntaxKind.ExportKeyword) &&
      !hasModifier(statement, ts.SyntaxKind.DefaultKeyword)
    ) {
      return statement;
    }
    if (
      !ts.isVariableStatement(statement) ||
      !hasModifier(statement, ts.SyntaxKind.ExportKeyword)
    ) {
      continue;
    }
    for (const declaration of statement.declarationList.declarations) {
      if (
        ts.isIdentifier(declaration.name) &&
        declaration.name.text === importedName &&
        declaration.initializer !== undefined &&
        (ts.isArrowFunction(declaration.initializer) ||
          ts.isFunctionExpression(declaration.initializer))
      ) {
        return declaration.initializer;
      }
    }
  }
  return undefined;
}

function hasModifier(node: ts.Node, kind: ts.SyntaxKind): boolean {
  return (
    ts.canHaveModifiers(node) &&
    (ts.getModifiers(node)?.some((modifier) => modifier.kind === kind) ?? false)
  );
}

function scanHandler(
  file: ScannableFile,
  sourceFile: ts.SourceFile,
  handler: HandlerFunction,
  bindings: Bindings,
): readonly FindingInput[] {
  return scanFunction(file, sourceFile, handler, bindings, {
    safePathParameterIndexes: new Set(),
    taintedParameterIndexes: new Set(handler.parameters.map((_, index) => index)),
  });
}

function scanFunction(
  file: ScannableFile,
  sourceFile: ts.SourceFile,
  target: HandlerFunction,
  bindings: Bindings,
  seed: FunctionSeed,
): readonly FindingInput[] {
  if (target.body === undefined) {
    return [];
  }
  const state = analyzeFunctionState(target, bindings, seed);

  const findings: FindingInput[] = [];
  walk(target.body, (node) => {
    if (ts.isCallExpression(node)) {
      inspectCall(file, sourceFile, node, bindings, state.tainted, state.safePaths, findings);
    } else if (
      ts.isNewExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.text === "Function"
    ) {
      findings.push(
        findingAtNode(
          file,
          sourceFile,
          node,
          RULES.dynamicCode,
          "An MCP request handler constructs executable code with Function.",
        ),
      );
    }
  });
  return findings;
}

function analyzeFunctionState(
  target: HandlerFunction,
  bindings: Bindings,
  seed: FunctionSeed,
): FunctionState {
  const state: FunctionState = {
    safePaths: new Set(),
    tainted: new Set(),
  };
  for (const [index, parameter] of target.parameters.entries()) {
    if (seed.taintedParameterIndexes.has(index)) {
      collectBindingNames(parameter.name, state.tainted);
    }
    if (seed.safePathParameterIndexes.has(index)) {
      collectBindingNames(parameter.name, state.safePaths);
    }
  }
  if (target.body !== undefined) {
    propagateTaint(target.body, state.tainted, state.safePaths, new Set(), bindings);
  }
  return state;
}

function inspectCall(
  file: ScannableFile,
  sourceFile: ts.SourceFile,
  call: ts.CallExpression,
  bindings: Bindings,
  tainted: ReadonlySet<string>,
  safePaths: ReadonlySet<string>,
  findings: FindingInput[],
): void {
  const firstArgument = call.arguments[0];
  if (ts.isIdentifier(call.expression) && call.expression.text === "eval") {
    findings.push(
      findingAtNode(
        file,
        sourceFile,
        call,
        RULES.dynamicCode,
        "An MCP request handler invokes eval.",
      ),
    );
    return;
  }

  const processKind = childProcessKind(call.expression, bindings);
  if (processKind === "exec" && isTainted(firstArgument, tainted)) {
    findings.push(
      findingAtNode(
        file,
        sourceFile,
        call,
        RULES.commandInjection,
        "Tool input is interpolated into a command interpreted by a shell.",
      ),
    );
  } else if (
    (processKind === "execFile" || processKind === "spawn") &&
    isTainted(firstArgument, tainted)
  ) {
    findings.push(
      findingAtNode(
        file,
        sourceFile,
        call,
        RULES.arbitraryExecutable,
        "Tool input selects the executable launched by this handler.",
      ),
    );
  } else if (
    (processKind === "execFile" || processKind === "spawn") &&
    hasShellEnabled(call) &&
    call.arguments.slice(0, 2).some((argument) => isTainted(argument, tainted))
  ) {
    findings.push(
      findingAtNode(
        file,
        sourceFile,
        call,
        RULES.commandInjection,
        "Tool input reaches a child process launched with shell mode enabled.",
      ),
    );
  }

  const unsafeFilesystemArgument = filesystemPathArguments(call, bindings).find(
    (argument) => isTainted(argument, tainted) && !isSafePath(argument, safePaths, bindings),
  );
  if (unsafeFilesystemArgument !== undefined) {
    findings.push(
      findingAtNode(
        file,
        sourceFile,
        call,
        RULES.pathTraversal,
        "Tool input is used as a filesystem path without a visible canonical-root check.",
      ),
    );
  }

  if (networkUrl(call, bindings) !== undefined && isTainted(networkUrl(call, bindings), tainted)) {
    findings.push(
      findingAtNode(
        file,
        sourceFile,
        call,
        RULES.serverSideRequestForgery,
        "Tool input controls an outbound URL without a visible destination allowlist.",
      ),
    );
  }
}

function propagateTaint(
  body: ts.ConciseBody,
  tainted: Set<string>,
  safePaths: Set<string>,
  invalidSafePaths: Set<string>,
  bindings: Bindings,
): void {
  let changed = true;
  while (changed) {
    changed = false;
    walk(body, (node) => {
      changed = propagateNode(node, tainted, safePaths, invalidSafePaths, bindings) || changed;
    });
  }
}

function propagateNode(
  node: ts.Node,
  tainted: Set<string>,
  safePaths: Set<string>,
  invalidSafePaths: Set<string>,
  bindings: Bindings,
): boolean {
  if (ts.isVariableDeclaration(node) && node.initializer !== undefined) {
    return propagateBindingState(
      node.name,
      node.initializer,
      tainted,
      safePaths,
      invalidSafePaths,
      bindings,
    );
  }
  if (ts.isBinaryExpression(node) && isAssignmentOperator(node.operatorToken.kind)) {
    return propagateAssignmentState(node, tainted, safePaths, invalidSafePaths, bindings);
  }
  return false;
}

function propagateBindingState(
  name: ts.Node,
  expression: ts.Expression,
  tainted: Set<string>,
  safePaths: Set<string>,
  invalidSafePaths: ReadonlySet<string>,
  bindings: Bindings,
): boolean {
  let changed = false;
  if (isTainted(expression, tainted)) {
    changed = addBindingNames(name, tainted) || changed;
  }
  if (isSafePath(expression, safePaths, bindings)) {
    changed = addSafeBindingNames(name, safePaths, invalidSafePaths) || changed;
  }
  return changed;
}

function propagateAssignmentState(
  assignment: ts.BinaryExpression,
  tainted: Set<string>,
  safePaths: Set<string>,
  invalidSafePaths: Set<string>,
  bindings: Bindings,
): boolean {
  const rightIsTainted = isTainted(assignment.right, tainted);
  const rightIsSafe = isSafePath(assignment.right, safePaths, bindings);
  let changed = false;
  if (rightIsTainted) {
    changed = addBindingNames(assignment.left, tainted) || changed;
  }
  if (
    assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken ||
    (rightIsTainted && !rightIsSafe)
  ) {
    changed = invalidateSafeBindingNames(assignment.left, safePaths, invalidSafePaths) || changed;
  } else if (rightIsSafe) {
    changed = addSafeBindingNames(assignment.left, safePaths, invalidSafePaths) || changed;
  }
  return changed;
}

function isAssignmentOperator(kind: ts.SyntaxKind): boolean {
  return (
    kind === ts.SyntaxKind.EqualsToken ||
    (kind >= ts.SyntaxKind.FirstCompoundAssignment && kind <= ts.SyntaxKind.LastCompoundAssignment)
  );
}

function isTainted(node: ts.Node | undefined, tainted: ReadonlySet<string>): boolean {
  if (node === undefined) {
    return false;
  }
  const unwrapped = unwrapTransparentExpression(node);
  if (unwrapped !== node) {
    return isTainted(unwrapped, tainted);
  }
  if (ts.isIdentifier(node)) {
    return tainted.has(node.text);
  }
  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    return isTainted(node.expression, tainted);
  }
  return isCompositeTainted(node, tainted);
}

function isCompositeTainted(node: ts.Node, tainted: ReadonlySet<string>): boolean {
  if (ts.isTemplateExpression(node)) {
    return node.templateSpans.some((span) => isTainted(span.expression, tainted));
  }
  if (ts.isBinaryExpression(node)) {
    return isTainted(node.left, tainted) || isTainted(node.right, tainted);
  }
  if (ts.isArrayLiteralExpression(node)) {
    return node.elements.some((element) => isTainted(element, tainted));
  }
  if (ts.isObjectLiteralExpression(node)) {
    return node.properties.some((property) => isTainted(property, tainted));
  }
  if (ts.isPropertyAssignment(node)) {
    return isTainted(node.initializer, tainted);
  }
  if (ts.isSpreadElement(node) || ts.isSpreadAssignment(node)) {
    return isTainted(node.expression, tainted);
  }
  if (ts.isCallExpression(node)) {
    return isCallResultTainted(node, tainted);
  }
  if (ts.isNewExpression(node)) {
    return node.arguments?.some((argument) => isTainted(argument, tainted)) ?? false;
  }
  if (ts.isAwaitExpression(node)) {
    return isTainted(node.expression, tainted);
  }
  if (ts.isConditionalExpression(node)) {
    return isTainted(node.whenTrue, tainted) || isTainted(node.whenFalse, tainted);
  }
  return false;
}

function isCallResultTainted(call: ts.CallExpression, tainted: ReadonlySet<string>): boolean {
  if (call.arguments.some((argument) => isTainted(argument, tainted))) {
    return true;
  }
  return (
    ts.isPropertyAccessExpression(call.expression) &&
    TAINT_PRESERVING_RECEIVER_METHODS.has(call.expression.name.text) &&
    isTainted(call.expression.expression, tainted)
  );
}

function isSafePath(
  node: ts.Node | undefined,
  safePaths: ReadonlySet<string>,
  bindings: Bindings,
): boolean {
  if (node === undefined) {
    return false;
  }
  const unwrapped = unwrapTransparentExpression(node);
  if (unwrapped !== node) {
    return isSafePath(unwrapped, safePaths, bindings);
  }
  if (ts.isIdentifier(node)) {
    return safePaths.has(node.text);
  }
  if (ts.isCallExpression(node) && isBasenameCall(node.expression, bindings)) {
    return true;
  }
  if (ts.isCallExpression(node) && callName(node.expression) === "join") {
    return node.arguments.some((argument) => isSafePath(argument, safePaths, bindings));
  }
  return false;
}

function unwrapTransparentExpression(node: ts.Node): ts.Node {
  let current = node;
  while (
    ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) ||
    ts.isNonNullExpression(current) ||
    ts.isSatisfiesExpression(current) ||
    ts.isParenthesizedExpression(current)
  ) {
    current = current.expression;
  }
  return current;
}

function childProcessKind(
  expression: ts.LeftHandSideExpression,
  bindings: Bindings,
): "exec" | "execFile" | "spawn" | undefined {
  if (ts.isIdentifier(expression)) {
    return identifierProcessKind(expression.text, bindings);
  }
  if (!ts.isPropertyAccessExpression(expression) || !ts.isIdentifier(expression.expression)) {
    return undefined;
  }
  if (!bindings.childNamespaces.has(expression.expression.text)) {
    return undefined;
  }
  return namespaceProcessKind(expression.name.text);
}

function identifierProcessKind(
  name: string,
  bindings: Bindings,
): "exec" | "execFile" | "spawn" | undefined {
  if (bindings.exec.has(name)) {
    return "exec";
  }
  if (bindings.execFile.has(name)) {
    return "execFile";
  }
  if (bindings.spawn.has(name)) {
    return "spawn";
  }
  return undefined;
}

function namespaceProcessKind(name: string): "exec" | "execFile" | "spawn" | undefined {
  if (name === "exec" || name === "execSync") {
    return "exec";
  }
  if (name === "execFile" || name === "execFileSync") {
    return "execFile";
  }
  return name === "spawn" || name === "spawnSync" ? "spawn" : undefined;
}

function filesystemSink(
  expression: ts.LeftHandSideExpression,
  bindings: Bindings,
): string | undefined {
  if (ts.isIdentifier(expression)) {
    return bindings.filesystem.get(expression.text);
  }
  if (
    ts.isPropertyAccessExpression(expression) &&
    ts.isIdentifier(expression.expression) &&
    bindings.filesystemNamespaces.has(expression.expression.text) &&
    FILESYSTEM_SINKS.has(expression.name.text)
  ) {
    return expression.name.text;
  }
  return undefined;
}

function filesystemPathArguments(
  call: ts.CallExpression,
  bindings: Bindings,
): readonly ts.Expression[] {
  const sink = filesystemSink(call.expression, bindings);
  if (sink === undefined) {
    return [];
  }
  const indexes = sink === "rename" ? [0, 1] : [0];
  return indexes.flatMap((index) => {
    const argument = call.arguments[index];
    return argument === undefined ? [] : [argument];
  });
}

function networkUrl(call: ts.CallExpression, bindings: Bindings): ts.Expression | undefined {
  if (ts.isIdentifier(call.expression)) {
    return identifierNetworkUrl(call, bindings);
  }
  if (
    ts.isPropertyAccessExpression(call.expression) &&
    ts.isIdentifier(call.expression.expression)
  ) {
    return propertyNetworkUrl(call, bindings);
  }
  return undefined;
}

function identifierNetworkUrl(
  call: ts.CallExpression,
  bindings: Bindings,
): ts.Expression | undefined {
  const name = (call.expression as ts.Identifier).text;
  if (name === "fetch" || bindings.networkNamespaces.has(name)) {
    return call.arguments[0];
  }
  if (!bindings.axios.has(name)) {
    return undefined;
  }
  return axiosOptionsUrl(call.arguments[0]);
}

function propertyNetworkUrl(
  call: ts.CallExpression,
  bindings: Bindings,
): ts.Expression | undefined {
  const expression = call.expression as ts.PropertyAccessExpression;
  const owner = (expression.expression as ts.Identifier).text;
  if (
    (bindings.networkNamespaces.has(owner) &&
      (expression.name.text === "get" || expression.name.text === "request")) ||
    bindings.axios.has(owner)
  ) {
    return call.arguments[0];
  }
  return undefined;
}

function axiosOptionsUrl(options: ts.Expression | undefined): ts.Expression | undefined {
  if (options === undefined || !ts.isObjectLiteralExpression(options)) {
    return undefined;
  }
  for (const property of options.properties) {
    if (ts.isPropertyAssignment(property) && propertyName(property.name) === "url") {
      return property.initializer;
    }
    if (ts.isShorthandPropertyAssignment(property) && property.name.text === "url") {
      return property.name;
    }
  }
  return undefined;
}

function hasShellEnabled(call: ts.CallExpression): boolean {
  return call.arguments.some(
    (argument) =>
      ts.isObjectLiteralExpression(argument) &&
      argument.properties.some(
        (property) =>
          ts.isPropertyAssignment(property) &&
          propertyName(property.name) === "shell" &&
          property.initializer.kind === ts.SyntaxKind.TrueKeyword,
      ),
  );
}

function scanEnvironmentPassthrough(
  file: ScannableFile,
  sourceFile: ts.SourceFile,
  bindings: Bindings,
): readonly FindingInput[] {
  const findings: FindingInput[] = [];
  walk(sourceFile, (node) => {
    if (!ts.isObjectLiteralExpression(node) || !isProcessLaunchOptions(node, bindings)) {
      return;
    }
    const envProperty = node.properties.find(
      (property): property is ts.PropertyAssignment =>
        ts.isPropertyAssignment(property) && propertyName(property.name) === "env",
    );
    if (envProperty !== undefined && containsWholeProcessEnv(envProperty.initializer)) {
      findings.push(
        findingAtNode(
          file,
          sourceFile,
          envProperty,
          RULES.environmentPassthrough,
          "This child process receives every variable from the host environment.",
        ),
      );
    }
  });
  return findings;
}

function isProcessLaunchOptions(node: ts.ObjectLiteralExpression, bindings: Bindings): boolean {
  const parent = node.parent;
  if (ts.isCallExpression(parent)) {
    return childProcessKind(parent.expression, bindings) !== undefined;
  }
  return (
    ts.isNewExpression(parent) &&
    ts.isIdentifier(parent.expression) &&
    parent.expression.text === "StdioClientTransport"
  );
}

function containsWholeProcessEnv(node: ts.Node): boolean {
  let found = false;
  walk(node, (candidate) => {
    if (isProcessEnv(candidate) && !isProcessEnvPropertySelection(candidate)) {
      found = true;
    }
  });
  return found;
}

function isProcessEnv(node: ts.Node): node is ts.PropertyAccessExpression {
  return (
    ts.isPropertyAccessExpression(node) &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === "process" &&
    node.name.text === "env"
  );
}

function isProcessEnvPropertySelection(node: ts.PropertyAccessExpression): boolean {
  const parent = node.parent;
  return (
    ((ts.isPropertyAccessExpression(parent) || ts.isElementAccessExpression(parent)) &&
      parent.expression === node) ||
    (ts.isCallExpression(parent) && parent.expression === node)
  );
}

function isBasenameCall(expression: ts.LeftHandSideExpression, bindings: Bindings): boolean {
  if (ts.isIdentifier(expression)) {
    return bindings.basename.has(expression.text);
  }
  return (
    ts.isPropertyAccessExpression(expression) &&
    ts.isIdentifier(expression.expression) &&
    bindings.basename.has(`${expression.expression.text}.${expression.name.text}`)
  );
}

function findDescription(
  nodes: readonly ts.Expression[],
): { readonly node: ts.StringLiteralLike; readonly text: string } | undefined {
  for (const node of nodes) {
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      return { node, text: node.text };
    }
    if (!ts.isObjectLiteralExpression(node)) {
      continue;
    }
    const description = node.properties.find(
      (property): property is ts.PropertyAssignment =>
        ts.isPropertyAssignment(property) && propertyName(property.name) === "description",
    );
    if (
      description !== undefined &&
      (ts.isStringLiteral(description.initializer) ||
        ts.isNoSubstitutionTemplateLiteral(description.initializer))
    ) {
      return { node: description.initializer, text: description.initializer.text };
    }
  }
  return undefined;
}

function hasDestructiveAnnotation(nodes: readonly ts.Expression[]): boolean {
  for (const node of nodes) {
    if (!ts.isObjectLiteralExpression(node)) {
      continue;
    }
    const annotations = node.properties.find(
      (property): property is ts.PropertyAssignment =>
        ts.isPropertyAssignment(property) && propertyName(property.name) === "annotations",
    );
    if (annotations === undefined || !ts.isObjectLiteralExpression(annotations.initializer)) {
      continue;
    }
    if (
      annotations.initializer.properties.some(
        (property) =>
          ts.isPropertyAssignment(property) &&
          propertyName(property.name) === "destructiveHint" &&
          property.initializer.kind === ts.SyntaxKind.TrueKeyword,
      )
    ) {
      return true;
    }
  }
  return false;
}

function isDestructiveToolName(name: string): boolean {
  const lowerName = name.toLowerCase();
  return DESTRUCTIVE_TOOL_VERBS.some((verb) => {
    if (
      lowerName === verb ||
      lowerName.startsWith(`${verb}_`) ||
      lowerName.startsWith(`${verb}-`)
    ) {
      return true;
    }
    return lowerName.startsWith(verb) && /^[A-Z]$/u.test(name.charAt(verb.length));
  });
}

function requiredModule(node: ts.Expression | undefined): string | undefined {
  if (
    node === undefined ||
    !ts.isCallExpression(node) ||
    !ts.isIdentifier(node.expression) ||
    node.expression.text !== "require"
  ) {
    return undefined;
  }
  return normalizeModule(literalText(node.arguments[0]) ?? "");
}

function normalizeModule(moduleName: string): string {
  return moduleName.replace(/^node:/, "");
}

function collectBindingNames(name: ts.BindingName, destination: Set<string>): void {
  addBindingNames(name, destination);
}

function addSafeBindingNames(
  name: ts.Node,
  destination: Set<string>,
  invalidSafePaths: ReadonlySet<string>,
): boolean {
  const names = new Set<string>();
  addBindingNames(name, names);
  let changed = false;
  for (const bindingName of names) {
    if (!invalidSafePaths.has(bindingName) && !destination.has(bindingName)) {
      destination.add(bindingName);
      changed = true;
    }
  }
  return changed;
}

function invalidateSafeBindingNames(
  name: ts.Node,
  safePaths: Set<string>,
  invalidSafePaths: Set<string>,
): boolean {
  const names = new Set<string>();
  addBindingNames(name, names);
  let changed = false;
  for (const bindingName of names) {
    if (!invalidSafePaths.has(bindingName)) {
      invalidSafePaths.add(bindingName);
      changed = true;
    }
    changed = safePaths.delete(bindingName) || changed;
  }
  return changed;
}

function addBindingNames(name: ts.Node, destination: Set<string>): boolean {
  let changed = false;
  if (ts.isIdentifier(name)) {
    if (!destination.has(name.text)) {
      destination.add(name.text);
      changed = true;
    }
  } else if (ts.isObjectBindingPattern(name) || ts.isArrayBindingPattern(name)) {
    for (const element of name.elements) {
      if (!ts.isOmittedExpression(element)) {
        changed = addBindingNames(element.name, destination) || changed;
      }
    }
  }
  return changed;
}

function deduplicate(findings: readonly FindingInput[]): readonly FindingInput[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.metadata.id}:${finding.file}:${finding.line}:${finding.column}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}
