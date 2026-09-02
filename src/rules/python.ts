import type { FindingInput, RuleMetadata } from "../domain.js";
import type { ScannableFile } from "../scanner/files.js";
import { findingAtOffset } from "../scanner/source.js";
import { RULES } from "./catalog.js";
import { isTestFile } from "./file-context.js";
import type { Rule } from "./types.js";

const HANDLER_DECORATORS = new Set(["call_tool", "prompt", "resource", "tool"]);
const MCP_CONSTRUCTORS = new Set(["FastMCP", "Server"]);
const PROCESS_METHODS = new Set(["Popen", "call", "check_call", "check_output", "run"]);
const SHELL_METHODS = new Set(["popen", "system"]);
const HTTP_METHODS = new Set(["delete", "get", "head", "options", "patch", "post", "put"]);
const PATH_METHOD_ARGUMENTS = new Map([
  ["chmod", 1],
  ["chown", 1],
  ["listdir", 1],
  ["lstat", 1],
  ["makedirs", 1],
  ["mkdir", 1],
  ["open", 1],
  ["readlink", 1],
  ["remove", 1],
  ["rename", 2],
  ["replace", 2],
  ["rmdir", 1],
  ["stat", 1],
  ["unlink", 1],
]);
const PATH_ARGUMENT_NAMES = new Set(["dst", "file", "path", "src"]);
const STRING_PREFIXES = new Set(["b", "br", "f", "fr", "r", "rb", "rf", "u"]);
const MAX_FORMATTED_STRING_NESTING = 64;
const IDENTIFIER = /^[A-Za-z_]\w*$/;
const IDENTIFIER_START = /[A-Za-z_]/;
const IDENTIFIER_PART = /[A-Za-z0-9_]/;

type NetworkFamily = "aiohttp" | "httpx" | "requests" | "urllib";
type ProcessKind = "executable" | "shell";

interface PythonStatement {
  readonly indent: number;
  readonly masked: string;
  readonly offset: number;
  readonly raw: string;
}

interface PythonHandler {
  readonly body: readonly PythonStatement[];
  readonly parameters: readonly string[];
}

interface PythonBindings {
  readonly asyncioNamespaces: Set<string>;
  readonly basenameFunctions: Set<string>;
  readonly builtinsNamespaces: Set<string>;
  readonly directNetwork: Map<string, NetworkCallShape>;
  readonly directPaths: Map<string, number>;
  readonly directProcesses: Map<string, ProcessKind>;
  readonly dynamicFunctions: Set<string>;
  readonly mcpConstructors: Set<string>;
  readonly mcpDecoratorFunctions: Set<string>;
  readonly mcpInstances: Set<string>;
  readonly mcpNamespaces: Set<string>;
  readonly networkClients: Map<string, NetworkFamily>;
  readonly networkNamespaces: Map<string, NetworkFamily>;
  readonly osNamespaces: Set<string>;
  readonly osPathNamespaces: Set<string>;
  readonly pathlibConstructors: Set<string>;
  readonly pathlibNamespaces: Set<string>;
  readonly subprocessNamespaces: Set<string>;
}

interface NetworkCallShape {
  readonly family: NetworkFamily;
  readonly method: string;
}

interface Assignment {
  readonly names: readonly string[];
  readonly value: string;
}

interface PythonCall {
  readonly arguments: readonly PythonArgument[];
  readonly callee: string;
  readonly endOffset: number;
  readonly offset: number;
}

interface PythonArgument {
  readonly masked: string;
  readonly name?: string;
  readonly raw: string;
}

interface IdentifierReference {
  readonly end: number;
  readonly name: string;
  readonly start: number;
}

interface StringScan {
  readonly end: number;
  readonly references: readonly IdentifierReference[];
}

interface FunctionHeader {
  readonly inlineBody?: PythonStatement;
  readonly parameters: readonly string[];
}

export const pythonSecurityRule: Rule = {
  metadata: RULES.commandInjection,
  scan({ file }): readonly FindingInput[] {
    if (!file.relativePath.toLowerCase().endsWith(".py") || isTestFile(file.relativePath)) {
      return [];
    }

    const statements = splitStatements(file.text);
    const bindings = collectBindings(statements);
    const handlers = collectHandlers(statements, bindings);
    return deduplicate(handlers.flatMap((handler) => scanHandler(file, handler, bindings)));
  },
};

function splitStatements(text: string): readonly PythonStatement[] {
  const masked = maskPythonSource(text);
  const rawLines = text.split("\n");
  const maskedLines = masked.split("\n");
  const statements: PythonStatement[] = [];
  let depth = 0;
  let offset = 0;
  let pending: PythonStatement | undefined;

  for (let index = 0; index < rawLines.length; index += 1) {
    const raw = rawLines[index] ?? "";
    const code = maskedLines[index] ?? "";
    const lineOffset = offset;
    offset += raw.length + 1;

    if (pending === undefined && code.trim() === "") continue;
    pending = appendLine(pending, raw, code, lineOffset);
    depth = Math.max(0, depth + bracketDelta(code));
    if (depth === 0 && !code.trimEnd().endsWith("\\")) {
      statements.push(pending);
      pending = undefined;
    }
  }

  if (pending !== undefined) statements.push(pending);
  return statements;
}

function appendLine(
  pending: PythonStatement | undefined,
  raw: string,
  masked: string,
  offset: number,
): PythonStatement {
  if (pending === undefined) {
    return { indent: indentation(raw), masked, offset, raw };
  }
  return {
    ...pending,
    masked: `${pending.masked}\n${masked}`,
    raw: `${pending.raw}\n${raw}`,
  };
}

function bracketDelta(text: string): number {
  let delta = 0;
  for (const character of text) {
    if (character === "(" || character === "[" || character === "{") delta += 1;
    else if (character === ")" || character === "]" || character === "}") delta -= 1;
  }
  return delta;
}

function indentation(text: string): number {
  let width = 0;
  for (const character of text) {
    if (character === " ") width += 1;
    else if (character === "\t") width += 8 - (width % 8);
    else break;
  }
  return width;
}

function maskPythonSource(text: string): string {
  const output = text.split("");
  let cursor = 0;
  while (cursor < text.length) {
    const character = text[cursor];
    if (character === "#") {
      cursor = maskComment(text, output, cursor);
    } else if (character === "'" || character === '"') {
      cursor = maskString(text, output, cursor);
    } else {
      cursor += 1;
    }
  }
  return output.join("");
}

function maskComment(text: string, output: string[], start: number): number {
  let cursor = start;
  while (cursor < text.length && text[cursor] !== "\n") {
    output[cursor] = " ";
    cursor += 1;
  }
  return cursor;
}

function maskString(text: string, output: string[], quoteIndex: number): number {
  const prefixStart = stringPrefixStart(text, quoteIndex);
  const quote = text[quoteIndex] ?? '"';
  const delimiterLength = text.slice(quoteIndex, quoteIndex + 3) === quote.repeat(3) ? 3 : 1;
  const end = skipString(text, quoteIndex, delimiterLength);
  maskRange(output, prefixStart, end);
  return end;
}

function stringPrefixStart(text: string, quoteIndex: number): number {
  let start = quoteIndex;
  while (start > 0 && quoteIndex - start < 2 && /[A-Za-z]/.test(text[start - 1] ?? "")) {
    start -= 1;
  }
  const prefix = text.slice(start, quoteIndex).toLowerCase();
  const preceding = text[start - 1];
  return STRING_PREFIXES.has(prefix) &&
    (preceding === undefined || !IDENTIFIER_PART.test(preceding))
    ? start
    : quoteIndex;
}

function skipString(text: string, quoteIndex: number, delimiterLength: number): number {
  const quote = text[quoteIndex] ?? '"';
  const delimiter = quote.repeat(delimiterLength);
  let cursor = quoteIndex + delimiterLength;
  while (cursor < text.length) {
    if (text.startsWith(delimiter, cursor)) return cursor + delimiterLength;
    if (text[cursor] === "\\") cursor += 2;
    else if (delimiterLength === 1 && text[cursor] === "\n") return cursor;
    else cursor += 1;
  }
  return text.length;
}

function maskRange(output: string[], start: number, end: number): void {
  for (let index = start; index < end; index += 1) {
    if (output[index] !== "\n") output[index] = " ";
  }
}

function collectBindings(statements: readonly PythonStatement[]): PythonBindings {
  const bindings: PythonBindings = {
    asyncioNamespaces: new Set(),
    basenameFunctions: new Set(),
    builtinsNamespaces: new Set(),
    directNetwork: new Map(),
    directPaths: new Map([["open", 1]]),
    directProcesses: new Map(),
    dynamicFunctions: new Set(["eval", "exec"]),
    mcpConstructors: new Set(),
    mcpDecoratorFunctions: new Set(),
    mcpInstances: new Set(),
    mcpNamespaces: new Set(),
    networkClients: new Map(),
    networkNamespaces: new Map(),
    osNamespaces: new Set(),
    osPathNamespaces: new Set(),
    pathlibConstructors: new Set(),
    pathlibNamespaces: new Set(),
    subprocessNamespaces: new Set(),
  };

  const topLevel = statements.filter((statement) => statement.indent === 0);
  for (const statement of topLevel) collectImport(statement, bindings);
  propagateConstructedBindings(topLevel, bindings);
  return bindings;
}

function collectImport(statement: PythonStatement, bindings: PythonBindings): void {
  const normalized = statement.masked.replaceAll("\\\n", " ").replace(/\s+/g, " ").trim();
  const fromMatch = /^from\s+([\w.]+)\s+import\s+(.+)$/.exec(normalized);
  if (fromMatch !== null) {
    collectFromImport(fromMatch[1] ?? "", fromMatch[2] ?? "", bindings);
    return;
  }
  const importMatch = /^import\s+(.+)$/.exec(normalized);
  if (importMatch === null) return;
  for (const part of splitImportList(importMatch[1] ?? "")) {
    const imported = parseImportedName(part);
    if (imported !== undefined) addNamespaceImport(imported.name, imported.alias, bindings);
  }
}

function collectFromImport(
  moduleName: string,
  importedText: string,
  bindings: PythonBindings,
): void {
  const cleaned = importedText.replace(/^\(|\)$/g, "");
  for (const part of splitImportList(cleaned)) {
    const imported = parseImportedName(part);
    if (imported === undefined) continue;
    addNamedImport(moduleName, imported.name, imported.alias ?? imported.name, bindings);
  }
}

function splitImportList(text: string): readonly string[] {
  return text
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function parseImportedName(text: string): { alias?: string; name: string } | undefined {
  const match = /^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)(?:\s+as\s+([A-Za-z_]\w*))?$/.exec(text.trim());
  if (match?.[1] === undefined) return undefined;
  return match[2] === undefined ? { name: match[1] } : { alias: match[2], name: match[1] };
}

function addNamespaceImport(
  moduleName: string,
  explicitAlias: string | undefined,
  bindings: PythonBindings,
): void {
  const localName = explicitAlias ?? moduleName;
  if (isMcpModule(moduleName)) bindings.mcpNamespaces.add(localName);
  if (moduleName === "os") bindings.osNamespaces.add(localName);
  else if (moduleName === "os.path") bindings.osPathNamespaces.add(localName);
  else if (moduleName === "subprocess") bindings.subprocessNamespaces.add(localName);
  else if (moduleName === "pathlib") bindings.pathlibNamespaces.add(localName);
  else if (moduleName === "builtins") bindings.builtinsNamespaces.add(localName);
  else if (moduleName === "asyncio") bindings.asyncioNamespaces.add(localName);
  else addNetworkNamespace(moduleName, localName, bindings);
}

function addNetworkNamespace(
  moduleName: string,
  localName: string,
  bindings: PythonBindings,
): void {
  if (moduleName === "requests" || moduleName.startsWith("requests.")) {
    bindings.networkNamespaces.set(localName, "requests");
  } else if (moduleName === "httpx" || moduleName.startsWith("httpx.")) {
    bindings.networkNamespaces.set(localName, "httpx");
  } else if (moduleName === "aiohttp" || moduleName.startsWith("aiohttp.")) {
    bindings.networkNamespaces.set(localName, "aiohttp");
  } else if (moduleName === "urllib.request") {
    bindings.networkNamespaces.set(localName, "urllib");
  }
}

function addNamedImport(
  moduleName: string,
  importedName: string,
  localName: string,
  bindings: PythonBindings,
): void {
  if (isMcpModule(moduleName)) addMcpNamedImport(importedName, localName, bindings);
  if (moduleName === "os") addOsNamedImport(importedName, localName, bindings);
  else if (moduleName === "os.path" && importedName === "basename") {
    bindings.basenameFunctions.add(localName);
  } else if (moduleName === "subprocess" && PROCESS_METHODS.has(importedName)) {
    bindings.directProcesses.set(localName, "executable");
  } else if (moduleName === "pathlib" && importedName === "Path") {
    bindings.pathlibConstructors.add(localName);
  } else if (moduleName === "builtins") {
    addBuiltinNamedImport(importedName, localName, bindings);
  } else if (moduleName === "asyncio") {
    addAsyncioNamedImport(importedName, localName, bindings);
  } else {
    addNetworkNamedImport(moduleName, importedName, localName, bindings);
  }
}

function addMcpNamedImport(
  importedName: string,
  localName: string,
  bindings: PythonBindings,
): void {
  if (MCP_CONSTRUCTORS.has(importedName)) bindings.mcpConstructors.add(localName);
  if (HANDLER_DECORATORS.has(importedName)) bindings.mcpDecoratorFunctions.add(localName);
}

function addOsNamedImport(importedName: string, localName: string, bindings: PythonBindings): void {
  if (SHELL_METHODS.has(importedName)) bindings.directProcesses.set(localName, "shell");
  const pathArguments = PATH_METHOD_ARGUMENTS.get(importedName);
  if (pathArguments !== undefined) bindings.directPaths.set(localName, pathArguments);
}

function addBuiltinNamedImport(
  importedName: string,
  localName: string,
  bindings: PythonBindings,
): void {
  if (importedName === "eval" || importedName === "exec") bindings.dynamicFunctions.add(localName);
  if (importedName === "open") bindings.directPaths.set(localName, 1);
}

function addAsyncioNamedImport(
  importedName: string,
  localName: string,
  bindings: PythonBindings,
): void {
  if (importedName === "create_subprocess_shell") {
    bindings.directProcesses.set(localName, "shell");
  } else if (importedName === "create_subprocess_exec") {
    bindings.directProcesses.set(localName, "executable");
  }
}

function addNetworkNamedImport(
  moduleName: string,
  importedName: string,
  localName: string,
  bindings: PythonBindings,
): void {
  const family = networkFamily(moduleName);
  if (family === undefined) return;
  if (HTTP_METHODS.has(importedName) || importedName === "request") {
    bindings.directNetwork.set(localName, { family, method: importedName });
  } else if (family === "urllib" && (importedName === "Request" || importedName === "urlopen")) {
    bindings.directNetwork.set(localName, { family, method: importedName });
  }
}

function networkFamily(moduleName: string): NetworkFamily | undefined {
  if (moduleName === "requests" || moduleName.startsWith("requests.")) return "requests";
  if (moduleName === "httpx" || moduleName.startsWith("httpx.")) return "httpx";
  if (moduleName === "aiohttp" || moduleName.startsWith("aiohttp.")) return "aiohttp";
  return moduleName === "urllib.request" ? "urllib" : undefined;
}

function isMcpModule(moduleName: string): boolean {
  return (
    moduleName === "mcp" ||
    moduleName.startsWith("mcp.") ||
    moduleName === "fastmcp" ||
    moduleName.startsWith("fastmcp.")
  );
}

function propagateConstructedBindings(
  statements: readonly PythonStatement[],
  bindings: PythonBindings,
): void {
  const aliases = new Map<string, string[]>();
  for (const statement of statements) {
    collectConstructedAssignment(statement, bindings, aliases);
    collectWithClient(statement, bindings);
  }
  propagateMcpAliases(bindings.mcpInstances, aliases);
  propagateClientAliases(bindings.networkClients, aliases);
}

function collectConstructedAssignment(
  statement: PythonStatement,
  bindings: PythonBindings,
  aliases: Map<string, string[]>,
): void {
  const assignment = parseAssignment(statement);
  const name = assignment?.names.length === 1 ? assignment.names[0] : undefined;
  if (assignment === undefined || name === undefined) return;
  const calls = extractCalls(assignment.value, maskPythonSource(assignment.value), 0);
  const constructorName = calls[0]?.callee;
  if (constructorName !== undefined && isMcpConstructor(constructorName, bindings)) {
    bindings.mcpInstances.add(name);
    return;
  }
  if (constructorName !== undefined) {
    const family = networkClientFamily(constructorName, bindings);
    if (family !== undefined) {
      bindings.networkClients.set(name, family);
      return;
    }
  }
  const source = assignment.value.trim();
  if (!IDENTIFIER.test(source)) return;
  const targets = aliases.get(source) ?? [];
  targets.push(name);
  aliases.set(source, targets);
}

function propagateMcpAliases(
  instances: Set<string>,
  aliases: ReadonlyMap<string, readonly string[]>,
): void {
  const queue = [...instances];
  for (let index = 0; index < queue.length; index += 1) {
    for (const target of aliases.get(queue[index] ?? "") ?? []) {
      if (addToSet(instances, target)) queue.push(target);
    }
  }
}

function propagateClientAliases(
  clients: Map<string, NetworkFamily>,
  aliases: ReadonlyMap<string, readonly string[]>,
): void {
  const queue = [...clients.entries()];
  for (let index = 0; index < queue.length; index += 1) {
    const [source, family] = queue[index] ?? [];
    if (source === undefined || family === undefined) continue;
    for (const target of aliases.get(source) ?? []) {
      if (clients.has(target)) continue;
      clients.set(target, family);
      queue.push([target, family]);
    }
  }
}

function collectWithClient(statement: PythonStatement, bindings: PythonBindings): void {
  const normalized = statement.masked.replace(/\s+/g, " ").trim();
  const match = /^(?:async\s+)?with\s+(.+)\s+as\s+([A-Za-z_]\w*)\s*:/.exec(normalized);
  if (match?.[1] === undefined || match[2] === undefined) return;
  const constructorName = extractCalls(match[1], maskPythonSource(match[1]), 0)[0]?.callee;
  const family =
    constructorName === undefined ? undefined : networkClientFamily(constructorName, bindings);
  if (family === undefined || bindings.networkClients.has(match[2])) return;
  bindings.networkClients.set(match[2], family);
}

function isMcpConstructor(callee: string, bindings: PythonBindings): boolean {
  if (bindings.mcpConstructors.has(callee)) return true;
  const parts = callee.split(".");
  const constructorName = parts.pop();
  const owner = parts.join(".");
  return (
    MCP_CONSTRUCTORS.has(constructorName ?? "") && matchesNamespace(owner, bindings.mcpNamespaces)
  );
}

function networkClientFamily(callee: string, bindings: PythonBindings): NetworkFamily | undefined {
  const parts = callee.split(".");
  const constructorName = parts.pop() ?? "";
  const family = matchingNamespaceFamily(parts.join("."), bindings.networkNamespaces);
  if (family === "httpx" && (constructorName === "Client" || constructorName === "AsyncClient")) {
    return family;
  }
  if (family === "requests" && constructorName === "Session") return family;
  return family === "aiohttp" && constructorName === "ClientSession" ? family : undefined;
}

function collectHandlers(
  statements: readonly PythonStatement[],
  bindings: PythonBindings,
): readonly PythonHandler[] {
  const handlers: PythonHandler[] = [];
  let decorators: PythonStatement[] = [];

  for (let index = 0; index < statements.length; index += 1) {
    const statement = statements[index];
    if (statement === undefined) continue;
    if (statement.masked.trimStart().startsWith("@")) {
      decorators.push(statement);
      continue;
    }

    const header = parseFunctionHeader(statement);
    if (header !== undefined && hasMcpDecorator(decorators, statement.indent, bindings)) {
      const body = collectFunctionBody(statements, index, statement.indent, header.inlineBody);
      handlers.push({ body, parameters: header.parameters });
    }
    decorators = [];
  }
  return handlers;
}

function hasMcpDecorator(
  decorators: readonly PythonStatement[],
  functionIndent: number,
  bindings: PythonBindings,
): boolean {
  return decorators.some(
    (decorator) => decorator.indent === functionIndent && isMcpDecorator(decorator, bindings),
  );
}

function isMcpDecorator(statement: PythonStatement, bindings: PythonBindings): boolean {
  const match = /^@\s*([A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*)/.exec(statement.masked.trimStart());
  const callee = match?.[1]?.replace(/\s+/g, "");
  if (callee === undefined) return false;
  if (bindings.mcpDecoratorFunctions.has(callee)) return true;
  const parts = callee.split(".");
  const method = parts.pop();
  return HANDLER_DECORATORS.has(method ?? "") && bindings.mcpInstances.has(parts.join("."));
}

function parseFunctionHeader(statement: PythonStatement): FunctionHeader | undefined {
  const match = /^\s*(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(/.exec(statement.masked);
  if (match === null) return undefined;
  const open = statement.masked.indexOf("(", match.index);
  const close = findMatchingDelimiter(statement.masked, open, "(", ")");
  if (open < 0 || close < 0) return undefined;
  const colon = findHeaderColon(statement.masked, close + 1);
  if (colon < 0) return undefined;
  const parameters = parseParameters(statement.raw.slice(open + 1, close));
  const inlineBody = createInlineBody(statement, colon);
  return inlineBody === undefined ? { parameters } : { inlineBody, parameters };
}

function findHeaderColon(text: string, start: number): number {
  let depth = 0;
  for (let index = start; index < text.length; index += 1) {
    const character = text[index];
    if (character === "(" || character === "[" || character === "{") depth += 1;
    else if (character === ")" || character === "]" || character === "}") depth -= 1;
    else if (character === ":" && depth === 0) return index;
  }
  return -1;
}

function createInlineBody(statement: PythonStatement, colon: number): PythonStatement | undefined {
  const masked = statement.masked.slice(colon + 1);
  if (masked.trim() === "") return undefined;
  const raw = statement.raw.slice(colon + 1);
  const leading = raw.length - raw.trimStart().length;
  return {
    indent: statement.indent + 1,
    masked: masked.slice(leading),
    offset: statement.offset + colon + 1 + leading,
    raw: raw.slice(leading),
  };
}

function parseParameters(text: string): readonly string[] {
  return splitTopLevel(text, maskPythonSource(text), ",").flatMap(({ masked }) => {
    const normalized = masked.trim().replace(/^\*{1,2}/, "");
    const name = /^([A-Za-z_]\w*)/.exec(normalized)?.[1];
    return name === undefined || name === "self" || name === "cls" ? [] : [name];
  });
}

function collectFunctionBody(
  statements: readonly PythonStatement[],
  functionIndex: number,
  functionIndent: number,
  inlineBody: PythonStatement | undefined,
): readonly PythonStatement[] {
  const body: PythonStatement[] = inlineBody === undefined ? [] : [inlineBody];
  for (let index = functionIndex + 1; index < statements.length; index += 1) {
    const statement = statements[index];
    if (statement === undefined || statement.indent <= functionIndent) break;
    body.push(statement);
  }
  return body;
}

function scanHandler(
  file: ScannableFile,
  handler: PythonHandler,
  bindings: PythonBindings,
): readonly FindingInput[] {
  const tainted = new Set(handler.parameters);
  const safePaths = new Set<string>();
  propagateAssignments(handler.body, tainted, safePaths, bindings);
  const localNames = collectLocalNames(handler);
  const scopedBindings = createHandlerBindings(handler, bindings, localNames);
  const findings: FindingInput[] = [];

  for (const statement of handler.body) {
    for (const call of extractCalls(statement.raw, statement.masked, statement.offset)) {
      inspectCall(file, call, scopedBindings, tainted, safePaths, localNames, findings);
    }
  }
  return findings;
}

function createHandlerBindings(
  handler: PythonHandler,
  bindings: PythonBindings,
  localNames: ReadonlySet<string>,
): PythonBindings {
  const scoped: PythonBindings = {
    ...bindings,
    mcpInstances: new Set(bindings.mcpInstances),
    networkClients: new Map(bindings.networkClients),
  };
  for (const name of localNames) scoped.networkClients.delete(name);
  propagateConstructedBindings(handler.body, scoped);
  return scoped;
}

function collectLocalNames(handler: PythonHandler): ReadonlySet<string> {
  const names = new Set(handler.parameters);
  for (const statement of handler.body) {
    for (const name of parseAssignment(statement)?.names ?? []) names.add(name);
  }
  return names;
}

function propagateAssignments(
  statements: readonly PythonStatement[],
  tainted: Set<string>,
  safePaths: Set<string>,
  bindings: PythonBindings,
): void {
  const dependents = collectAssignmentDependents(statements);
  const queue = [...tainted];
  for (let index = 0; index < queue.length; index += 1) {
    for (const assignment of dependents.get(queue[index] ?? "") ?? []) {
      if (isSafePathExpression(assignment.value, tainted, safePaths, bindings)) {
        addNames(safePaths, assignment.names);
        continue;
      }
      for (const name of assignment.names) {
        if (addToSet(tainted, name)) queue.push(name);
      }
    }
  }
}

function collectAssignmentDependents(
  statements: readonly PythonStatement[],
): ReadonlyMap<string, readonly Assignment[]> {
  const dependents = new Map<string, Assignment[]>();
  for (const statement of statements) {
    const assignment = parseAssignment(statement);
    if (assignment === undefined) continue;
    const references = new Set(identifierReferences(assignment.value).map(({ name }) => name));
    for (const reference of references) {
      const assignments = dependents.get(reference) ?? [];
      assignments.push(assignment);
      dependents.set(reference, assignments);
    }
  }
  return dependents;
}

function parseAssignment(statement: PythonStatement): Assignment | undefined {
  const augmented = /^\s*([A-Za-z_]\w*)\s*(?:\*\*|<<|>>|[+\-*/%@&|^])=/.exec(statement.masked);
  if (augmented?.[1] !== undefined) {
    const equals = statement.masked.indexOf("=", augmented.index);
    return {
      names: [augmented[1]],
      value: `${augmented[1]} ${statement.raw.slice(equals + 1).trim()}`,
    };
  }
  const equals = findTopLevelAssignment(statement.masked);
  if (equals < 0) return undefined;
  const left = statement.masked.slice(0, equals).trim();
  const names = assignmentNames(left);
  if (names.length === 0) return undefined;
  return { names, value: statement.raw.slice(equals + 1).trim() };
}

function findTopLevelAssignment(text: string): number {
  let depth = 0;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (character === "(" || character === "[" || character === "{") depth += 1;
    else if (character === ")" || character === "]" || character === "}") depth -= 1;
    else if (character === "=" && depth === 0 && isAssignmentOperator(text, index)) return index;
  }
  return -1;
}

function isAssignmentOperator(text: string, index: number): boolean {
  const previous = text[index - 1] ?? "";
  const next = text[index + 1] ?? "";
  return next !== "=" && !"<>=!:".includes(previous);
}

function assignmentNames(text: string): readonly string[] {
  const annotated = /^([A-Za-z_]\w*)\s*(?::[\s\S]+)?$/.exec(text);
  if (annotated?.[1] !== undefined) return [annotated[1]];
  if (!/^[\s()[\],*A-Za-z0-9_]+$/.test(text)) return [];
  return [...text.matchAll(/\b[A-Za-z_]\w*\b/g)].map((match) => match[0]);
}

function inspectCall(
  file: ScannableFile,
  call: PythonCall,
  bindings: PythonBindings,
  tainted: ReadonlySet<string>,
  safePaths: ReadonlySet<string>,
  localNames: ReadonlySet<string>,
  findings: FindingInput[],
): void {
  inspectProcessCall(file, call, bindings, tainted, localNames, findings);
  inspectDynamicCall(file, call, bindings, tainted, localNames, findings);
  inspectPathCall(file, call, bindings, tainted, safePaths, localNames, findings);
  inspectNetworkCall(file, call, bindings, tainted, localNames, findings);
}

function inspectProcessCall(
  file: ScannableFile,
  call: PythonCall,
  bindings: PythonBindings,
  tainted: ReadonlySet<string>,
  localNames: ReadonlySet<string>,
  findings: FindingInput[],
): void {
  const kind = processKind(call.callee, bindings, localNames);
  if (kind === undefined) return;
  const command = namedOrPositional(call.arguments, "args", 0);
  if (kind === "shell" && isTaintedArgument(command, tainted)) {
    findings.push(
      finding(file, call, RULES.commandInjection, "Tool input reaches a Python shell API."),
    );
    return;
  }
  if (kind !== "executable" || command === undefined) return;
  if (shellEnabled(call.arguments) && isTaintedArgument(command, tainted)) {
    findings.push(
      finding(
        file,
        call,
        RULES.commandInjection,
        "Tool input reaches a Python subprocess launched with shell mode enabled.",
      ),
    );
    return;
  }
  const executable = call.arguments.find((argument) => argument.name === "executable");
  if (isTaintedArgument(executable, tainted)) {
    findings.push(
      finding(
        file,
        call,
        RULES.arbitraryExecutable,
        "Tool input overrides the executable launched by this Python handler.",
      ),
    );
    return;
  }
  if (toolInputSelectsExecutable(command.raw, command.masked, tainted)) {
    findings.push(
      finding(
        file,
        call,
        RULES.arbitraryExecutable,
        "Tool input selects the executable launched by this Python handler.",
      ),
    );
  }
}

function processKind(
  callee: string,
  bindings: PythonBindings,
  localNames: ReadonlySet<string>,
): ProcessKind | undefined {
  const direct = bindings.directProcesses.get(callee);
  if (direct !== undefined && !localNames.has(callee)) return direct;
  const { method, owner, root } = splitCallee(callee);
  if (localNames.has(root)) return undefined;
  if (SHELL_METHODS.has(method) && matchesNamespace(owner, bindings.osNamespaces)) return "shell";
  if (PROCESS_METHODS.has(method) && matchesNamespace(owner, bindings.subprocessNamespaces)) {
    return "executable";
  }
  if (!matchesNamespace(owner, bindings.asyncioNamespaces)) return undefined;
  if (method === "create_subprocess_shell") return "shell";
  return method === "create_subprocess_exec" ? "executable" : undefined;
}

function shellEnabled(argumentsList: readonly PythonArgument[]): boolean {
  return argumentsList.some(
    (argument) => argument.name === "shell" && argument.masked.trim() === "True",
  );
}

function toolInputSelectsExecutable(
  raw: string,
  masked: string,
  tainted: ReadonlySet<string>,
): boolean {
  if (!isTainted(raw, tainted)) return false;
  const trimmed = masked.trim();
  if (!trimmed.startsWith("[") && !trimmed.startsWith("(")) return true;
  const first = splitTopLevel(raw.slice(1, -1), masked.slice(1, -1), ",")[0];
  return first !== undefined && isTainted(first.raw, tainted);
}

function inspectDynamicCall(
  file: ScannableFile,
  call: PythonCall,
  bindings: PythonBindings,
  tainted: ReadonlySet<string>,
  localNames: ReadonlySet<string>,
  findings: FindingInput[],
): void {
  if (!isDynamicCall(call.callee, bindings, localNames)) return;
  const expression = namedOrPositional(call.arguments, "source", 0);
  if (isTaintedArgument(expression, tainted)) {
    findings.push(
      finding(
        file,
        call,
        RULES.dynamicCode,
        "An MCP handler evaluates tool-controlled Python code.",
      ),
    );
  }
}

function isDynamicCall(
  callee: string,
  bindings: PythonBindings,
  localNames: ReadonlySet<string>,
): boolean {
  if (bindings.dynamicFunctions.has(callee)) return !localNames.has(callee);
  const { method, owner, root } = splitCallee(callee);
  return (
    !localNames.has(root) &&
    (method === "eval" || method === "exec") &&
    matchesNamespace(owner, bindings.builtinsNamespaces)
  );
}

function inspectPathCall(
  file: ScannableFile,
  call: PythonCall,
  bindings: PythonBindings,
  tainted: ReadonlySet<string>,
  safePaths: ReadonlySet<string>,
  localNames: ReadonlySet<string>,
  findings: FindingInput[],
): void {
  const argumentCount = pathArgumentCount(call.callee, bindings, localNames);
  if (argumentCount === undefined) return;
  const positional = call.arguments
    .filter((argument) => argument.name === undefined)
    .slice(0, argumentCount);
  const named = call.arguments
    .filter((argument) => argument.name !== undefined && PATH_ARGUMENT_NAMES.has(argument.name))
    .slice(0, argumentCount);
  const candidates = [...positional, ...named];
  const unsafe = candidates.some(
    (argument) =>
      isTainted(argument.raw, tainted) &&
      !isSafePathExpression(argument.raw, tainted, safePaths, bindings),
  );
  if (unsafe) {
    findings.push(
      finding(
        file,
        call,
        RULES.pathTraversal,
        "Tool input is used as a Python filesystem path without a visible basename guard.",
      ),
    );
  }
}

function pathArgumentCount(
  callee: string,
  bindings: PythonBindings,
  localNames: ReadonlySet<string>,
): number | undefined {
  const direct = bindings.directPaths.get(callee);
  if (direct !== undefined && !localNames.has(callee)) return direct;
  if (bindings.pathlibConstructors.has(callee) && !localNames.has(callee)) return 1;
  const { method, owner, root } = splitCallee(callee);
  if (localNames.has(root)) return undefined;
  if (method === "open" && matchesNamespace(owner, bindings.builtinsNamespaces)) return 1;
  if (method === "Path" && matchesNamespace(owner, bindings.pathlibNamespaces)) return 1;
  if (!matchesNamespace(owner, bindings.osNamespaces)) return undefined;
  return PATH_METHOD_ARGUMENTS.get(method);
}

function inspectNetworkCall(
  file: ScannableFile,
  call: PythonCall,
  bindings: PythonBindings,
  tainted: ReadonlySet<string>,
  localNames: ReadonlySet<string>,
  findings: FindingInput[],
): void {
  const url = networkUrl(call, bindings, localNames);
  if (
    !isTaintedArgument(url, tainted) ||
    (url !== undefined && hasFixedNetworkDestination(url.raw))
  ) {
    return;
  }
  findings.push(
    finding(
      file,
      call,
      RULES.serverSideRequestForgery,
      "Tool input controls an outbound Python request URL.",
    ),
  );
}

function networkUrl(
  call: PythonCall,
  bindings: PythonBindings,
  localNames: ReadonlySet<string>,
): PythonArgument | undefined {
  const direct = bindings.directNetwork.get(call.callee);
  if (direct !== undefined && !localNames.has(call.callee)) {
    return networkUrlArgument(call.arguments, direct);
  }
  const { method, owner, root } = splitCallee(call.callee);
  if (localNames.has(root) && !bindings.networkClients.has(root)) return undefined;
  const clientFamily = bindings.networkClients.get(owner);
  const family = clientFamily ?? matchingNamespaceFamily(owner, bindings.networkNamespaces);
  return family === undefined ? undefined : networkUrlArgument(call.arguments, { family, method });
}

function networkUrlArgument(
  argumentsList: readonly PythonArgument[],
  shape: NetworkCallShape,
): PythonArgument | undefined {
  if (shape.family === "urllib") return namedOrPositional(argumentsList, "url", 0);
  const index = shape.method === "request" ? 1 : 0;
  return namedOrPositional(argumentsList, "url", index);
}

function namedOrPositional(
  argumentsList: readonly PythonArgument[],
  name: string,
  index: number,
): PythonArgument | undefined {
  return (
    argumentsList.find((argument) => argument.name === name) ??
    argumentsList.filter((argument) => argument.name === undefined)[index]
  );
}

function isTaintedArgument(
  argument: PythonArgument | undefined,
  tainted: ReadonlySet<string>,
): boolean {
  return argument !== undefined && isTainted(argument.raw, tainted);
}

function isTainted(expression: string, tainted: ReadonlySet<string>): boolean {
  return identifierReferences(expression).some((reference) => tainted.has(reference.name));
}

function hasFixedNetworkDestination(expression: string): boolean {
  const literalPrefix = formattedStringLiteralPrefix(expression);
  return (
    literalPrefix !== undefined && /^https?:\/\/(?:\[[^\]]+\]|[^/?#\s]+)[/?#]/i.test(literalPrefix)
  );
}

function formattedStringLiteralPrefix(expression: string): string | undefined {
  const normalized = expression.trim();
  const opening = /^([rRuUbBfF]{1,3})("""|'''|"|')/.exec(normalized);
  const stringPrefixes = opening?.[1];
  const delimiter = opening?.[2];
  if (
    stringPrefixes === undefined ||
    delimiter === undefined ||
    !stringPrefixes.toLowerCase().includes("f")
  ) {
    return undefined;
  }

  let cursor = stringPrefixes.length + delimiter.length;
  let prefix = "";
  while (cursor < normalized.length) {
    if (normalized.startsWith(delimiter, cursor)) return undefined;
    if (normalized.startsWith("{{", cursor)) {
      prefix += "{";
      cursor += 2;
      continue;
    }
    const character = normalized[cursor] ?? "";
    if (character === "{") return prefix;
    if (character === "\\") return undefined;
    prefix += character;
    cursor += 1;
  }
  return undefined;
}

function isSafePathExpression(
  expression: string,
  tainted: ReadonlySet<string>,
  safePaths: ReadonlySet<string>,
  bindings: PythonBindings,
): boolean {
  if (safePaths.has(expression.trim()) && !tainted.has(expression.trim())) return true;
  const references = identifierReferences(expression).filter((reference) =>
    tainted.has(reference.name),
  );
  if (references.length === 0) return false;
  const calls = extractCalls(expression, maskPythonSource(expression), 0).filter((call) =>
    isBasenameCall(call.callee, bindings),
  );
  return references.every((reference) =>
    calls.some((call) => reference.start >= call.offset && reference.end <= call.endOffset),
  );
}

function isBasenameCall(callee: string, bindings: PythonBindings): boolean {
  if (bindings.basenameFunctions.has(callee)) return true;
  const { method, owner } = splitCallee(callee);
  if (method !== "basename") return false;
  if (matchesNamespace(owner, bindings.osPathNamespaces)) return true;
  return [...bindings.osNamespaces].some((namespace) => owner === `${namespace}.path`);
}

function extractCalls(raw: string, masked: string, baseOffset: number): readonly PythonCall[] {
  const calls: PythonCall[] = [];
  const pattern = /\b[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*\s*\(/g;
  const closingParentheses = delimiterPairs(masked, "(", ")");
  for (const match of masked.matchAll(pattern)) {
    if (match.index === undefined) continue;
    const matched = match[0] ?? "";
    const open = match.index + matched.lastIndexOf("(");
    const close = closingParentheses.get(open);
    if (open < match.index || close === undefined) continue;
    const callee = matched.slice(0, matched.lastIndexOf("(")).replace(/\s+/g, "");
    const argumentsList = parseArguments(raw.slice(open + 1, close), masked.slice(open + 1, close));
    calls.push({
      arguments: argumentsList,
      callee,
      endOffset: baseOffset + close + 1,
      offset: baseOffset + match.index,
    });
  }
  return calls;
}

function delimiterPairs(
  text: string,
  opening: string,
  closing: string,
): ReadonlyMap<number, number> {
  const pairs = new Map<number, number>();
  const stack: number[] = [];
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === opening) stack.push(index);
    else if (text[index] === closing) {
      const open = stack.pop();
      if (open !== undefined) pairs.set(open, index);
    }
  }
  return pairs;
}

function parseArguments(raw: string, masked: string): readonly PythonArgument[] {
  return splitTopLevel(raw, masked, ",").flatMap((segment) => {
    if (segment.raw.trim() === "") return [];
    const equals = findTopLevelAssignment(segment.masked);
    if (equals < 0) return [{ masked: segment.masked.trim(), raw: segment.raw.trim() }];
    const name = segment.masked.slice(0, equals).trim();
    if (!IDENTIFIER.test(name)) return [{ masked: segment.masked.trim(), raw: segment.raw.trim() }];
    return [
      {
        masked: segment.masked.slice(equals + 1).trim(),
        name,
        raw: segment.raw.slice(equals + 1).trim(),
      },
    ];
  });
}

function splitTopLevel(
  raw: string,
  masked: string,
  separator: string,
): readonly { masked: string; raw: string }[] {
  const segments: { masked: string; raw: string }[] = [];
  let depth = 0;
  let start = 0;
  for (let index = 0; index < masked.length; index += 1) {
    const character = masked[index];
    if (character === "(" || character === "[" || character === "{") depth += 1;
    else if (character === ")" || character === "]" || character === "}") depth -= 1;
    else if (character === separator && depth === 0) {
      segments.push({ masked: masked.slice(start, index), raw: raw.slice(start, index) });
      start = index + 1;
    }
  }
  segments.push({ masked: masked.slice(start), raw: raw.slice(start) });
  return segments;
}

function findMatchingDelimiter(
  text: string,
  open: number,
  opening: string,
  closing: string,
): number {
  let depth = 0;
  for (let index = open; index < text.length; index += 1) {
    if (text[index] === opening) depth += 1;
    else if (text[index] === closing) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function identifierReferences(text: string, depth = 0): readonly IdentifierReference[] {
  if (depth > MAX_FORMATTED_STRING_NESTING) return [];
  const references: IdentifierReference[] = [];
  let cursor = 0;
  while (cursor < text.length) {
    const character = text[cursor] ?? "";
    if (character === "#") cursor = skipComment(text, cursor);
    else if (character === "'" || character === '"') {
      const scanned = scanStringReferences(text, cursor, false, depth);
      references.push(...scanned.references);
      cursor = scanned.end;
    } else if (IDENTIFIER_START.test(character)) {
      const scanned = scanIdentifier(text, cursor, depth);
      references.push(...scanned.references);
      cursor = scanned.end;
    } else cursor += 1;
  }
  return references;
}

function skipComment(text: string, start: number): number {
  const newline = text.indexOf("\n", start);
  return newline < 0 ? text.length : newline;
}

function scanIdentifier(text: string, start: number, depth: number): StringScan {
  let end = start + 1;
  while (end < text.length && IDENTIFIER_PART.test(text[end] ?? "")) end += 1;
  const name = text.slice(start, end);
  const quote = text[end];
  if ((quote === "'" || quote === '"') && STRING_PREFIXES.has(name.toLowerCase())) {
    return scanStringReferences(text, end, name.toLowerCase().includes("f"), depth);
  }
  const references = isVariableReference(text, start, end) ? [{ end, name, start }] : [];
  return { end, references };
}

function isVariableReference(text: string, start: number, end: number): boolean {
  const previous = nonWhitespaceBefore(text, start);
  if (previous === ".") return false;
  const nextIndex = nonWhitespaceIndexAfter(text, end);
  return text[nextIndex] !== "=" || text[nextIndex + 1] === "=";
}

function nonWhitespaceBefore(text: string, start: number): string | undefined {
  let cursor = start - 1;
  while (cursor >= 0 && /\s/.test(text[cursor] ?? "")) cursor -= 1;
  return text[cursor];
}

function nonWhitespaceIndexAfter(text: string, end: number): number {
  let cursor = end;
  while (cursor < text.length && /\s/.test(text[cursor] ?? "")) cursor += 1;
  return cursor;
}

function scanStringReferences(
  text: string,
  quoteIndex: number,
  formatted: boolean,
  depth: number,
): StringScan {
  const quote = text[quoteIndex] ?? '"';
  const delimiterLength = text.slice(quoteIndex, quoteIndex + 3) === quote.repeat(3) ? 3 : 1;
  const delimiter = quote.repeat(delimiterLength);
  const references: IdentifierReference[] = [];
  let cursor = quoteIndex + delimiterLength;
  while (cursor < text.length) {
    if (text.startsWith(delimiter, cursor)) return { end: cursor + delimiterLength, references };
    const advanced = advanceStringContent(text, cursor, formatted, references, depth);
    if (advanced !== undefined) cursor = advanced;
    else if (delimiterLength === 1 && text[cursor] === "\n") return { end: cursor, references };
    else cursor += 1;
  }
  return { end: text.length, references };
}

function advanceStringContent(
  text: string,
  cursor: number,
  formatted: boolean,
  references: IdentifierReference[],
  depth: number,
): number | undefined {
  if (text[cursor] === "\\") return cursor + 2;
  if (formatted && (text.startsWith("{{", cursor) || text.startsWith("}}", cursor))) {
    return cursor + 2;
  }
  if (!formatted || text[cursor] !== "{") return undefined;
  const replacement = scanFormattedReplacement(text, cursor + 1, depth);
  references.push(...replacement.references);
  return replacement.end;
}

function scanFormattedReplacement(text: string, start: number, nestingDepth: number): StringScan {
  let bracketDepth = 0;
  let cursor = start;
  while (cursor < text.length) {
    const character = text[cursor];
    const quotedEnd = replacementStringEnd(text, cursor);
    if (quotedEnd !== undefined) {
      cursor = quotedEnd;
      continue;
    }
    if (character === "}" && bracketDepth === 0) {
      return {
        end: cursor + 1,
        references: offsetReferences(
          identifierReferences(text.slice(start, cursor), nestingDepth + 1),
          start,
        ),
      };
    }
    bracketDepth += replacementBracketDelta(character);
    cursor += 1;
  }
  return { end: text.length, references: [] };
}

function offsetReferences(
  references: readonly IdentifierReference[],
  offset: number,
): readonly IdentifierReference[] {
  return references.map((reference) => ({
    ...reference,
    end: reference.end + offset,
    start: reference.start + offset,
  }));
}

function replacementStringEnd(text: string, cursor: number): number | undefined {
  const character = text[cursor];
  if (character !== "'" && character !== '"') return undefined;
  const triple = text.slice(cursor, cursor + 3) === character.repeat(3);
  return skipString(text, cursor, triple ? 3 : 1);
}

function replacementBracketDelta(character: string | undefined): number {
  if (character === "{" || character === "(" || character === "[") return 1;
  return character === "}" || character === ")" || character === "]" ? -1 : 0;
}

function splitCallee(callee: string): { method: string; owner: string; root: string } {
  const parts = callee.split(".");
  const method = parts.pop() ?? "";
  return { method, owner: parts.join("."), root: parts[0] ?? callee };
}

function matchesNamespace(owner: string, namespaces: ReadonlySet<string>): boolean {
  return [...namespaces].some(
    (namespace) => owner === namespace || owner.startsWith(`${namespace}.`),
  );
}

function matchingNamespaceFamily(
  owner: string,
  namespaces: ReadonlyMap<string, NetworkFamily>,
): NetworkFamily | undefined {
  for (const [namespace, family] of namespaces) {
    if (owner === namespace || owner.startsWith(`${namespace}.`)) return family;
  }
  return undefined;
}

function addToSet(set: Set<string>, value: string): boolean {
  if (set.has(value)) return false;
  set.add(value);
  return true;
}

function addNames(set: Set<string>, names: readonly string[]): boolean {
  let changed = false;
  for (const name of names) changed = addToSet(set, name) || changed;
  return changed;
}

function finding(
  file: ScannableFile,
  call: PythonCall,
  metadata: RuleMetadata,
  message: string,
): FindingInput {
  return findingAtOffset(file, call.offset, Math.max(1, call.callee.length), metadata, message);
}

function deduplicate(findings: readonly FindingInput[]): readonly FindingInput[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = `${finding.metadata.id}:${finding.line}:${finding.column}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
