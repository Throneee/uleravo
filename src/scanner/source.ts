import ts from "typescript";
import type { FindingInput, RuleMetadata, SourceLocation } from "../domain.js";
import { findPrivateKeyRanges, type PrivateKeyRange, redactEvidence } from "../redact.js";
import type { ScannableFile } from "./files.js";

const MAX_EVIDENCE_LENGTH = 240;
const MAX_EVIDENCE_SNIPPETS_PER_FILE = 64;
const evidenceCounts = new WeakMap<ScannableFile, number>();
const lineStartsByFile = new WeakMap<ScannableFile, readonly number[]>();
const privateKeyRangesByFile = new WeakMap<ScannableFile, readonly PrivateKeyRange[]>();
const redactedLinesByFile = new WeakMap<ScannableFile, Map<number, string>>();

export function parseSource(file: ScannableFile): ts.SourceFile {
  return ts.createSourceFile(
    file.relativePath,
    file.text,
    ts.ScriptTarget.Latest,
    true,
    scriptKind(file.relativePath),
  );
}

export function findingAtNode(
  file: ScannableFile,
  sourceFile: ts.SourceFile,
  node: ts.Node,
  metadata: RuleMetadata,
  message: string,
): FindingInput {
  reserveEvidenceSnippet(file);
  const location = locationAtNode(file, sourceFile, node);
  return {
    ...location,
    evidence: evidenceAt(file, node.getStart(sourceFile)),
    message: safeFindingMessage(file, node.getStart(sourceFile), message),
    metadata,
  };
}

export function findingAtOffset(
  file: ScannableFile,
  offset: number,
  length: number,
  metadata: RuleMetadata,
  message: string,
): FindingInput {
  reserveEvidenceSnippet(file);
  const location = locationAtOffset(file, offset, offset + length);
  return {
    ...location,
    evidence: evidenceAt(file, offset),
    message: safeFindingMessage(file, offset, message),
    metadata,
  };
}

export function findingAtRedactedOffset(
  file: ScannableFile,
  offset: number,
  length: number,
  metadata: RuleMetadata,
  message: string,
): FindingInput {
  reserveEvidenceSnippet(file);
  const location = locationAtOffset(file, offset, offset + length);
  return {
    ...location,
    evidence: evidenceAt(file, offset, { end: offset + length, start: offset }),
    message: safeFindingMessage(file, offset, message),
    metadata,
  };
}

export function locationAtNode(
  file: ScannableFile,
  sourceFile: ts.SourceFile,
  node: ts.Node,
): SourceLocation {
  const start = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  const end = sourceFile.getLineAndCharacterOfPosition(node.getEnd());
  return {
    column: start.character + 1,
    endColumn: end.character + 1,
    endLine: end.line + 1,
    file: file.relativePath,
    line: start.line + 1,
  };
}

export function locationAtOffset(
  file: ScannableFile,
  startOffset: number,
  endOffset: number,
): SourceLocation {
  const start = lineAndColumn(file, startOffset);
  const end = lineAndColumn(file, endOffset);
  return {
    column: start.column,
    endColumn: end.column,
    endLine: end.line,
    file: file.relativePath,
    line: start.line,
  };
}

export function literalText(node: ts.Node | undefined): string | undefined {
  if (
    node !== undefined &&
    (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node))
  ) {
    return node.text;
  }
  return undefined;
}

export function propertyName(node: ts.PropertyName | undefined): string | undefined {
  if (node === undefined) {
    return undefined;
  }
  if (ts.isIdentifier(node) || ts.isStringLiteral(node) || ts.isNumericLiteral(node)) {
    return node.text;
  }
  return undefined;
}

export function callName(expression: ts.LeftHandSideExpression): string | undefined {
  if (ts.isIdentifier(expression)) {
    return expression.text;
  }
  if (ts.isPropertyAccessExpression(expression)) {
    return expression.name.text;
  }
  return undefined;
}

export function walk(node: ts.Node, visitor: (node: ts.Node) => void): void {
  visitor(node);
  node.forEachChild((child) => walk(child, visitor));
}

function scriptKind(filePath: string): ts.ScriptKind {
  if (filePath.endsWith(".tsx")) {
    return ts.ScriptKind.TSX;
  }
  if (filePath.endsWith(".jsx")) {
    return ts.ScriptKind.JSX;
  }
  if (/\.(?:c|m)?js$/.test(filePath)) {
    return ts.ScriptKind.JS;
  }
  return ts.ScriptKind.TS;
}

function evidenceAt(
  file: ScannableFile,
  offset: number,
  sensitiveRange?: { readonly end: number; readonly start: number },
): string {
  const text = file.text;
  const lineStart = text.lastIndexOf("\n", Math.max(0, offset - 1)) + 1;
  const nextBreak = text.indexOf("\n", offset);
  const lineEnd = nextBreak === -1 ? text.length : nextBreak;
  let line = text.slice(lineStart, lineEnd);
  let anchor = Math.max(0, Math.min(line.length, offset - lineStart));
  const ranges = privateKeyRanges(file).filter(
    (range) => range.start < lineEnd && range.end > lineStart,
  );
  if (sensitiveRange !== undefined) {
    ranges.push(sensitiveRange);
  }
  if (ranges.length > 0) {
    ({ anchor, line } = redactLineRanges(line, lineStart, lineEnd, anchor, ranges));
    if (sensitiveRange !== undefined) {
      const sensitiveValue = text.slice(sensitiveRange.start, sensitiveRange.end);
      if (sensitiveValue.length > 0) {
        line = line.replaceAll(sensitiveValue, "<redacted>");
      }
    }
  }
  const prefix = line.slice(0, anchor);
  line = ranges.length === 0 ? cachedRedactedLine(file, lineStart, line) : redactEvidence(line);
  anchor = Math.min(line.length, redactEvidence(prefix).length);
  const leadingWhitespace = line.length - line.trimStart().length;
  line = line.trim();
  anchor = Math.max(0, Math.min(line.length, anchor - leadingWhitespace));
  if (line.length <= MAX_EVIDENCE_LENGTH) {
    return line;
  }
  const contextBefore = Math.floor(MAX_EVIDENCE_LENGTH / 3);
  const start = Math.min(Math.max(0, anchor - contextBefore), line.length - MAX_EVIDENCE_LENGTH);
  const end = start + MAX_EVIDENCE_LENGTH;
  let evidence = line.slice(start, end);
  if (start > 0) {
    evidence = `…${evidence.slice(1)}`;
  }
  if (end < line.length) {
    evidence = `${evidence.slice(0, -1)}…`;
  }
  return evidence;
}

function reserveEvidenceSnippet(file: ScannableFile): void {
  const count = evidenceCounts.get(file) ?? 0;
  if (count >= MAX_EVIDENCE_SNIPPETS_PER_FILE) {
    throw new Error(
      `Per-file evidence limit exceeded (${MAX_EVIDENCE_SNIPPETS_PER_FILE.toString()} findings).`,
    );
  }
  evidenceCounts.set(file, count + 1);
}

function cachedRedactedLine(file: ScannableFile, lineStart: number, line: string): string {
  let cache = redactedLinesByFile.get(file);
  if (cache === undefined) {
    cache = new Map();
    redactedLinesByFile.set(file, cache);
  }
  const cached = cache.get(lineStart);
  if (cached !== undefined) {
    return cached;
  }
  const redacted = redactEvidence(line);
  cache.set(lineStart, redacted);
  return redacted;
}

function redactLineRanges(
  originalLine: string,
  lineStart: number,
  lineEnd: number,
  originalAnchor: number,
  ranges: readonly { readonly end: number; readonly start: number }[],
): { anchor: number; line: string } {
  const merged = mergeLineRanges(ranges, lineStart, lineEnd);
  let anchor = originalAnchor;
  let line = originalLine;
  for (const range of merged.toReversed()) {
    const relativeStart = range.start - lineStart;
    const relativeEnd = range.end - lineStart;
    line = `${line.slice(0, relativeStart)}<redacted>${line.slice(relativeEnd)}`;
    if (anchor >= relativeStart && anchor < relativeEnd) {
      anchor = relativeStart;
    } else if (anchor >= relativeEnd) {
      anchor += "<redacted>".length - (relativeEnd - relativeStart);
    }
  }
  return { anchor, line };
}

function mergeLineRanges(
  ranges: readonly { readonly end: number; readonly start: number }[],
  lineStart: number,
  lineEnd: number,
): Array<{ end: number; start: number }> {
  const clipped = ranges
    .map((range) => ({
      end: Math.min(lineEnd, range.end),
      start: Math.max(lineStart, range.start),
    }))
    .filter((range) => range.start < range.end)
    .sort((left, right) => left.start - right.start || left.end - right.end);
  const merged: Array<{ end: number; start: number }> = [];
  for (const range of clipped) {
    const previous = merged.at(-1);
    if (previous !== undefined && range.start <= previous.end) {
      previous.end = Math.max(previous.end, range.end);
    } else {
      merged.push(range);
    }
  }
  return merged;
}

function privateKeyRanges(file: ScannableFile): readonly PrivateKeyRange[] {
  const cached = privateKeyRangesByFile.get(file);
  if (cached !== undefined) {
    return cached;
  }
  const ranges = findPrivateKeyRanges(file.text);
  privateKeyRangesByFile.set(file, ranges);
  return ranges;
}

function safeFindingMessage(file: ScannableFile, offset: number, message: string): string {
  return privateKeyRanges(file).some((range) => offset >= range.start && offset < range.end)
    ? "A rule matched content inside a redacted private-key block."
    : message;
}

function lineAndColumn(file: ScannableFile, offset: number): { column: number; line: number } {
  const starts = cachedLineStarts(file);
  const boundedOffset = Math.max(0, Math.min(offset, file.text.length));
  let low = 0;
  let high = starts.length;
  while (low + 1 < high) {
    const middle = Math.floor((low + high) / 2);
    if ((starts[middle] ?? 0) <= boundedOffset) {
      low = middle;
    } else {
      high = middle;
    }
  }
  const lineStart = starts[low] ?? 0;
  return { column: boundedOffset - lineStart + 1, line: low + 1 };
}

function cachedLineStarts(file: ScannableFile): readonly number[] {
  const cached = lineStartsByFile.get(file);
  if (cached !== undefined) {
    return cached;
  }
  const starts = [0];
  for (let index = 0; index < file.text.length; index += 1) {
    if (file.text.charCodeAt(index) === 10) {
      starts.push(index + 1);
    }
  }
  lineStartsByFile.set(file, starts);
  return starts;
}
