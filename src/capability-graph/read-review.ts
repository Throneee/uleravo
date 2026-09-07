import { constants, type Stats } from "node:fs";
import { lstat, open } from "node:fs/promises";
import path from "node:path";
import { sameOpenedFileSnapshot, samePathAndOpenedFileSnapshot } from "../scanner/files.js";
import {
  MAX_SKILL_REVIEW_RECEIPT_BYTES,
  parseSkillReviewReceipt,
  type SkillReviewReceipt,
} from "./review.js";

const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

export async function readSkillReviewReceipt(source: string): Promise<SkillReviewReceipt> {
  const resolved = path.resolve(source);
  const listed = await lstat(resolved);
  assertReceiptFile(listed);
  const handle = await open(resolved, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const opened = await handle.stat();
    assertReceiptFile(opened);
    if (!samePathAndOpenedFileSnapshot(listed, opened)) {
      throw new Error("Skill review receipt changed before it could be read safely.");
    }
    const buffer = Buffer.allocUnsafe(opened.size + 1);
    let used = 0;
    while (used < buffer.byteLength) {
      const { bytesRead } = await handle.read(buffer, used, buffer.byteLength - used, used);
      if (bytesRead === 0) break;
      used += bytesRead;
    }
    if (used > MAX_SKILL_REVIEW_RECEIPT_BYTES) {
      throw new Error("Skill review receipt exceeds the report byte limit.");
    }
    const [after, pathAfter] = await Promise.all([handle.stat(), lstat(resolved)]);
    if (
      used !== opened.size ||
      !sameOpenedFileSnapshot(opened, after) ||
      !samePathAndOpenedFileSnapshot(pathAfter, opened)
    ) {
      throw new Error("Skill review receipt changed while it was being read.");
    }
    let serialized: string;
    try {
      serialized = utf8Decoder.decode(buffer.subarray(0, used));
    } catch {
      throw new Error("Skill review receipt is not valid UTF-8.");
    }
    return parseSkillReviewReceipt(serialized);
  } finally {
    await handle.close();
  }
}

function assertReceiptFile(metadata: Stats): void {
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error("Skill review receipt must be a regular, non-linked file.");
  }
  if (metadata.size < 0 || metadata.size > MAX_SKILL_REVIEW_RECEIPT_BYTES) {
    throw new Error("Skill review receipt exceeds the report byte limit.");
  }
}
