import path from "node:path";
import { redactEvidence } from "../redact.js";

const MAX_ARTIFACT_PATH_CHARACTERS = 4_000;
// biome-ignore lint/complexity/useRegexLiterals: the constructor keeps intentional control ranges out of source text.
const UNSAFE_DISPLAY_PATTERN = new RegExp(
  "[\\u0000-\\u001f\\u007f-\\u009f\\u061c\\u200e\\u200f\\u2028\\u2029\\u202a-\\u202e\\u2066-\\u2069]",
  "u",
);

export function isPortableArtifactPath(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= MAX_ARTIFACT_PATH_CHARACTERS &&
    isWellFormedUnicode(value) &&
    value === value.normalize("NFC") &&
    !value.includes("\\") &&
    !path.posix.isAbsolute(value) &&
    !/^[A-Za-z]:[\\/]/u.test(value) &&
    !containsUnsafeArtifactText(value) &&
    value.split("/").every((segment) => segment.length > 0 && segment !== "." && segment !== "..")
  );
}

export function isSafeArtifactReportPath(value: string): boolean {
  return isPortableArtifactPath(value) && redactEvidence(value) === value;
}

export function containsUnsafeArtifactText(value: string): boolean {
  return UNSAFE_DISPLAY_PATTERN.test(value);
}

export function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= value.length) {
        return false;
      }
      const following = value.charCodeAt(index + 1);
      if (following < 0xdc00 || following > 0xdfff) {
        return false;
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}
