import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const repositoryRoot = path.resolve(path.dirname(scriptPath), "..");
const workflowPath = path.join(repositoryRoot, "examples", "github-actions", "uleravo-observe.yml");
const expectedProductPrefix = "Throneee/uleravo@";

await main(process.argv.slice(2)).catch((error) => {
  process.stderr.write(`publication check: ${safeErrorMessage(error)}\n`);
  process.exitCode = 1;
});

async function main(argv) {
  const expectedProductSha = parseExpectedProductSha(argv);
  const workflow = await readFile(workflowPath, "utf8");
  const references = [...workflow.matchAll(/^[^\S\r\n]*uses:[^\S\r\n]+([^\s#]+)/gmu)].map(
    (match) => match[1],
  );
  if (references.length !== 3 || references.some((reference) => reference === undefined)) {
    throw new Error("The observation workflow must contain exactly three Action references.");
  }
  if (workflow.includes("PUBLIC_COMMIT_A") || workflow.includes("OWNER/REPOSITORY")) {
    throw new Error("Commit B must replace the staged Commit A placeholder before publication.");
  }
  if (references.some((reference) => !/^[^@\s]+@[0-9a-f]{40}$/u.test(reference))) {
    throw new Error(
      "Every observation-workflow Action must be pinned to a full 40-hex commit SHA.",
    );
  }
  const productReferences = references.filter((reference) =>
    reference.startsWith(expectedProductPrefix),
  );
  if (productReferences.length !== 1) {
    throw new Error("The observation workflow must pin exactly one Throneee/uleravo Action.");
  }
  if (
    expectedProductSha !== undefined &&
    productReferences[0] !== `${expectedProductPrefix}${expectedProductSha}`
  ) {
    throw new Error(
      `The observation workflow must pin the reviewed Uleravo commit ${expectedProductSha}.`,
    );
  }
  process.stdout.write("Final publication Action pins validated.\n");
}

function parseExpectedProductSha(argv) {
  if (argv.length === 0) {
    return undefined;
  }
  if (
    argv.length !== 2 ||
    argv[0] !== "--expected-product-sha" ||
    !/^[0-9a-f]{40}$/u.test(argv[1] ?? "")
  ) {
    throw new Error(
      "Usage: node scripts/check-publication-ready.mjs [--expected-product-sha <40-hex-sha>]",
    );
  }
  return argv[1];
}

function safeErrorMessage(error) {
  return error instanceof Error
    ? error.message.replace(/[\r\n\u2028\u2029]/gu, " ")
    : "Unknown error";
}
