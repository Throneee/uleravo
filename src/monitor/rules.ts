import type { Harness } from "./types.js";

// Deliberately inspect argv only. Never invoke or expand launchers or shells.
export function mutableLauncher(server: Record<string, unknown>): boolean {
  if (typeof server.command !== "string") return false;
  const command = server.command
    .split(/[\\/]/)
    .at(-1)
    ?.replace(/\.(?:cmd|exe)$/i, "")
    .toLowerCase();
  if (command !== "npx" && command !== "uvx") return false;
  const args: string[] = Array.isArray(server.args)
    ? server.args.filter((a): a is string => typeof a === "string")
    : [];
  const packages: string[] = [];
  let positional: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] ?? "";
    const option = command === "npx" ? "--package" : "--from";
    if (arg === option || (command === "npx" && arg === "-p")) packages.push(args[++i] ?? "");
    else if (arg.startsWith(`${option}=`)) packages.push(arg.slice(option.length + 1));
    else if (command === "uvx" && ["--python", "-p"].includes(arg)) i++;
    else if (["-y", "--yes", "--no", "--quiet", "-q", "--offline", "--"].includes(arg)) continue;
    else if (arg.startsWith("-")) return true;
    else {
      positional = arg;
      break;
    }
  }
  if (!packages.length) {
    // uvx's positional command@version is shorthand, not --from syntax.
    const spec = positional ?? "";
    packages.push(command === "uvx" ? spec.replace(/@(?=\d)/, "==") : spec);
  }
  const pinned =
    command === "npx"
      ? /^(?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+@\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/i
      : /^[a-z0-9_.-]+(?:\[[a-z0-9_,.-]+\])?==\d+(?:\.\d+)+(?:[a-z]+\d+)?$/i;
  return packages.some((pkg) => !pinned.test(pkg));
}

export function literalCredential(config: Record<string, unknown>, harness: Harness): boolean {
  const sensitive =
    /(?:token|secret|password|passwd|api[_-]?key|authorization|credential|cookie|auth)/i;
  const reference =
    harness === "claude-code"
      ? /^(?:Bearer\s+|Basic\s+)?\$\{[A-Za-z_][A-Za-z0-9_]*\}$/i
      : harness === "cursor"
        ? /^(?:Bearer\s+|Basic\s+)?\$\{env:[A-Za-z_][A-Za-z0-9_]*\}$/i
        : /$^/;
  const tokens = ["token", "bearer_token", "api_key", "apiKey", "password", "client_secret"];
  if (
    tokens.some(
      (key) =>
        typeof config[key] === "string" && config[key] !== "" && !reference.test(config[key]),
    )
  )
    return true;
  const oauth = config.oauth;
  if (harness === "codex" && oauth && typeof oauth === "object" && !Array.isArray(oauth)) {
    const secret = (oauth as Record<string, unknown>).client_secret;
    if (typeof secret === "string" && secret.trim() !== "") return true;
  }
  for (const field of ["env", "headers", "http_headers", "auth"]) {
    const entries = config[field];
    if (entries && typeof entries === "object" && !Array.isArray(entries)) {
      if (
        Object.entries(entries).some(
          ([key, value]) =>
            typeof value === "string" &&
            value.trim() !== "" &&
            (sensitive.test(key) || /^(?:Bearer|Basic)\s+/i.test(value)) &&
            !reference.test(value),
        )
      )
        return true;
    }
  }
  return false;
}
