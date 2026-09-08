export interface MonitorOptions {
  project: string;
  includeUser: boolean;
  watch: boolean;
  interval: number;
  upload: boolean;
  endpoint: string | undefined;
  tokenEnv: string;
  explain?: string;
}

export function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "[::1]" || /^127\.\d+\.\d+\.\d+$/.test(hostname);
}

export function parseOptions(argv: string[]): MonitorOptions {
  const flags = new Set(["--include-user", "--watch", "--once", "--upload"]);
  const values = new Set(["--project", "--interval", "--endpoint", "--token-env", "--explain"]);
  const parsed = new Map<string, string>();
  for (let i = 0; i < argv.length; i++) {
    const key = argv[i] ?? "";
    if (parsed.has(key)) throw new Error("usage");
    if (flags.has(key)) parsed.set(key, "true");
    else if (values.has(key)) {
      const value = argv[++i];
      if (
        !value ||
        value.startsWith("--") ||
        Array.from(value).some((char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127)
      )
        throw new Error("usage");
      parsed.set(key, value);
    } else throw new Error("usage");
  }
  const project = parsed.get("--project");
  const intervalText = parsed.get("--interval") ?? "300";
  const interval = Number(intervalText);
  const tokenEnv = parsed.get("--token-env") ?? "ULERAVO_TOKEN";
  const endpoint = parsed.get("--endpoint");
  const explain = parsed.get("--explain");
  if (
    !project ||
    !/^\d+$/.test(intervalText) ||
    interval < 30 ||
    interval > 86400 ||
    !/^[A-Za-z_][A-Za-z0-9_]*$/.test(tokenEnv) ||
    (parsed.has("--once") && parsed.has("--watch")) ||
    (parsed.has("--upload") && !endpoint) ||
    (explain !== undefined &&
      (!/^[a-f0-9]{64}$/.test(explain) || parsed.has("--upload") || parsed.has("--watch")))
  )
    throw new Error("usage");
  if (endpoint) {
    const url = new URL(endpoint);
    if (
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback(url.hostname)))
    ) {
      throw new Error("usage");
    }
  }
  return {
    project,
    includeUser: parsed.has("--include-user"),
    watch: parsed.has("--watch"),
    interval,
    upload: parsed.has("--upload"),
    endpoint,
    tokenEnv,
    ...(explain !== undefined ? { explain } : {}),
  };
}
