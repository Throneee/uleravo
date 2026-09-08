import { capture } from "./capture.js";
import { explain } from "./explain.js";
import type { MonitorOptions } from "./options.js";
import { parseOptions } from "./options.js";
import { upload } from "./upload.js";

export interface MonitorRuntime {
  signal?: AbortSignal;
  sleep?: (milliseconds: number, signal: AbortSignal) => Promise<void>;
}

export async function runMonitor(argv: string[], runtime: MonitorRuntime = {}): Promise<number> {
  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) {
    console.log(`uleravo monitor --project DIR [--once | --watch] [--interval SECONDS]
  [--include-user] [--upload --endpoint https://HOST/api/ingest]
  [--token-env NAME]
uleravo monitor --project DIR --explain SUBJECT_ID [--include-user]

Read-only configuration posture, not runtime or effective permissions.
No commands or hooks are executed; no files are edited.
First local capture (replace the quoted path with an existing project):
  uleravo monitor --project "PATH/TO/EXISTING/PROJECT" --once
No account, endpoint or token is needed for local capture.
Defaults: once, no upload, project files only; interval 300 seconds (30..86400).
No coverage is not a secure project, even with exit 0.
--endpoint is the exact ingestion URL, including /api/ingest. HTTPS is required
except HTTP on localhost, 127.0.0.0/8, or [::1]. Redirects are never followed.
Device credential comes only from --token-env (default ULERAVO_TOKEN).
One JSON snapshot per capture on stdout; safe diagnostics on stderr.
Findings do not block agents. Exit 0 for completed capture; 2 for incomplete,
usage or upload failure. Stop foreground watch with Ctrl+C.
--explain accepts local JSON findings[].subjectId or a cloud finding.subjectId
(64 lowercase hex), not a finding ID.
Use the same project location and scope as the original capture.
It freshly reads declarations and prints a local-only report, not telemetry;
cannot combine with --upload or --watch. No credentials are resolved.
Only relative config filenames, safe selectors and static advice are printed.
Not observed is not verification of security or resolution.`);
    return 0;
  }
  let options: MonitorOptions;
  try {
    options = parseOptions(argv);
  } catch {
    console.error(
      "Invalid monitor arguments. Use --project DIR; --upload requires --endpoint. Interval: 30..86400 seconds. Credentials: --token-env NAME only. --explain requires 64 lowercase hex and cannot combine with --upload or --watch.",
    );
    return 2;
  }
  if (options.explain !== undefined) return explain(options);
  const token = options.upload ? process.env[options.tokenEnv] : undefined;
  if (options.upload && (!token || token.length > 4096 || !/^[A-Za-z0-9._~+/-]+=*$/.test(token))) {
    console.error(
      "Upload credential is missing or invalid; set the selected token environment variable.",
    );
    return 2;
  }
  const controller = new AbortController();
  const stop = () => controller.abort();
  const signal = runtime.signal
    ? AbortSignal.any([runtime.signal, controller.signal])
    : controller.signal;
  const sleep = runtime.sleep ?? wait;
  if (options.watch) {
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
  }
  let code = 0;
  try {
    do {
      if (signal.aborted) break;
      const snapshot = await capture(options);
      console.log(JSON.stringify(snapshot));
      console.error(
        "Configuration declarations only; runtime state and effective permissions are unobserved.",
      );
      if (!snapshot.complete)
        console.error(
          "Incomplete capture: one or more configurations could not be safely read or parsed.",
        );
      if (!snapshot.configurations.some((c) => c.status === "read")) {
        console.error("No coverage: no supported configuration files were read.");
      }
      let uploaded = !options.upload;
      if (options.upload) {
        for (let attempt = 0; attempt < (options.watch ? 3 : 1) && !signal.aborted; attempt++) {
          if (attempt > 0) {
            console.error("Retrying upload after bounded backoff.");
            await sleep(1000 * 2 ** (attempt - 1), signal);
            if (signal.aborted) break;
          }
          uploaded = await upload(snapshot, options.endpoint ?? "", token ?? "");
          if (uploaded) break;
        }
      }
      code = snapshot.complete && uploaded ? 0 : 2;
      if (options.watch) await sleep(options.interval * 1000, signal);
    } while (options.watch && !signal.aborted);
  } finally {
    if (options.watch) {
      process.off("SIGINT", stop);
      process.off("SIGTERM", stop);
    }
  }
  return code;
}

async function wait(milliseconds: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return;
  await new Promise<void>((resolve) => {
    const done = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, milliseconds);
    signal.addEventListener("abort", done, { once: true });
  });
}
