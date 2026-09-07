import { mkdtemp, rm, writeFile } from "node:fs/promises";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { createServer } from "node:http";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { runMonitor } from "../src/monitor/index.js";

let project: string;
let output: string[];
let server: Server | undefined;
beforeEach(async () => {
  project = await mkdtemp(path.join(os.tmpdir(), "uleravo-monitor-upload-"));
  output = [];
  vi.stubEnv("ULERAVO_TOKEN", undefined);
  vi.spyOn(console, "log").mockImplementation((line: string) => {
    output.push(line);
  });
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(async () => {
  vi.useRealTimers();
  if (server) {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) =>
      server?.close((error) => (error ? reject(error) : resolve())),
    );
    server = undefined;
  }
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  await rm(project, { recursive: true, force: true });
});
async function listen(
  handler: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<string> {
  server = createServer(handler);
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fixture server unavailable");
  return `http://127.0.0.1:${address.port}/api/ingest`;
}

it.each([undefined, "", "with space", "secret-fixture\r\nInjected: value", "x".repeat(4097)])(
  "rejects absent or malformed env credentials before making requests",
  async (token) => {
    let requests = 0;
    const endpoint = await listen((_req, res) => {
      requests++;
      res.end('{"accepted":true}');
    });
    vi.stubEnv("ULERAVO_TOKEN", token);
    expect(await runMonitor(["--project", project, "--upload", "--endpoint", endpoint])).toBe(2);
    expect(requests).toBe(0);
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining("credential"));
    expect(output.join("") + JSON.stringify(vi.mocked(console.error).mock.calls)).not.toContain(
      "secret-fixture",
    );
  },
);

it.each([
  [503, '{"error":"secret-fixture"}'],
  [401, '{"error":"secret-fixture"}'],
  [429, "{}"],
  [200, "not-json-secret-fixture"],
  [200, '{"accepted":true}'],
  [
    200,
    JSON.stringify({
      accepted: true,
      duplicate: false,
      openFindings: 0,
      padding: "x".repeat(8192),
    }),
  ],
])("reports failed or invalid upload acknowledgment safely (%i)", async (status, body) => {
  const endpoint = await listen((_req, res) => {
    res.writeHead(status);
    res.end(body);
  });
  vi.stubEnv("ULERAVO_TOKEN", "fixture-device-token");
  expect(await runMonitor(["--project", project, "--upload", "--endpoint", endpoint])).toBe(2);
  expect(console.error).toHaveBeenCalledWith(expect.stringContaining("Upload failed"));
  expect(output.join("") + JSON.stringify(vi.mocked(console.error).mock.calls)).not.toMatch(
    /secret-fixture|fixture-device-token/,
  );
});

it("gives fixed project-binding recovery advice for HTTP 409 without echoing the response", async () => {
  const endpoint = await listen((_req, res) => {
    res.writeHead(409);
    res.end('{"error":"project_conflict","message":"secret-fixture\\u001b[2J"}');
  });
  vi.stubEnv("ULERAVO_TOKEN", "fixture-device-token");
  expect(await runMonitor(["--project", project, "--upload", "--endpoint", endpoint])).toBe(2);
  expect(console.error).toHaveBeenCalledWith(
    "Upload failed (HTTP 409). If this token belongs to another project, use a separate token for this project. Keep the original project at its original path.",
  );
  expect(output.join("") + JSON.stringify(vi.mocked(console.error).mock.calls)).not.toMatch(
    /secret-fixture|fixture-device-token|project_conflict/,
  );
});

it("does not forward a device token or snapshot across redirects", async () => {
  const requests: string[] = [];
  const endpoint = await listen((req, res) => {
    requests.push(req.url ?? "");
    if (req.url === "/api/ingest") {
      res.writeHead(307, { Location: "/unexpected" });
      res.end();
    } else res.end('{"accepted":true,"duplicate":false,"openFindings":0}');
  });
  vi.stubEnv("ULERAVO_TOKEN", "fixture-device-token");
  expect(await runMonitor(["--project", project, "--upload", "--endpoint", endpoint])).toBe(2);
  expect(requests).toEqual(["/api/ingest"]);
});

it("retries transient watch uploads with bounded backoff and the same idempotency capture ID", async () => {
  const bodies: string[] = [];
  const endpoint = await listen((req, res) => {
    let body = "";
    req.on("data", (data) => {
      body += String(data);
    });
    req.on("end", () => {
      bodies.push(body);
      res.writeHead(bodies.length < 3 ? 503 : 200);
      res.end(bodies.length < 3 ? "{}" : '{"accepted":true,"duplicate":true,"openFindings":0}');
    });
  });
  vi.stubEnv("ULERAVO_TOKEN", "fixture-device-token");
  const stop = new AbortController();
  const sleeps: number[] = [];
  expect(
    await runMonitor(
      ["--project", project, "--watch", "--interval", "30", "--upload", "--endpoint", endpoint],
      {
        signal: stop.signal,
        sleep: async (ms: number) => {
          sleeps.push(ms);
          if (ms >= 30000) stop.abort();
        },
      },
    ),
  ).toBe(0);
  expect(bodies).toHaveLength(3);
  expect(new Set(bodies).size).toBe(1);
  expect(sleeps).toEqual([1000, 2000, 30000]);
  expect(output).toHaveLength(1);
});

it("bounds a stalled HTTP response body with a ten-second whole-request timeout", async () => {
  let requested: (() => void) | undefined;
  const requestSeen = new Promise<void>((resolve) => {
    requested = resolve;
  });
  const endpoint = await listen((_req, res) => {
    res.writeHead(200);
    res.flushHeaders();
    requested?.();
  });
  const realSetTimeout = setTimeout;
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  vi.stubEnv("ULERAVO_TOKEN", "fixture-device-token");
  const pending = runMonitor(["--project", project, "--upload", "--endpoint", endpoint]);
  await requestSeen;
  await vi.advanceTimersByTimeAsync(10000);
  const result = await Promise.race([
    pending,
    new Promise((resolve) => realSetTimeout(() => resolve("unbounded"), 100)),
  ]);
  expect(result).toBe(2);
  expect(console.error).toHaveBeenCalledWith(expect.stringContaining("Upload failed"));
});

it("uploads exactly the secret-free v1 snapshot only with an explicit token-env credential", async () => {
  const received: { body: string; authorization: string | undefined; url: string | undefined }[] =
    [];
  const endpoint = await listen((req, res) => {
    let body = "";
    req.on("data", (data) => {
      body += String(data);
    });
    req.on("end", () => {
      received.push({ body, authorization: req.headers.authorization, url: req.url });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ accepted: true, duplicate: false, openFindings: 1 }));
    });
  });
  await writeFile(
    path.join(project, ".mcp.json"),
    JSON.stringify({
      mcpServers: {
        privateName: {
          command: "node",
          args: ["private-command-fixture"],
          env: { PRIVATE_API_KEY: "secret-fixture" },
        },
      },
    }),
  );
  vi.stubEnv("TEST_MONITOR_TOKEN", "fixture-device-token");
  expect(
    await runMonitor([
      "--project",
      project,
      "--upload",
      "--endpoint",
      endpoint,
      "--token-env",
      "TEST_MONITOR_TOKEN",
    ]),
  ).toBe(0);
  expect(received).toHaveLength(1);
  const wire = JSON.parse(received[0]?.body ?? "null");
  expect(wire).toEqual(JSON.parse(output.at(-1) ?? "null"));
  expect(Object.keys(wire).sort()).toEqual([
    "captureId",
    "capturedAt",
    "complete",
    "configurations",
    "findings",
    "projectId",
    "schemaVersion",
  ]);
  expect(received[0]?.authorization).toBe("Bearer fixture-device-token");
  expect(received[0]?.url).toBe("/api/ingest");
  expect(received[0]?.body).not.toMatch(
    /secret-fixture|privateName|private-command|PRIVATE_API_KEY|fixture-device-token/,
  );
  expect(console.error).toHaveBeenCalledWith(expect.stringContaining("Upload accepted"));
});
