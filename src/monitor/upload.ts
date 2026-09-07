import type { Snapshot } from "./types.js";

export async function upload(
  snapshot: Snapshot,
  endpoint: string,
  token: string,
): Promise<boolean> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      redirect: "manual",
      credentials: "omit",
      cache: "no-store",
      signal: controller.signal,
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(snapshot),
    });
    if (!response.ok) {
      await response.body?.cancel();
      const advice =
        response.status === 409
          ? " If this token belongs to another project, use a separate token for this project. Keep the original project at its original path."
          : "";
      console.error(`Upload failed (HTTP ${response.status}).${advice}`);
      return false;
    }
    const reader = response.body?.getReader();
    if (!reader) throw new Error("acknowledgment");
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > 8192) throw new Error("acknowledgment");
        chunks.push(value);
      }
    } finally {
      await reader.cancel();
    }
    const acknowledgment: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (
      acknowledgment !== null &&
      typeof acknowledgment === "object" &&
      "accepted" in acknowledgment &&
      acknowledgment.accepted === true &&
      "duplicate" in acknowledgment &&
      typeof acknowledgment.duplicate === "boolean" &&
      "openFindings" in acknowledgment &&
      typeof acknowledgment.openFindings === "number" &&
      Number.isSafeInteger(acknowledgment.openFindings) &&
      acknowledgment.openFindings >= 0
    ) {
      console.error("Upload accepted.");
      return true;
    }
  } catch {
    /* Never expose response bodies, exception messages, or credentials. */
  } finally {
    clearTimeout(timeout);
  }
  console.error("Upload failed (network or invalid acknowledgment).");
  return false;
}
