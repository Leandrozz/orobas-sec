// El canal se abre sólo en la IP que declaró el operador; el modelo no elige dónde escuchar.
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { isIP, type AddressInfo } from "node:net";
import type { Artifacts } from "./artifacts.ts";

export interface ListenerConfig {
  host: string;
  port?: number;
}

export interface ListenerHit {
  at: string;
  method: string;
  remoteAddress: string;
  artifact: string;
}

export interface ProbeListener {
  url: string;
  hits: ListenerHit[];
  wait(ms: number, signal: AbortSignal): Promise<void>;
  close(): Promise<void>;
}

export async function startProbeListener(config: ListenerConfig, artifacts: Artifacts): Promise<ProbeListener> {
  const host = config.host;
  const port = config.port ?? 0;
  // Un comodín admitiría interfaces que el operador no declaró alcanzables.
  let canonical = host;
  try { if (isIP(host) === 6) canonical = new URL(`http://[${host}]/`).hostname; } catch { canonical = ""; }
  if (!isIP(host) || !canonical || ["0.0.0.0", "[::]", "[::ffff:0:0]"].includes(canonical)) {
    throw new Error("El oyente necesita una IP local concreta declarada por el operador; no admite comodines ni nombres");
  }
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error("Puerto del oyente inválido: usá 0 a 65535");
  const path = `/cyber-outbound/${randomBytes(24).toString("hex")}`;
  const hits: ListenerHit[] = [];
  const waiting = new Set<() => void>();
  let received = 0;
  const server = createServer({ maxHeaderSize: 8192 }, (request, response) => {
    if (request.url?.split("?")[0] !== path || received >= 10) {
      response.writeHead(404, { connection: "close" });
      response.end();
      request.resume();
      return;
    }
    received++;
    const chunks: Buffer[] = [];
    let bytes = 0;
    let saved = 0;
    let done = false;
    const finish = (status: number) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      const at = new Date().toISOString();
      const remoteAddress = request.socket.remoteAddress ?? "";
      const headers = { "content-type": "text/plain", connection: "close" };
      const artifact = artifacts.put(JSON.stringify({
        at, remoteAddress,
        request: { method: request.method, url: request.url, headers: request.headers, body: Buffer.concat(chunks).toString("utf8"), bodyBytes: bytes, truncated: bytes > saved },
        response: { status, headers, body: "" },
      }), "application/json", "outbound_listener").hash;
      hits.push({ at, method: request.method ?? "GET", remoteAddress, artifact });
      response.writeHead(status, headers);
      response.end();
      for (const resolve of waiting) resolve();
    };
    // Un callback lento o enorme no puede retener el oyente ni llenar los artefactos.
    const timer = setTimeout(() => { finish(408); request.destroy(); }, 2000);
    request.on("data", (chunk: Buffer) => {
      if (done) return;
      bytes += chunk.length;
      const part = chunk.subarray(0, Math.max(0, 4096 - saved));
      chunks.push(part);
      saved += part.length;
      if (bytes > 4096) { finish(413); request.resume(); }
    });
    request.on("end", () => finish(204));
    request.on("error", () => { clearTimeout(timer); });
    request.on("close", () => { clearTimeout(timer); });
  });
  server.maxConnections = 16;
  server.requestTimeout = 2000;
  server.headersTimeout = 2000;
  server.timeout = 2000;
  server.keepAliveTimeout = 1;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host, port, exclusive: true }, () => { server.off("error", reject); resolve(); });
  });
  return {
    url: `http://${isIP(host) === 6 ? `[${host}]` : host}:${(server.address() as AddressInfo).port}${path}`,
    hits,
    wait: (ms, signal) => new Promise<void>((resolve) => {
      if (hits.length || signal.aborted || ms <= 0) { resolve(); return; }
      const done = () => {
        clearTimeout(timer);
        waiting.delete(done);
        signal.removeEventListener("abort", done);
        resolve();
      };
      const timer = setTimeout(done, Math.min(ms, 5000));
      waiting.add(done);
      signal.addEventListener("abort", done, { once: true });
    }),
    close: async () => {
      for (const resolve of waiting) resolve();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
