// Sonda WebSocket: handshake acotado contra un endpoint del alcance. Cuatro variantes (control con
// identidad y Origin correcto, sin identidad, Origin ajeno, subprotocolo ajeno) y comparación
// contra el control. Sin dependencias: el upgrade se hace con http.request. Ningún mensaje de
// aplicación se manda (nada cambia estado en el objetivo): lo que se prueba es quién puede abrir
// el canal. Una variante aceptada sola no es un hallazgo: es una señal para confirmar.
import { request as httpRequest, type IncomingMessage } from "node:http";
import type { Tool, ToolResult } from "./agent.ts";
import { randomUUID } from "node:crypto";
import type { Artifacts } from "./artifacts.ts";
import type { HttpClient } from "./http.ts";

const str = (extra: object = {}) => ({ type: "string", ...extra });
const int = (extra: object = {}) => ({ type: "integer", ...extra });
const obj = (properties: Record<string, object>, required: string[]) => ({ type: "object", properties, required });
const finish = (text: string, details: Record<string, unknown> = {}): ToolResult => ({ text, details });

interface Handshake {
  ok: boolean;
  status?: number;
  rejection?: string;
  subprotocol?: string;
  ms: number;
}

/** Handshake manual de WebSocket sobre http.request con upgrade. Sin librerías: el canal se cierra apenas responde. */
function handshake(url: string, headers: Record<string, string>, timeoutMs: number, signal: AbortSignal): Promise<Handshake> {
  const started = Date.now();
  return new Promise((resolve) => {
    let settled = false;
    const close = (result: Omit<Handshake, "ms">, socket?: { destroy(): void }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket?.destroy();
      resolve({ ...result, ms: Date.now() - started });
    };
    const timer = setTimeout(() => close({ ok: false, rejection: `sin respuesta en ${timeoutMs} ms` }), timeoutMs);
    signal.addEventListener("abort", () => close({ ok: false, rejection: "cancelado" }), { once: true });
    const key = randomUUID().replace(/-/g, "");
    const inner = httpRequest(url.replace(/^ws/, "http"), {
      headers: {
        connection: "Upgrade",
        upgrade: "websocket",
        "sec-websocket-key": key,
        "sec-websocket-version": "13",
        ...headers,
      },
      timeout: timeoutMs,
    });
    inner.on("upgrade", (response: IncomingMessage, socket) => {
      close({ ok: true, status: response.statusCode, subprotocol: response.headers["sec-websocket-protocol"] as string | undefined }, socket);
    });
    inner.on("response", (response: IncomingMessage) => {
      // Sin upgrade: el servidor respondió HTTP común (403, 400, 200 con HTML): es un rechazo con código.
      response.resume();
      close({ ok: false, status: response.statusCode, rejection: response.statusCode === 101 ? "" : "sin upgrade" }, undefined);
    });
    inner.on("timeout", () => close({ ok: false, rejection: "tiempo de espera del handshake" }, inner.socket ?? undefined));
    inner.on("error", (error: Error) => close({ ok: false, rejection: String(error.message ?? error).slice(0, 120) }));
    inner.end();
  });
}

export interface WsProbeContext {
  http: HttpClient;
  artifacts: Artifacts;
}

export function createWsProbe({ http, artifacts }: WsProbeContext): import("./agent.ts").Tool {
  return {
    name: "ws_probe",
    label: "Sonda WebSocket",
    description:
      "Prueba el handshake de un endpoint WebSocket con cuatro variantes: control (con identidad y Origin correcto), sin identidad, con Origin ajeno (cross-site WebSocket) y con un subprotocolo no declarado. Compara cada una contra el control y señala las que el servidor acepta igual. " +
      "No manda mensajes de aplicación: lo que se prueba es quién puede abrir el canal. Una variante aceptada sola no es un hallazgo: confirmalo con una prueba propia y registrá candidato con evidencia.",
    parameters: obj({ url: str({ description: "URL ws:// o wss:// del endpoint" }), identity: str(), origin: str({ description: "Origin correcto del sitio; por defecto el propio de la URL" }), timeoutMs: { type: "integer", minimum: 500, maximum: 10_000, description: "Por defecto 4000" } }, ["url"]),
    execute: async (params, signal) => {
      const url = String(params.url ?? "").trim();
      if (!/^wss?:\/\//i.test(url)) throw new Error("Pasa la URL del endpoint WebSocket con su esquema ws:// o wss://");
      if (!http.inScope(url)) throw new Error(`Fuera del alcance: ${url}. El alcance decide: definilo con /scope.`);
      if (!params.identity && !http.identityNames().length) throw new Error("Sin identidades: cargá una con /identity para tener control con credenciales; sin identidad no hay contraqué comparar el handshake.");
      const timeout = Math.min(10_000, Math.max(500, Number(params.timeoutMs) || 4_000));
      const identity = params.identity ? http.identityHeaders(params.identity) : undefined;
      const origin = params.origin ?? new URL(url.replace(/^ws/, "http")).origin;
      const variants: Array<{ label: string; headers: Record<string, string> }> = [
        { label: "control (identidad + origin correcto)", headers: { ...identity, origin } },
        { label: "sin identidad", headers: { origin } },
        { label: "origin ajeno", headers: { ...identity, origin: "https://sitio-ajeno.invalid" } },
        { label: "subprotocolo ajeno", headers: { ...identity, origin, "sec-websocket-protocol": "orobas-sonda" } },
      ];
      const results: Array<{ label: string } & Handshake> = [];
      for (const variant of variants) results.push({ label: variant.label, ...(await handshake(url, variant.headers, timeout, signal)) });
      const artifact = artifacts.put(JSON.stringify({ url, variants: results }, null, 1), "application/json", "ws_probe");
      const by = (label: string) => results.find((row) => row.label.startsWith(label));
      const notes: string[] = [];
      if (results.find((row) => row.label.startsWith("origin ajeno"))?.ok) notes.push("acepta un Origin ajeno: revisá si el canal valida sesión; un cross-site WebSocket (CSWSH) se confirma con una página ajena real que abra el canal, no acá");
      if (results.find((row) => row.label === "sin identidad")?.ok && by("control")?.ok) notes.push("acepta la conexión sin credenciales: compará qué datos fluyen con y sin identidad antes de afirmar nada");
      if (results.find((row) => row.label.startsWith("subprotocolo"))?.ok) notes.push("acepta un subprotocolo no declarado");
      const line = (row: (typeof results)[number]) => `${row.label.padEnd(34)} ${row.ok ? `ACEPTADO${row.subprotocol ? ` (protocolo ${row.subprotocol})` : ""}` : row.status ? `rechazado ${row.status}` : `rechazado (${row.rejection})`}`;
      return finish(
        `Handshake de ${url}:\n${results.map(line).join("\n")}\n${notes.length ? `Señales: ${notes.join("; ")}. Confirmá con una prueba propia y registrá candidato con evidencia: una conexión aceptada sola no es un hallazgo.` : "Sin señales: el handshake rechaza lo que debía rechazar."}\nArtefacto: ${artifact.hash}`,
        { url, variantes: results.length, aceptadas: results.filter((row) => row.ok).length, artefacto: artifact.hash },
      );
    },
  };
}