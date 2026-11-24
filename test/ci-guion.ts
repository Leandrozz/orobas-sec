// Ayudas para probar «cyber ci» de punta a punta sin claves ni modelos reales: un proveedor simulado con guion (el
// agente principal y el verificador deciden qué herramienta llamar mirando lo que ya pasó), un laboratorio HTTP
// propio con un IDOR que se puede «arreglar», un tercero que cuenta si alguien lo tocó, y repositorios de prueba.
import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import type { AssistantMessage, LlmRequest, Message } from "../src/llm.ts";
import type { Provider } from "../src/providers.ts";

export interface Paso {
  texto?: string;
  llamadas?: Array<{ name: string; arguments: object }>;
  falla?: { mensaje: string; agotado?: boolean };
  demora?: number;
}

export interface Contexto {
  worker: string;
  /** Pasos ya dados por este worker en este pedido (respuestas del asistente en el historial). */
  paso: number;
  mensajes: Message[];
  /** El primer mensaje del usuario (la consigna o el candidato). */
  primero: string;
  /** Los ids hN de los resultados de herramientas, en orden. */
  ids: string[];
  /** Los resultados de herramientas, en orden. */
  resultados: Array<{ nombre: string; texto: string; error: boolean }>;
}

/** Un proveedor que responde según el guion. Las tarifas son inventadas (USD por millón), para probar los topes. */
export function proveedorGuion(guion: (c: Contexto) => Paso, tarifas = { input: 1, output: 2, cacheRead: 0.5, cacheWrite: 0 }): Provider & { pedidos: Array<{ worker: string; system: string; primero: string }> } {
  const pedidos: Array<{ worker: string; system: string; primero: string }> = [];
  const transport = async (pedido: LlmRequest): Promise<AssistantMessage> => {
    const worker = pedido.tags?.worker ?? "principal";
    const mensajes = pedido.messages;
    const primero = String((mensajes.find((m) => m.role === "user") as { content?: unknown } | undefined)?.content ?? "");
    pedidos.push({ worker, system: pedido.system, primero });
    const resultados = mensajes.filter((m) => m.role === "tool").map((m) => ({ nombre: (m as { name: string }).name, texto: String((m as { content: unknown }).content), error: !!(m as { isError?: boolean }).isError }));
    const ids = resultados.map((r) => /^(h\d+) /.exec(r.texto)?.[1]).filter((x): x is string => !!x);
    const paso = guion({ worker, paso: mensajes.filter((m) => m.role === "assistant").length, mensajes, primero, ids, resultados });
    if (paso.demora) await new Promise((fin, mal) => {
      const t = setTimeout(fin, paso.demora);
      pedido.signal?.addEventListener("abort", () => { clearTimeout(t); mal(new Error("cortado")); }, { once: true });
    }).catch(() => undefined);
    const base = { role: "assistant" as const, provider: pedido.model.provider, model: pedido.model.id, at: Date.now(), requestId: `guion:${randomUUID()}` };
    if (pedido.signal?.aborted) return { ...base, content: "", toolCalls: [], stopReason: "aborted", errorMessage: "Turno detenido" };
    if (paso.falla) return { ...base, content: "", toolCalls: [], stopReason: "error", errorMessage: paso.falla.mensaje, ...(paso.falla.agotado ? { exhausted: true } : {}) };
    const toolCalls = (paso.llamadas ?? []).map((c, k) => ({ id: `c${pedidos.length}_${k}`, name: c.name, arguments: JSON.stringify(c.arguments) }));
    const tam = (v: unknown) => Math.ceil(JSON.stringify(v).length / 4);
    return { ...base, content: paso.texto ?? "", toolCalls, stopReason: toolCalls.length ? "toolUse" : "stop", usage: { input: tam([pedido.system, mensajes, pedido.tools]), cacheRead: 0, cacheWrite: 0, output: tam([paso.texto, toolCalls]) } };
  };
  return { model: { provider: "guion", id: "guion-1", baseUrl: "", cost: tarifas, maxTokens: 2048 }, transport, account: "guion", pedidos };
}

export interface Laboratorio {
  url: string;
  server: Server;
  estado: { arreglado: boolean; metodos: string[]; pedidos: number };
  cerrar(): Promise<void>;
}

/**
 * Tienda de prueba: ana (token de ana) y beto. GET /api/pedidos/:id devuelve el pedido a cualquiera con token (IDOR:
 * ana lee el 2 de beto) salvo «arreglado»; sin token, 401. /api/yo refleja el token (el tapado tiene que taparlo).
 * POST /api/login con {email, password} da un token. Todo método queda anotado.
 */
export async function laboratorio(tokens: { ana: string; beto: string }, clave: { email: string; password: string }): Promise<Laboratorio> {
  const estado = { arreglado: false, metodos: [] as string[], pedidos: 0 };
  const quien = (auth: string | undefined) => (auth === `Bearer ${tokens.ana}` ? 1 : auth === `Bearer ${tokens.beto}` ? 2 : undefined);
  const server = createServer((req, res) => {
    estado.pedidos++;
    estado.metodos.push(`${req.method} ${req.url}`);
    let cuerpo = "";
    req.on("data", (c) => (cuerpo += c));
    req.on("end", () => {
      const url = new URL(req.url ?? "/", "http://x");
      const json = (s: number, b: unknown) => res.writeHead(s, { "content-type": "application/json" }).end(JSON.stringify(b));
      if (url.pathname === "/") return res.writeHead(200, { "content-type": "text/html" }).end('<a href="/api/pedidos/1">pedido</a> <a href="/api/yo">yo</a>');
      if (url.pathname === "/api/login" && req.method === "POST") {
        try {
          const b = JSON.parse(cuerpo) as { email?: string; password?: string };
          if (b.email === clave.email && b.password === clave.password) return json(200, { data: { token: tokens.beto } });
        } catch { /* cuerpo inválido */ }
        return json(401, { error: "credenciales inválidas" });
      }
      const yo = quien(req.headers.authorization);
      if (url.pathname === "/api/yo") return yo ? json(200, { id: yo, token: String(req.headers.authorization).replace(/^Bearer /, "") }) : json(401, { error: "token requerido" });
      const m = /^\/api\/pedidos\/(\d+)$/.exec(url.pathname);
      if (m) {
        if (!yo) return json(401, { error: "token requerido" });
        const id = Number(m[1]);
        const dueno = id === 1 ? 1 : 2;
        if (estado.arreglado && dueno !== yo) return json(403, { error: "el pedido no es tuyo" });
        return json(200, { id, dueno, total: id * 1000, direccion: dueno === 2 ? "Calle Falsa 123" : "Av. Siempreviva 742" });
      }
      return json(404, { error: "no existe" });
    });
  });
  await new Promise<void>((fin) => server.listen(0, "127.0.0.1", fin));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { url, server, estado, cerrar: () => new Promise((fin) => server.close(() => fin())) };
}

/** Un servidor que sólo cuenta si alguien lo tocó (no tiene que tocarlo nadie). */
export async function tercero(): Promise<{ url: string; tocado: () => number; cerrar(): Promise<void> }> {
  let n = 0;
  const server = createServer((_req, res) => { n++; res.end("ok"); });
  await new Promise<void>((fin) => server.listen(0, "127.0.0.1", fin));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, tocado: () => n, cerrar: () => new Promise((fin) => server.close(() => fin())) };
}

const GIT = ["-c", "user.name=prueba", "-c", "user.email=prueba@example.test", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"];
export const git = (cwd: string, ...args: string[]) => execFileSync("git", [...GIT, "-C", cwd, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

/** Carpetas que crearon las pruebas: borrarlas con limpiar() al final. */
const creadas: string[] = [];
export function limpiar(): void {
  for (const dir of creadas.splice(0)) rmSync(dir, { recursive: true, force: true });
}

/** El id hN del resultado de herramienta que nombra este fragmento (la URL pedida, por ejemplo). */
export const idDe = (c: Contexto, fragmento: string) => c.resultados.filter((r) => r.texto.includes(fragmento)).map((r) => /^(h\d+) /.exec(r.texto)?.[1]).find(Boolean);

/** Un repositorio con estos archivos, commiteados en main. */
export function repo(archivos: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "orobas-ci-repo-"));
  creadas.push(dir);
  git(dir, "init", "-q");
  escribir(dir, archivos);
  git(dir, "add", "-A");
  git(dir, "commit", "-qm", "inicial", "--allow-empty");
  return dir;
}

export function escribir(dir: string, archivos: Record<string, string>): void {
  for (const [ruta, texto] of Object.entries(archivos)) {
    mkdirSync(dirname(join(dir, ruta)), { recursive: true });
    writeFileSync(join(dir, ruta), texto);
  }
}
