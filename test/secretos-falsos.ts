// Piezas de las pruebas de punta a punta de los secretos de la sesión (secretos-no-salen, secretos-punta-a-punta):
// un proveedor de modelos de mentira que habla los dos transportes reales (Chat Completions y Anthropic Messages)
// y guarda cada cuerpo tal como le llega, un «cerebro» que decide la próxima llamada según lo que ve, y escáneres
// de mentira que anotan su argv y hacen de verdad una petición con las cabeceras que recibieron.
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";

export async function escuchar(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
}

export type Formato = "openai" | "anthropic";
export type Paso = { texto?: string; llamada?: { name: string; args: object } };
export type Cerebro = (body: any, formato: Formato, base: string) => Paso;

/** Lo que mandó el harness, en bloques en orden (mensaje por mensaje; en Anthropic, bloque por bloque). */
export function bloques(body: any, formato: Formato): Array<{ role: string; type: string; text: string; raw: string }> {
  if (formato === "openai") {
    return (body.messages ?? []).map((m: any) => ({ role: m.role, type: m.role === "tool" ? "tool_result" : m.tool_calls ? "tool_use" : "text", text: String(m.content ?? JSON.stringify(m.tool_calls ?? "")), raw: JSON.stringify(m) }));
  }
  return (body.messages ?? []).flatMap((m: any) => (m.content as any[]).map((b: any) => ({ role: m.role, type: b.type, text: String(b.text ?? b.content ?? JSON.stringify(b.input ?? "")), raw: JSON.stringify({ role: m.role, b }) })));
}

export const resultados = (body: any, formato: Formato) => bloques(body, formato).filter((b) => b.type === "tool_result").map((b) => b.text);

function sse(res: ServerResponse, formato: Formato, paso: Paso, n: number, cabeceras: Record<string, string> = {}): void {
  res.writeHead(200, { "content-type": "text/event-stream", ...cabeceras });
  const send = (event: object) => res.write(`data: ${JSON.stringify(event)}\n\n`);
  if (formato === "openai") {
    if (paso.llamada) send({ id: `r${n}`, choices: [{ delta: { tool_calls: [{ index: 0, id: `c${n}`, function: { name: paso.llamada.name, arguments: JSON.stringify(paso.llamada.args) } }] } }] });
    else send({ id: `r${n}`, choices: [{ delta: { content: paso.texto } }] });
    send({ choices: [{ delta: {}, finish_reason: paso.llamada ? "tool_calls" : "stop" }], usage: { prompt_tokens: 100, completion_tokens: 10 } });
    res.end("data: [DONE]\n\n");
    return;
  }
  send({ type: "message_start", message: { id: `m${n}`, usage: { input_tokens: 100, output_tokens: 0 } } });
  if (paso.llamada) {
    send({ type: "content_block_start", index: 0, content_block: { type: "tool_use", id: `t${n}`, name: paso.llamada.name } });
    send({ type: "content_block_delta", index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify(paso.llamada.args) } });
  } else {
    send({ type: "content_block_start", index: 0, content_block: { type: "text" } });
    send({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: paso.texto } });
  }
  send({ type: "content_block_stop", index: 0 });
  send({ type: "message_delta", delta: { stop_reason: paso.llamada ? "tool_use" : "end_turn" }, usage: { output_tokens: 10 } });
  send({ type: "message_stop" });
  res.end();
}

export type Envio = { url: string; body: string; trazas?: string | string[]; id?: string; respuesta?: string; status?: number };

/**
 * Proveedor y servicio propio de mentira: guarda cada cuerpo que recibe, tal cual llegó. Con `ids`, cada pedido al
 * modelo recibe un id de pedido del servicio (x-request-id: oro_req_…, como el gateway) y se anota lo que respondió;
 * `descartar` decide qué contesta POST /traces/descartar (por defecto 204).
 */
export function proveedor(formato: Formato, objetivoBase: () => string, cerebro: Cerebro, opciones: { ids?: boolean; descartar?: () => number } = {}) {
  const cuerpos: Envio[] = [];
  let n = 0;
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    let raw = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      const envio: Envio = { url: req.url ?? "", body: raw, trazas: req.headers["x-cyber-trazas"] };
      cuerpos.push(envio);
      if (req.url?.endsWith("/chat/completions") || req.url?.endsWith("/messages")) {
        const paso = cerebro(JSON.parse(raw), formato, objetivoBase());
        n++;
        if (opciones.ids) { envio.id = `oro_req_${n.toString(16).padStart(16, "0")}`; envio.respuesta = JSON.stringify(paso); }
        return sse(res, formato, paso, n, envio.id ? { "x-request-id": envio.id } : {});
      }
      if (req.url?.endsWith("/traces/descartar")) { envio.status = opciones.descartar?.() ?? 204; return res.writeHead(envio.status).end(); }
      // /traces (el registro del turno), /models y cualquier otra cosa: se guarda y se contesta vacío.
      res.writeHead(req.url?.endsWith("/traces") ? 204 : 404).end();
    });
  });
  return { server, cuerpos, modelo: () => cuerpos.filter((item) => /\/(chat\/completions|messages)$/.test(item.url)) };
}

/**
 * Lo que el gateway de orobas-sec-web (PR #68) termina guardando de una sesión, con su regla: el pedido al modelo y su
 * respuesta sólo si salió en «compartir» y nadie pidió descartarlo; el turno y la trayectoria si salieron en
 * «compartir». (El servicio real se prueba en orobas-sec-web: test/trazas-material-objetivo.test.ts.)
 */
export function guardadoPorElGateway(cuerpos: Envio[]): Array<{ url: string; body: string }> {
  const comparte = (envio: Envio) => envio.trazas === undefined || envio.trazas === "compartir";
  const descartados = new Set(cuerpos.filter((envio) => envio.url.endsWith("/traces/descartar") && envio.status === 204).flatMap((envio) => (JSON.parse(envio.body) as { traces: string[] }).traces));
  return cuerpos.flatMap((envio) => {
    if (/\/(chat\/completions|messages)$/.test(envio.url)) return comparte(envio) && !descartados.has(envio.id ?? "") ? [{ url: envio.url, body: `${envio.body}\n${envio.respuesta ?? ""}` }] : [];
    if (/\/(traces|trayectorias)$/.test(envio.url)) return comparte(envio) ? [{ url: envio.url, body: envio.body }] : [];
    return [];
  });
}

/** Las formas en que un canario podría viajar: tal cual, escapado en JSON (una y dos veces) o codificado en una URL. */
export function formas(valor: string): string[] {
  const una = JSON.stringify(valor).slice(1, -1);
  return [...new Set([valor, una, JSON.stringify(una).slice(1, -1), encodeURIComponent(valor)])];
}

export function sinCanarios(cuerpos: Array<{ url: string; body: string }>, canarios: Record<string, string>): void {
  for (const { url, body } of cuerpos) {
    for (const [donde, valor] of Object.entries(canarios)) {
      for (const forma of formas(valor)) assert.ok(!body.includes(forma), `el canario «${donde}» salió en ${url} (forma ${JSON.stringify(forma)})`);
    }
  }
}

/** Lo que dejó el modo local en la carpeta de trazas, archivo por archivo. */
export function trazasLocales(dir: string): Array<{ url: string; body: string }> {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { recursive: true }).map(String).filter((f) => /\.(jsonl?|md)$/.test(f)).map((f) => ({ url: f, body: readFileSync(join(dir, f), "utf8") }));
}

/** Lo que salió hacia el servicio que no es un pedido al modelo: turnos, trayectorias, citas, cuenta. */
export const noModelo = <T extends { url: string; body: string }>(cuerpos: T[]) => cuerpos.filter((item) => !/\/(chat\/completions|messages)$/.test(item.url));

export async function esperar(check: () => boolean) {
  for (let i = 0; i < 100 && !check(); i++) await new Promise((resolve) => setTimeout(resolve, 20));
}

/**
 * Un escáner de mentira (ffuf, httpx, nuclei, katana, sqlmap): contesta a la comprobación de versión, anota su argv
 * en `registro` y hace de verdad un GET a cada URL que recibe (-u o por la entrada) con las cabeceras de sus -H,
 * como haría el escáner real. Devuelve la ruta del ejecutable, para BINARIES[nombre].binary.
 */
export function escanerFalso(nombre: string, registro: string, dir = mkdtempSync(join(tmpdir(), `escaner-${nombre}-`))): string {
  const ruta = join(dir, nombre);
  writeFileSync(ruta, `#!${process.execPath}
const fs = require("node:fs");
const args = process.argv.slice(2);
if (args.length === 1 && /^-+(?:V|version)$/.test(args[0])) { console.log("${nombre} de prueba 1.0"); process.exit(0); }
fs.appendFileSync(${JSON.stringify(registro)}, JSON.stringify({ escaner: ${JSON.stringify(nombre)}, argv: args }) + "\\n");
const headers = {};
const urls = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "-H") { const h = args[++i]; const at = h.indexOf(":"); headers[h.slice(0, at).trim()] = h.slice(at + 1).trim(); }
  else if (args[i] === "-u") urls.push(args[++i]);
}
let entrada = "";
try { entrada = fs.readFileSync(0, "utf8"); } catch {}
for (const linea of entrada.split("\\n")) if (/^https?:\\/\\//.test(linea.trim())) urls.push(linea.trim());
(async () => {
  for (const url of urls) { try { await (await fetch(url.replace("FUZZ", "admin"), { headers, redirect: "manual" })).text(); } catch {} }
  if (${JSON.stringify(nombre)} === "ffuf") console.log(JSON.stringify({ results: [] }));
})();
`);
  chmodSync(ruta, 0o755);
  return ruta;
}
