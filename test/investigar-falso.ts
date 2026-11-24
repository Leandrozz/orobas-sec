// Mundo simulado para el modo investigar: proveedores falsos con tarifa y caché de prompts por modelo (el
// prefijo común con los últimos pedidos a ese modelo se cobra como cache_read), guiones por quién pide (el
// bucle, el orquestador, cada tramo por estado e hipótesis, el verificador) y dobles de las herramientas de
// la caja (harness_build, fuzz_run, poc_run), que acá no existen. Nada sale a la red.
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Tool } from "../src/agent.ts";
import { Engine, type EngineOptions } from "../src/engine.ts";
import type { AssistantMessage, LlmRequest, Rates, Scripted } from "../src/llm.ts";
import { ratePico } from "../src/money.ts";
import type { Provider } from "../src/providers.ts";

/** Precios ficticios para comparar modelos en la simulación. */
export const TARIFAS = {
  glm: { input: 0.25, cacheRead: 0.05, cacheWrite: 0, output: 1 },
  ultra: { input: 8, cacheRead: 1, cacheWrite: 0, output: 16 },
  kimi: { input: 2, cacheRead: 0.25, cacheWrite: 0, output: 8 },
  hy4: { input: 1, cacheRead: 0.1, cacheWrite: 0, output: 2 },
} satisfies Record<string, Rates>;

/** Lo que va en el código del objetivo y en ningún otro lado: si aparece en un pedido, ese pedido leyó el repo. */
export const CANARIO_REPO = "CANARIO_REPO_7f3a";

export interface Pedido { worker: string; modelo: string; system: string; mensajes: string; primero: string; herramientas: string[]; prompt: number; cacheado: number; salida: number; pico: bigint }
export interface InfoTramo { estado: string; hipotesis?: string; paso: number; worker: string; ultimo: string; primero: string }

const tokens = (text: string) => Math.ceil(text.length / 4);

export class MundoInv {
  readonly pedidos: Pedido[] = [];
  /** Guion del bucle principal, en orden; vacío: «Listo.». */
  bucle: Scripted[] = [];
  /** Guion de cada tramo: según estado, hipótesis y número de paso dentro del tramo. */
  tramo: (info: InfoTramo) => Scripted = guionFeliz;
  /** Lo que contesta el orquestador cuando hay más de una movida. */
  orquestador: (prompt: string) => string = () => "MOVIDA: 1\nMOTIVO: la primera de la lista.";
  /** El verificador del modelo (hallazgos web): por defecto, «candidato» sin más. */
  verificador: (paso: number) => Scripted = (paso) => (paso === 0 ? { toolCalls: [{ name: "verdict", arguments: { state: "candidato", reason: "sin acceso para reproducir" } }] } : { text: "Listo." });
  /** Si devuelve una promesa, el pedido de ese worker espera a que se resuelva (para ver el pie, o cortar a mitad). */
  frenar: (worker: string, signal?: AbortSignal) => Promise<void> | undefined = () => undefined;
  private pasos = new Map<string, number>();
  private cache = new Map<string, string[][]>();
  private n = 0;

  proveedor(id: string, tarifa: Rates): Provider {
    return { model: { provider: "faux", id, baseUrl: "", cost: tarifa }, transport: (request) => this.responder(request), account: "faux" };
  }

  private cobrar(modelo: string, partes: string[]): { prompt: number; cacheado: number } {
    const previos = this.cache.get(modelo) ?? [];
    let mejor = 0;
    for (const previo of previos) {
      let k = 0;
      while (k < previo.length && k < partes.length && previo[k] === partes[k]) k++;
      mejor = Math.max(mejor, k);
    }
    this.cache.set(modelo, [partes, ...previos].slice(0, 6));
    return { prompt: partes.reduce((sum, parte) => sum + tokens(parte), 0), cacheado: partes.slice(0, mejor).reduce((sum, parte) => sum + tokens(parte), 0) };
  }

  private paso(worker: string): number {
    const n = this.pasos.get(worker) ?? 0;
    this.pasos.set(worker, n + 1);
    return n;
  }

  private guion(request: LlmRequest, worker: string): Scripted {
    const ultimo = String((request.messages.at(-1) as { content?: unknown } | undefined)?.content ?? "");
    const primero = String((request.messages[0] as { content?: unknown } | undefined)?.content ?? "");
    if (worker === "principal") return this.bucle.shift() ?? { text: "Listo." };
    if (/^inv:[0-9a-f]{8}:orquestador$/.test(worker)) return { text: this.orquestador(ultimo) };
    const tramo = /^inv:[0-9a-f]{8}:([a-z0-9-]+):(?:(h\d+):)?\d+b?$/.exec(worker);
    if (tramo) return this.tramo({ estado: tramo[1]!, hipotesis: tramo[2], paso: this.paso(worker), worker, ultimo, primero });
    if (worker.startsWith("verificador:")) return this.verificador(this.paso(worker));
    if (worker === "traspaso") return { text: "OBJETIVO Y ALCANCE: x. PLAN: y. PREGUNTA: ¿sigue?" };
    if (worker.startsWith("router:")) return { text: "DECISIÓN: seguir. PLAN: 1. seguir." };
    return { text: "ok" };
  }

  private responder = async (request: LlmRequest): Promise<AssistantMessage> => {
    const worker = request.tags?.worker ?? "?";
    const freno = this.frenar(worker, request.signal);
    // Un pedido frenado se suelta al cortarse el tramo, también si ya llegó cortado.
    if (freno) await Promise.race([freno, new Promise<void>((resolve) => (request.signal?.aborted ? resolve() : request.signal?.addEventListener("abort", () => resolve(), { once: true })))]);
    if (request.signal?.aborted) return { role: "assistant", content: "", toolCalls: [], stopReason: "aborted", provider: "faux", model: request.model.id, requestId: `falso:${++this.n}`, at: Date.now() };
    const partes = [`${request.system}\n${JSON.stringify(request.tools)}`, ...request.messages.map((message) => JSON.stringify({ ...message, at: 0 }))];
    const { prompt, cacheado } = this.cobrar(request.model.id, partes);
    const guion = this.guion(request, worker);
    if (guion.fail) return { role: "assistant", content: "", toolCalls: [], stopReason: "error", errorMessage: guion.fail.message, retryable: guion.fail.retryable, ...(guion.fail.exhausted ? { exhausted: true } : {}), provider: "faux", model: request.model.id, requestId: `falso:${++this.n}`, at: Date.now() };
    const toolCalls = (guion.toolCalls ?? []).map((call, index) => ({ id: `call_${++this.n}_${index}`, name: call.name, arguments: JSON.stringify(call.arguments) }));
    const texto = guion.text ?? "";
    const salida = tokens(texto + JSON.stringify(toolCalls)) + 20;
    const tarifa = request.model.cost!;
    const pico = BigInt(prompt - cacheado) * ratePico(tarifa.input) + BigInt(cacheado) * ratePico(tarifa.cacheRead) + BigInt(salida) * ratePico(tarifa.output);
    const mensajes = JSON.stringify(request.messages);
    this.pedidos.push({ worker, modelo: request.model.id, system: request.system, mensajes, primero: String((request.messages[0] as { content?: unknown } | undefined)?.content ?? ""), herramientas: request.tools.map((tool) => tool.name), prompt, cacheado, salida, pico });
    return { role: "assistant", content: texto, toolCalls, stopReason: toolCalls.length ? "toolUse" : "stop", provider: "faux", model: request.model.id, requestId: `falso:${++this.n}`, usage: { input: prompt - cacheado, cacheRead: cacheado, cacheWrite: 0, output: salida }, at: Date.now() };
  };

  /** Pedidos de un worker que cumple el patrón. */
  de(patron: RegExp): Pedido[] {
    return this.pedidos.filter((pedido) => patron.test(pedido.worker));
  }
}

const out = (args: object): Scripted => ({ toolCalls: [{ name: "investigation_output", arguments: args }] });
const llama = (name: string, args: object, text?: string): Scripted => ({ ...(text ? { text } : {}), toolCalls: [{ name, arguments: args }] });

/**
 * Guion de una investigación que sale bien: el analista lee el código, tres hipótesis, h1 dispara en los tres
 * niveles, h2 no dispara, y el reporte. El orquestador por defecto elige la primera movida.
 */
export function guionFeliz(info: InfoTramo): Scripted {
  const { estado, hipotesis, paso } = info;
  if (estado === "analista") {
    if (paso === 0) return llama("code_read", { path: "src/parser.c" }, "Leo el parser.");
    if (paso === 1) return out({ mapa: `parse_header (src/parser.c:4) copia len bytes de la entrada a un buffer de 64; ${CANARIO_REPO} marca el parser. Llega desde read_request (src/server.c:10).`, puntos_entrada: ["src/server.c:10 read_request", "src/parser.c:4 parse_header"], resumen: "mapa listo" });
    return { text: "Mapa entregado." };
  }
  if (estado === "hipotesis") {
    if (paso === 0) return out({ hipotesis: [
      { titulo: "Desborde de buffer en parse_header", clase: "desborde de buffer", activo: "src/parser.c:parse_header", porque: "len viene de la entrada y no se compara con 64", evidencia: "src/parser.c:6 memcpy(buf, in, len)", prioridad: "alta" },
      { titulo: "Lectura fuera de rango en parse_trailer", clase: "lectura fuera de rango", activo: "src/parser.c:parse_trailer", porque: "offset sin validar", evidencia: "src/parser.c:12", prioridad: "media" },
      { titulo: "Entero con signo en read_request", clase: "conversión de signo", activo: "src/server.c:read_request", porque: "int a size_t", evidencia: "src/server.c:11", prioridad: "baja" },
    ], resumen: "tres hipótesis" });
    return { text: "Hipótesis entregadas." };
  }
  if (estado.startsWith("harness-")) {
    const nivel = Number(estado.slice(-1));
    if (hipotesis === "h1") {
      if (paso === 0) return llama("harness_build", { fuente: `harness nivel ${nivel} para parse_header`, sanitizadores: ["address"] }, "Armo el harness.");
      if (paso === 1) return llama("fuzz_run", { harness: `h1-n${nivel}`, segundos: 30 });
      if (paso === 2) return out({ dispara: true, comando: `./h1-n${nivel} crash-h1`, cwd: "harness/", senal: "AddressSanitizer: heap-buffer-overflow", resumen: `ASan en parse_header al nivel ${nivel}` });
      return { text: "Listo." };
    }
    if (paso === 0) return out({ dispara: false, resumen: "el harness no disparó en 30 s de fuzzing" });
    return { text: "No disparó." };
  }
  if (estado === "reporte") {
    if (paso === 0) return out({ titulo: "Desborde en parse_header", informe: "## h1\nNivel 3: punta a punta. Reproducción: ./h1-n3 crash-h1.\n## Sin disparar\nh2, h3.", resumen: "informe" });
    return { text: "Informe entregado." };
  }
  return { text: "?" };
}

/** Dobles de las herramientas de la caja. poc_run «dispara» si el comando trae «crash»; «flaky» dispara una vez sí y otra no. */
export function herramientasCaja(): { tools: Tool[]; corridas: string[] } {
  const corridas: string[] = [];
  let flaky = 0;
  const tools: Tool[] = [
    { name: "harness_build", label: "Armar harness", description: "Compila un harness con sanitizadores (doble).", parameters: { type: "object", properties: {}, additionalProperties: true }, execute: () => ({ text: `harness compilado: harness/bin ${"x".repeat(1500)}` }) },
    { name: "fuzz_run", label: "Fuzzear", description: "Fuzzea un harness (doble).", parameters: { type: "object", properties: {}, additionalProperties: true }, execute: () => ({ text: `fuzz: 1 caída guardada en crash-h1 ${"y".repeat(3000)}` }) },
    {
      name: "poc_run",
      label: "Correr PoC",
      description: "Corre un PoC en limpio (doble).",
      parameters: { type: "object", properties: { command: { type: "string" } }, required: ["command"] },
      execute: (args: { command: string }) => {
        corridas.push(args.command);
        const dispara = /flaky/.test(args.command) ? flaky++ % 2 === 0 : /crash/.test(args.command);
        return dispara ? { text: "==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020", details: { exitCode: 1 } } : { text: "terminó sin errores", details: { exitCode: 0 } };
      },
    },
  ];
  return { tools, corridas };
}

/** Un repo chico con el canario en el código. */
export function repo(): string {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-inv-"));
  mkdirSync(join(cwd, "src"));
  writeFileSync(join(cwd, "src", "parser.c"), `#include <string.h>\n// ${CANARIO_REPO}\n/* parser de cabeceras */\nint parse_header(const char *in, size_t len) {\n  char buf[64];\n  memcpy(buf, in, len);\n  return buf[0];\n}\n`);
  writeFileSync(join(cwd, "src", "server.c"), "int read_request(int fd) { return 0; }\n");
  return cwd;
}

/**
 * Un motor con el ejecutor barato (glm), el fuerte red (ultra), un estándar blue para el fuerte (kimi) y el
 * medio (hy4), y los dobles de la caja en el catálogo.
 */
export function motor(mundo: MundoInv, opciones: Partial<EngineOptions> & { cwd?: string; caja?: boolean } = {}): { engine: Engine; corridas: string[]; avisos: string[] } {
  const providers: Record<string, Provider> = { glm: mundo.proveedor("glm", TARIFAS.glm), ultra: mundo.proveedor("ultra", TARIFAS.ultra), kimi: mundo.proveedor("kimi", TARIFAS.kimi), hy4: mundo.proveedor("hy4", TARIFAS.hy4) };
  const { cwd = repo(), caja = true, ...resto } = opciones;
  const engine = new Engine({
    cwd,
    provider: providers.glm!,
    strong: providers.ultra!,
    resolve: (spec) => ({ ...providers[spec.slice(5)]!, model: { ...providers[spec.slice(5)]!.model } }),
    routerModels: { blue: { fuerte: "faux/kimi" } },
    autoVerify: false,
    cveFeed: false,
    ...resto,
  });
  const avisos: string[] = [];
  engine.onNotice = (text) => avisos.push(text);
  const { tools, corridas } = herramientasCaja();
  if (caja) engine.catalog.register(tools);
  return { engine, corridas, avisos };
}
