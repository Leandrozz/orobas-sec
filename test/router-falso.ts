// Mundo simulado para el router: tarifas por modelo, caché de prompts POR MODELO (el prefijo común con
// los últimos pedidos a ese mismo modelo se cobra como cache_read, el resto como input) y respuestas
// guionadas según quién pide (el bucle, el traspaso, una consulta, un tramo). Un modelo «estándar» puede
// negarse. Nada sale a la red.
import type { Engine } from "../src/engine.ts";
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

export interface Llamada { modelo: string; worker: string; prompt: number; cacheado: number; salida: number; pico: bigint; rechazo: boolean; texto: string }

const tokens = (text: string) => Math.ceil(text.length / 4);

export class MundoFalso {
  readonly llamadas: Llamada[] = [];
  /** Guion del bucle principal, en orden; vacío: «Listo.». */
  bucle: Scripted[] = [];
  /** Guiones de los tramos (subagentes), en orden; vacío: lo que diga `tramo`. */
  tramos: Scripted[] = [];
  /** Paso `n` (desde 0) de un tramo sin guion; por defecto, un informe corto en el primero. */
  tramo: (worker: string, n: number) => Scripted = () => ({ text: "RESULTADO: comprobado; ver h9. LÍMITES: ninguno. SIGUIENTE: registrar." });
  private pasosTramo = new Map<string, number>();
  /** Respuesta de una consulta, por modelo y prompt. */
  consulta: (modelo: string, prompt: string) => string = () => "DECISIÓN: se sostiene. PLAN: 1. GET /api/pedidos/7 con la otra identidad y mirá si vuelve 200.";
  traspaso = "OBJETIVO Y ALCANCE: probar el control de acceso de app.test.\nPLAN: barrido de /api hecho; falta comprobar /api/pedidos.\nHIPÓTESIS: IDOR en pedidos (abierta).\nCANDIDATOS: h3 (GET /api/pedidos/7 → 200 con otra identidad).\nÚLTIMO: 3 sondeos.\nPREGUNTA: ¿se sostiene?";
  /** ¿Se niega este modelo a este pedido? (un estándar ante algo ofensivo, por ejemplo). */
  niega: (modelo: string, worker: string, prompt: string) => boolean = () => false;
  /** Prefijos recientes por modelo: el proveedor cachea varios, no sólo el último. */
  private cache = new Map<string, string[][]>();
  private n = 0;

  proveedor(id: string, tarifa: Rates): Provider {
    return { model: { provider: "faux", id, baseUrl: "", cost: tarifa }, transport: (request) => this.responder(request), account: "faux" };
  }

  /** Partes del prompt en el orden en que se cachean: sistema y herramientas, después cada mensaje. */
  private partes(request: LlmRequest): string[] {
    return [`${request.system}\n${JSON.stringify(request.tools)}`, ...request.messages.map((message) => JSON.stringify({ ...message, at: 0 }))];
  }

  private cobrar(modelo: string, partes: string[]): { prompt: number; cacheado: number } {
    const previos = this.cache.get(modelo) ?? [];
    let mejor = 0;
    for (const previo of previos) {
      let k = 0;
      while (k < previo.length && k < partes.length && previo[k] === partes[k]) k++;
      mejor = Math.max(mejor, k);
    }
    this.cache.set(modelo, [partes, ...previos].slice(0, 4));
    const prompt = partes.reduce((sum, parte) => sum + tokens(parte), 0);
    const cacheado = partes.slice(0, mejor).reduce((sum, parte) => sum + tokens(parte), 0);
    return { prompt, cacheado };
  }

  private guion(worker: string, modelo: string, prompt: string): Scripted & { rechazo?: boolean } {
    const rechazo = this.niega(modelo, worker, prompt);
    if (rechazo) return { text: "Lo siento, no puedo ayudar con eso.", rechazo };
    if (worker === "principal") return this.bucle.shift() ?? { text: "Listo." };
    if (worker === "traspaso") return { text: this.traspaso };
    if (worker === "compactacion") return { text: "OBJETIVO: probar app.test. HECHOS: h1..h3. PENDIENTE: seguir." };
    if (worker.startsWith("router:")) return { text: this.consulta(modelo, prompt) };
    if (worker.startsWith("sub:")) {
      const n = this.pasosTramo.get(worker) ?? 0;
      this.pasosTramo.set(worker, n + 1);
      return this.tramos.shift() ?? this.tramo(worker, n);
    }
    return { text: "ok" };
  }

  private responder = async (request: LlmRequest): Promise<AssistantMessage> => {
    const worker = request.tags?.worker ?? "?";
    const partes = this.partes(request);
    const { prompt, cacheado } = this.cobrar(request.model.id, partes);
    const ultimo = request.messages.at(-1);
    const guion = this.guion(worker, request.model.id, ultimo && "content" in ultimo ? String(ultimo.content) : "");
    const toolCalls = (guion.toolCalls ?? []).map((call, index) => ({ id: `call_${++this.n}_${index}`, name: call.name, arguments: JSON.stringify(call.arguments) }));
    const texto = guion.text ?? "";
    const salida = tokens(texto + JSON.stringify(toolCalls)) + 20;
    const tarifa = request.model.cost!;
    const pico = BigInt(prompt - cacheado) * ratePico(tarifa.input) + BigInt(cacheado) * ratePico(tarifa.cacheRead) + BigInt(salida) * ratePico(tarifa.output);
    this.llamadas.push({ modelo: request.model.id, worker, prompt, cacheado, salida, pico, rechazo: !!guion.rechazo, texto });
    if (guion.fail) return { role: "assistant", content: "", toolCalls: [], stopReason: "error", errorMessage: guion.fail.message, retryable: guion.fail.retryable, provider: "faux", model: request.model.id, requestId: `falso:${++this.n}`, at: Date.now() };
    return {
      role: "assistant",
      content: texto,
      toolCalls,
      stopReason: toolCalls.length ? "toolUse" : "stop",
      provider: "faux",
      model: request.model.id,
      requestId: `falso:${++this.n}`,
      usage: { input: prompt - cacheado, cacheRead: cacheado, cacheWrite: 0, output: salida },
      at: Date.now(),
    };
  };
}

/** Lo que devuelve cada llamada simulada, por id: así el resultado no viaja en los argumentos (inflaría la salida). */
export const RESULTADOS = new Map<string, string>();
let resultados = 0;

/** Reemplaza lo que hace una herramienta del agente (y de sus subagentes): devuelve el resultado guardado o lo que diga `fn`. */
export function simular(engine: Engine, nombre: string, fn: (args: Record<string, unknown>) => string = (args) => RESULTADOS.get(String(args.r)) ?? "HTTP 200: nada raro"): void {
  for (const tool of engine.agent.tools) if (tool.name === nombre) tool.execute = async (args) => ({ text: fn(args) });
}

/** Un paso del bucle que llama a una herramienta; `texto` es lo que escribe el modelo antes de llamarla. */
export const llama = (name: string, args: Record<string, unknown>, texto?: string): Scripted => ({ ...(texto ? { text: texto } : {}), toolCalls: [{ name, arguments: args }] });
/** Un paso que llama a `name` y recibe `resultado`. */
export function con(name: string, args: Record<string, unknown>, resultado: string, texto?: string): Scripted {
  const r = `r${++resultados}`;
  RESULTADOS.set(r, resultado);
  return llama(name, { ...args, r }, texto);
}
export const sondeo = (ruta: string, resultado = "HTTP 200 OK: listado normal, sin datos ajenos", texto?: string) => con("http_request", { url: `https://app.test${ruta}` }, resultado, texto);
