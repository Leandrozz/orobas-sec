// Registro de entradas tipadas: guarda los datos crudos de la conversación para que cada pestaña los dibuje con su filtro.
import type { ClientEvent } from "../client.ts";
import { t } from "../idioma.ts";
import type { Message } from "../llm.ts";
import type { Panel } from "./comandos.ts";
import type { Tipo } from "./pestanas.ts";

export type Tono = "warn" | "dim" | "normal";
export type Entrada =
  | { id: number; tipo: "mensajes"; texto: string; en?: number }
  | { id: number; tipo: "texto"; markdown: string; completo: boolean; reservado?: boolean; en?: number; llegadas?: Array<[desde: number, ms: number]> }
  | { id: number; tipo: "acciones"; llamada: string; nombre: string; etiqueta: string; argumentos?: unknown; estado: "en curso" | "ok" | "error"; resumen: string; worker?: string; inicio?: number; fin?: number }
  | { id: number; tipo: "resultados"; llamada: string; hash?: string; texto?: string }
  | { id: number; tipo: "comandos"; panel: Panel }
  | { id: number; tipo: "avisos"; texto: string; tono: Tono };
type Accion = Extract<Entrada, { tipo: "acciones" }>;
type Texto = Extract<Entrada, { tipo: "texto" }>;
type Resultado = Extract<Entrada, { tipo: "resultados" }>;
// Si el tipo de entrada deja de coincidir con Tipo, esto no compila.
type _Coincide = Entrada["tipo"] extends Tipo ? (Tipo extends Entrada["tipo"] ? true : never) : never;
const _coincide: _Coincide = true;
void _coincide;

const json = (s: string): unknown => { try { return JSON.parse(s); } catch { return undefined; } };

export class Registro {
  private ahora: () => number;
  constructor(ahora: () => number = Date.now) { this.ahora = ahora; }
  private lista: Entrada[] = [];
  private siguiente = 1;
  private abierta: Texto | undefined;
  private acciones = new Map<string, Accion>();
  private argumentos = new Map<string, unknown>();

  entradas(): readonly Entrada[] { return this.lista; }

  private nueva<T extends Entrada>(e: Omit<T, "id">): T {
    const entrada = { ...e, id: this.siguiente++ } as unknown as T;
    this.lista.push(entrada);
    return entrada;
  }

  respuestaPersonal(markdown: string): Entrada { return this.nueva<Texto>({ tipo: "texto", markdown, completo: true, en: this.ahora() }); }
  mensaje(texto: string): Entrada { return this.nueva<Extract<Entrada, { tipo: "mensajes" }>>({ tipo: "mensajes", texto, en: this.ahora() }); }
  panel(panel: Panel): Entrada { return this.nueva<Extract<Entrada, { tipo: "comandos" }>>({ tipo: "comandos", panel }); }
  aviso(texto: string, tono: Tono): Entrada { return this.nueva<Extract<Entrada, { tipo: "avisos" }>>({ tipo: "avisos", texto, tono }); }

  private accion(id: string, datos: Partial<Accion> & { nombre: string }): Accion {
    let a = this.acciones.get(id);
    if (!a) {
      a = this.nueva<Accion>({ tipo: "acciones", llamada: id, etiqueta: datos.nombre, estado: "en curso", resumen: "", argumentos: this.argumentos.get(id), ...datos });
      this.acciones.set(id, a);
    } else Object.assign(a, datos);
    return a;
  }

  evento(event: ClientEvent): Entrada[] {
    switch (event.type) {
      case "text": {
        if (event.worker) return [];
        const ms = this.ahora();
        this.abierta ??= this.nueva<Texto>({ tipo: "texto", markdown: "", completo: false, en: ms, llegadas: [] });
        this.abierta.llegadas!.push([this.abierta.markdown.length, ms]);
        this.abierta.markdown += event.delta;
        return [this.abierta];
      }
      case "message": {
        const m = event.message;
        if (m.role === "checkpoint") return [this.aviso(t("Contexto compactado: la conversación anterior quedó resumida.", "Context compacted: the earlier conversation was summarized."), "dim")];
        if (m.role !== "assistant") return [];
        const salida: Entrada[] = [];
        if (this.abierta) {
          this.abierta.completo = true;
          if (!["stop", "toolUse"].includes(m.stopReason) || m.content !== this.abierta.markdown) this.abierta.reservado = true;
          salida.push(this.abierta);
          this.abierta = undefined;
        }
        for (const c of m.toolCalls) {
          const args = json(c.arguments);
          this.argumentos.set(c.id, args);
          const a = this.acciones.get(c.id);
          if (a) { a.argumentos = args; salida.push(a); }
        }
        if (m.stopReason === "error") salida.push(this.aviso(m.errorMessage ?? t("Error del proveedor", "Provider error"), "warn"));
        if (m.stopReason === "aborted") salida.push(this.aviso(t("Turno detenido.", "Turn stopped."), "dim"));
        return salida;
      }
      case "tool_start": {
        const a = this.accion(event.id, { nombre: event.name, etiqueta: event.worker ? `${event.worker} › ${event.label}` : event.label, worker: event.worker });
        a.inicio ??= this.ahora();
        return [a];
      }
      case "tool_end": {
        const resumen = event.isError
          ? event.text.slice(0, 80)
          : Object.entries(event.details).map(([k, v]) => `${k} ${String(v).replace(/^sha256:(.{12}).*/, "$1")}`).join(" · ");
        const a = this.acciones.get(event.id) ?? this.accion(event.id, { nombre: event.name, etiqueta: event.worker ? `${event.worker} › ${event.name}` : event.name, worker: event.worker });
        a.fin = this.ahora();
        a.estado = event.isError ? "error" : "ok";
        a.resumen = resumen;
        const hash = event.details.artefacto;
        return [a, this.nueva<Resultado>({ tipo: "resultados", llamada: event.id, ...(typeof hash === "string" ? { hash } : {}) })];
      }
      case "retry":
        // El reintento reenvía la respuesta desde el principio: se descarta lo parcial.
        if (this.abierta) { this.lista = this.lista.filter((e) => e !== this.abierta); this.abierta = undefined; }
        return [this.aviso(t(`El proveedor falló (${event.reason.slice(0, 80)}). Reintento ${event.attempt} en ${Math.round(event.waitMs / 1000)} s.`, `The provider failed (${event.reason.slice(0, 80)}). Retry ${event.attempt} in ${Math.round(event.waitMs / 1000)} s.`), "dim")];
      case "notice": return [this.aviso(event.text, "warn")];
      case "recall": return [this.aviso(`memoria: ${event.ids.join(", ")}`, "dim")];
      case "answer": return [this.aviso(event.text, "normal")];
      case "disconnected": return [this.aviso(t("Se perdió la conexión con el daemon.", "Lost the connection to the daemon."), "warn")];
      default: return [];
    }
  }

  static desdeSnapshot(messages: Message[]): Registro {
    const r = new Registro();
    const herramientas = new Map(messages.flatMap((m) => (m.role === "tool" ? [[m.toolCallId, m] as const] : [])));
    for (const m of messages) {
      if (m.role === "checkpoint") r.evento({ type: "message", message: m });
      else if (m.role === "user") r.nueva<Extract<Entrada, { tipo: "mensajes" }>>({ tipo: "mensajes", texto: m.content.replace(/\n\n<(memoria|alcance|terminal|canarios|cves_nuevos|gasto)>[\s\S]*$/, ""), en: m.at });
      else if (m.role === "assistant") {
        if (m.content.trim()) r.nueva<Texto>({ tipo: "texto", markdown: m.content, completo: true, ...(!["stop", "toolUse"].includes(m.stopReason) && { reservado: true }), en: m.at });
        for (const c of m.toolCalls) {
          const h = herramientas.get(c.id);
          r.accion(c.id, { nombre: c.name, argumentos: json(c.arguments), estado: !h ? "en curso" : h.isError ? "error" : "ok" });
          if (h) r.nueva<Resultado>({ tipo: "resultados", llamada: c.id, texto: h.content });
        }
      }
    }
    return r;
  }
}
