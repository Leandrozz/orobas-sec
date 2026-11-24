// Acumulador de subagentes: un Registro por worker, con su objetivo, su estado y su informe.
import type { ClientEvent } from "../client.ts";
import { Registro } from "./entradas.ts";

export type EstadoSub = "trabajando" | "terminó" | "no terminó";
export interface Subagente {
  worker: string; objetivo?: string; estado: EstadoSub; registro: Registro; informe?: string;
  solicitudes?: number; usd?: string; inicio: number; fin?: number;
}
interface Llamada { id: string; objetivo?: string; worker?: string; terminada: boolean }

const objetivoDe = (args: string): string | undefined => {
  try { const o = (JSON.parse(args) as { objective?: unknown }).objective; return typeof o === "string" ? o : undefined; } catch { return undefined; }
};

export class Subagentes {
  private subs = new Map<string, Subagente>();
  private llamadas: Llamada[] = [];

  lista(): Subagente[] { return [...this.subs.values()].reverse(); }
  de(worker: string): Subagente | undefined { return this.subs.get(worker); }

  private llamada(id: string): Llamada {
    let l = this.llamadas.find((x) => x.id === id);
    if (!l) { l = { id, terminada: false }; this.llamadas.push(l); }
    return l;
  }

  // Con `propia` (cierre de una delegate) no se reasigna: ese worker es de esa llamada.
  private sub(worker: string, propia?: Llamada): Subagente {
    let s = this.subs.get(worker);
    if (!s) {
      s = { worker, estado: "trabajando", registro: new Registro(), inicio: Date.now() };
      this.subs.set(worker, s);
      if (propia) { propia.worker = worker; s.objetivo = propia.objetivo; } else this.reasignar();
    }
    return s;
  }

  // Los sub:N se numeran en el orden de las llamadas, pero emiten en cualquier orden: las llamadas sin cerrar,
  // en orden, se reparten entre los workers en curso sin confirmar, ordenados por número.
  private reasignar(): void {
    const num = (w: string) => Number(w.slice(4));
    const ws = [...this.subs.values()].filter((x) => x.estado === "trabajando").sort((a, b) => num(a.worker) - num(b.worker));
    const pend = this.llamadas.filter((x) => !x.terminada);
    for (const l of pend) l.worker = undefined;
    ws.forEach((w, i) => { const l = pend[i]; if (l) l.worker = w.worker; w.objetivo = l?.objetivo; });
  }

  // Un message de asistente vacío cierra el texto abierto del worker.
  private cerrarTexto(s: Subagente, at: number): void {
    s.registro.evento({ type: "message", message: { role: "assistant", content: "", toolCalls: [], stopReason: "stop", provider: "", model: "", requestId: "", at } });
  }

  evento(e: ClientEvent): Subagente | undefined {
    if (e.type === "message") {
      if (e.message.role === "assistant") for (const c of e.message.toolCalls) if (c.name === "delegate") this.llamada(c.id).objetivo = objetivoDe(c.arguments);
      return undefined;
    }
    if ((e.type === "text" || e.type === "tool_start" || e.type === "tool_end") && e.worker?.startsWith("sub:")) {
      const s = this.sub(e.worker);
      if (e.type === "tool_start") this.cerrarTexto(s, Date.now());
      const { worker, ...resto } = e;
      const prefijo = `${worker}/`;
      const sinWorker = "id" in resto && resto.id.startsWith(prefijo) ? { ...resto, id: resto.id.slice(prefijo.length) } : resto;
      s.registro.evento(sinWorker as ClientEvent);
      return s;
    }
    // Los delegates terminan dentro del turno: al quedar la sesión en reposo, los que siguen «trabajando» no cerraron.
    if (e.type === "idle") {
      for (const s of this.subs.values()) if (s.estado === "trabajando") { s.estado = "no terminó"; this.terminar(s); }
      return undefined;
    }
    if ((e.type === "tool_start" || e.type === "tool_end") && e.name === "delegate") {
      this.llamada(e.id);
      if (e.type === "tool_start") return undefined;
      return this.cerrar(e);
    }
    return undefined;
  }

  private cerrar(e: Extract<ClientEvent, { type: "tool_end" }>): Subagente | undefined {
    const l = this.llamada(e.id);
    l.terminada = true;
    const real = typeof e.details.worker === "string" ? e.details.worker : undefined;
    if (!real) { l.worker = undefined; this.reasignar(); return undefined; }
    l.worker = real;
    const s = this.sub(real, l);
    s.objetivo = l.objetivo ?? s.objetivo;
    s.estado = e.details.estado === "listo" ? "terminó" : "no terminó";
    if (typeof e.details.solicitudes === "number") s.solicitudes = e.details.solicitudes;
    if (typeof e.details.usd === "string") s.usd = e.details.usd;
    this.terminar(s);
    return s;
  }

  private terminar(s: Subagente): void {
    s.fin = Date.now();
    this.cerrarTexto(s, s.fin);
    this.reasignar();
    s.informe = s.registro.entradas().flatMap((x) => (x.tipo === "texto" && x.markdown ? [x.markdown] : [])).at(-1);
  }

  get total(): number { return this.subs.size; }
}
