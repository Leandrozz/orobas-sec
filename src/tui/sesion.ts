// Sesión: lo que comparten las ventanas que muestran la misma conversación (el resto lo guarda cada ventana).
import type { Client, ClientEvent } from "../client.ts";
import type { Snapshot } from "../daemon.ts";
import { type Corrida } from "./dolar.ts";
import { type Entrada, Registro } from "./entradas.ts";
import { Harnesses } from "./harnesses.ts";
import { type Subagente, Subagentes } from "./subagentes.ts";
import { linkify } from "./text.ts";

export class Sesion {
  client: Client;
  registro: Registro;
  hasContent: boolean;
  /** Subagentes (texto por sub:N) y corridas de harnesses de esta sesión. */
  subagentes = new Subagentes();
  harnesses: Harnesses;
  /** Ids de entradas ya contadas como novedad: un texto en streaming vuelve a llegar en cada delta. */
  contadas = new Set<number>();
  activeTools: Map<string, string>;
  /** Resultados completos: artefactos traídos bajo demanda (de a 2). */
  evidencia = new Map<string, string | "cargando" | "error">();
  private cola: string[] = [];
  private enVuelo = 0;
  /** Se avisa cuando una evidencia terminó de traerse (la pantalla se redibuja). */
  alTraer: () => void = () => {};
  turno: { inicio: number; costo: number } | undefined;
  /** «$ comando»: corridas que el agente todavía no vio (viajan con el próximo mensaje) y la que está en curso. */
  pendientes: Corrida[] = [];
  corriendo: AbortController | undefined;
  /** Permiso de shell que el motor está esperando. */
  permiso: Extract<ClientEvent, { type: "confirm" }> | undefined;
  /** Herramientas en curso cuando llegó el permiso: el daemon no avisa que lo resolvió, se deduce de que terminen. */
  private esperando = new Set<string>();

  constructor(client: Client, snapshot: Snapshot, harnesses?: (ask: (op: string, p: object) => Promise<string[]>) => Harnesses) {
    this.client = client;
    const ask = (op: string, p: object) => this.client.ask(op, p);
    this.harnesses = harnesses ? harnesses(ask) : new Harnesses(ask);
    this.registro = Registro.desdeSnapshot(snapshot.messages);
    if (snapshot.partial) this.registro.evento({ type: "text", delta: snapshot.partial });
    this.hasContent = snapshot.messages.length > 0 || !!snapshot.partial || snapshot.status.running || Object.keys(snapshot.tools).length > 0;
    this.activeTools = new Map(Object.entries(snapshot.tools));
  }

  /** `status.title` si hay; si no, los primeros 8 del id. */
  nombre(): string { return this.client.status.title || (this.client.status.session ?? "").slice(0, 8); }

  private bombear() {
    while (this.enVuelo < 2 && this.cola.length) {
      const hash = this.cola.shift()!;
      this.enVuelo++;
      this.client.view("evidencia", hash).then((l) => this.evidencia.set(hash, l.slice(1).join("\n")), () => this.evidencia.set(hash, "error")).finally(() => { this.enVuelo--; this.alTraer(); this.bombear(); });
    }
  }
  traer(hash: string) {
    if (this.evidencia.has(hash)) return;
    this.evidencia.set(hash, "cargando");
    this.cola.push(hash);
    this.bombear();
  }

  /** El permiso ya no espera a nadie (respondido acá). */
  soltarPermiso() { this.permiso = undefined; this.esperando.clear(); }

  /** Se resolvió por otro lado (otro cliente, vencimiento, turno abortado): terminaron sus herramientas, `idle` o el turno paró. */
  private permisoResuelto(event: ClientEvent): boolean {
    if (!this.permiso) return false;
    if (event.type === "tool_end") this.esperando.delete(event.id);
    const resuelto = (event.type === "tool_end" && this.esperando.size === 0) || event.type === "idle" || (event.type === "status" && !this.client.status.running);
    if (resuelto) this.soltarPermiso();
    return resuelto;
  }

  /** Reenvía los eventos del client después de actualizar herramientas y registro; `nuevas` son las entradas que trajo y `resuelto` si un permiso pendiente quedó resuelto por el daemon. */
  on(cb: (e: ClientEvent, nuevas: readonly Entrada[], resuelto: boolean, nuevoSub?: Subagente) => void) {
    this.client.on((event) => {
      const antes = this.subagentes.total;
      let nuevoSub: Subagente | undefined;
      try { this.subagentes.evento(event); if (this.subagentes.total > antes) nuevoSub = this.subagentes.lista()[0]; } catch { /* un error acá no debe cortar el registro de la principal */ }
      let nuevas: readonly Entrada[] = [];
      let resuelto = false;
      if (event.type === "notice") nuevas = [this.registro.aviso(linkify(event.text), "warn")];
      else if (event.type === "confirm") {
        // Un segundo pedido pisa al primero: el primero se rechaza, no queda esperando cinco minutos sin aviso.
        const previo = this.permiso;
        if (previo && previo.id !== event.id) void this.client.ask("confirm", { permiso: previo.id, ok: false, decision: "no" }).catch(() => {});
        this.permiso = event;
        this.esperando = new Set(this.activeTools.keys());
      }
      else {
        if (event.type === "tool_start") this.activeTools.set(event.id, event.worker ? `${event.worker} › ${event.label}` : event.label);
        else if (event.type === "tool_end") this.activeTools.delete(event.id);
        nuevas = this.registro.evento(event);
        resuelto = this.permisoResuelto(event);
      }
      cb(event, nuevas, resuelto, nuevoSub);
    });
  }
}
