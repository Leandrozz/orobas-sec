import { t } from "../idioma.ts";
import { stripAnsi } from "./text.ts";
import { leerCorridas } from "./ultra.ts";

export interface Harness { id: string; harness: string; estado: string; enCurso: boolean; anterior: boolean; tarea: string; rama?: string; segundos?: number; salida?: number; cola: string; error?: string }

/** La cola es salida cruda de procesos externos: sin secuencias de escape, sin lo que un `\r` sobreescribe y sin controles. */
const limpiarCola = (cola: string): string =>
  stripAnsi(cola).split("\n").map((l) => l.replace(/\r+$/, "")).map((l) => l.slice(l.lastIndexOf("\r") + 1).replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "")).join("\n");

/** Lee la respuesta de `orquesta ver` (formato de Orquesta.summary): estado, segundos, salida y la cola del log. */
export function parsearVer(lineas: string[]): { estado?: string; segundos?: number; salida?: number; cola: string } {
  // El nombre del harness puede traer espacios («Claude Code»): se ancla al final de la línea.
  const m = /· (\S+) · (\d+) s(?: · salida (-?\d+))?\s*$/.exec(lineas[0] ?? "");
  const i = lineas.indexOf("salida (final):");
  return { estado: m?.[1], segundos: m ? Number(m[2]) : undefined, salida: m?.[3] !== undefined ? Number(m[3]) : undefined, cola: i < 0 ? "" : limpiarCola(lineas.slice(i + 1).join("\n")) };
}

export class Harnesses {
  private filas = new Map<string, Harness>();
  /** Último error al pedir la lista (se limpia al lograrlo). */
  errorLista?: string;
  private genLista = 0;
  private contador = 0;
  private ultimoVer = new Map<string, number>();
  private ask: (op: string, payload: object) => Promise<string[]>;
  constructor(ask: (op: string, payload: object) => Promise<string[]>) { this.ask = ask; }

  async refrescar(): Promise<Harness[]> {
    const mia = ++this.genLista;
    let lineas: string[];
    try { lineas = await this.ask("orquesta", {}); } catch (e) {
      if (mia === this.genLista) this.errorLista = e instanceof Error ? e.message : String(e);
      return [...this.filas.values()];
    }
    // Una lista lanzada después ya resolvió: ésta es más vieja y no pisa nada.
    if (mia !== this.genLista) return [...this.filas.values()];
    this.errorLista = undefined;
    const nuevas = new Map<string, Harness>();
    for (const c of leerCorridas(lineas)) nuevas.set(c.id, { cola: "", ...this.filas.get(c.id), ...c });
    this.filas = nuevas;
    return [...nuevas.values()];
  }

  async seguir(id: string): Promise<Harness | undefined> {
    const h0 = this.filas.get(id);
    if (!h0 || h0.anterior) return h0;
    const mia = ++this.contador;
    this.ultimoVer.set(id, mia);
    let v: ReturnType<typeof parsearVer> | undefined;
    let error: string | undefined;
    try {
      v = parsearVer(await this.ask("orquesta", { action: "ver", run: id }));
      if (!v.estado) error = t("orquesta ver: respuesta ilegible", "orquesta ver: unreadable reply");
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
    // Se escribe sobre la fila vigente (refrescar pudo reemplazarla) y sólo si ninguna respuesta más nueva la tocó.
    const h = this.filas.get(id);
    if (!h || this.ultimoVer.get(id) !== mia) return h;
    if (error || !v) { h.error = error; return h; }
    h.cola = v.cola;
    h.segundos = v.segundos;
    h.salida = v.salida;
    h.estado = v.estado!;
    h.enCurso = v.estado === "corriendo" || v.estado === "esperando";
    h.error = undefined;
    return h;
  }

  lista(): Harness[] { return [...this.filas.values()]; }
  de(id: string): Harness | undefined { return this.filas.get(id); }
}
