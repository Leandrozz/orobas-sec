// Descartes de trazas del gateway. En «compartir», un pedido al modelo que lleva a la vista material del objetivo
// sale con «x-cyber-trazas: no» (el gateway no guarda su cuerpo). Pero el pedido en el que el agente INVENTA la
// contraseña de una cuenta de prueba no la lleva: la trae la respuesta, y el gateway guarda pedido y respuesta
// enteros. El motor lo nota al recibir la respuesta (SecretosSesion.respuestaConMaterial) y pide descartar la traza
// de ese pedido con POST /traces/descartar, que recibe sólo ids de pedido (oro_req_…, de x-request-id), nunca
// contenido. El material útil no se pierde: el turno y la trayectoria salen igual, con todo tapado.
//
// Los pedidos a descartar se anotan en la base del proyecto antes de mandarlos: si el servicio no contesta o el
// proceso se corta, se reintentan al terminar el turno, al cerrar y la próxima vez que se abra el proyecto.
import type { DatabaseSync } from "node:sqlite";
import { cabecerasDePrivacidad } from "./privacidad-trazas.ts";

export const ID_DE_PEDIDO = /^oro_req_[a-f0-9]{16}$/;
const TANDA = 50;

export type Destino = { base: string; clave?: string };

export class DescartesDeTrazas {
  private readonly db: DatabaseSync;
  private readonly clave: (nombre: string) => string | undefined;
  private readonly fetchImpl: typeof fetch;
  private cola: Promise<number> = Promise.resolve(0);

  /** `clave`: lee la clave a partir del nombre de su variable (en la base se guarda el nombre, nunca la clave). */
  constructor(db: DatabaseSync, clave: (nombre: string) => string | undefined, fetchImpl: typeof fetch = fetch) {
    this.db = db;
    this.clave = clave;
    this.fetchImpl = fetchImpl;
    db.exec("create table if not exists trazas_a_descartar(pedido text primary key, base text not null, clave text not null, at text not null)");
  }

  /** Anota un pedido para descartar y lo manda. `claveEnv`: el nombre de la variable de la clave (OROBAS_API_KEY). */
  anotar(pedido: string, base: string, claveEnv: string): Promise<number> {
    if (!ID_DE_PEDIDO.test(pedido) || !base) return Promise.resolve(0);
    this.db.prepare("insert or ignore into trazas_a_descartar(pedido, base, clave, at) values (?, ?, ?, ?)").run(pedido, base.replace(/\/$/, ""), claveEnv, new Date().toISOString());
    return this.enviar();
  }

  pendientes(): string[] {
    return (this.db.prepare("select pedido from trazas_a_descartar order by at").all() as Array<{ pedido: string }>).map((fila) => fila.pedido);
  }

  /** Manda lo pendiente, de a una tanda por servicio. Devuelve cuántos quedaron descartados. De a uno por vez. */
  enviar(): Promise<number> {
    this.cola = this.cola.then(() => this.enviarYa(), () => this.enviarYa());
    return this.cola;
  }

  private async enviarYa(): Promise<number> {
    const filas = this.db.prepare("select pedido, base, clave from trazas_a_descartar order by at limit 500").all() as Array<{ pedido: string; base: string; clave: string }>;
    let hechos = 0;
    const grupos = new Map<string, string[]>();
    for (const fila of filas) {
      const grupo = `${fila.base}\n${fila.clave}`;
      grupos.set(grupo, [...(grupos.get(grupo) ?? []), fila.pedido]);
    }
    for (const [grupo, pedidos] of grupos) {
      const [base, claveEnv] = grupo.split("\n") as [string, string];
      const clave = this.clave(claveEnv);
      if (!clave) continue;
      for (let i = 0; i < pedidos.length; i += TANDA) {
        const tanda = pedidos.slice(i, i + TANDA);
        try {
          const response = await this.fetchImpl(`${base}/traces/descartar`, {
            method: "POST",
            headers: { ...cabecerasDePrivacidad(), "content-type": "application/json", authorization: `Bearer ${clave}` },
            body: JSON.stringify({ traces: tanda }),
            signal: AbortSignal.timeout(10_000),
          });
          // 400: el servicio no entiende alguno (un id viejo o de otra forma); reintentarlo no lo arregla.
          if (!response.ok && response.status !== 400) continue;
          const borrar = this.db.prepare("delete from trazas_a_descartar where pedido = ?");
          for (const pedido of tanda) borrar.run(pedido);
          if (response.ok) hechos += tanda.length;
        } catch { /* sin servicio: queda para el próximo intento */ }
      }
    }
    return hechos;
  }
}
