import { cabecerasDePrivacidad, comparteConServicio } from "./privacidad-trazas.ts";
import { redactSecrets } from "./plataformas.ts";
import { createHash } from "node:crypto";
// Consentimientos del operador para acciones de doble efecto: el borrado de recursos ajenos es la
// primera. El consent se guarda en la base del proyecto con hash (cita textual + fecha, como la
// evidencia), y se envía a los servidores de orobas con la clave de la cuenta; si el servicio
// todavía no lo recibe, queda local y el aviso lo dice. Cada petición destructiva además exige su
// propio allowDestructive: consent general + confirmación por petición.
// La cita es parte de las trazas: sólo viaja en el modo «compartir», tapada. En «local» y «no» al
// servicio le llegan el tipo, la huella y la fecha con una constancia fija.

import type { DatabaseSync } from "node:sqlite";

// «subida-activa»: upload_probe sube archivos con contenido activo (SVG con script, XML con entidades
// externas) aunque el perfil sea «bounty». Quedan guardados en el objetivo y pueden ejecutarse en el
// navegador de otro usuario o hacer que el parser del servidor lea o pida algo: lo decide el operador,
// citando la política del programa. En pentest, laboratorio, defensa y full-blast ya lo habilita el perfil.
export const CONSENT_KINDS = ["borrar-ajeno", "trayectorias", "trayectorias-no", "subida-activa"] as const;


export interface Consent {
  kind: string;
  at: string;
  /** Hash del consentimiento: cita textual + fecha (cadena de custodia). */
  hash: string;
  pedido: string;
  enviado?: string;
  resultado?: string;
}

export class ConsentStore {
  readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
    db.exec("create table if not exists consents(kind text primary key, at text not null, hash text not null, pedido text not null, sent_at text, sent_resultado text)");
  }

  grant(kind: string, pedido: string): Consent {
    if (!CONSENT_KINDS.includes(kind as (typeof CONSENT_KINDS)[number])) throw new Error(`Consentimiento desconocido «${kind}». Válidos: ${CONSENT_KINDS.join(", ")}`);
    const at = new Date().toISOString();
    const hash = `sha256:${createHash("sha256").update(`${kind}\n${at}\n${pedido.trim()}`).digest("hex").slice(0, 32)}`;
    this.db.prepare("insert or replace into consents(kind,at,hash,pedido) values(?,?,?,?)").run(kind, at, hash, pedido.trim());
    return this.get(kind)!;
  }

  revoke(kind: string): void {
    this.db.prepare("delete from consents where kind=?").run(kind);
  }

  has(kind: string): boolean {
    return !!this.db.prepare("select kind from consents where kind=?").get(kind);
  }

  get(kind: string): Consent | undefined {
    const row = this.db.prepare("select kind,at,hash,pedido,sent_at,sent_resultado from consents where kind=?").get(kind) as any;
    return row ? { kind: row.kind, at: row.at, hash: row.hash, pedido: row.pedido, enviado: row.sent_at, resultado: row.sent_resultado } : undefined;
  }

  markSent(kind: string, resultado: string): void {
    this.db.prepare("update consents set sent_at=?, sent_resultado=? where kind=?").run(new Date().toISOString(), resultado, String(kind));
  }

  /** Vista para /consent y cyber consent. */
  view(): string[] {
    const rows = this.db.prepare("select kind,at,hash,pedido,sent_at,sent_resultado from consents order by at").all() as any[];
    if (!rows.length) return ["Sin consentimientos en este proyecto. `consent borrar-ajeno si «cita»` habilita el borrado de recursos ajenos; cada petición además lleva su propia confirmación (allowDestructive)."];
    return rows.map((row) => {
      const at = new Date(row.at).toLocaleString("es-AR");
      const sent = row.sent_at ? `enviado a los servidores: ${row.sent_resultado}` : "sólo local (no se pudo enviar)";
      return `consent ${row.kind} · desde ${at} · hash ${row.hash}\n  pedido citado: «${row.pedido}»${row.sent_at ? `\n  ${sent}` : ""}`;
    });
  }
}

/** Hash del consentimiento: cita + fecha, para la cadena de custodia. */
export function consentHash(kind: string, pedido: string, at: string): string {
  return `sha256:${createHash("sha256").update(`${kind}\n${at}\n${pedido.trim()}`).digest("hex").slice(0, 32)}`;
}

/** Lo que viaja en lugar de la cita cuando el modo no es «compartir». */
export const CONSTANCIA = "Cita conservada por el operador.";

/** La cita como viajaría en «compartir»: con los secretos de la sesión y los de forma conocida tapados. */
export const citaTapada = (pedido: string, tapar: (texto: string) => string = (texto) => texto) => redactSecrets(tapar(pedido.trim())).slice(0, 2000);

/** Envía el consentimiento a los servidores de orobas (mismo canal que las trazas). Falla suave: queda local. */
export async function sendConsent(kind: string, pedido: string, hash: string, at: string, apiKey: string | undefined, fetchImpl: typeof fetch = fetch, opciones: { tapar?: (texto: string) => string } = {}): Promise<string> {
  if (!apiKey) throw new Error("Sin cuenta de orobas no se envía nada: el consentimiento quedó guardado localmente.");
  const base = process.env.OROBAS_BASE_URL?.replace(/\/$/, "") ?? "https://cyber.elevateai.ar/api/v1";
  const cita = comparteConServicio() ? citaTapada(pedido, opciones.tapar) : CONSTANCIA;
  const response = await fetchImpl(`${base}/consent`, {
    method: "POST",
    headers: { ...cabecerasDePrivacidad(), accept: "application/json", "content-type": "application/json", authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({ kind, hash, pedido: cita, at, client: "orobas-sec" }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`El servicio respondió HTTP ${response.status}: el consentimiento quedó guardado localmente.`);
  return `recibido por los servidores (${response.status})`;
}