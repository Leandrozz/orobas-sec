// Residuos que dejan las sondas en el objetivo y que no salen de una escritura con identificador:
// archivos subidos (upload_probe) o la contraseña cambiada de una cuenta de prueba (reset_probe).
// El informe los lista en «Para limpiar», junto a las escrituras con id y las direcciones de prueba.
import type { DatabaseSync } from "node:sqlite";

export interface Residue {
  at: string;
  /** Herramienta que lo dejó. */
  tool: string;
  /** Qué es: «archivo», «cuenta». */
  kind: string;
  /** Dónde quedó: la URL donde se sirve, o el endpoint si no se supo. */
  target: string;
  /** Nombre enviado, variante, identificadores devueltos. */
  detail: string;
}

const ensure = (db: DatabaseSync) => db.exec("create table if not exists probe_residues(session_id text, at text not null, tool text not null, kind text not null, target text not null, detail text not null)");

export function recordResidue(db: DatabaseSync, sessionId: string, residue: Omit<Residue, "at">): void {
  ensure(db);
  db.prepare("insert into probe_residues(session_id,at,tool,kind,target,detail) values(?,?,?,?,?,?)").run(sessionId, new Date().toISOString(), residue.tool, residue.kind, residue.target, residue.detail);
}

/** Los de una sesión, o los de todo el proyecto. Sin tabla (proyecto viejo), ninguno. */
export function listResidues(db: DatabaseSync, sessionId?: string): Residue[] {
  try {
    return (sessionId
      ? db.prepare("select at,tool,kind,target,detail from probe_residues where session_id=? order by at").all(sessionId)
      : db.prepare("select at,tool,kind,target,detail from probe_residues order by at").all()) as unknown as Residue[];
  } catch {
    return [];
  }
}
