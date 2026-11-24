// Artefactos por hash: temporal + fsync + rename atómico, y recién después la fila en SQLite.
import { createHash, randomUUID } from "node:crypto";
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeSync } from "node:fs";
import { join } from "node:path";
import type { DatabaseSync } from "node:sqlite";

export interface ArtifactRef {
  hash: string;
  bytes: number;
  mediaType: string;
}

export class Artifacts {
  readonly db: DatabaseSync;
  readonly dir: string;

  constructor(db: DatabaseSync, dir: string) {
    this.db = db;
    this.dir = dir;
  }

  private path(hash: string): string {
    const hex = hash.replace(/^sha256:/, "");
    if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`Hash inválido: ${hash}`);
    return join(this.dir, hex.slice(0, 2), hex);
  }

  put(data: Buffer | string, mediaType: string, producer: string): ArtifactRef {
    const bytes = Buffer.isBuffer(data) ? data : Buffer.from(data);
    const hash = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    const target = this.path(hash);
    if (!existsSync(target)) {
      mkdirSync(join(target, ".."), { recursive: true });
      const tmp = `${target}.${randomUUID()}.tmp`;
      const fd = openSync(tmp, "wx");
      try {
        writeSync(fd, bytes);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      renameSync(tmp, target);
    }
    this.db
      .prepare("insert or ignore into artifacts(hash,bytes,media_type,producer,created_at) values(?,?,?,?,?)")
      .run(hash, bytes.length, mediaType, producer, new Date().toISOString());
    return { hash, bytes: bytes.length, mediaType };
  }

  /** Acepta el hash completo o un prefijo único de al menos 8 caracteres. */
  resolve(hashOrPrefix: string): string {
    const hex = hashOrPrefix.replace(/^sha256:/, "");
    if (!/^[0-9a-f]{8,64}$/.test(hex)) throw new Error("Indicá al menos 8 caracteres hexadecimales del hash");
    // Hash completo: búsqueda exacta por la clave. El LIKE de prefijo no usa el índice y recorre la tabla entera.
    if (hex.length === 64) {
      if (!this.db.prepare("select 1 from artifacts where hash=?").get(`sha256:${hex}`)) throw new Error("Artefacto inexistente");
      return `sha256:${hex}`;
    }
    const rows = this.db.prepare("select hash from artifacts where hash like ? limit 2").all(`sha256:${hex}%`);
    if (rows.length !== 1) throw new Error(rows.length ? "Prefijo ambiguo" : "Artefacto inexistente");
    return rows[0]!.hash as string;
  }

  /** Hash completo si existe; si no, undefined. */
  find(hashOrPrefix: string): string | undefined {
    try {
      return this.resolve(hashOrPrefix);
    } catch {
      return undefined;
    }
  }

  /** Archivo de un hash completo del catálogo, sin consultar la base (para leerlo sin bloquear). */
  file(hash: string): string {
    return this.path(hash);
  }

  /** Quién produjo un artefacto («http», «shell», «herramienta:x»…), o undefined si no existe. */
  producer(hashOrPrefix: string): string | undefined {
    const hash = this.find(hashOrPrefix);
    const row = hash ? this.db.prepare("select producer from artifacts where hash=?").get(hash) as { producer?: string } | undefined : undefined;
    return row?.producer ?? undefined;
  }

  read(hashOrPrefix: string): Buffer {
    return readFileSync(this.path(this.resolve(hashOrPrefix)));
  }
}
