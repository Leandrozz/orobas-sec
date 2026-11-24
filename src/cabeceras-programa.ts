// Identificación fija del programa: sólo pedidos al objetivo, nunca servicios auxiliares.
import type { DatabaseSync } from "node:sqlite";
import { claveSensible } from "./secretos-sesion.ts";
import { tokenConPrefijo } from "./formatos-credencial.ts";

const CLAVE = "cabeceras_programa";
const NOMBRE = /^[A-Za-z][A-Za-z0-9-]{0,63}$/;

export function leerCabecera(linea: string): [string, string] {
  const match = /^([^:]+):\s*(.*)$/.exec(linea);
  if (!match) throw new Error("Cabecera inválida: usá «Nombre: valor».");
  const nombre = match[1]!.trim();
  const valor = match[2]!.trim();
  if (!NOMBRE.test(nombre) || !valor || /[\x00-\x1f\x7f\u2028\u2029]/.test(valor)) throw new Error("Cabecera inválida: nombre HTTP y valor sin caracteres de control.");
  if (claveSensible(nombre) || /authori[sz]ation|cookie|token|session|secret|password|credential|csrf|xsrf|(?:^|-)auth(?:$|-)|(?:^|-)key(?:$|-)|(?:^|-)jwt(?:$|-)/i.test(nombre)
    || /^(?:proxy-|set-cookie|www-authenticate|host|content-length|content-type|transfer-encoding|connection)$/i.test(nombre))
    throw new Error(`«${nombre}» es una cabecera reservada o de credencial. Usá una identidad para credenciales.`);
  if (/^(?:Bearer|Basic|Token)\s+\S|^(?:Authorization|Cookie)\s*[:=]\s*\S|(?:^|[;\s])(?:sid|sessionid|token|api[-_]?key)\s*=\s*\S|eyJ[A-Za-z0-9_-]{20,}\./i.test(valor)
    || /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/.test(valor) || valor.match(tokenConPrefijo))
    throw new Error("El valor parece una credencial. Cargala como identidad.");
  return [nombre, valor];
}

export class CabecerasPrograma {
  private readonly db: DatabaseSync;
  constructor(db: DatabaseSync) { this.db = db; }

  listar(): Record<string, string> {
    const row = this.db.prepare("select value from meta where key=?").get(CLAVE) as { value: string } | undefined;
    if (!row) return {};
    const guardadas = JSON.parse(row.value) as Record<string, string>;
    return Object.fromEntries(Object.entries(guardadas).filter(([nombre, valor]) => {
      try { leerCabecera(`${nombre}: ${valor}`); return true; } catch { return false; }
    }));
  }

  poner(linea: string): Record<string, string> {
    const [nombre, valor] = leerCabecera(linea);
    const siguientes = Object.fromEntries(Object.entries(this.listar()).filter(([actual]) => actual.toLowerCase() !== nombre.toLowerCase()));
    siguientes[nombre] = valor;
    this.guardar(siguientes);
    return siguientes;
  }

  quitar(nombre: string): Record<string, string> {
    const siguientes = Object.fromEntries(Object.entries(this.listar()).filter(([actual]) => actual.toLowerCase() !== nombre.trim().toLowerCase()));
    this.guardar(siguientes);
    return siguientes;
  }

  private guardar(cabeceras: Record<string, string>): void {
    this.db.prepare("insert into meta(key,value) values(?,?) on conflict(key) do update set value=excluded.value").run(CLAVE, JSON.stringify(cabeceras));
  }
}

export function lineasCabeceras(cabeceras: Record<string, string>): string[] {
  const lineas = Object.entries(cabeceras).map(([nombre, valor]) => `${nombre}: ${valor}`);
  return lineas.length ? ["Cabeceras fijas del proyecto, enviadas al objetivo:", ...lineas.map((linea) => `  ${linea}`)] : ["Cabeceras fijas del proyecto: ninguna."];
}
