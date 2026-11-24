// Los nombres salen de menciones literales. El valor de la política nunca se usa como configuración.
import { ReportRedactor } from "./redact.ts";
import { claveSensible } from "./secretos-sesion.ts";

const NOMBRES = ["User-Agent", "X-HackerOne", "X-HackerOne-Research", "X-BugCrowd", "X-Intigriti", "X-Intigriti-Username", "X-Cyber-Agent"];
const identificacion = new Map(NOMBRES.map((nombre) => [nombre.toLowerCase(), nombre]));
const asignacion = /(?<![\w-])([a-z][a-z0-9-]{0,63})[ \t]*:[ \t]*/gi;

/** La vista sólo cita nombres conocidos. El operador comprueba el valor y las condiciones en el original. */
export function avisoDeCabeceras(...fuentes: unknown[]): string {
  const menciones = new Set<string>();
  for (const fuente of fuentes) {
    if (typeof fuente !== "string") continue;
    for (const cita of fuente.matchAll(asignacion)) {
      const nombre = identificacion.get(cita[1]!.toLowerCase());
      const inicioValor = cita.index + cita[0].length;
      if (nombre && /[^\s`»]/.test(fuente.charAt(inicioValor))) menciones.add(nombre);
    }
  }
  return menciones.size ? `Revisá en la política las cabeceras citadas (${[...menciones].join(", ")}). Propuestas sin aplicar: confirmá con el operador el valor exacto de cada una; recién después configurala con /alcance cabecera Nombre: valor o session_settings. Si la política no es clara, no inventes el valor.` : "";
}

/** Limpia antes de acortar la nota, para que un corte no deje media credencial en el alcance. */
export function textoDePolitica(fuente: unknown): string {
  if (typeof fuente !== "string" || !fuente) return "";
  const redactor = new ReportRedactor();
  let cabeceraAnterior: "Cookie" | "Authorization" | undefined;
  const lineas = fuente.split(/\r\n?|\n/).map((linea) => {
    if (cabeceraAnterior && /^[ \t]+\S/.test(linea)) {
      redactor.headers({ [cabeceraAnterior]: linea.trim() });
      return "[continuación reservada]";
    }
    cabeceraAnterior = undefined;
    const partes: string[] = [];
    let desde = 0;
    for (const cita of linea.matchAll(asignacion)) {
      if (cita.index < desde) continue;
      const nombre = cita[1]!;
      if (!claveSensible(nombre) && !/^(?:x-)?(?:api-key|auth|key)$/i.test(nombre)) continue;
      const inicio = cita.index + cita[0].length;
      const apertura = linea[cita.index - 1];
      const cierre = apertura === "«" ? "»" : apertura === "`" ? "`" : undefined;
      const fin = cierre ? linea.indexOf(cierre, inicio) : -1;
      const hasta = fin >= 0 ? fin : linea.length;
      const valor = linea.slice(inicio, hasta);
      const campo = /cookie/i.test(nombre) ? "Cookie" : "Authorization";
      redactor.headers({ [campo]: valor });
      partes.push(linea.slice(desde, cita.index), nombre + ": [campo reservado]");
      desde = hasta;
      if (!cierre && !linea.slice(0, cita.index).trim()) cabeceraAnterior = campo;
    }
    return partes.length ? partes.join("") + linea.slice(desde) : linea;
  });
  return redactor.finish(lineas.join("\n"));
}
