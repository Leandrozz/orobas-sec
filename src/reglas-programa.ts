// Citas breves de la política que condicionan qué vale la pena investigar.
import { textoDePolitica } from "./politica-cabeceras.ts";

export interface CitaRegla { cita: string; fuente: string }
export interface ReglasPrograma {
  exclusiones: CitaRegla[];
  honestos: CitaRegla[];
  posicionAtacante: CitaRegla[];
}

export const reglasVacias = (): ReglasPrograma => ({ exclusiones: [], honestos: [], posicionAtacante: [] });
export const TOPE_CITA = 160;
export const TOPES_REGLAS: Readonly<Record<keyof ReglasPrograma, number>> = { exclusiones: 6, honestos: 3, posicionAtacante: 3 };

// Con límites de palabra: «trusted» no coincide dentro de «untrusted». «self-hosted» sola no excluye nada (las
// instrucciones de un activo describen así lo que SÍ está en alcance); cuenta con «only» cerca.
const EXCLUSION = /\b(?:out[ -]of[ -]scope|outside (?:of )?(?:the )?scope|not (?:in[ -]scope|eligible|rewarded|accepted)|excluded|ineligible|no (?:se (?:acept|pag|recompens)\w*|paga|califica|es elegible)|fuera del? alcance|no elegible|local[ -]only|self[ -]hosted[ -]only)\b|\bonly\b[^.;]{0,40}\bself[ -]hosted\b/i;
const HONESTO = /\btrusted\b|\bhonest(?:[oa]s?)?\b|\bassum(?:e|ed|es)\b.*?\b(?:safe|secure|trusted|honest)\b|\bde confianza\b|\bse asume\b.*?\b(?:honest|segur|confiable)\w*/i;
const ATACANTE = /\b(?:attackers?|attack position|threat model|unprivileged|unauthenticated|atacantes?|modelo de amenaza|sin (?:acceso|privilegios))\b/i;
/** Tramos negados que no cuentan como regla: «not trusted», «non-trusted», «no es de confianza», «no se asume…», «nothing is excluded». */
const NEGADA = /\b(?:not|never|no|cannot|can't|isn't|aren't|nunca)\s+(?:[\w'-]+\s+)?(?:trusted|honest\w*|de confianza|confiables?)\b|\bnon-?trusted\b|\bno\s+se\s+asume\b[^.;]*|\b(?:not|never|nothing|none)\s+(?:(?:is|are|be|been|was|were)\s+)?excluded\b/gi;

/** Extrae frases citables; descarta bloques largos en vez de convertir toda la política en prompt. */
export function extraerReglas(fuentes: Array<{ texto: unknown; fuente: string }>): ReglasPrograma {
  const reglas = reglasVacias();
  const agregar = (tipo: keyof ReglasPrograma, lista: CitaRegla[], cita: string, fuente: string) => {
    const limpia = cita.replace(/\s+/g, " ").trim();
    if (limpia.length < 8 || limpia.length > TOPE_CITA || lista.some((item) => item.cita === limpia)) return;
    if (lista.length < TOPES_REGLAS[tipo]) lista.push({ cita: limpia, fuente });
  };
  for (const { texto, fuente } of fuentes) {
    for (const linea of textoDePolitica(texto).split(/\n|(?<=[.!?])\s+(?=[A-ZÁÉÍÓÚ])/)) {
      const afirmada = linea.replace(NEGADA, " ");
      if (EXCLUSION.test(afirmada)) agregar("exclusiones", reglas.exclusiones, linea, fuente);
      if (HONESTO.test(afirmada)) agregar("honestos", reglas.honestos, linea, fuente);
      if (ATACANTE.test(linea)) agregar("posicionAtacante", reglas.posicionAtacante, linea, fuente);
    }
  }
  return reglas;
}

/**
 * Las citas que agregó el operador (/alcance reglas, session_settings: fuente «operador…») sobreviven a reimportar
 * el programa; las del programa se reemplazan por las nuevas. Si no entran todas, ceden las del programa.
 */
export function conCitasDelOperador(previas: ReglasPrograma | undefined, nuevas: ReglasPrograma | undefined): ReglasPrograma | undefined {
  const tipos = Object.keys(TOPES_REGLAS) as Array<keyof ReglasPrograma>;
  const delOperador = (tipo: keyof ReglasPrograma) => (previas?.[tipo] ?? []).filter((item) => item.fuente.startsWith("operador"));
  if (!tipos.some((tipo) => delOperador(tipo).length)) return nuevas;
  const reglas = reglasVacias();
  for (const tipo of tipos) {
    const operador = delOperador(tipo);
    const programa = (nuevas?.[tipo] ?? []).filter((item) => !operador.some((suya) => suya.cita === item.cita));
    reglas[tipo] = [...programa.slice(0, Math.max(0, TOPES_REGLAS[tipo] - operador.length)), ...operador];
  }
  return reglas;
}

export function bloqueReglas(reglas: ReglasPrograma | undefined): string {
  if (!reglas) return "REGLAS DEL PROGRAMA: sin citas cargadas; consultá la política antes de invertir en una hipótesis.";
  const lineas = ["REGLAS DEL PROGRAMA (citas; prevalecen sobre sugerencias de continuar):"];
  for (const [titulo, citas] of [["Exclusiones", reglas.exclusiones], ["Partes asumidas honestas", reglas.honestos], ["Posición del atacante", reglas.posicionAtacante]] as const) {
    lineas.push(`${titulo}: ${citas.length ? citas.map((item) => `«${item.cita}» [${item.fuente}]`).join("; ") : "sin cita cargada"}`);
  }
  return lineas.join("\n");
}
