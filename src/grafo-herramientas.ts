// Herramientas del grafo de hechos para el modelo. `grafo` (núcleo, sólo lectura) consulta lo que el harness ya
// observó; `grafo_anotar` (catálogo) registra una hipótesis o una relación, que queda «inferida»: el modelo nunca
// pone un hecho como observado ni verificado, ni agrega destinos (sólo hipótesis sobre nodos que ya existen y
// están dentro del alcance).
import { createHash } from "node:crypto";
import type { Tool, ToolResult } from "./agent.ts";
import type { Artifacts } from "./artifacts.ts";
import type { Findings } from "./findings.ts";
import { limpio, type Grafo, type NodoSpec, type NodoVista, type TipoArista, type Vista } from "./grafo.ts";
import { caminos, faltantes, resolver, resumen, subgrafoHallazgo, vecinos } from "./grafo-consultas.ts";
import type { HttpClient } from "./http.ts";
import { nodos } from "./grafo-alimentar.ts";

export interface ContextoHerramientas {
  grafo: Grafo;
  sesion: string;
  /** Identidades del operador cargadas ahora. */
  identidades: () => string[];
  /** Escaladas propuestas para un hallazgo (src/cadenas.ts), con nodos del grafo. */
  propuestas?: (vista: Vista, hallazgo: NodoVista) => string[];
  http?: HttpClient;
  artifacts?: Artifacts;
  findings?: Findings;
}

const MODOS = ["resumen", "faltantes", "vecinos", "caminos", "hallazgo"] as const;
/** Lo que el modelo puede anotar entre dos nodos existentes. */
const RELACIONES: TipoArista[] = ["habilita", "deriva_de", "refuta", "accesible_por", "expone", "acepta", "pertenece_a", "observado_en"];

export function createGrafoTools(contexto: ContextoHerramientas): Tool[] {
  const grafo: Tool = {
    name: "grafo",
    label: "Grafo de hechos",
    description:
      "Lo que el harness ya observó del objetivo (rutas con método, parámetros, qué obtuvo cada identidad, objetos, tecnologías, hallazgos y cadenas), con estado y evidencia. " +
      "modo faltantes: qué falta probar (rutas × identidades, objetos no pedidos con otra identidad, escrituras, parámetros sin sondear); vecinos, caminos (nodo → hasta), hallazgo, resumen. Antes de repetir pruebas o de cerrar. Anotar: grafo_anotar.",
    parameters: {
      type: "object",
      properties: {
        modo: { type: "string", enum: [...MODOS] },
        nodo: { type: "string", description: "Ruta («GET /api/x/{n}»), identidad, id de objeto o de hallazgo" },
        hasta: { type: "string" },
        tipo: { type: "string", description: "Filtro: objeto, identidad, escritura, parametro, ruta…" },
        pagina: { type: "integer", minimum: 1 },
      },
      required: ["modo"],
    },
    parallel: true,
    replay: "safe",
    execute: (params): ToolResult => {
      const modo = String(params.modo ?? "resumen");
      const vista = contexto.grafo.ver();
      const opciones = { pagina: Number(params.pagina) || 1, identidades: contexto.identidades(), tipo: params.tipo ? String(params.tipo) : undefined, propuestas: contexto.propuestas ? (nodo: NodoVista) => contexto.propuestas!(vista, nodo) : undefined };
      const necesita = (campo: string) => { if (!String(params[campo] ?? "").trim()) throw new Error(`El modo ${modo} necesita «${campo}».`); return String(params[campo]); };
      const texto = modo === "faltantes" ? faltantes(vista, opciones)
        : modo === "vecinos" ? vecinos(vista, necesita("nodo"), opciones)
        : modo === "caminos" ? caminos(vista, necesita("nodo"), necesita("hasta"), opciones)
        : modo === "hallazgo" ? subgrafoHallazgo(vista, necesita("nodo"), opciones)
        : modo === "resumen" ? resumen(vista, opciones)
        : (() => { throw new Error(`Modo desconocido «${modo}». Usar: ${MODOS.join(", ")}.`); })();
      return { text: texto, details: { modo, nodos: vista.nodos.size, aristas: vista.aristas.size } };
    },
  };

  const anotar: Tool = {
    name: "grafo_anotar",
    label: "Anotar en el grafo",
    description:
      "Registra en el grafo de hechos una hipótesis (texto corto, sobre nodos que ya existen) o una relación entre dos nodos existentes (habilita, deriva_de, refuta…). Queda «inferida»: sólo el harness la vuelve observada, y un hallazgo verificado o descartado la confirma o la refuta. " +
      "Con hallazgo, ata la hipótesis a ese hallazgo. Citá la evidencia (ids h12, hashes o ids de hallazgo). No agrega destinos ni nada fuera del alcance.",
    parameters: {
      type: "object",
      properties: {
        hipotesis: { type: "string", maxLength: 300, description: "Qué creés que pasa, en una frase" },
        sobre: { type: "array", items: { type: "string" }, maxItems: 6, description: "Nodos a los que se refiere (como en grafo: rutas, objetos, identidades, hallazgos)" },
        relacion: { type: "object", properties: { de: { type: "string" }, tipo: { type: "string", enum: RELACIONES }, a: { type: "string" } }, required: ["de", "tipo", "a"] },
        hallazgo: { type: "string", description: "Id (o prefijo) del hallazgo que confirma o refuta la hipótesis" },
        evidencia: { type: "array", items: { type: "string" }, maxItems: 8, description: "Ids de intercambio (h12), hashes de artefacto o ids de hallazgo" },
      },
      required: [],
    },
    execute: (params): ToolResult => {
      const vista = contexto.grafo.ver();
      const unico = (texto: string, para: string): NodoVista => {
        const encontrados = resolver(vista, texto);
        if (!encontrados.length) throw new Error(`No hay ningún nodo «${limpio(texto, 80)}» (${para}). Sólo se anota sobre lo que el grafo ya tiene: mirá grafo modo resumen o vecinos.`);
        const nodo = encontrados[0]!;
        if (vista.ubicacion(nodo) !== "dentro") throw new Error(`«${limpio(texto, 80)}» está fuera del alcance vigente o es un señuelo: no se anota.`);
        return nodo;
      };
      const citas = ((params.evidencia ?? []) as unknown[]).map((ref) => String(ref).trim()).filter(Boolean).map((ref) => {
        if (/^h\d+$/.test(ref)) return contexto.http?.hashOf(ref) ?? (() => { throw new Error(`No hay un intercambio ${ref} en esta sesión.`); })();
        if (/^sha256:/i.test(ref)) return contexto.artifacts?.find(ref) ?? (() => { throw new Error(`No hay un artefacto ${ref} en este proyecto.`); })();
        const hallazgo = contexto.findings?.get(ref);
        if (hallazgo) return `hallazgo:${hallazgo.id}`;
        throw new Error(`«${limpio(ref, 40)}» no es un intercambio (h12), un artefacto (sha256:…) ni un hallazgo de este proyecto.`);
      });
      // Sin cita, la anotación misma es la referencia: sesión y momento (únicos aunque la sesión se retome).
      const evidencia = citas[0] ?? `anotacion:${contexto.sesion}:${new Date().toISOString()}`;
      const comoSpec = (nodo: NodoVista): NodoSpec => ({ tipo: nodo.tipo, id: nodo.id, etiqueta: nodo.etiqueta, estado: nodo.estado, ...(nodo.destino ? { destino: nodo.destino } : {}) });
      const hechos: string[] = [];
      const hallazgoRef = params.hallazgo ? String(params.hallazgo) : undefined;
      const finding = hallazgoRef ? contexto.findings?.get(hallazgoRef) : undefined;
      if (hallazgoRef && !finding) throw new Error(`No existe el hallazgo ${limpio(hallazgoRef, 40)} (finding_list da los ids).`);
      if (params.hipotesis) {
        const texto = limpio(String(params.hipotesis), 300);
        if (texto.length < 8) throw new Error("La hipótesis tiene que decir algo: una frase.");
        const sobre = ((params.sobre ?? []) as unknown[]).map((ref) => unico(String(ref), "sobre"));
        if (!sobre.length && !citas.length && !finding) throw new Error("Una hipótesis necesita en qué se apoya: sobre (nodos del grafo), evidencia o hallazgo.");
        const id = `anotada:${createHash("sha256").update(texto.toLowerCase()).digest("hex").slice(0, 12)}`;
        const estado = finding?.state === "verificado" ? "verificado" : finding?.state === "descartado" ? "refutado" : "inferido";
        const hipotesis = nodos.hipotesis(id, texto, estado, { origen: "agente", ...(citas.length ? { citas: citas.map((cita) => cita.slice(0, 19)) } : {}) });
        contexto.grafo.nodo({ ...hipotesis, forzar: estado !== "inferido" }, evidencia, "grafo_anotar");
        for (const nodo of sobre) contexto.grafo.arista(hipotesis, "deriva_de", comoSpec(nodo), "inferido", evidencia, { anotada: true }, { herramienta: "grafo_anotar" });
        if (finding) contexto.grafo.arista(nodos.hallazgo(finding), "deriva_de", hipotesis, "inferido", `hallazgo:${finding.id}`, { anotada: true }, { herramienta: "grafo_anotar" });
        hechos.push(`hipótesis ${id.slice(0, 20)} «${texto}» (${estado})${sobre.length ? ` sobre ${sobre.map((nodo) => nodo.etiqueta).join(", ")}` : ""}${finding ? `, atada al hallazgo ${finding.id.slice(0, 8)}` : ""}`);
      }
      if (params.relacion) {
        const relacion = params.relacion as { de?: unknown; tipo?: unknown; a?: unknown };
        const tipo = String(relacion.tipo ?? "") as TipoArista;
        if (!RELACIONES.includes(tipo)) throw new Error(`Relación inválida «${limpio(String(relacion.tipo ?? ""), 30)}». Usar: ${RELACIONES.join(", ")}.`);
        const de = unico(String(relacion.de ?? ""), "relacion.de");
        const a = unico(String(relacion.a ?? ""), "relacion.a");
        if (de.clave === a.clave) throw new Error("Una relación necesita dos nodos distintos.");
        contexto.grafo.arista(comoSpec(de), tipo, comoSpec(a), "inferido", evidencia, { anotada: true, ...(citas.length ? { citas: citas.map((cita) => cita.slice(0, 19)) } : {}) }, { herramienta: "grafo_anotar" });
        hechos.push(`${de.etiqueta} ${tipo.replace("_", " ")} ${a.etiqueta} (inferida)`);
      }
      if (!hechos.length) throw new Error("Nada que anotar: pasá hipotesis (con sobre, evidencia o hallazgo) o relacion.");
      contexto.grafo.vaciar();
      return { text: `Anotado: ${hechos.join("; ")}. Queda inferido hasta que el harness lo observe o un hallazgo lo confirme o lo descarte.`, details: { anotaciones: hechos.length } };
    },
  };
  return [grafo, anotar];
}
