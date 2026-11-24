// SARIF 2.1.0 para la pestaña de seguridad (GitHub code scanning, GitLab). Un hallazgo de una evaluación dinámica no
// tiene archivo de código: la ubicación es la regla del alcance en .orobas/ci.yml (o, en un PR, el archivo y la
// línea donde se declaró la ruta afectada), y la petición y la respuesta van en webRequest y webResponse.
// partialFingerprints lleva la huella estable: así GitHub reconoce la misma alerta entre corridas.
import type { HallazgoCi, Paso, ResultadoCi, RetestCi } from "./resultado.ts";

export const SARIF_ESQUEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

/** Gravedad para GitHub (security-severity, 0 a 10) y nivel SARIF por severidad del harness. */
const GRAVEDAD: Record<string, { puntaje: string; nivel: "error" | "warning" | "note" }> = {
  critica: { puntaje: "9.5", nivel: "error" },
  alta: { puntaje: "8.0", nivel: "error" },
  media: { puntaje: "5.5", nivel: "warning" },
  baja: { puntaje: "3.0", nivel: "note" },
  informativa: { puntaje: "0.1", nivel: "note" },
};

export interface OpcionesSarif {
  /** El archivo de configuración (ruta relativa al repositorio). */
  archivoConfig: string;
  /** Línea de cada destino (nombre o regla) en el archivo de configuración. */
  lineas: Record<string, number>;
  /** Línea de «objetivo.alcance», para lo que no cae en un destino. */
  lineaAlcance: number;
  /** Incluir los candidatos sin verificar (como «review»). Por defecto no: la pestaña de seguridad es para lo verificado. */
  candidatos: boolean;
}

const web = (p: Paso | undefined) =>
  p
    ? {
        webRequest: { protocol: "HTTP", version: "1.1", method: p.metodo, target: p.url, headers: p.cabeceras, ...(p.cuerpo ? { body: { text: p.cuerpo } } : {}) },
        webResponse: p.respuesta ? { protocol: "HTTP", version: "1.1", statusCode: p.respuesta.estado, headers: p.respuesta.cabeceras, body: { text: p.respuesta.extracto } } : { noResponseReceived: true },
      }
    : {};

/** ¿La ruta del hallazgo es una de las que cambió el PR? Devuelve dónde se declaró. */
function declarada(r: ResultadoCi, ruta: string): { archivo: string; linea?: number } | undefined {
  const plantilla = (x: string) => x.replace(/\{[^}]*\}/g, "{id}").toLowerCase();
  return r.cobertura.solo_cambios.rutas.find((c) => plantilla(c.ruta) === plantilla(ruta) && c.archivo !== "(rutas_siempre)");
}

export function armarSarif(r: ResultadoCi, op: OpcionesSarif): Record<string, unknown> {
  const reglas: Array<Record<string, unknown>> = [];
  const indice = new Map<string, number>();
  const regla = (clase: HallazgoCi["clase"], severidad: string): { id: string; index: number } => {
    const id = `orobas/${clase.id}/${severidad}`;
    if (!indice.has(id)) {
      indice.set(id, reglas.length);
      reglas.push({
        id,
        name: clase.id.replace(/(^|-)([a-z])/g, (_t, _g, c: string) => c.toUpperCase()),
        shortDescription: { text: `${clase.nombre} (severidad ${severidad})` },
        fullDescription: { text: `${clase.nombre}: falla demostrada contra el entorno evaluado y reproducida por el verificador independiente de Orobas (prueba y control).` },
        ...(clase.cwe ? { helpUri: `https://cwe.mitre.org/data/definitions/${clase.cwe}.html` } : {}),
        help: { text: `Cada resultado trae la petición que lo demuestra (curl en las propiedades) y el control. Clase: ${clase.nombre}${clase.cwe ? ` (CWE-${clase.cwe})` : ""}.` },
        defaultConfiguration: { level: GRAVEDAD[severidad]?.nivel ?? "warning" },
        properties: { tags: ["security", "dast", ...(clase.cwe ? [`external/cwe/cwe-${clase.cwe}`] : [])], precision: "high", "security-severity": GRAVEDAD[severidad]?.puntaje ?? "5.0" },
      });
    }
    return { id, index: indice.get(id)! };
  };
  const ubicacion = (destino: string, ruta?: string) => {
    const enCodigo = ruta ? declarada(r, ruta) : undefined;
    if (enCodigo) return { physicalLocation: { artifactLocation: { uri: enCodigo.archivo, uriBaseId: "%SRCROOT%" }, ...(enCodigo.linea ? { region: { startLine: enCodigo.linea } } : {}) } };
    return { physicalLocation: { artifactLocation: { uri: op.archivoConfig, uriBaseId: "%SRCROOT%" }, region: { startLine: op.lineas[destino] ?? op.lineaAlcance } } };
  };
  const resultados: Array<Record<string, unknown>> = [];
  for (const h of r.hallazgos) {
    if (h.estado !== "verificado" && !(op.candidatos && h.estado === "candidato")) continue;
    const { id, index } = regla(h.clase, h.severidad);
    const prueba = h.verificacion?.prueba ?? h.reproduccion.find((p) => p.respuesta) ?? h.reproduccion[0];
    resultados.push({
      ruleId: id,
      ruleIndex: index,
      kind: h.estado === "verificado" ? "fail" : "review",
      level: h.estado === "verificado" ? GRAVEDAD[h.severidad]?.nivel ?? "warning" : "note",
      message: { text: `${h.titulo}${h.estado === "candidato" ? " (candidato sin verificar: no bloquea)" : ""}. ${h.metodo} ${h.ruta} en «${h.destino}». ${h.resumen}`.slice(0, 4000) },
      locations: [{ ...ubicacion(h.destino, h.ruta), logicalLocations: [{ fullyQualifiedName: `${h.metodo} ${h.ruta}`, kind: "resource" }] }],
      partialFingerprints: { "orobasHuella/v1": h.huella },
      ...(r.comparacion.anterior && h.estado === "verificado" ? { baselineState: h.comparacion === "persiste" ? "unchanged" : "new" } : {}),
      ...(h.supresion ? { suppressions: [{ kind: "external", status: "accepted", justification: `${h.supresion.motivo} (${h.supresion.autor}; vence ${h.supresion.vence})` }] } : {}),
      ...web(prueba),
      properties: {
        huella: h.huella,
        estado: h.estado,
        severidad: h.severidad,
        bloqueante: h.bloqueante,
        destino: h.destino,
        activo: h.activo,
        decidido_por: h.decidido_por,
        ...(prueba ? { curl: prueba.curl } : {}),
        ...(h.verificacion?.control ? { control: `${h.verificacion.control.metodo} ${h.verificacion.control.url} → ${h.verificacion.control.respuesta?.estado ?? "sin respuesta"}` } : {}),
      },
    });
  }
  // Lo verificado antes que sigue sin confirmarse arreglado queda abierto (no reaparecer no es estar arreglado).
  const abiertos = (t: RetestCi) => t.resultado === "persiste" || t.resultado === "sin-confirmar";
  for (const t of r.retest.filter(abiertos)) {
    if (r.hallazgos.some((h) => h.huella === t.huella && h.estado === "verificado")) continue;
    const { id, index } = regla(t.clase, t.severidad);
    resultados.push({
      ruleId: id,
      ruleIndex: index,
      kind: "fail",
      level: GRAVEDAD[t.severidad]?.nivel ?? "warning",
      message: { text: `${t.titulo} (de una corrida anterior; retest: ${t.resultado === "persiste" ? "persiste" : "sin confirmar que esté arreglado"}). ${t.motivo}`.slice(0, 4000) },
      locations: [ubicacion("?")],
      partialFingerprints: { "orobasHuella/v1": t.huella },
      baselineState: "unchanged",
      ...(t.supresion ? { suppressions: [{ kind: "external", status: "accepted", justification: `${t.supresion.motivo} (${t.supresion.autor}; vence ${t.supresion.vence})` }] } : {}),
      ...web(t.prueba ?? t.repeticion),
      properties: { huella: t.huella, retest: t.resultado, bloqueante: t.bloqueante, severidad: t.severidad },
    });
  }
  const exito = r.resultado.estado === "ok" || r.resultado.estado === "hallazgos";
  const notificaciones = [
    ...(exito ? [] : [{ level: "error", message: { text: r.resultado.motivo } }]),
    ...r.avisos.slice(0, 50).map((a) => ({ level: "warning", message: { text: a } })),
  ];
  const version = r.herramienta.version.split(" ")[0]!;
  return {
    $schema: SARIF_ESQUEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "orobas-sec",
            fullName: "Orobas (orobas-sec), agente de pentest de Elevate AI",
            informationUri: "https://github.com/Leandrozz/orobas-sec",
            version,
            ...(/^v?\d+\.\d+\.\d+/.test(version) ? { semanticVersion: version.replace(/^v/, "") } : {}),
            rules: reglas,
          },
        },
        automationDetails: { id: `orobas-ci/${r.nombre}/` },
        invocations: [
          {
            executionSuccessful: exito,
            exitCode: r.resultado.codigo,
            exitCodeDescription: r.resultado.descripcion,
            startTimeUtc: r.corrida.inicio,
            endTimeUtc: r.corrida.fin,
            ...(notificaciones.length ? { toolExecutionNotifications: notificaciones } : {}),
          },
        ],
        originalUriBaseIds: { "%SRCROOT%": { description: { text: "La raíz del repositorio." } } },
        results: resultados,
        properties: { formato: r.formato, huellaDelAlcance: r.autorizacion?.huella ?? null, gastoUsd: r.gasto.usd, peticiones: r.trafico.peticiones },
      },
    ],
  };
}
