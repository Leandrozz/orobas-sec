// De lo que dejó la sesión (hallazgos, artefactos, veredictos) a los hallazgos del resultado de CI: con su huella,
// sus pasos para reproducir (curl incluido) y todo tapado.
import type { Engine } from "../engine.ts";
import { effectiveSeverity, type Finding } from "../findings.ts";
import type { HttpExchange } from "../http.ts";
import { curlOf } from "../report.ts";
import type { Verdict } from "../verifier.ts";
import { claseCanonica, destinoDe, type DestinoHuella, huella, normalizarRuta } from "./huella.ts";
import type { HallazgoCi, Paso } from "./resultado.ts";
import type { Tapador } from "./tapado.ts";

/** El intercambio HTTP guardado en un artefacto, o undefined si el artefacto es otra cosa. */
export function intercambio(engine: Engine, hash: string): HttpExchange | undefined {
  try {
    const datos = JSON.parse(engine.artifacts.read(hash).toString("utf8")) as HttpExchange;
    return datos && typeof datos === "object" && datos.request && typeof datos.request.url === "string" ? datos : undefined;
  } catch {
    return undefined;
  }
}

/** Un paso para reproducir: la petición (con la identidad como variable en el curl) y lo que respondió, tapado. */
export function paso(engine: Engine, tapador: Tapador, hash: string, extracto = 1500): Paso | undefined {
  const ex = intercambio(engine, hash);
  if (!ex) return undefined;
  tapador.aprender(ex);
  const identidad = Object.values(ex.request.headers).map((v) => /^<identidad ([^>]+)>$/.exec(v)?.[1]).find(Boolean);
  const cabeceras = tapador.cabeceras(Object.fromEntries(Object.entries(ex.request.headers).filter(([k]) => k.toLowerCase() !== "content-length")));
  const url = tapador.url(ex.request.url);
  const cuerpo = ex.request.body === undefined ? undefined : tapador.texto(ex.request.body, "objetivo");
  const respuesta = ex.response
    ? (() => {
        const cuerpoResp = ex.response.bodyEncoding === "base64" ? `(${ex.response.bodyBytes} bytes binarios)` : tapador.texto(ex.response.body, "objetivo");
        return { estado: ex.response.status, cabeceras: tapador.cabeceras(ex.response.headers), extracto: cuerpoResp.slice(0, extracto), recortado: cuerpoResp.length > extracto || ex.response.truncated };
      })()
    : undefined;
  return {
    metodo: ex.request.method,
    url,
    cabeceras,
    ...(cuerpo !== undefined && cuerpo !== "" ? { cuerpo } : {}),
    ...(identidad ? { identidad } : {}),
    curl: tapador.final(curlOf({ method: ex.request.method, url, headers: cabeceras, ...(cuerpo ? { body: cuerpo } : {}) }, "es")),
    ...(respuesta ? { respuesta } : {}),
    ...(ex.error ? { error: tapador.texto(ex.error) } : {}),
    artefacto: hash,
  };
}

/** Saca un método HTTP del principio de un activo («GET /api/x»). */
const metodoDelActivo = (activo: string) => /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+/i.exec(activo.trim())?.[1]?.toUpperCase();
const sinMetodo = (activo: string) => activo.trim().replace(/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+/i, "").split(/\s/)[0] ?? "";

/** Los datos de la huella de un hallazgo: activo, evidencia y destinos del alcance. */
export function datosDeHuella(engine: Engine, finding: Pick<Finding, "asset" | "kind" | "title" | "evidence">, destinos: DestinoHuella[]) {
  const activo = sinMetodo(finding.asset).replace(/\{[^}/]*\}|:[a-z_]+(?=\/|$)|<[^>/]+>/gi, "1");
  const delActivo = normalizarRuta(activo);
  const intercambios = finding.evidence.map((h) => intercambio(engine, h)).filter((e): e is HttpExchange => !!e);
  const coincide = intercambios.find((e) => normalizarRuta(e.request.url).ruta === delActivo.ruta) ?? intercambios[0];
  const absoluto = /^[a-z][a-z0-9+.-]*:\/\//i.test(activo) ? activo : coincide?.request.url;
  const destino = absoluto ? destinoDe(destinos, absoluto) : "?";
  const ruta = /^[a-z][a-z0-9+.-]*:\/\//i.test(activo) || activo.startsWith("/") ? delActivo.ruta : coincide ? normalizarRuta(coincide.request.url).ruta : delActivo.ruta;
  const metodo = (coincide && normalizarRuta(coincide.request.url).ruta === ruta ? coincide.request.method : undefined) ?? metodoDelActivo(finding.asset) ?? coincide?.request.method ?? "*";
  const clase = claseCanonica(finding.kind, finding.title);
  return { destino, clase, metodo: metodo.toUpperCase(), ruta, consulta: delActivo.consulta };
}

/** Hallazgo de la sesión → hallazgo del resultado (sin comparación ni supresión: las pone la corrida). */
export function hallazgoCi(engine: Engine, tapador: Tapador, finding: Finding, destinos: DestinoHuella[], veredicto?: Verdict): HallazgoCi {
  const d = datosDeHuella(engine, finding, destinos);
  const reproduccion = finding.evidence.slice(0, 6).map((h) => paso(engine, tapador, h)).filter((p): p is Paso => !!p);
  const verificacion =
    veredicto && veredicto.state === "verificado" && veredicto.evidence.length >= 2
      ? { prueba: paso(engine, tapador, veredicto.evidence[0]!), control: paso(engine, tapador, veredicto.evidence[1]!), costo_usd: veredicto.costUsd }
      : undefined;
  return {
    huella: huella({ destino: d.destino, clase: d.clase.id, metodo: d.metodo, ruta: d.ruta, consulta: d.consulta }),
    id: finding.id,
    estado: finding.state,
    severidad: effectiveSeverity(finding),
    clase: d.clase,
    clase_declarada: tapador.texto(finding.kind),
    titulo: tapador.texto(finding.title),
    activo: tapador.url(finding.asset),
    destino: d.destino,
    metodo: d.metodo,
    ruta: d.ruta,
    consulta: d.consulta,
    resumen: tapador.texto(finding.summary),
    limites: tapador.texto(finding.limits),
    motivo: tapador.texto(finding.reason),
    decidido_por: finding.decidedBy,
    comparacion: "sin-anterior",
    bloqueante: false,
    reproduccion,
    ...(verificacion ? { verificacion: Object.fromEntries(Object.entries(verificacion).filter(([, v]) => v !== undefined)) as HallazgoCi["verificacion"] } : {}),
    evidencia: finding.evidence,
  };
}
