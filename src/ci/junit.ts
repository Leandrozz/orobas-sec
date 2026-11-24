// JUnit XML (opcional), para los CI que muestran pruebas: un caso por hallazgo verificado (falla si bloquea), uno por
// retest, los candidatos como omitidos, y un caso «la corrida terminó entera» que es error si fue de infraestructura
// o de configuración y falla si quedó incompleta.
import type { ResultadoCi } from "./resultado.ts";

const xml = (texto: string) => texto.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

export function armarJunit(r: ResultadoCi): string {
  const casos: string[] = [];
  let fallas = 0;
  let errores = 0;
  let omitidos = 0;
  const corrida = r.resultado.estado;
  if (corrida === "configuracion" || corrida === "infraestructura") {
    errores++;
    casos.push(`    <testcase classname="orobas.corrida" name="la corrida terminó entera"><error type="${corrida}" message="${xml(r.resultado.motivo)}">${xml(r.resultado.descripcion)}</error></testcase>`);
  } else if (corrida === "incompleto") {
    fallas++;
    casos.push(`    <testcase classname="orobas.corrida" name="la corrida terminó entera"><failure type="incompleto" message="${xml(r.resultado.motivo)}">${xml(r.resultado.descripcion)}</failure></testcase>`);
  } else casos.push(`    <testcase classname="orobas.corrida" name="la corrida terminó entera"/>`);
  for (const h of r.hallazgos) {
    const nombre = xml(`${h.severidad} · ${h.titulo} (${h.metodo} ${h.ruta}) [${h.huella}]`);
    const clase = xml(`orobas.${h.clase.id}`);
    if (h.estado === "verificado") {
      const cuerpo = xml([h.resumen, h.verificacion?.prueba?.curl ?? h.reproduccion[0]?.curl ?? "", h.supresion ? `Suprimido: ${h.supresion.motivo} (${h.supresion.autor}, vence ${h.supresion.vence})` : ""].filter(Boolean).join("\n\n"));
      if (h.bloqueante) {
        fallas++;
        casos.push(`    <testcase classname="${clase}" name="${nombre}"><failure type="${xml(h.severidad)}" message="${xml(h.titulo)}">${cuerpo}</failure></testcase>`);
      } else casos.push(`    <testcase classname="${clase}" name="${nombre}"><system-out>${cuerpo}</system-out></testcase>`);
    } else if (h.estado === "candidato") {
      omitidos++;
      casos.push(`    <testcase classname="${clase}" name="${nombre}"><skipped message="candidato sin verificar: no bloquea"/></testcase>`);
    }
  }
  for (const t of r.retest) {
    const nombre = xml(`retest · ${t.titulo} [${t.huella}]`);
    if (t.resultado === "persiste" && t.bloqueante) {
      fallas++;
      casos.push(`    <testcase classname="orobas.retest" name="${nombre}"><failure type="persiste" message="${xml(t.motivo)}"/></testcase>`);
    } else if (t.resultado === "sin-confirmar") {
      omitidos++;
      casos.push(`    <testcase classname="orobas.retest" name="${nombre}"><skipped message="${xml(`sin confirmar: ${t.motivo}`)}"/></testcase>`);
    } else casos.push(`    <testcase classname="orobas.retest" name="${nombre}"><system-out>${xml(`${t.resultado}: ${t.motivo}`)}</system-out></testcase>`);
  }
  const total = casos.length;
  const tiempo = r.tiempo.duracion_s.toFixed(0);
  return [
    `<?xml version="1.0" encoding="UTF-8"?>`,
    `<testsuites name="orobas-sec" tests="${total}" failures="${fallas}" errors="${errores}" skipped="${omitidos}" time="${tiempo}">`,
    `  <testsuite name="${xml(`orobas-ci/${r.nombre}`)}" tests="${total}" failures="${fallas}" errors="${errores}" skipped="${omitidos}" time="${tiempo}" timestamp="${xml(r.corrida.inicio.replace(/\.\d+Z$/, ""))}">`,
    ...casos,
    `  </testsuite>`,
    `</testsuites>`,
    "",
  ].join("\n");
}
