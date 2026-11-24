// El resumen en Markdown: el comentario del PR (uno solo, que se edita en cada corrida gracias al marcador) y el
// resumen del job. Primero lo que decide: si falla y por qué; después los hallazgos verificados con cómo
// reproducirlos, los candidatos aparte, la comparación, qué se probó y qué no, y lo que costó.
import type { HallazgoCi, Paso, ResultadoCi } from "./resultado.ts";

/** El marcador que identifica el comentario de esta configuración en el PR. */
export const marcador = (nombre: string) => `<!-- orobas-sec:ci:${nombre} -->`;
/** GitHub corta los comentarios en 65 536 caracteres. */
export const MAXIMO = 60_000;

const ESTADO: Record<string, string> = {
  ok: "✓ Sin hallazgos que bloqueen",
  hallazgos: "✗ Falla: hallazgos verificados",
  configuracion: "✗ Error de configuración",
  infraestructura: "✗ No concluyente: falló el proveedor o el objetivo",
  incompleto: "✗ Incompleta: se agotó el presupuesto o el tiempo",
};
const SEV: Record<string, string> = { critica: "crítica", alta: "alta", media: "media", baja: "baja", informativa: "informativa" };

const celda = (texto: string) => texto.replace(/\r?\n/g, " ").replace(/\|/g, "\\|").slice(0, 160);
const bloque = (texto: string, lenguaje = "") => {
  const cerco = "`".repeat(Math.max(3, ...[...texto.matchAll(/`+/g)].map((m) => m[0].length + 1)));
  return `${cerco}${lenguaje}\n${texto}\n${cerco}`;
};
const duracion = (s: number) => (s >= 3600 ? `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min` : s >= 60 ? `${Math.floor(s / 60)} min ${s % 60} s` : `${s} s`);

function paso(p: Paso, titulo: string): string[] {
  const salida = [`${titulo}${p.identidad ? ` (identidad «${p.identidad}»)` : ""}:`, "", bloque(p.curl, "sh"), ""];
  if (p.respuesta) salida.push(`Respondió **HTTP ${p.respuesta.estado}**${p.respuesta.extracto ? ":" : "."}`, "", ...(p.respuesta.extracto ? [bloque(p.respuesta.extracto.slice(0, 800) + (p.respuesta.extracto.length > 800 || p.respuesta.recortado ? "\n…" : "")), ""] : []));
  else if (p.error) salida.push(`Sin respuesta: ${p.error}`, "");
  return salida;
}

function detalle(h: HallazgoCi): string[] {
  const salida = [
    `<details><summary><b>${SEV[h.severidad]}</b> · ${celda(h.titulo)} · <code>${h.metodo} ${celda(h.ruta)}</code></summary>`,
    "",
    `- Huella: \`${h.huella}\` · clase: ${h.clase.nombre}${h.clase.cwe ? ` (CWE-${h.clase.cwe})` : ""} · destino: \`${h.destino}\``,
    `- Activo: \`${celda(h.activo)}\``,
    `- Decidido por: ${h.decidido_por}${h.comparacion !== "sin-anterior" ? ` · ${h.comparacion === "nuevo" ? "nuevo" : "ya estaba"}` : ""}`,
    ...(h.supresion ? [`- Suprimido: ${celda(h.supresion.motivo)} (${celda(h.supresion.autor)}, vence ${h.supresion.vence})`] : []),
    "",
    h.resumen,
    "",
  ];
  const prueba = h.verificacion?.prueba;
  if (prueba) salida.push(...paso(prueba, "Prueba del verificador"));
  if (h.verificacion?.control) salida.push(...paso(h.verificacion.control, "Control (cambia sólo la causa)"));
  if (!prueba) for (const [k, p] of h.reproduccion.slice(0, 2).entries()) salida.push(...paso(p, `Paso ${k + 1}`));
  if (h.motivo) salida.push(`Veredicto: ${h.motivo.split("\n")[0]}`, "");
  if (h.limites) salida.push(`Límites: ${h.limites}`, "");
  salida.push("</details>", "");
  return salida;
}

export function armarMarkdown(r: ResultadoCi): string {
  const verificados = r.hallazgos.filter((h) => h.estado === "verificado");
  const candidatos = r.hallazgos.filter((h) => h.estado === "candidato");
  const pistas = r.hallazgos.filter((h) => h.estado === "pista").length;
  const descartados = r.hallazgos.filter((h) => h.estado === "descartado").length;
  const l: string[] = [
    marcador(r.nombre),
    `### Orobas · ${r.modo === "retest" ? "retest" : "evaluación"} de seguridad «${r.nombre}»`,
    "",
    `**${ESTADO[r.resultado.estado]}** (código ${r.resultado.codigo}). ${r.resultado.motivo}`,
    "",
    `| Verificados | Bloquean | Candidatos (no bloquean) | Gasto | Duración | Peticiones |`,
    `| ---: | ---: | ---: | ---: | ---: | ---: |`,
    `| ${verificados.length} | ${r.resultado.bloqueantes} | ${candidatos.length} | USD ${Number(r.gasto.usd).toFixed(4)} de ${r.gasto.tope_usd} | ${duracion(r.tiempo.duracion_s)} de ${r.tiempo.tope_min} min | ${r.trafico.peticiones} |`,
    "",
  ];
  if (verificados.length) {
    l.push("#### Hallazgos verificados", "", "Reproducidos por el verificador independiente con una prueba y un control. Política: fallar desde severidad **" + r.politica.fallar_desde + "**" + (r.politica.solo_nuevos ? " (sólo nuevos)" : "") + ".", "");
    l.push("| Severidad | Hallazgo | Ruta | Bloquea | Huella |", "| --- | --- | --- | --- | --- |");
    for (const h of verificados) l.push(`| ${SEV[h.severidad]} | ${celda(h.titulo)} | \`${h.metodo} ${celda(h.ruta)}\` | ${h.bloqueante ? "sí" : h.supresion ? "suprimido" : "no"} | \`${h.huella.slice(-12)}\` |`);
    l.push("");
    for (const h of verificados) l.push(...detalle(h));
  }
  if (r.retest.length) {
    l.push("#### Retest de hallazgos conocidos", "", "| Resultado | Hallazgo | Severidad | Motivo |", "| --- | --- | --- | --- |");
    for (const t of r.retest) l.push(`| ${t.resultado === "arreglado" ? "✓ arreglado" : t.resultado === "persiste" ? "✗ persiste" : "? sin confirmar"} | ${celda(t.titulo)} | ${SEV[t.severidad]} | ${celda(t.motivo)} |`);
    l.push("");
    for (const t of r.retest.filter((x) => x.resultado === "arreglado")) {
      l.push(`<details><summary>Evidencia de que ${celda(t.titulo)} quedó arreglado</summary>`, "");
      if (t.repeticion) l.push(...paso(t.repeticion, "La petición original, repetida ahora"));
      if (t.prueba) l.push(...paso(t.prueba, "Prueba del verificador"));
      if (t.control) l.push(...paso(t.control, "Control"));
      l.push("</details>", "");
    }
  }
  if (candidatos.length) {
    l.push("#### Candidatos sin verificar (no bloquean)", "", "El agente los registró con evidencia, pero el verificador no los reprodujo (o no llegó): revisalos a mano.", "", "| Severidad | Candidato | Ruta | Motivo |", "| --- | --- | --- | --- |");
    for (const h of candidatos) l.push(`| ${SEV[h.severidad]} | ${celda(h.titulo)} | \`${h.metodo} ${celda(h.ruta)}\` | ${celda(h.motivo || "sin verificar")} |`);
    l.push("");
  }
  const c = r.comparacion;
  if (c.anterior) {
    l.push("#### Contra la corrida anterior", "", `Nuevos: ${c.nuevos.length} · persisten: ${c.persisten.length} · resueltos (confirmados por retest): ${c.resueltos.length} · no reaparecieron sin confirmar: ${c.sin_confirmar.length}.`, "");
  }
  if (r.supresiones.aplicadas.length || r.supresiones.vencidas.length) {
    l.push(`Supresiones (${r.supresiones.archivo}): ${r.supresiones.aplicadas.length} aplicada(s)${r.supresiones.vencidas.length ? `, ${r.supresiones.vencidas.length} vencida(s) que ya no valen` : ""}.`, "");
  }
  l.push("#### Qué se probó y qué no", "");
  const sc = r.cobertura.solo_cambios;
  l.push(`- Alcance autorizado (huella \`${r.autorizacion?.huella ?? "—"}\`): ${r.alcance.reglas.map((x) => `\`${x.valor}\``).join(", ") || "—"}${r.alcance.excluido.length ? `; excluido: ${r.alcance.excluido.map((x) => `\`${x}\``).join(", ")}` : ""}.${r.alcance.acotado_a_cambios ? " Acotado a las rutas del PR." : ""}`);
  l.push(`- Sólo lo que cambió: ${sc.activo ? `sí, ${sc.motivo}` : `no (${sc.motivo})`}.`);
  if (sc.activo && sc.rutas.length) l.push(`  Rutas: ${sc.rutas.slice(0, 20).map((x) => `\`${x.ruta}\``).join(", ")}${sc.rutas.length > 20 ? ` y ${sc.rutas.length - 20} más` : ""}.`);
  l.push(`- Rutas probadas: ${r.cobertura.probadas.length}${r.cobertura.probadas.length ? ` (${r.cobertura.probadas.slice(0, 12).map((x) => `\`${celda(x)}\``).join(", ")}${r.cobertura.probadas.length > 12 ? ", …" : ""})` : ""}.`);
  l.push(`- Sin probar: ${r.cobertura.sin_probar.length ? r.cobertura.sin_probar.slice(0, 12).map((x) => `\`${celda(x)}\``).join(", ") + (r.cobertura.sin_probar.length > 12 ? `, y ${r.cobertura.sin_probar.length - 12} más` : "") : "nada que se haya visto y quedado sin probar"}.`);
  l.push(`- Tráfico: ${r.trafico.peticiones} peticiones a ${r.trafico.hosts.join(", ") || "—"}; ${r.trafico.bloqueadas_por_alcance} intento(s) fuera del alcance frenados${r.trafico.intentos_fuera_de_alcance.length ? ` (${r.trafico.intentos_fuera_de_alcance.slice(0, 5).map((x) => `\`${celda(x)}\``).join(", ")})` : ""}.${r.trafico.solo_lectura ? " Sólo lectura." : ""}`);
  if (pistas || descartados) l.push(`- Además: ${pistas} pista(s) sin evidencia y ${descartados} descartado(s) por el verificador (en resultado.json).`);
  l.push("");
  if (r.avisos.length) l.push("#### Avisos", "", ...r.avisos.slice(0, 20).map((a) => `- ${celda(a)}`), "");
  l.push(`<sub>Modelo ${r.modelo.nombre} · gasto USD ${r.gasto.usd} (verificación USD ${r.gasto.verificacion_usd}) · ${r.gasto.solicitudes} solicitudes · sesión \`${r.corrida.sesion.slice(0, 8) || "—"}\`${r.corrida.commit ? ` · commit \`${r.corrida.commit.slice(0, 12)}\`` : ""}${r.corrida.url ? ` · [corrida](${r.corrida.url})` : ""} · orobas-sec ${r.herramienta.version}</sub>`);
  let texto = l.join("\n");
  if (texto.length > MAXIMO) texto = `${texto.slice(0, MAXIMO - 300)}\n\n…\n\n_El resumen se cortó por su largo: el detalle completo está en resultado.json y en los artefactos del job._\n`;
  return texto;
}
