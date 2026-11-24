// Pestañas de la TUI: tipos, valores por defecto, validación y dibujo de las entradas según filtro y detalle. Se guardan por proyecto (ver ajustes.ts).
import { t } from "../idioma.ts";
import type { Panel } from "./comandos.ts";
import type { Entrada } from "./entradas.ts";
import { descifrar, descifradoActivo, DURACION } from "./descifrado.ts";
import { renderMarkdown } from "./markdown.ts";
import { accent, adorno, adornoTUI, avisoLinea, bold, dim, type Style, visibleWidth, warn, wrapSpans, wrapText } from "./text.ts";
import { simbolos, temaActivo } from "./temas.ts";

export type Tipo = "mensajes" | "texto" | "acciones" | "resultados" | "comandos" | "avisos";
export const TIPOS: readonly Tipo[] = ["mensajes", "texto", "acciones", "resultados", "comandos", "avisos"];
export type Detalle = "minimo" | "normal" | "completo";
const DETALLES: readonly Detalle[] = ["minimo", "normal", "completo"];
export type Vista = "hallazgos" | "artefactos" | "cobertura" | "costos" | "trabajos";
const VISTAS: readonly Vista[] = ["hallazgos", "artefactos", "cobertura", "costos", "trabajos"];
export type Pestana =
  | { nombre: string; tipo: "conversacion"; contenido: Tipo[]; detalle: Detalle }
  | { nombre: string; tipo: "vista"; vista: Vista };

export const PESTANA_CHAT: Pestana = { nombre: "Chat", tipo: "conversacion", contenido: [...TIPOS], detalle: "normal" };
/** Una «Chat» propia: las ventanas no comparten el objeto (mover una por identidad borraría las dos). */
export const chat = (): Pestana => ({ ...PESTANA_CHAT, contenido: [...TIPOS] });

function pestana(x: unknown): Pestana | undefined {
  if (!x || typeof x !== "object") return undefined;
  const p = x as Record<string, unknown>;
  if (typeof p.nombre !== "string" || !p.nombre.trim()) return undefined;
  const nombre = p.nombre.trim().slice(0, 24);
  if (p.tipo === "vista") return VISTAS.includes(p.vista as Vista) ? { nombre, tipo: "vista", vista: p.vista as Vista } : undefined;
  if (p.tipo !== "conversacion" || !DETALLES.includes(p.detalle as Detalle) || !Array.isArray(p.contenido)) return undefined;
  return { nombre, tipo: "conversacion", contenido: TIPOS.filter((t) => (p.contenido as unknown[]).includes(t)), detalle: p.detalle as Detalle };
}

/** Lista válida de pestañas: descarta lo inválido; si no queda nada, la pestaña «Chat» por defecto. */
export function validarPestanas(valor: unknown): Pestana[] {
  const lista = Array.isArray(valor) ? valor.map(pestana).filter((p): p is Pestana => !!p) : [];
  return lista.length ? lista : [chat()];
}

/** Líneas de un resultado en «completo» antes de «… N líneas más · Enter expande». */
export const RECORTE = 12;
export interface Opciones {
  ancho: number;
  expandidas: ReadonlySet<number>;
  seleccion?: number;
  resultados: (entrada: Entrada & { tipo: "resultados" }) => string | "cargando" | "error" | undefined;
  /** Llamadas con herramienta viva: la región viva ya las muestra. */
  vivas?: ReadonlySet<string>;
  /** Reloj del efecto descifrado; sin definir, sin efecto. */
  ahora?: number;
  /** Cuadro del spinner para las acciones en curso (sin definir, «·»). */
  marco?: string;
  /** Lo ya dibujado por entrada (por pestaña): se rehace sólo si cambia el ancho, el detalle o la entrada. */
  cache?: Map<number, { clave: string; r: string | undefined; lineas: string[] }>;
  /** Si el efecto descifrado está activo: quien dibuja varias ventanas lo calcula una vez por cuadro; sin definir, se lee acá. */
  efecto?: () => boolean;
}
type Conversacion = Pestana & { tipo: "conversacion" };

/** Si la pestaña dibuja la entrada: por filtro de tipos y, en «minimo», sin resultados. */
export function muestra(pestana: Conversacion, entrada: Entrada): boolean {
  return pestana.contenido.includes(entrada.tipo) && (entrada.tipo !== "resultados" || pestana.detalle === "completo");
}

export const corners = (): [string, string, string, string] => simbolos().bordes.slice(0, 4) as [string, string, string, string];
export const lineaBorde = (): [h: string, v: string] => { const b = simbolos().bordes; return [b[4], b[5]]; };

/** Un aviso lleva el símbolo del tema al principio, salvo que el texto ya traiga el suyo. */
export const conSimboloAviso = (texto: string): string => (/^(?:⚠|\[!\])/.test(texto) ? texto : `${simbolos().avisoSimbolo} ${texto}`);

/** Borde superior o inferior de un recuadro; con adorno en el tema, el título va entre adornos (`═ ❦ Título ❦ ═…`). */
export function bordeRecuadro(left: string, label: string, right: string, inner: number, tone: (s: string) => string, adornar: boolean): string {
  const [h] = lineaBorde();
  const glifo = adornar ? simbolos().adorno : undefined;
  const text = label ? ` ${glifo ? `${glifo} ${label} ${glifo}` : label} ` : "";
  const rest = (n: string) => `${h.repeat(Math.max(0, inner + 1 - visibleWidth(text)))}${n}`;
  if (!glifo || !label) return `  ${adornoTUI(tone(`${left}${h}${text}${rest(right)}`))}`;
  return `  ${adornoTUI(`${tone(`${left}${h} `)}${adorno(glifo)}${tone(` ${label} `)}${adorno(glifo)}${tone(` ${rest(right)}`)}`)}`;
}

/** Respuesta de un comando: un panel con título, cuerpo envuelto y pie con cómo seguir. */
export function dibujarPanel(view: Panel, ancho: number): string[] {
  const inner = Math.max(10, ancho - 8);
  const tone = view.tone === "warn" ? warn : view.tone === "ok" ? accent : dim;
  const [tl, tr, bl, br] = corners();
  const [, v] = lineaBorde();
  const edge = (left: string, label: string, right: string, adornar = false) => bordeRecuadro(left, label && visibleWidth(label) + (adornar && simbolos().adorno ? 6 : 2) < inner ? label : "", right, inner, tone, adornar);
  // Una línea con sangría o viñeta sigue alineada al cortarse: la continuación no vuelve al borde.
  const wrap = (line: string) => {
    const marca = (/^\x1b\[28;28m[^]*?\x1b\[29;29m /.exec(line) ?? [""])[0]; // marcador de lista: va en la sangría, nunca es punto de corte
    const resto = line.slice(marca.length);
    const lead = marca + /^\s*(?:[○✓~–●•·›*-] )?/.exec(resto)![0];
    return wrapSpans([{ text: resto.slice(lead.length - marca.length) }], inner, lead, " ".repeat(visibleWidth(lead)));
  };
  const body = view.lines.flatMap((line) => (line.trim() ? wrap(line) : [""])).map((row) => `  ${adornoTUI(`${tone(v)} `)}${row}${adornoTUI(`${" ".repeat(Math.max(0, inner - visibleWidth(row)))} ${tone(v)}`)}`);
  return ["", edge(tl, view.title, tr, true), ...body, edge(bl, view.footer ?? "", br)];
}

function argumentos(nombre: string, args: unknown, ancho: number): string[] {
  if (args === undefined || args === null) return [];
  const a = (typeof args === "object" ? args : {}) as Record<string, unknown>;
  const envolver = (texto: string, sangria: string) => texto.split("\n").flatMap((l) => wrapText(l, ancho - 2, sangria, dim));
  if (nombre === "shell" && typeof a.command === "string") return envolver(`$ ${a.command}`, "    ");
  if (typeof a.url === "string" && nombre.startsWith("http")) {
    const cuerpo = typeof a.body === "string" && a.body ? envolver(a.body, "    ") : [];
    return [...envolver(`${typeof a.method === "string" ? a.method : "GET"} ${a.url}`, "    "), ...cuerpo];
  }
  return envolver(JSON.stringify(args), "    ");
}

/** Una acción «en curso» con herramienta viva la muestra la región viva, salvo en «completo». */
const enRegionViva = (pestana: Conversacion, e: Entrada & { tipo: "acciones" }, vivas: ReadonlySet<string> | undefined) =>
  e.estado === "en curso" && pestana.detalle !== "completo" && !!vivas?.has(e.llamada);

const hhmm = (ms: number) => { const d = new Date(ms); return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`; };

/** `── Nombre ──────── 23:41 ──` de ancho exacto `ancho`; sin hora si no se sabe. */
export function separador(nombre: string, en: number | undefined, ancho: number, linea: Style, estiloNombre: Style): string {
  nombre = nombre.slice(0, Math.max(0, ancho - 5)); // los nombres son ASCII
  let hora = en ? ` ${hhmm(en)} ` : "";
  let cola = "──";
  const fijo = 5 + nombre.length;
  if (fijo + 2 + hora.length + cola.length > ancho) hora = ""; // sin lugar: primero se pierde la hora
  if (fijo + 2 + cola.length > ancho) cola = ""; // y luego el cierre
  const rayas = ancho - fijo - hora.length - cola.length - 1;
  return "  " + adornoTUI(linea("── ")) + estiloNombre(nombre) + (rayas >= 1 ? adornoTUI(linea(" " + "─".repeat(rayas))) : "") + (hora ? adornoTUI(dim(hora)) : "") + adornoTUI(linea(cola));
}

/** Las líneas de una entrada (sin la marca de selección). */
function dibujarEntrada(pestana: Conversacion, e: Entrada, tras: boolean, r: string | undefined, o: Opciones, a: Arbol, md: string): string[] {
  const dibujo: string[] = [];
  const w = o.ancho;
  if (e.tipo === "mensajes") dibujo.push("", separador(t("Vos", "You"), e.en, w, dim, dim), ...wrapText(e.texto, w - 2, "  "));
  else if (e.tipo === "texto") { if (e.markdown.trim()) dibujo.push("", separador("Orobas", e.en, w, accent, (s) => bold(accent(s))), ...renderMarkdown(md, w - 2)); }
  else if (e.tipo === "avisos") dibujo.push("", ...(e.tono === "warn" ? wrapText(conSimboloAviso(e.texto), w - 2, "  ", avisoLinea) : wrapText(e.texto, w - 2, "  ", e.tono === "dim" ? dim : undefined)));
  else if (e.tipo === "comandos") dibujo.push(...dibujarPanel(e.panel, w));
  else if (e.tipo === "acciones") {
    if (enRegionViva(pestana, e, o.vivas)) return dibujo;
    if (!tras) dibujo.push("");
    // En curso se ve el cuadro del spinner (o «·»): con herramienta viva la región viva ya lleva el suyo; sólo «completo» o sin herramienta llegan acá.
    const marca = e.estado === "error" ? warn(simbolos().error) : e.estado === "en curso" ? dim(o.marco ?? "·") : accent(simbolos().ok);
    const texto = pestana.detalle === "minimo" ? e.nombre : e.etiqueta + (e.resumen ? ` · ${e.resumen}` : "");
    if (a.titulo) dibujo.push(`  ${accent(a.titulo)}`);
    dibujo.push(`  ${a.rama ? adornoTUI(dim(a.rama)) + " " : ""}${marca} ${dim(texto)}`);
    if (pestana.detalle === "completo") dibujo.push(...argumentos(e.nombre, e.argumentos, w));
  } else if (e.tipo === "resultados") {
    const pre = adornoTUI(dim(a.prefijo)) + "  ";
    if (r === "cargando") dibujo.push(`${pre}${adornoTUI(dim("│"))}${dim(t(" cargando…", " loading…"))}`);
    else if (r === "error") dibujo.push(`${pre}${adornoTUI(dim("│"))}${dim(t(" no se pudo traer", " could not fetch"))}`);
    else if (r !== undefined) {
      const todas = r.split("\n").flatMap((l) => {
        const lead = /^\s*/.exec(l)![0].replace(/\t/g, "  "); // la sangría se conserva, también en la continuación
        return wrapSpans([{ text: l.trimStart() }], w - 9, lead, lead);
      });
      const cortar = !o.expandidas.has(e.id) && todas.length > RECORTE;
      for (const l of cortar ? todas.slice(0, RECORTE) : todas) dibujo.push(`${pre}${adornoTUI(dim("│"))} ${dim(l)}`);
      if (cortar) dibujo.push(`${pre}${dim(t(`… ${todas.length - RECORTE} líneas más · Enter expande`, `… ${todas.length - RECORTE} more lines · Enter expands`))}`);
    }
  }
  return dibujo;
}

/** Lugar de una acción o resultado en su grupo: rama propia, título del grupo (sólo la primera) y sangría de los resultados. */
type Arbol = { rama: string; titulo: string; prefijo: string };
const SIN_ARBOL: Arbol = { rama: "", titulo: "", prefijo: "     " };

/** Agrupa las acciones seguidas (con sus resultados) entre las entradas que se dibujan; cualquier otro tipo corta el grupo. */
function armarArboles(pestana: Conversacion, entradas: readonly Entrada[], o: Opciones): Map<number, Arbol> {
  const arboles = new Map<number, Arbol>();
  let grupo: (Entrada & { tipo: "acciones" })[] = [];
  const resultados = new Map<number, number>(); // resultado → acción
  const cerrar = () => {
    const n = grupo.length;
    const errores = grupo.filter((a) => a.estado === "error").length;
    const ini = grupo.map((a) => a.inicio).filter((x): x is number => x !== undefined);
    const fin = grupo.map((a) => a.fin).filter((x): x is number => x !== undefined);
    const seg = ini.length && fin.length ? Math.round((Math.max(...fin) - Math.min(...ini)) / 1000) : undefined;
    const titulo = n < 2 ? "" : `◆ ${n} ${t("acciones", "actions")}` + (seg ? ` · ${seg} s` : "") + (errores ? ` · ${errores} ${t("con error", "failed")}` : "");
    grupo.forEach((a, i) => {
      const ultima = i === n - 1;
      arboles.set(a.id, { rama: n < 2 ? "" : ultima ? "└─" : "├─", titulo: i === 0 ? titulo : "", prefijo: n < 2 || ultima ? "     " : "  │  " });
    });
    for (const [r, a] of resultados) arboles.set(r, { ...arboles.get(a)!, rama: "", titulo: "" });
    grupo = [];
    resultados.clear();
  };
  for (const e of entradas) {
    if (!muestra(pestana, e)) continue;
    if (e.tipo === "acciones") { if (!enRegionViva(pestana, e, o.vivas)) grupo.push(e); }
    else if (e.tipo === "resultados") { if (grupo.length) resultados.set(e.id, (grupo.find((a) => a.llamada === e.llamada) ?? grupo[grupo.length - 1]!).id); }
    else if (e.tipo !== "texto" || e.markdown.trim()) cerrar();
  }
  cerrar();
  return arboles;
}

/** Lo que cambia el dibujo de una entrada (el valor de un resultado va aparte, en `r`). */
function claveDe(pestana: Conversacion, e: Entrada, tras: boolean, o: Opciones, a: Arbol, animando: boolean): string {
  const base = `${temaActivo().id}|${o.ancho}|${pestana.detalle}|${tras ? 1 : 0}`;
  const arbol = `${a.rama}|${a.prefijo}|${a.titulo}`;
  switch (e.tipo) {
    case "mensajes": return `${base}|${e.texto.length}`;
    case "texto": return `${base}|${e.markdown.length}|${e.completo ? 1 : 0}${animando ? `|${Math.floor(o.ahora! / 33)}` : ""}`;
    case "avisos": return `${base}|${e.texto.length}|${e.tono}`;
    case "comandos": return base;
    case "acciones": return `${base}|${e.estado}|${e.resumen}|${e.etiqueta}|${e.argumentos === undefined ? 0 : 1}|${enRegionViva(pestana, e, o.vivas) ? 1 : 0}|${arbol}${e.estado === "en curso" ? `|${o.marco ?? ""}` : ""}`;
    case "resultados": return `${base}|${o.expandidas.has(e.id) ? 1 : 0}|${arbol}`;
  }
}

/** Convierte las entradas que muestra la pestaña en líneas; `desde` guarda la primera línea de cada entrada para llevar el scroll a la selección. */
export function dibujar(pestana: Conversacion, entradas: readonly Entrada[], o: Opciones): { lineas: string[]; desde: Map<number, number>; animando: boolean } {
  let animando = false;
  let efecto: boolean | undefined; // descifradoActivo() lee la configuración del disco: una vez por cuadro y sólo si hay algo recién llegado
  const hayEfecto = o.efecto ?? (() => (efecto ??= descifradoActivo()));
  const lineas: string[] = [];
  const desde = new Map<number, number>();
  const arboles = armarArboles(pestana, entradas, o);
  let tras = false; // la entrada anterior fue una línea de herramienta: las siguientes van pegadas
  for (const e of entradas) {
    if (!muestra(pestana, e)) continue;
    const pegada = e.tipo === "acciones" || e.tipo === "resultados";
    const r = e.tipo === "resultados" ? o.resultados(e) : undefined;
    const arbol = arboles.get(e.id) ?? SIN_ARBOL;
    // Sólo lo que llegó en vivo (con `llegadas`) se descifra; el historial recargado se dibuja tal cual.
    const fx = o.ahora !== undefined && e.tipo === "texto" && e.llegadas?.length && o.ahora < e.llegadas[e.llegadas.length - 1]![1] + DURACION.fuerte && temaActivo().descifrado !== "no" && hayEfecto() ? descifrar(e.markdown, e.llegadas, o.ahora!, temaActivo().descifrado, temaActivo().glifos) : undefined;
    if (fx?.animando) animando = true;
    const clave = claveDe(pestana, e, tras, o, arbol, !!fx?.animando);
    let hecho = o.cache?.get(e.id);
    if (!hecho || hecho.clave !== clave || hecho.r !== r) {
      hecho = { clave, r, lineas: dibujarEntrada(pestana, e, tras, r, o, arbol, fx?.texto ?? (e.tipo === "texto" ? e.markdown : "")) };
      o.cache?.set(e.id, hecho);
    }
    let dibujo = hecho.lineas;
    if (!dibujo.length) continue;
    tras = pegada;
    if (o.seleccion === e.id) {
      const i = dibujo[0] === "" && dibujo.length > 1 ? 1 : 0;
      dibujo = [...dibujo];
      dibujo[i] = adornoTUI(accent("▌")) + dibujo[i]!.slice(1);
    }
    desde.set(e.id, lineas.length);
    lineas.push(...dibujo);
  }
  return { lineas, desde, animando };
}
