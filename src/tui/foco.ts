// Foco: conversación abierta, editor amplio y detalles bajo demanda.
import { compartido, otrasVentanas } from "../compartido.ts";
import { descifradoActivo } from "./descifrado.ts";
import { type Client, connectDaemon } from "../client.ts";
import type { Snapshot } from "../daemon.ts";
import { Privacidad, entradaPublica, prendido } from "./streamer.ts";
import { FuenteOBS } from "./obs.ts";
import { projectPaths } from "../store.ts";
import { Editor } from "./editor.ts";
import { type Key, KeyParser, esPegadoConhost } from "./keys.ts";
import type { Output } from "./screen.ts";
import { Pantalla } from "./pantalla.ts";
import { type Entrada, Registro, type Tono } from "./entradas.ts";
import { simbolos, usarTema } from "./temas.ts";
import { accent, adornoTUI, avisoLinea, badge, badgeWarn, bold, dim, graphemes, link, segment, segmentDim, stripAnsi, truncate, visibleWidth, warn, wrapText } from "./text.ts";
import { type CommandIO, type CycleResult, findCommand, fromLines, menuIO, type Panel, type Row, sugerencias } from "./comandos.ts";
import { deviceLink } from "../menu.ts";
import { lineasDe, NOVEDADES, pendientes } from "./novedades.ts";
import { runWizard, wizardSummary, type WizardStep } from "./inicio.ts";
import { abrirProyecto, ajustes, arregloGuardado, guardarAjuste, guardarArreglo, marcarNovedades, mouseGuardado, novedadesVistas, sinHistoria, RECORDADOS, temaGuardado, type Recordado } from "./ajustes.ts";
import { cantidad, type Forma, type Rect, repartir } from "./ventanas.ts";
import { detectTerminal, ImageReplies, type ImageTerminal } from "./terminal.ts";
import { bordeRecuadro, conSimboloAviso, corners, dibujar, lineaBorde, dibujarPanel, muestra, type Opciones, chat, type Pestana, TIPOS } from "./pestanas.ts";
import { etiquetarHallazgo, filasDe, VISTAS, type Fila } from "./vistas.ts";
import { Sigil } from "./sigil.ts";
import { Sesion } from "./sesion.ts";
import type { Harnesses } from "./harnesses.ts";
import { Subagentes } from "./subagentes.ts";
import { lineaLogica, palabraEn, type Punto, resaltar, textoSeleccionado } from "./seleccion.ts";
import { copiar } from "./portapapeles.ts";
import { t } from "../idioma.ts";
import { decodeRows, type SessionRow } from "../sesiones.ts";
import { bloqueTerminal, comandoDolar, correrComando } from "./dolar.ts";
import { queueKey } from "../engine.ts";
import { writeSync } from "node:fs";
import { resolve } from "node:path";
import { StringDecoder } from "node:string_decoder";

/** Fila siguiente cuya etiqueta (sin la «/» de los hijos de un grupo) empieza con la letra, dando la vuelta. */
export function saltoPorLetra(labels: string[], at: number, letter: string): number | undefined {
  return Array.from({ length: labels.length }, (_, i) => (at + 1 + i) % labels.length).find((i) => labels[i]!.toLowerCase().replace(/^\//, "").startsWith(letter));
}

export interface FocoIO {
  output: Output;
  terminal?: ImageTerminal;
  /** Registra el receptor de entrada cruda y devuelve cómo soltarlo. */
  listen(onData: (data: string) => void, onResize: () => void, onShutdown?: () => void): () => void;
}

function processIO(): FocoIO {
  const terminal = detectTerminal(process.env);
  const disabled = terminal.allowImages === false;
  const fixedCell = terminal.cellSizeKnown;
  const replies = new ImageReplies();
  return {
    output: process.stdout as unknown as Output,
    terminal,
    listen(onData, onResize, onShutdown) {
      const decoder = new StringDecoder("utf8");
      const wasRaw = !!process.stdin.isRaw;
      let released = false;
      let replyTimer: ReturnType<typeof setTimeout> | undefined;
      const data = (chunk: Buffer) => {
        const text = decoder.write(chunk);
        if (!text) return;
        clearTimeout(replyTimer);
        terminal.columns = process.stdout.columns;
        terminal.rows = process.stdout.rows;
        const result = replies.consume(text, terminal);
        if (result.input) onData(result.input);
        if (result.changed) onResize();
        if (replies.flushDelay !== undefined) replyTimer = setTimeout(() => {
          const input = replies.flush();
          if (input) onData(input);
        }, replies.flushDelay);
      };
      const resize = () => {
        if (!disabled) {
          if (!fixedCell) terminal.cellSizeKnown = false;
          process.stdout.write("\x1b[16t\x1b[14t");
        }
        onResize();
      };
      const shutdown = () => {
        if (onShutdown) onShutdown();
        else restore();
      };
      const restore = () => {
        if (released) return;
        released = true;
        clearTimeout(replyTimer);
        process.stdin.off("data", data);
        process.stdout.off("resize", resize);
        for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"] as const) process.off(signal, shutdown);
        process.off("exit", restore);
        process.off("uncaughtExceptionMonitor", restore);
        // También funciona si murió a mitad de un cuadro o con escrituras pendientes.
        try { writeSync(process.stdout.fd, "\x1b\\\x1b[?2026l\x1b[?2004l\x1b[?25h\x1b[0m"); } catch { /* la terminal puede haberse cerrado */ }
        try { process.stdin.setRawMode(wasRaw); } catch { /* stdin puede estar cerrado */ }
        process.stdin.pause();
      };
      process.stdin.setRawMode(true);
      process.stdin.resume();
      process.stdin.on("data", data);
      process.stdout.on("resize", resize);
      for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"] as const) process.on(signal, shutdown);
      process.once("exit", restore);
      process.on("uncaughtExceptionMonitor", restore);
      process.stdout.write("\x1b[?2004h"); // pegado delimitado
      if (!disabled) process.stdout.write(replies.query());
      return restore;
    },
  };
}

const mayus = (texto: string) => texto.charAt(0).toLocaleUpperCase() + texto.slice(1);

/** Deja `scroll` (líneas desde el final) entre 0 y lo que el contenido permite subir. */
export function clampScroll(scroll: number, total: number, alto: number): number {
  return Math.max(0, Math.min(scroll, total - alto));
}

/**
 * `project` es la ruta real del proyecto: con ella se recuerdan los ajustes (sin ella, como en los tests, no
 * se guarda nada). `explicit` son los ajustes que vinieron por flag en esta corrida: ganan sobre lo recordado.
 */
export function startFoco(client: Client, snapshot: Snapshot, options: { cwd?: string; io?: FocoIO; onExit?: (protegida: boolean) => void; streamer?: boolean; obs?: string; alCambiarStreamer?: (activo: boolean) => void; animate?: boolean; onboarding?: boolean; project?: string; explicit?: Recordado[]; novedades?: boolean; harnesses?: (ask: (op: string, p: object) => Promise<string[]>) => Harnesses } = {}) {
  abrirProyecto(options.project ?? "");
  usarTema(temaGuardado());
  const io = options.io ?? processIO();
  const pantalla = new Pantalla(io.output, { mouse: mouseGuardado() });
  // Pantalla alternativa: el arranque empieza limpio, no debajo del comando del shell.
  pantalla.entrar();
  const terminal = io.terminal ?? { graphics: false, cellWidth: 10, cellHeight: 20 };
  const sesion = new Sesion(client, snapshot, options.harnesses);
  let enVivo = options.streamer ?? prendido(process.env.CYBER_STREAMER);
  let panico = false;
  let desconectado = false;
  const proteccion = new Privacidad(projectPaths(options.cwd ?? options.project ?? process.cwd()).db);
  if (enVivo) for (const m of snapshot.messages) proteccion.aprenderMensaje(m);
  const publico = (texto: string) => enVivo ? proteccion.texto(texto) : texto;
  const archivoOBS = options.obs ?? process.env.CYBER_STREAMER_OBS;
  const rutaOBS = archivoOBS && resolve(options.cwd ?? process.cwd(), archivoOBS);
  let obs: FuenteOBS | undefined;
  let relojOBS: ReturnType<typeof setInterval> | undefined;
  let avisoOBS = "";
  let inicioVivo = Date.now();
  const sigil = new Sigil(options.animate ?? (!options.io && !sesion.hasContent && !snapshot.resumed && process.env.CYBER_ANIMATIONS !== "0" && process.env.TERM !== "dumb"));
  const editor = new Editor();
  const parser = new KeyParser();
  // scroll: líneas desde el final (0 sigue el final); total y ancho sirven para que lo nuevo no mueva lo que se está leyendo.
  type Datos = { lineas: string[]; filas: Fila[]; at: number; detalle?: string[]; ver?: boolean };
  type Estado = { scroll: number; novedades: number; total?: number; ancho: number };
  const nuevoEstado = (): Estado => ({ scroll: 0, novedades: 0, ancho: 0 });
  /** Lo que muestra y recuerda cada ventana; la sesión (conversación, herramientas, evidencia) puede ser compartida. */
  type Fuente = { tipo: "sub"; worker: string } | { tipo: "harness"; id: string };
  type Ventana = {
    sesion: Sesion;
    cachePublica?: { version: string; filas: NonNullable<Opciones["cache"]>; pestana: Pestana };
    /** Si no es undefined, la ventana muestra un subagente o un harness en vez de sus pestañas. */
    fuente?: Fuente;
    /** Scroll y cache de lo dibujado de la fuente; se rehacen al cambiar de worker. */
    vistaFuente?: { worker: string; estado: Estado; cache: NonNullable<Opciones["cache"]> };
    pestanas: Pestana[];
    estados: Estado[];
    activa: number;
    /** Lo dibujado por entrada de cada pestaña de conversación (ver `dibujar`). */
    caches: WeakMap<Pestana, NonNullable<Opciones["cache"]>>;
    /** Lo último que trajo el daemon para cada pestaña de vista (por posición); `sinVer` marca las que cambiaron sin verlas. */
    datos: Map<number, Datos>;
    sinVer: Set<number>;
    pedidos: Map<number, number>;
    seleccion: number | undefined;
    expandidas: Set<number>;
    ultimo: { total: number; desde: Map<number, number>; todas: string[]; inicio: number; arriba: number; alto: number };
  };
  const nuevaVentana = (sesion: Sesion, pestanas: Pestana[]): Ventana => ({
    sesion,
    pestanas,
    estados: pestanas.map(nuevoEstado),
    activa: 0,
    caches: new WeakMap(),
    datos: new Map(),
    sinVer: new Set(),
    pedidos: new Map(),
    seleccion: undefined,
    expandidas: new Set(),
    ultimo: { total: 0, desde: new Map<number, number>(), todas: [] as string[], inicio: 0, arriba: 0, alto: 0 },
  });
  const arreglo = arregloGuardado();
  let forma: Forma = arreglo.forma;
  const divisores = arreglo.divisores;
  let conLista = arreglo.lista;
  // Al arrancar todas las ventanas muestran la sesión del arranque; `abrirSesion` les pone otras.
  const ventanas: Ventana[] = arreglo.pestanas.map((pestanas) => nuevaVentana(sesion, pestanas));
  let actual = 0;
  // Ventana y sesión actuales: siguen a `actual` (ver `fijar`).
  // Todo código que espera (await, timers, callbacks) debe capturarlas antes: `const v = vent, s = ses`.
  let vent = ventanas[actual]!;
  let ses = vent.sesion;
  /** Las conexiones abiertas: la principal primero y, después, una por cada otra sesión (con o sin ventana). */
  const todas: Sesion[] = [sesion];
  const idDe = (s: Sesion) => s.client.status.session ?? "";
  const nombrePestana = (p: Pestana, i: number) => enVivo && p.nombre !== "Chat" ? `Pestaña ${i + 1}` : p.nombre;
  const nombreVisible = (s: Sesion) => enVivo ? `Sesión ${todas.indexOf(s) + 1}` : s.nombre();
  const buscar = (id: string) => todas.find((s) => idDe(s) === id);
  // Al pasar a una ventana cuya sesión espera un permiso, se abre (si no hay otro menú abierto).
  const fijar = (i: number) => { actual = i; vent = ventanas[i]!; ses = vent.sesion; if (!mode && ses.permiso) abrirPermiso(ses); };
  /** Lista de sesiones (F2): lo que trajo el daemon, la fila elegida y cuál es la primera visible. */
  const lista = { enfocada: false, at: 0, primera: 0, sesiones: [] as SessionRow[] };
  let rectLista: Rect | undefined;
  /** Dónde quedó cada ventana en el último cuadro (sólo con varias), y el ancho útil de la activa. */
  let rects: Array<Rect | undefined> = [];
  let anchoUtil = 0;
  /** Lo que `contenido` pide al efecto descifrado en este cuadro: lo decide `draw` entre todas las ventanas. */
  let animar = false;
  /** Si el efecto descifrado está activo: se lee de la configuración una vez por cuadro, no por ventana. */
  let efectoCuadro: boolean | undefined;
  /** La lista de sesiones entró en el último cuadro (F2 sólo sirve si entra). */
  let listaCabe = true;
  /** Los eventos de las sesiones piden redibujar; se juntan en un solo cuadro cada 16 ms. */
  let cuadro: ReturnType<typeof setTimeout> | undefined;
  const agendar = () => { cuadro ??= setTimeout(() => { cuadro = undefined; if (!closed) draw(); }, 16); };
  const guardar = () => {
    const aviso = guardarArreglo({ forma, pestanas: ventanas.map((w) => w.pestanas), divisores, lista: conLista });
    if (aviso) notice = aviso;
  };
  let altoContenido = 10;
  // Selección con el mouse: puntos en índices de `todas`; `fijo` cuando ya se soltó (o se copió por doble/triple clic).
  let marcado: { a: Punto; b: Punto; ancho: number; fijo: boolean; arrastro: boolean } | undefined;
  let clics = { n: 0, t: 0, fila: -1, col: -1 };
  let autoscroll: ReturnType<typeof setInterval> | undefined;
  let sentido = 0;
  const parar = () => { if (autoscroll) { clearInterval(autoscroll); autoscroll = undefined; } };
  const desmarcar = () => { marcado = undefined; parar(); };
  let notice = "";
  /** «sub:N arrancó»: dura unos 5 s y muestra el último; un solo timer, que se limpia al salir. */
  let arranco: { worker: string; de: string; timer: ReturnType<typeof setTimeout> } | undefined;
  /** Texto del aviso de copia exitosa: sólo un `notice` idéntico a él se pinta sin ⚠; todo lo demás es aviso. */
  let copiado = "";
  let lastCtrlC = 0;
  /** Comando resaltado en la lista de `/`; se mueve con ↑↓. */
  let selected = 0;
  let closed = false;
  /** Menú o entrada que tiene el foco; mientras no sea null, onKey le deriva las teclas. */
  let mode:
    /** `at` es la posición dentro de las filas visibles (filtradas por `query` si el menú busca). */
    | { kind: "pick"; title: string; rows: Row[]; at: number; footer: string; done: (value: number | undefined) => void; search: boolean; query: string; cycle?: (index: number, step: 1 | -1) => Promise<CycleResult>; move?: (index: number) => void }
    | { kind: "input"; label: string; hidden: boolean; done: (value: string | undefined) => void }
    /** Permiso de shell: no es un diálogo del comando sino del motor, y frena el turno hasta responder. */
    | { kind: "permiso"; s: Sesion; id: number; command: string; kind2: string; risky: boolean; reasons: string[]; prefix: string; at: number }
    | null = null;
  /** Editor aparte para las entradas de los comandos: no toca el texto ni el historial del normal. */
  const secret = new Editor();
  /** Comando esperando al daemon: se muestra con un spinner hasta que responde. */
  let busy: string | null = null;
  /** Paso del inicio guiado en pantalla (sobre el sello), con la barra que se va llenando. */
  let wizard: WizardStep | null = null;
  let wizardFill = 0;
  let wizardTimer: ReturnType<typeof setInterval> | undefined;
  let spin = 0;
  let turno: { inicio: number; costo: number } | undefined;
  let spinner: ReturnType<typeof setInterval> | undefined;
  // La consola clásica de Windows no dibuja los puntos braille.
  const SPIN = process.env.CYBER_CONSOLE === "conhost" ? ["|", "/", "-", "\\"] : ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

  /** Entradas nuevas del registro: cada pestaña que las muestra suma una novedad (se borra al verlas). */
  const novedad = (lista: readonly Entrada[], sesion: Sesion = ses) => {
    for (const entrada of lista) {
      sesion.hasContent = true;
      // Se cuenta lo que se dibuja: una acción en curso la muestra la región viva y un resultado sin hash ni texto no tiene líneas.
      if ((entrada.tipo === "acciones" && entrada.estado === "en curso") || (entrada.tipo === "resultados" && !entrada.hash && !entrada.texto)) continue;
      if (sesion.contadas.has(entrada.id)) continue;
      sesion.contadas.add(entrada.id);
      for (const w of ventanas) if (w.sesion === sesion) w.pestanas.forEach((p, i) => { if (p.tipo === "conversacion" && muestra(p, entrada)) w.estados[i]!.novedades++; });
    }
  };
  const say = (lines: string[], tono: Tono = "normal", s: Sesion = ses) => novedad(lines.map((line) => s.registro.aviso(line, tono)), s);
  /** Respuesta de un comando: un panel con título, cuerpo envuelto y pie con cómo seguir. */
  const panel = (view: Panel, s: Sesion = ses) => novedad([s.registro.panel(view)], s);
  const pedir = (indice: number, w: Ventana = vent) => {
    const c = w.sesion.client;
    const p = w.pestanas[indice];
    if (p?.tipo !== "vista") return;
    const v = VISTAS[p.vista];
    const turno = (w.pedidos.get(indice) ?? 0) + 1;
    w.pedidos.set(indice, turno);
    const poner = (lineas: string[]) => {
      if (w.pestanas[indice] !== p || w.pedidos.get(indice) !== turno) return;
      const previo = w.datos.get(indice);
      const filas = filasDe(p.vista, lineas);
      w.datos.set(indice, { ...previo, ver: previo ? previo.ver : true, lineas: v.lineas?.(lineas) ?? lineas, filas, at: Math.min(previo?.at ?? 0, Math.max(0, filas.length - 1)) });
      draw();
    };
    c.view(v.comando, "").then(poner, (e: Error) => poner([t(`no se pudo traer ${v.titulo()}: ${e.message}`, `could not fetch ${v.titulo()}: ${e.message}`)]));
  };
  const abrirDetalle = (indice: number) => {
    const w = vent, c = ses.client;
    const p = w.pestanas[indice];
    const d = w.datos.get(indice);
    const fila = d?.filas[d.at];
    if (p?.tipo !== "vista" || !d || !fila) return;
    const v = VISTAS[p.vista];
    const mio = [t("cargando…", "loading…")];
    d.detalle = mio;
    w.estados[indice]!.scroll = 0;
    const poner = (lineas: string[]) => { if (d.detalle === mio) { d.detalle = lineas; draw(); } };
    c.view(v.comando, fila.id).then(poner, (e: Error) => poner([t(`no se pudo traer el detalle: ${e.message}`, `could not fetch the detail: ${e.message}`)]));
  };
  const irA = (indice: number) => {
    if (indice < 0 || indice >= vent.pestanas.length) return;
    vent.activa = indice;
    vent.fuente = undefined;
    desmarcar();
    vent.seleccion = undefined;
    vent.estados[indice] = { ...vent.estados[indice]!, novedades: 0 };
    vent.sinVer.delete(indice);
    pedir(indice);
  };
  /** Algo cambió en el proyecto: la vista activa se vuelve a pedir y las demás quedan marcadas. */
  const refrescarVistas = (s?: Sesion) => ventanas.forEach((w) => w.pestanas.forEach((p, i) => {
    if (p.tipo !== "vista" || (s && w.sesion !== s)) return;
    if (i === w.activa) pedir(i, w);
    else w.sinVer.add(i);
  }));
  const aplicarPestanas = (lista: Pestana[], w: Ventana = vent) => {
    // La activa se sigue por identidad. Si no está porque se editó (misma cantidad, el editor la copia), sigue en su lugar; si se borró, la primera.
    const previa = w.pestanas[w.activa];
    const cantidad = w.pestanas.length;
    w.pestanas = lista;
    w.fuente = undefined;
    w.estados = lista.map(nuevoEstado);
    w.datos = new Map();
    w.cachePublica = undefined;
    w.pedidos.clear();
    w.sinVer = new Set();
    w.seleccion = undefined;
    const sigue = lista.indexOf(previa!);
    w.activa = sigue >= 0 ? sigue : lista.length === cantidad ? w.activa : 0;
    pedir(w.activa, w);
    guardar();
    draw();
  };
  /** El scroll de lo que la ventana muestra: la fuente (subagente) o la pestaña activa. */
  const estadoDe = (w: Ventana) => (w.fuente && w.vistaFuente ? w.vistaFuente.estado : w.estados[w.activa]!);
  const scrollar = (lineas: number, w: Ventana = vent) => { estadoDe(w).scroll += lineas; };
  /** Redibujo a ~30 cuadros por segundo mientras alguna respuesta se descifra; se apaga solo apenas nada se anima. */
  let descifrando: ReturnType<typeof setInterval> | undefined;
  const seguirDescifrado = (animando: boolean) => {
    if (animando) descifrando ??= setInterval(draw, 33);
    else if (descifrando) { clearInterval(descifrando); descifrando = undefined; }
  };
  const girar = () => { spinner ??= setInterval(() => { spin++; draw(); }, 80); };
  const startBusy = (label: string) => {
    busy = label;
    if (!spinner) spin = 0;
    girar();
  };
  /** El spinner gira mientras haya un comando esperando o alguna sesión con un turno en marcha. */
  const apagarSpinner = () => { if (spinner && !busy && !todas.some((s) => s.turno)) { clearInterval(spinner); spinner = undefined; } };
  const stopBusy = () => {
    busy = null;
    apagarSpinner();
  };
  const costoUsd = (s: Sesion = ses) => Number(/USD (\d+(?:\.\d+)?)/.exec(s.client.status.cost)?.[1] ?? 0);
  /** Al empezar un turno de la sesión guarda el reloj y el costo de la barra; al terminar suelta el spinner si nadie más lo usa. */
  const seguirTurno = (s: Sesion = ses) => {
    if (s.client.status.running && !s.turno) { s.turno = { inicio: Date.now(), costo: costoUsd(s) }; girar(); }
    else if (!s.client.status.running && s.turno) { s.turno = undefined; apagarSpinner(); }
  };
  /** «12 s» o «2 min 5 s» y, si el costo subió desde que empezó el turno, el gasto. */
  const tiempoTurno = (turno: { inicio: number; costo: number }) => {
    const seg = Math.floor((Date.now() - turno.inicio) / 1000);
    const dur = seg >= 60 ? `${Math.floor(seg / 60)} min ${seg % 60} s` : `${seg} s`;
    const d = costoUsd() - turno.costo;
    return `· ${dur}${(!enVivo || proteccion.mostrarUso) && d >= 0.005 ? ` ${t(`· USD ${d.toFixed(2)} este turno`, `· USD ${d.toFixed(2)} this turn`)}` : ""}`;
  };
  /** Cambia de paso: la barra avanza en varios cuadros hasta la marca nueva. */
  const showWizard = (step: WizardStep) => {
    wizard = step;
    if (wizardTimer) clearInterval(wizardTimer);
    wizardTimer = setInterval(() => {
      const inner = Math.max(10, pantalla.width - 8);
      const target = Math.round((step.step / step.total) * Math.max(10, inner - 14));
      if (wizardFill >= target || !wizard) { clearInterval(wizardTimer); wizardTimer = undefined; wizardFill = Math.max(wizardFill, target); return; }
      wizardFill = Math.min(target, wizardFill + Math.max(1, Math.ceil(target / 8)));
      draw();
    }, 40);
    draw();
  };
  const hideWizard = () => {
    wizard = null;
    wizardFill = 0;
    if (wizardTimer) { clearInterval(wizardTimer); wizardTimer = undefined; }
  };
  const runInicio = async () => {
    finishBoot();
    const s = ses;
    const outcome = await runWizard({
      io: crearCio(s),
      show: showWizard,
      hide: hideWizard,
      needsKey: () => s.client.status.needsKey,
      hasKey: () => s.client.status.hasKey ?? !s.client.status.needsKey,
      pasteKey: async () => {
        const key = await askHidden(t(`Pegá tu clave de ${link("https://cyber.elevateai.ar/cuenta")}`, `Paste your key from ${link("https://cyber.elevateai.ar/cuenta")}`));
        if (!key) return false;
        try { panel({ title: "orobas", lines: await s.client.ask("account", { service: "orobas", action: "save", value: key }), tone: "ok" }, s); return true; }
        catch (error) { panel({ title: "orobas", lines: [(error as Error).message], tone: "warn" }, s); return false; }
      },
      busy: (label) => (label ? startBusy(label) : stopBusy()),
    });
    hideWizard();
    let aviso = "";
    if (outcome !== "despues") await s.client.ask("inicio", { action: "done", skipped: outcome === "saltado" }).catch((error: Error) => { aviso = error.message; });
    panel({ ...wizardSummary(outcome), tone: outcome === "completo" ? "ok" : undefined }, s);
    if (aviso) panel({ title: "inicio", lines: [aviso], tone: "warn" }, s);
    draw();
  };
  const user = (text: string, s: Sesion = ses) => novedad([s.registro.mensaje(text)], s);

  /** El cursor del tema; en una terminal angosta, un cursor de más de una columna cae a «>». */
  const cursorTema = (ancho: number): string => {
    const c = simbolos().cursor;
    return visibleWidth(c) > 1 && ancho - visibleWidth(`${c} `) - 2 < 40 ? ">" : c;
  };

  /**
   * Lo que el operador escribió durante el turno queda a la vista, fijo sobre el editor, hasta que el agente
   * lo toma: cuántos esperan, el último y la tecla para no esperar.
   */
  const filaCola = (width: number): string[] => {
    const cola = ses.client.status.queue ?? [];
    if (!cola.length) return [];
    const tecla = dim(t("Ctrl+Y manda ya · /cola", "Ctrl+Y sends now · /cola"));
    const izquierda = `  ${accent(bold(t(`en cola (${cola.length})`, `queued (${cola.length})`)))} `;
    const resto = cola.length > 1 ? t(` y ${cola.length - 1} más`, ` and ${cola.length - 1} more`) : "";
    const lugar = width - visibleWidth(izquierda) - visibleWidth(tecla) - 2;
    if (lugar < 12) return [truncate(izquierda + tecla, width)];
    const texto = truncate(enVivo ? "Mensaje reservado" : `«${cola.at(-1)!.text}»${resto}`, lugar);
    return [izquierda + texto + " ".repeat(Math.max(2, width - visibleWidth(izquierda + texto) - visibleWidth(tecla))) + tecla];
  };

  /** Región viva (herramientas en curso, estado, editor y pie); el historial lo dibuja la pestaña activa. */
  const live = () => {
    const width = pantalla.width;
    const rule = dim("─".repeat(width));
    const lines: string[] = [];
    if (ses.activeTools.size) lines.push("");
    for (const label of ses.activeTools.values()) {
      const left = `  ${accent(cursorTema(width))} ${bold(enVivo ? "Herramienta" : label)}`;
      lines.push(left + " ".repeat(Math.max(2, width - visibleWidth(left) - 10)) + accent("en curso"));
    }
    if (wizard) {
      const inner = Math.max(10, width - 8);
      const cells = Math.max(10, inner - 14);
      const target = Math.round((wizard.step / wizard.total) * cells);
      const filled = Math.min(target, wizardFill);
      const bar = accent("━".repeat(filled)) + dim("─".repeat(Math.max(0, cells - filled)));
      lines.push("", `  ${accent("◆")} ${bold(`${t("Paso", "Step")} ${wizard.step} ${t("de", "of")} ${wizard.total}`)} · ${publico(wizard.title)}`, `  ${bar} ${dim(`${wizard.step}/${wizard.total}`)}`, "");
      for (const line of (enVivo ? [publico(wizard.body.join("\n"))] : wizard.body)) lines.push(...(line ? wrapText(line, inner, "  ") : [""]));
    }
    if (arranco && !enVivo) lines.push("", `  ${accent("●")} ${bold(((n, tecla) => t(`${n} arrancó (${tecla} para verlo)`, `${n} started (${tecla} to see it)`))(arranco.de ? t(`${arranco.worker} de ${arranco.de}`, `${arranco.worker} of ${arranco.de}`) : arranco.worker, listaCabe ? "F2" : t("agrandá la terminal y F2", "enlarge the terminal and F2")))}`);
    lines.push(
      "",
      vent.seleccion !== undefined ? `  ${dim(t("Alt+↑↓ o Tab/Shift+Tab elegir acción · Enter expandir · Esc salir", "Alt+↑↓ or Tab/Shift+Tab pick action · Enter expand · Esc exit"))}` : busy ? `  ${accent(SPIN[spin % SPIN.length]!)} ${dim(enVivo ? "Procesando…" : ses.turno ? `${busy} ${tiempoTurno(ses.turno)}` : busy)}` : notice ? `  ${notice === copiado ? accent(publico(notice)) : avisoLinea(conSimboloAviso(publico(notice)))}` : ses.turno ? `  ${accent(SPIN[spin % SPIN.length]!)} ${dim(`${t("trabajando", "working")} ${tiempoTurno(ses.turno)}`)}` : "",
      ...filaCola(width),
      rule,
      // Una sesión que no estás mirando pide permiso: no te cambia de ventana, te avisa.
      ...todas.filter((s) => s !== ses && s.permiso).slice(0, 2).map((s) => {
        // Sin ventana visible no hay a dónde ir con F6: se abre desde la lista.
        const tecla = ventanas.some((w, i) => w.sesion === s && (!rects.length || rects[i])) ? "F6" : listaCabe ? "F2" : "/sesiones";
        return `  ${avisoLinea(conSimboloAviso(t(`⚠ ${truncate(nombreVisible(s), 16)} espera tu respuesta (${tecla} para ir)`, `⚠ ${truncate(nombreVisible(s), 16)} is waiting for your answer (${tecla} to go)`)))}`;
      }),
    );
    if (mode) {
      // Los menús con buscador (como /config) son largos: usan más alto si la terminal lo tiene.
      const shown = Math.max(1, Math.min(mode.kind === "pick" && mode.search ? 16 : 8, pantalla.height - 10));
      if (mode.kind === "pick") {
        const menu = mode;
        const visible = pickVisible(menu).map((index) => menu.rows[index]!);
        const first = Math.max(0, Math.min(mode.at - shown + 1, visible.length - shown));
        const rows = visible.slice(first, first + shown);
        // Con buscador, la primera fila es lo que se va escribiendo.
        const head: Row[] = mode.search ? [{ label: `⌕ ${(enVivo && mode.query ? "•••" : mode.query) || dim(t("escribí para buscar", "type to search"))}` }] : [];
        if (mode.search && !visible.length) rows.push({ label: dim(t("sin resultados", "no results")) });
        const keys = mode.cycle ? t("↑↓ mover · ←→ cambiar · Enter abre · Esc cierra", "↑↓ move · ←→ change · Enter open · Esc close") : t("↑↓ elegir · Enter aceptar · Esc cancelar", "↑↓ move · Enter accept · Esc cancel");
        const footer = [mode.footer, keys].filter(Boolean).join("  ·  ");
        lines.push(...box(`${publico(mode.title)} · ${visible.length ? mode.at + 1 : 0}/${visible.length}`, [...head, ...rows], visible.length ? mode.at - first + head.length : -1, footer, width));
        return { lines, cursor: { row: lines.length - 1, col: 0 } };
      }
      if (mode.kind === "permiso") {
        // El aviso muestra la línea exacta: es lo que el operador tiene que poder leer antes de
        // aceptar. Los motivos van primero, y «siempre» dice qué prefijo queda guardado.
        const ancho = Math.max(24, width - 8);
        const comando = wrapText(publico(mode.command), ancho - 4, "").slice(0, 6).map((linea) => ({ label: linea }));
        const motivos = mode.reasons.slice(0, 4).map((razon) => ({ label: `· ${publico(razon)}` }));
        const opciones = [
          { label: `aceptar`, hint: "una vez" },
          { label: `siempre`, hint: `recuerda «${publico(mode.prefix)}»` },
          { label: `rechazar`, hint: "no ejecuta nada" },
        ];
        const aviso = enVivo && publico(mode.command) !== mode.command ? [{ label: "Hay datos tapados. Revisá el comando en privado antes de aceptar." }] : [];
        const filas = [...aviso, ...comando, ...(motivos.length ? [{ label: "" }, ...motivos] : []), { label: "" }, ...opciones];
        const primero = filas.length - opciones.length;
        lines.push("");
        lines.push(...box(`${mode.risky ? "permiso de shell · riesgoso" : "permiso de shell"} · ${publico(mode.kind2)}`, filas, primero + mode.at, "a aceptar · s siempre · r rechazar · Esc rechaza", width));
        return { lines, cursor: { row: lines.length - 1, col: 0 } };
      }
      const shownText = enVivo && secret.text ? "•••" : mode.hidden ? "•".repeat(graphemes(secret.text).length) : secret.text;
      lines.push(`  ${publico(mode.label)} ${cursorTema(width)} ${shownText}`, rule, dim("  Enter aceptar · Esc cancelar"));
      return { lines, cursor: { row: lines.length - 3, col: visibleWidth(`  ${publico(mode.label)} ${cursorTema(width)} `) + visibleWidth(shownText) } };
    }
    const matches = completions();
    const shown = Math.max(0, Math.min(6, pantalla.height - 10));
    // La ventana se desplaza para que el resaltado siempre quede visible.
    const first = Math.max(0, Math.min(selected - shown + 1, matches.length - shown));
    const suggestions = matches.slice(first, first + shown);
    // Con varias ventanas el editor dice a quién le escribís.
    const para = ventanas.length > 1 ? `${t("para", "for")} ${truncate(nombreVisible(ses), 16)}: ` : "";
    const view = enVivo && editor.text ? { lines: [`  ${para}${cursorTema(width)} •••`], cursorRow: 0, cursorCol: visibleWidth(`  ${para}${cursorTema(width)} •••`) } : editor.view(width, Math.max(3, pantalla.height - lines.length - suggestions.length - (suggestions.length ? 5 : 4)), `${para}${cursorTema(width)} `);
    const cursor = { row: lines.length + view.cursorRow, col: view.cursorCol };
    if (editor.text) lines.push(...view.lines);
    else lines.push(`  ${para}${cursorTema(width)} ${dim("¿Qué querés investigar ahora?")}`);
    lines.push(rule);
    if (suggestions.length) lines.push(...box(`comandos · ${selected + 1}/${matches.length}`, suggestions.map((item) => ({ label: item.label, hint: item.description })), selected - first, "↑↓ elegir · Enter ejecutar · Tab completar", width));
    // Con la lista abierta, la lista ocupa el lugar del pie.
    if (!suggestions.length) lines.push(statusBar(width));
    return { lines, cursor };
  };
  const finishBoot = () => {
    if (!sigil.booting) return;
    sigil.settle();
    pantalla.liberarImagenes();
  };
  /** Filas de pestañas (sólo si hay más de una): la activa en acento con una línea `━` debajo; en las demás, lo que llegó (número) y lo sin ver (●). */
  const filasPestanas = (vent: Ventana, width: number) => {
    let col = 1, bajo = 0, ancho = 0;
    const nombres = vent.pestanas.map((p, i) => {
      const n = vent.estados[i]!.novedades;
      if (i === vent.activa) { bajo = col; ancho = visibleWidth(nombrePestana(p, i)); col += ancho + 3; return bold(accent(nombrePestana(p, i))); }
      const texto = dim(nombrePestana(p, i)) + (n ? ` ${badgeWarn(` ${n} `)}` : "") + (vent.sinVer.has(i) ? dim(" ●") : "");
      col += visibleWidth(nombrePestana(p, i)) + (n ? String(n).length + 3 : 0) + (vent.sinVer.has(i) ? 2 : 0) + 3;
      return texto;
    });
    const sub = " ".repeat(bajo) + accent("━".repeat(ancho)) + dim("─".repeat(Math.max(0, width - bajo - ancho)));
    return [truncate(" " + nombres.join("   "), width), truncate(sub, width)];
  };
  /** Contenido de la pestaña activa: las últimas líneas según el scroll, o el sello si todavía no hay nada. */
  const contenido = (vent: Ventana, width: number, alto: number) => {
    const pestana = vent.pestanas[vent.activa]!;
    const activaV = vent === ventanas[actual];
    const sub = vent.fuente?.tipo === "sub" ? vent.sesion.subagentes.de(vent.fuente.worker) : undefined;
    const h = vent.fuente?.tipo === "harness" ? vent.sesion.harnesses.de(vent.fuente.id) : undefined;
    const clave = sub ? sub.worker : h ? `#${h.id}` : undefined;
    if (clave && vent.vistaFuente?.worker !== clave) vent.vistaFuente = { worker: clave, estado: nuevoEstado(), cache: new Map() };
    const estado = estadoDe(vent);
    if (vent.fuente && !clave) return { lineas: [vent.fuente.tipo === "sub" ? t(`(${publico(vent.fuente.worker)})…`, `(${publico(vent.fuente.worker)})…`) : t(`(#${publico(vent.fuente.id)})…`, `(#${publico(vent.fuente.id)})…`)], imagen: undefined };
    if (activaV && marcado && marcado.ancho !== width) desmarcar();
    if (!clave && pestana.tipo === "conversacion" && !vent.sesion.hasContent && (wizard || !mode) && !vent.sesion.client.status.running && vent.sesion.activeTools.size === 0) {
      // En el inicio guiado el pie cambia de alto en cada paso: el sello usa una altura fija para no redibujarse entero.
      vent.ultimo = { ...vent.ultimo, todas: [] };
      const sello = sigil.view(width, wizard ? Math.min(alto, Math.floor(pantalla.height / 3)) : alto, terminal);
      return { lineas: sello.lines, imagen: sello.image };
    }
    let desde = new Map<number, number>();
    let todas: string[];
    let fila = -1;
    let ver = false;
    if (enVivo && vent.fuente) {
      todas = ["  Actividad de la sesión · detalle reservado"];
    } else if (sub) {
      const d = dibujar(chat() as Extract<Pestana, { tipo: "conversacion" }>, sub.registro.entradas(), { ancho: width, expandidas: vent.expandidas, cache: vent.vistaFuente!.cache, ahora: Date.now(), efecto: () => (efectoCuadro ??= descifradoActivo()), marco: SPIN[spin % SPIN.length]!, resultados: (e) => e.texto });
      animar ||= d.animando;
      const fin = sub.estado === "trabajando" ? [] : ["", bold(t("Informe:", "Report:")), ...wrapText(sub.informe ?? "", width, "  "), ...(sub.solicitudes !== undefined || sub.usd ? ["", dim(`${t(`${sub.solicitudes ?? 0} solicitud${sub.solicitudes === 1 ? "" : "es"}`, `${sub.solicitudes ?? 0} request${sub.solicitudes === 1 ? "" : "s"}`)}${sub.usd ? ` · USD ${sub.usd}` : ""}`)] : [])];
      todas = [...wrapText(sub.objetivo ? t(`Objetivo: ${sub.objetivo}`, `Goal: ${sub.objetivo}`) : t("Objetivo: (todavía no se sabe)", "Goal: (not known yet)"), width, "  "), "", ...d.lineas, ...fin];
      desde = new Map();
    } else if (h) {
      todas = [...wrapText(`${h.harness} · ${estadoHarness(h.estado)}${h.segundos !== undefined ? ` · ${h.segundos} s` : ""}`, width, "  "), ...wrapText(h.tarea, width, "  "), ...(h.rama ? [`  ${t("rama", "branch")} ${h.rama}`] : []), "", ...(h.cola ? h.cola.split("\n").flatMap((l) => wrapText(l, width, "  ")) : []), ...(h.error ? [`  ${avisoLinea(conSimboloAviso(h.error))}`] : [])];
    } else if (pestana.tipo === "conversacion") {
      let cache = vent.caches.get(pestana);
      if (!cache) vent.caches.set(pestana, (cache = new Map()));
      const entradas = vent.sesion.registro.entradas();
      const mostradas = enVivo ? entradas.map((e) => entradaPublica(e, proteccion)) : entradas;
      if (enVivo && (vent.cachePublica?.version !== proteccion.version || vent.cachePublica.pestana !== pestana)) {
        vent.cachePublica = { version: proteccion.version, pestana, filas: new Map() };
      }
      const d = dibujar(pestana, mostradas, { ancho: width, expandidas: vent.expandidas, cache: enVivo ? vent.cachePublica!.filas : cache, ahora: Date.now(), efecto: () => (efectoCuadro ??= descifradoActivo()), marco: SPIN[spin % SPIN.length]!, vivas: new Set(vent.sesion.activeTools.keys()), ...(vent.seleccion !== undefined ? { seleccion: vent.seleccion } : {}), resultados: (e) => {
        const cuerpo = e.texto ?? (e.hash ? vent.sesion.evidencia.get(e.hash) ?? "cargando" : undefined);
        return cuerpo === undefined ? undefined : publico(cuerpo);
      } });
      todas = d.lineas;
      desde = d.desde;
      animar ||= d.animando;
      if (!todas.length && pestana.contenido.length < TIPOS.length) todas = [dim(`  ${t("Nada para mostrar en esta pestaña todavía.", "Nothing to show in this tab yet.")}`)];
    } else {
      const d = vent.datos.get(vent.activa);
      const v = VISTAS[pestana.vista];
      const titulo = mayus(v.titulo());
      if (enVivo && (pestana.vista !== "costos" || !proteccion.mostrarUso)) todas = [`  ${titulo} · detalle reservado`];
      else if (!d) todas = [dim(`  ${t("cargando…", "loading…")}`)];
      else if (d.detalle) todas = dibujarPanel(fromLines(titulo, enVivo ? publico(d.detalle.join("\n")).split("\n") : d.detalle, { footer: t("Esc vuelve a la lista", "Esc back to the list") }), width);
      else if (!d.lineas.some((l) => l.trim())) todas = dibujarPanel(fromLines(titulo, [t(`Sin ${v.titulo()} todavía.`, `No ${v.titulo()} yet.`)]), width);
      else {
        let k = 0;
        const marcadas = d.lineas.map((l) => (d.filas[k]?.texto === l ? `${adornoTUI(k++ === d.at ? accent("▌") : " ")} ${pestana.vista === "hallazgos" ? etiquetarHallazgo(l) : l}` : l));
        todas = dibujarPanel(fromLines(titulo, enVivo ? publico(marcadas.join("\n")).split("\n") : marcadas, d.filas.length ? { footer: t("↑↓ elegir · Enter abre", "↑↓ pick · Enter opens") } : {}), width);
        if (d.ver) fila = todas.findIndex((l) => l.includes("▌"));
        d.ver = false;
      }
    }
    // Con scroll arriba, lo que llega abajo no mueve lo que se está leyendo (salvo que haya cambiado el ancho).
    if (estado.scroll > 0 && estado.ancho === width && estado.total !== undefined) estado.scroll += Math.max(0, todas.length - estado.total);
    estado.ancho = width;
    estado.total = todas.length;
    estado.scroll = clampScroll(estado.scroll, todas.length, alto);
    // Al abrir la lista o mover la fila, el scroll deja la fila elegida a la vista.
    if (fila >= 0) {
      if (fila < todas.length - estado.scroll - alto) estado.scroll = Math.max(0, todas.length - fila - alto);
      else if (fila >= todas.length - estado.scroll) estado.scroll = Math.max(0, todas.length - fila - 1);
    }
    if (!estado.scroll) estado.novedades = 0;
    const fin = todas.length - estado.scroll;
    vent.ultimo = { total: todas.length, desde, todas, inicio: Math.max(0, fin - alto), arriba: vent.pestanas.length > 1 ? 2 : 0, alto };
    // Sólo se piden los artefactos cuyo resultado está en pantalla.
    if (!clave && pestana.tipo === "conversacion" && pestana.detalle === "completo")
      for (const e of vent.sesion.registro.entradas()) {
        const l = desde.get(e.id);
        if (e.tipo === "resultados" && e.hash && !e.texto && l !== undefined && l >= fin - alto && l < fin) vent.sesion.traer(e.hash);
      }
    const vista = todas.slice(Math.max(0, fin - alto), fin);
    if (activaV && marcado) {
      const [p, q] = marcado.a.fila < marcado.b.fila || (marcado.a.fila === marcado.b.fila && marcado.a.col <= marcado.b.col) ? [marcado.a, marcado.b] : [marcado.b, marcado.a];
      for (let i = 0; i < vista.length; i++) {
        const n = vent.ultimo.inicio + i;
        if (n >= p.fila && n <= q.fila) vista[i] = resaltar(vista[i]!, n === p.fila ? p.col : 0, n === q.fila ? q.col : Infinity);
      }
    }
    if (estado.scroll && estado.novedades && vista.length) vista[vista.length - 1] = dim(t(`▼ ${estado.novedades} nuevas · Ctrl+Fin`, `▼ ${estado.novedades} new · Ctrl+End`));
    return { lineas: vista, imagen: undefined };
  };
  const tituloSub = (x: { worker: string; estado: string }) => `${x.estado === "trabajando" ? "⋯" : x.estado === "terminó" ? "✓" : "✗"} ${x.worker} · ${x.estado === "trabajando" ? t("trabajando", "working") : x.estado === "terminó" ? t("terminó", "finished") : t("no terminó", "did not finish")}`;
  const estadoHarness = (e: string) => ({ corriendo: t("corriendo", "running"), esperando: t("esperando", "waiting"), terminado: t("terminado", "finished"), fallido: t("fallido", "failed"), detenido: t("detenido", "stopped"), vencido: t("vencido", "timed out"), rechazado: t("rechazado", "rejected") } as Record<string, string>)[e] ?? e;
  const tituloHarness = (h: { id: string; estado: string; enCurso: boolean }) => `${h.enCurso ? "⋯" : h.estado === "terminado" ? "✓" : "✗"} #${h.id} · ${estadoHarness(h.estado)}`;
  /** Estado y nombre de lo que muestra una ventana con fuente (el mismo texto en el borde y sin recuadro). */
  const tituloFuente = (w: Ventana): string | undefined => {
    const sub = w.fuente?.tipo === "sub" ? w.sesion.subagentes.de(w.fuente.worker) : undefined;
    const h = w.fuente?.tipo === "harness" ? w.sesion.harnesses.de(w.fuente.id) : undefined;
    if (enVivo && w.fuente) return "Actividad de la sesión";
    return sub ? tituloSub(sub) : h ? tituloHarness(h) : undefined;
  };
  /** El recuadro de una ventana: borde en acento con ● si es la activa, apagado y sin ● en las demás; adentro, pestañas y contenido. */
  const caja = (w: Ventana, rect: Rect, esActiva: boolean, ocultas: number): string[] => {
    const [tl, tr, bl, br] = corners();
    const [h, v] = lineaBorde();
    const tono = esActiva && !lista.enfocada ? accent : dim;
    const inner = Math.max(0, rect.ancho - 2);
    const filas = w.pestanas.length > 1 ? 2 : 0;
    const alto = Math.max(1, rect.alto - 2 - filas);
    if (esActiva) { anchoUtil = inner; altoContenido = alto; }
    const espera = w.sesion.permiso && w.sesion !== ses;
    const titulo = truncate(`${esActiva && !lista.enfocada ? "● " : ""}${espera ? `⚠ ${nombreVisible(w.sesion)} · ${t("espera respuesta", "waiting for an answer")}` : tituloFuente(w) ?? `${nombreVisible(w.sesion)} · ${nombrePestana(w.pestanas[w.activa]!, w.activa)}`}`, Math.max(1, inner - 4));
    const arriba = `${tl}${h} ${titulo} `;
    const pie = esActiva && ocultas > 0 ? ` ${truncate(ocultas === 1 ? t("1 ventana oculta: agrandá la terminal", "1 window hidden: enlarge the terminal") : t(`${ocultas} ventanas ocultas: agrandá la terminal`, `${ocultas} windows hidden: enlarge the terminal`), Math.max(1, inner - 4))} ` : "";
    const { lineas } = contenido(w, inner, alto);
    const cuerpo = [...(filas ? filasPestanas(w, inner) : []), ...lineas, ...Array.from({ length: Math.max(0, alto - lineas.length) }, () => "")];
    const celda = (l: string) => { const x = visibleWidth(l) > inner ? truncate(l, inner) : l; return `${tono(v)}${x}${" ".repeat(Math.max(0, inner - visibleWidth(x)))}${tono(v)}`; };
    return [tono(`${arriba}${h.repeat(Math.max(0, inner + 2 - visibleWidth(arriba) - 1))}${tr}`), ...cuerpo.map(celda), tono(`${bl}${h}${pie}${h.repeat(Math.max(0, inner + 2 - visibleWidth(pie) - 3))}${br}`)];
  };
  type FilaLista = { tipo: "nueva" } | { tipo: "sesion"; id: string; nombre: string; s: Sesion | undefined } | { tipo: "pestana"; w: Ventana; i: number }
    | { tipo: "encabezado" } | { tipo: "sub"; s: Sesion; worker: string } | { tipo: "harness"; s: Sesion; id: string };
  /** «+ nueva», las sesiones del proyecto (las abiertas con sus pestañas debajo) y las abiertas que el daemon todavía no listó. */
  const filasLista = (): FilaLista[] => {
    const filas: FilaLista[] = [{ tipo: "nueva" }];
    const sabidas = new Set(lista.sesiones.map((r) => r.id));
    const nombres = [...todas.filter((s) => !sabidas.has(idDe(s))).map((s) => ({ id: idDe(s), title: "" })), ...lista.sesiones.map((r) => ({ id: r.id, title: r.title }))];
    for (const { id, title } of nombres) {
      const s = buscar(id);
      filas.push({ tipo: "sesion", id, nombre: s?.nombre() || title || id.slice(0, 8), s });
      if (s) for (const w of ventanas) if (w.sesion === s) w.pestanas.forEach((_, i) => filas.push({ tipo: "pestana", w, i }));
      if (s) for (const x of s.subagentes.lista()) filas.push({ tipo: "sub", s, worker: x.worker });
      // Cada sesión tiene su propio Orquesta: lo vivo es de esa sesión; lo que otra sesión ve como `anterior` no se sigue.
      if (s) for (const h of s.harnesses.lista()) if (!h.anterior) filas.push({ tipo: "harness", s, id: h.id });
    }
    // Las `anterior` (sólo lectura) cuyo id no está vivo en ninguna sesión abierta, una sola vez.
    const vivos = new Set(todas.flatMap((s) => s.harnesses.lista().filter((h) => !h.anterior).map((h) => h.id)));
    const vistos = new Set<string>();
    const previos = [ses, ...todas.filter((s) => s !== ses)].flatMap((s) => s.harnesses.lista().filter((h) => h.anterior && !vivos.has(h.id) && !vistos.has(h.id) && vistos.add(h.id)).map((h) => ({ s, id: h.id })));
    if (previos.length) { filas.push({ tipo: "encabezado" }); for (const p of previos) filas.push({ tipo: "harness", ...p }); }
    return filas;
  };
  // ⋯ trabajando, ✓ terminó, ✗ no terminó o falló: el símbolo dice el estado, no sólo el tono.
  const textoSub = (s: Sesion, worker: string) => { const x = s.subagentes.de(worker); return `  ${x?.estado === "trabajando" ? "⋯" : x?.estado === "terminó" ? "✓" : "✗"} ${worker} · ${(x?.objetivo ?? "").replace(/\s+/g, " ").slice(0, 30)}`; };
  const textoHarness = (s: Sesion, id: string) => { const h = s.harnesses.de(id); return `  ${h?.enCurso ? "⋯" : h?.estado === "terminado" ? "✓" : "✗"} #${id} ${h?.harness ?? ""} · ${(h?.tarea ?? "").slice(0, 30)}`; };
  /** El recuadro de la lista: la fila elegida lleva el cursor del tema, las abiertas ◆ y las que esperan ⚠. */
  const cajaLista = (rect: Rect): string[] => {
    const [tl, tr, bl, br] = corners();
    const [h, v] = lineaBorde();
    const tono = lista.enfocada ? accent : dim;
    const inner = rect.ancho - 2, alto = Math.max(1, rect.alto - 2);
    const filas = filasLista();
    lista.at = Math.max(0, Math.min(lista.at, filas.length - 1));
    lista.primera = Math.max(0, Math.min(lista.primera, filas.length - alto, lista.at));
    if (lista.at >= lista.primera + alto) lista.primera = lista.at - alto + 1;
    const cursor = cursorTema(inner);
    const cuerpo = filas.slice(lista.primera, lista.primera + alto).map((f, k) => {
      const sel = lista.enfocada && lista.primera + k === lista.at;
      const texto = enVivo && f.tipo === "sesion" ? (f.s ? nombreVisible(f.s) : "Sesión guardada")
        : enVivo && (f.tipo === "sub" || f.tipo === "harness") ? "  Actividad"
        : f.tipo === "nueva" ? t("+ nueva", "+ new") : f.tipo === "sesion" ? `${f.s ? (f.s.permiso ? "⚠" : "◆") : " "} ${f.nombre}` : f.tipo === "pestana" ? `  ${nombrePestana(f.w.pestanas[f.i]!, f.i)}` : f.tipo === "sub" ? textoSub(f.s, f.worker) : f.tipo === "encabezado" ? t("/ultra · harnesses", "/ultra · harnesses") : textoHarness(f.s, f.id);
      const fila = truncate(`${sel ? cursor : " ".repeat(visibleWidth(cursor))}${texto}`, inner);
      return `${tono(v)}${sel ? bold(accent(fila)) : fila}${" ".repeat(Math.max(0, inner - visibleWidth(fila)))}${tono(v)}`;
    });
    while (cuerpo.length < alto) cuerpo.push(`${tono(v)}${" ".repeat(inner)}${tono(v)}`);
    const arriba = `${tl}${h} ${truncate(`${lista.enfocada ? "● " : ""}${t("Sesiones", "Sessions")}`, Math.max(1, inner - 4))} `;
    return [tono(`${arriba}${h.repeat(Math.max(0, inner + 2 - visibleWidth(arriba) - 1))}${tr}`), ...cuerpo, tono(`${bl}${h.repeat(inner)}${br}`)];
  };
  const draw = () => { pintar(); ajustarSondeo(); };
  const pintar = () => {
    if (closed) return;
    if (panico) return pantalla.dibujar({ lineas: [] });
    if (enVivo) proteccion.actualizar();
    const width = pantalla.width, height = pantalla.height - Number(enVivo);
    const encabezado = enVivo ? [badgeWarn(" EN VIVO · modo streamer ") + dim(avisoOBS || (proteccion.lista ? "  F8 cubre la pantalla" : "  Datos reservados · alcance sin leer"))] : [];
    if (sigil.booting) {
      const arranque = sigil.view(width, height - 1, terminal, false);
      return pantalla.dibujar({ lineas: [...encabezado, ...arranque.lines], ...(arranque.image ? { imagen: { ...arranque.image, row: arranque.image.row + encabezado.length } } : {}) });
    }
    const vivo = live();
    animar = false;
    efectoCuadro = undefined;
    listaCabe = !!repartir(forma, { x: 0, y: 0, ancho: width, alto: height - Math.min(vivo.lines.length, height - 3) }, divisores, true, actual).lista;
    if (ventanas.length > 1 || conLista) {
      // Las ventanas ocupan lo que deja la región viva, que va abajo a todo el ancho.
      const corte = Math.max(0, vivo.lines.length - (height - 3));
      const abajo = vivo.lines.slice(corte);
      const alto = height - abajo.length;
      const r = repartir(forma, { x: 0, y: 0, ancho: width, alto }, divisores, conLista, actual);
      // Con una sola ventana, la lista es lo único que pide recuadros: si no entra, se dibuja como siempre.
      if (ventanas.length > 1 || r.lista) {
        rects = r.ventanas;
        rectLista = r.lista;
        if (!rectLista) lista.enfocada = false;
        const partes: Array<Array<{ x: number; l: string }>> = Array.from({ length: alto }, () => []);
        r.ventanas.forEach((rect, i) => {
          if (rect) caja(ventanas[i]!, rect, i === actual, r.ocultas).forEach((l, k) => partes[rect.y + k]?.push({ x: rect.x, l }));
        });
        if (rectLista) cajaLista(rectLista).forEach((l, k) => partes[k]?.push({ x: 0, l }));
        seguirDescifrado(animar);
        pantalla.dibujar({
          lineas: [...encabezado, ...partes.map((fila) => fila.sort((a, b) => a.x - b.x).map((p) => p.l).join("")), ...abajo],
          cursor: { row: encabezado.length + alto + vivo.cursor.row - corte, col: vivo.cursor.col },
        });
        return;
      }
    }
    rectLista = undefined;
    lista.enfocada = false;
    rects = [];
    const titulo = tituloFuente(vent);
    const filas = titulo || vent.pestanas.length > 1 ? 2 : 0;
    // Si la región viva no entra (terminal muy baja), se recorta por arriba.
    const corte = Math.max(0, vivo.lines.length - (height - filas));
    const abajo = vivo.lines.slice(corte);
    const alto = height - filas - abajo.length;
    altoContenido = Math.max(1, alto);
    anchoUtil = width;
    const { lineas, imagen } = contenido(vent, width, alto);
    vent.ultimo.arriba = filas;
    seguirDescifrado(animar);
    const arriba = [...(titulo ? [truncate(` ${titulo}`, width), dim("─".repeat(width))] : filas ? filasPestanas(vent, width) : []), ...lineas, ...Array.from({ length: Math.max(0, alto - lineas.length) }, () => "")];
    pantalla.dibujar({
      lineas: [...encabezado, ...arriba, ...abajo],
      cursor: { row: encabezado.length + arriba.length + vivo.cursor.row - corte, col: vivo.cursor.col },
      ...(imagen ? { imagen: { ...imagen, row: encabezado.length + imagen.row + filas } } : {}),
    });
  };

  /** Una fila a todo el ancho: estado, gasto contra el tope, uso y la tecla que sirve ahora. */
  /** Tokens aproximados de un conteo de caracteres, cortito: 1,2k. */
  const kChars = (chars: number) => { const tokens = chars / 4; return tokens >= 1000 ? `${(tokens / 1000).toFixed(1).replace(".", ",")}k` : String(Math.round(tokens)); };
  const statusBar = (width: number): string => {
    const { running, interrupted, budget, cost, usage } = ses.client.status;
    if (enVivo) {
      const estado = running ? "EN CURSO" : interrupted ? "INTERRUMPIDO" : "OROBAS";
      const uso = proteccion.mostrarUso ? ` · ${publico(cost)} · ${publico(usage)}` : "";
      return truncate(badge(` ${estado} `) + dim(` ${proteccion.modelo(ses.client.status.model ?? "")}${uso}`), width);
    }
    const thinking = running && ses.client.status.thinking ? ` ${t("RAZONANDO", "THINKING")} ~${kChars(ses.client.status.thinking)} ` : "";
    const escarapela = simbolos().escarapela ? `${simbolos().escarapela} ` : "";
    const state = running ? badge(thinking || ` ${escarapela}EN CURSO `) : interrupted ? badgeWarn(" INTERRUMPIDO ") : badge(` ${escarapela}OROBAS `);
    const spent = ` ${cost.replace(/^API est\. /, "").replace(" / tope ", " / ").replace(/ · proyecto .*/, "")} `;
    const used = ` ${usage.replace(/^Contexto (\S+) · uso (\S+) tokens/, "$2 tokens · ctx $1")} `;
    const queued = ses.client.status.queued ? ` · ${ses.client.status.queued} en cola · /cola` : "";
    const hint = `${running ? `Esc detener${queued}` : interrupted ? "/continuar retoma" : ventanas.length > 1 ? t("F6 ventana · F2 lista · /diseño", "F6 window · F2 list · /diseño") : "/ comandos"}  `;
    const left = state + ((budget ?? 0) >= 0.8 ? badgeWarn : segment)(spent);
    const session = ses.client.status.session ? ` · ${ses.client.status.session.slice(0, 8)}` : "";
    const model = ses.client.status.model ? ` ${ses.client.status.model.slice(ses.client.status.model.indexOf("/") + 1)}${session} ` : "";
    // Navegador del operador: conectado, dormido, sin emparejar o sin autorizar (/navegador dice qué hacer).
    const browser = ses.client.status.browser;
    const nav = browser ? ` ${browser.label} ` : "";
    const navPaint = (text: string) => (!browser?.authorized || browser.state === "dormido" ? segmentDim : browser.state === "conectado" ? segment : badgeWarn)(text);
    // Router de modelos: «router: ejecutor» tenue y con poca prioridad; mientras trabaja otro rol («router:
    // fuerte·tramo (candidato)», o «fuerte·tramo» si no entra) se resalta y le gana el lugar al uso, que vuelve
    // cuando termina. En una terminal angosta se caen primero el navegador y el router en reposo, después el
    // modelo y el uso, y después se corta lo que sobre.
    const router = ses.client.status.router;
    const rtPaint = (text: string) => (router?.active ? badge : segmentDim)(text);
    // Modo investigar: sólo con una investigación abierta («inv: harness-1 · h3/7 · USD 1,20»), resaltado
    // mientras corre. Lo abrió el operador: le gana el lugar al modelo y al router en reposo.
    const inv = ses.client.status.investigacion;
    const invPaint = (text: string) => (inv?.activa ? badge : segment)(text);
    const pieces = { used: [used, segmentDim], model: [model, segment], rt: [router ? ` ${router.label} ` : "", rtPaint], rts: [router?.short ? ` ${router.short} ` : "", rtPaint], nav: [nav, navPaint], inv: [inv ? ` ${inv.label} ` : "", invPaint], invs: [inv ? ` ${inv.short} ` : "", invPaint] } as const;
    type Piece = keyof typeof pieces;
    const fits = (...parts: string[]) => visibleWidth(parts.join("") + hint) <= width;
    const base: Piece[][] = router?.active
      ? [["used", "model", "rt", "nav"], ["used", "model", "rt"], ["used", "rt"], ["used", "rts"], ["rt"], ["rts"], ["used"]]
      : [["used", "model", "rt", "nav"], ["used", "model", "nav"], ["used", "model", "rt"], ["used", "model"], ["used", "nav"], ["used"]];
    const combos: Piece[][] = inv
      ? [["used", "model", "inv", "rt", "nav"], ["used", "model", "inv", "rt"], ["used", "model", "inv"], ...(router?.active ? [["used", "inv", "rts"] as Piece[]] : []), ["used", "inv"], ["used", "invs"], ["inv"], ["invs"], ...base]
      : base;
    const combo = combos.find((keys) => keys.every((key) => pieces[key][0]) && fits(left, ...keys.map((key) => pieces[key][0])));
    const full = left + (combo ?? []).map((key) => pieces[key][1](pieces[key][0])).join("");
    const gap = Math.max(1, width - visibleWidth(full) - visibleWidth(hint));
    return truncate(full + segmentDim(" ".repeat(gap) + hint), width);
  };

  /** Caja de menú: título, filas con la elegida resaltada y un pie con las teclas. */
  const box = (title: string, rows: Array<{ label: string; hint?: string }>, selected: number, footer: string, width: number): string[] => {
    const inner = Math.max(10, width - 8);
    // Las fuentes de conhost no tienen las esquinas redondeadas.
    const [tl, tr, bl, br] = corners();
    const [, v] = lineaBorde();
    const edge = (left: string, label: string, right: string, adornar = false) =>
      // Un título o pie que no entra se corta con «…»; no desaparece (el pie lleva las teclas).
      bordeRecuadro(left, inner > 6 ? truncate(label, inner - (adornar && simbolos().adorno ? 8 : 4)) : "", right, inner, accent, adornar);
    // Mayúscula inicial en título, opciones y pistas; comandos, modelos, hosts y rutas se muestran tal cual.
    const capital = (text: string) => (/[/.:@_\d]/.test(text.split(" ")[0]!) ? text : text.charAt(0).toLocaleUpperCase() + text.slice(1));
    rows = rows.map((item) => ({ label: capital(publico(item.label)), hint: item.hint && capital(publico(item.hint)) }));
    title = capital(publico(title));
    footer = publico(footer);
    const labelWidth = Math.min(Math.max(13, ...rows.map((item) => visibleWidth(item.label))), Math.max(13, Math.floor(inner / 2)));
    const body = rows.map((item, index) => {
      const active = index === selected;
      const row = truncate(`${active ? accent(cursorTema(width)) : " ".repeat(visibleWidth(cursorTema(width)))} ${(active ? accent : dim)(item.label.padEnd(labelWidth))}${item.hint ? `  ${(active ? accent : dim)(item.hint)}` : ""}`, inner);
      return `  ${accent(v)} ${row}${" ".repeat(Math.max(0, inner - visibleWidth(row)))} ${accent(v)}`;
    });
    return [edge(tl!, title, tr!, true), ...body, edge(bl!, footer, br!)];
  };

  const abrirPermiso = (s: Sesion) => {
    const e = s.permiso;
    if (e) mode = { kind: "permiso", s, id: e.id, command: e.command, kind2: e.kind, risky: e.risky, reasons: e.reasons, prefix: e.prefix, at: 0 };
  };
  /** Cierra el menú abierto resolviéndolo con undefined: nadie queda colgado ni queda el secreto en memoria. */
  const dropMode = (rechazar = true) => {
    const current = mode;
    mode = null;
    secret.set("");
    // Al salir o ante otro pedido de la misma sesión, un permiso se rechaza: el turno no puede quedar esperándolo.
    // Si sólo lo desplaza un menú, queda en `s.permiso` y la caja vuelve cuando el menú se cierra.
    if (current?.kind === "permiso") { if (rechazar && current.s.permiso?.id === current.id) void responderPermiso(current.s, current, 2); }
    else (current?.done as ((value: undefined) => void) | undefined)?.(undefined);
  };
  const pick = (title: string, options: Array<string | Row>, extra: { at?: number; footer?: string; search?: boolean; cycle?: (index: number, step: 1 | -1) => Promise<CycleResult>; move?: (index: number) => void } = {}): Promise<number | undefined> =>
    new Promise((done) => {
      dropMode(false);
      const rows = options.map((option) => (typeof option === "string" ? { label: option } : option));
      if (!rows.length) { if (ses.permiso) abrirPermiso(ses); return done(undefined); }
      // Mientras el menú espera a la persona no hay nada en curso: el spinner del comando no sigue girando.
      stopBusy();
      mode = { kind: "pick", title, rows, at: Math.min(Math.max(0, extra.at ?? 0), rows.length - 1), footer: extra.footer ?? "", done, search: extra.search ?? false, query: "", cycle: extra.cycle, move: extra.move };
      draw();
    });
  /** Índices de las filas que coinciden con lo buscado (sin tildes ni mayúsculas), en su orden. */
  const pickVisible = (current: { rows: Row[]; query: string }) => {
    const plain = (text: string) => stripAnsi(text).normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();
    const query = plain(current.query.trim());
    return current.rows.flatMap((row, index) => (!query || plain(`${row.label} ${row.hint ?? ""} ${row.busqueda ?? ""}`).includes(query) ? [index] : []));
  };
  const input = (label: string, extra: { hidden?: boolean } = {}): Promise<string | undefined> =>
    new Promise((done) => { dropMode(false); stopBusy(); mode = { kind: "input", label, hidden: extra.hidden ?? false, done }; draw(); });
  const askHidden = (label: string) => input(label, { hidden: true });
  const confirm = async (question: string) => (await pick(question, [{ label: t("sí", "yes") }, { label: t("cancelar", "cancel") }], { at: 1 })) === 0;

  /** Responde un permiso de shell: 0 acepta, 1 acepta siempre, 2 rechaza. */
  const responderPermiso = async (s: Sesion, pedido: { id: number }, indice: number) => {
    if (s.permiso?.id === pedido.id) s.soltarPermiso();
    const decision = indice === 1 ? "siempre" : indice === 0 ? "si" : "no";
    try {
      const [linea] = await s.client.ask("confirm", { permiso: pedido.id, ok: indice !== 2, decision });
      say([linea ?? (decision === "no" ? "Rechazado." : "Permitido.")], decision === "no" ? "warn" : "dim", s);
    } catch (error) {
      say([(error as Error).message], "warn", s);
    }
    draw();
  };

  /** Teclas mientras hay un menú o una entrada oculta abiertos. */
  const modeKey = (key: Key) => {
    modeKeyInner(key);
    // Al cerrarse un menú, un permiso que quedó esperando en la sesión activa se abre (después de lo que el menú haya encadenado).
    if (!mode) queueMicrotask(() => { if (!closed && !mode && ses.permiso) { abrirPermiso(ses); draw(); } });
  };
  const modeKeyInner = (key: Key) => {
    const current = mode!;
    const close = () => { mode = null; };
    if (key.name === "escape" || key.name === "ctrl+c") {
      close();
      secret.set("");
      if (current.kind === "permiso") void responderPermiso(current.s, current, 2);
      else (current.done as (value: undefined) => void)(undefined);
    } else if (current.kind === "permiso") {
      const opciones = 3;
      if (key.name === "left" || key.name === "up" || key.name === "right" || key.name === "down") {
        const paso = key.name === "left" || key.name === "up" ? opciones - 1 : 1;
        current.at = (current.at + paso) % opciones;
      } else if (key.name === "enter") {
        const elegido = current.at;
        close();
        void responderPermiso(current.s, current, elegido);
      } else if (key.name === "text" && key.text) {
        const letra = key.text.toLowerCase();
        const indice = ["a", "s", "r"].indexOf(letra);
        if (indice >= 0) { close(); void responderPermiso(current.s, current, indice); }
      }
    } else if (current.kind === "pick") {
      const visible = pickVisible(current);
      const count = visible.length;
      const antes = visible[current.at];
      if (current.search && (key.name === "backspace" || (key.name === "text" && key.text))) {
        // Con buscador, lo que se escribe filtra: los números y las letras no eligen.
        current.query = key.name === "backspace" ? current.query.slice(0, -1) : current.query + key.text;
        current.at = 0;
      } else if (!count) return;
      else if (key.name === "up" || key.name === "down") current.at = (current.at + (key.name === "up" ? count - 1 : 1)) % count;
      else if (key.name === "home") current.at = 0;
      else if (key.name === "end") current.at = count - 1;
      else if ((key.name === "left" || key.name === "right") && current.cycle) {
        const index = visible[current.at]!;
        void current.cycle(index, key.name === "left" ? -1 : 1).then((row) => {
          if (row && mode === current) {
            if ("rows" in row) { current.rows = row.rows.map((option) => (typeof option === "string" ? { label: option } : option)); current.at = Math.min(row.at, current.rows.length - 1); }
            else current.rows[index] = row;
          }
          draw();
        }, (error: Error) => { notice = error.message; draw(); });
      }
      // En un menú con ←→ (sin buscador) Espacio actúa como Enter: marca y desmarca las casillas del editor de pestañas.
      else if (key.name === "enter" || (key.name === "text" && key.text === " " && current.cycle)) { close(); current.done(visible[current.at]); }
      else if (key.name === "text" && key.text && /^\d$/.test(key.text) && Number(key.text) >= 1 && Number(key.text) <= count) { close(); current.done(visible[Number(key.text) - 1]); }
      else if (key.name === "text" && key.text) {
        // Escribir una letra salta a la siguiente opción que empieza con ella.
        const letter = key.text.toLowerCase();
        const next = saltoPorLetra(current.rows.slice(0, count).map((r) => r.label), current.at, letter);
        if (next !== undefined) current.at = next;
      }
      // Vista previa: avisa a quien abrió el menú cada vez que cambia la fila elegida.
      const ahora = pickVisible(current)[current.at];
      if (mode === current && ahora !== undefined && ahora !== antes) current.move?.(ahora);
    } else if (key.name === "enter") {
      const value = secret.text.trim();
      close();
      secret.set("");
      if (current.hidden && value) proteccion.recordar(value);
      current.done(current.kind === "input" && current.hidden ? value || undefined : value); // Enter vacío es «», Esc es undefined (las claves ocultas siguen dando undefined en ambos)
    } else secret.handle(key);
  };

  const completions = () => (/^\/\S*$/.test(editor.text) ? sugerencias(editor.text.slice(1)) : []);

  /** Sondeo de harnesses: un solo intervalo, vivo sólo con una ventana de harness a la vista o la lista visible. */
  let sondeo: ReturnType<typeof setInterval> | undefined;
  const visibles = () => (rects.length ? ventanas.filter((_, i) => rects[i]) : [vent]);
  /** Harnesses cuyo estado final ya se confirmó con un `ver`: no se vuelve a pedir. */
  const finales = new WeakMap<Sesion, Set<string>>();
  const finalesDe = (s: Sesion) => { let f = finales.get(s); if (!f) finales.set(s, (f = new Set())); return f; };
  const pendiente = (w: Ventana) => w.fuente?.tipo === "harness" && !finalesDe(w.sesion).has(w.fuente.id);
  /** La lista sólo se sondea si ya hay harnesses conocidos; si no, bastan el refresco al abrirla y el del `harness_run`. */
  const listaViva = () => !!rectLista && todas.some((s) => s.harnesses.lista().some((h) => h.enCurso && !h.anterior));
  /** Sesiones con un tick sin terminar: si `ask` tarda más de 3 s no se apilan pedidos. */
  const enVuelo = new Set<Sesion>();
  const tickHarness = () => {
    if (closed) return;
    const ws = visibles().filter(pendiente);
    const sesiones = new Set(ws.map((w) => w.sesion));
    if (listaViva()) for (const s of todas) sesiones.add(s);
    for (const s of sesiones) {
      if (enVuelo.has(s)) continue;
      enVuelo.add(s);
      const ids = new Set(ws.filter((w) => w.sesion === s).map((w) => (w.fuente as { id: string }).id));
      void s.harnesses.refrescar()
        .then(() => Promise.all([...ids].map(async (id) => { const h = await s.harnesses.seguir(id); if (h ? !h.enCurso && !h.error : !s.harnesses.errorLista) finalesDe(s).add(id); })))
        .catch(() => {})
        .finally(() => { enVuelo.delete(s); if (!closed) draw(); });
    }
  };
  const ajustarSondeo = () => {
    const quiere = !closed && (listaViva() || visibles().some(pendiente));
    if (quiere && !sondeo) { sondeo = setInterval(tickHarness, 3000); sondeo.unref(); }
    else if (!quiere && sondeo) { clearInterval(sondeo); sondeo = undefined; }
  };
  /** Última ventana de un contenedor compartido con un turno en curso: avisa que el agente sigue en segundo plano. */
  const salirConAviso = async () => {
    if (compartido() && otrasVentanas() === 0 && todas.some((s) => s.client.status.running)
      && !(await confirm(t("El agente sigue trabajando: si salís, termina en segundo plano y después se apaga. ¿Salir?", "The agent is still working: if you quit, it finishes in the background and then shuts down. Quit?")))) return;
    exit();
  };
  const exit = (despedida?: string) => {
    if (closed) return;
    closed = true;
    apagarOBS();
    proteccion.cerrar();
    clearTimeout(cuadro);
    if (arranco) clearTimeout(arranco.timer);
    if (sondeo) clearInterval(sondeo);
    for (const s of todas) if (s.permiso) void responderPermiso(s, s.permiso, 2); // también el desplazado por un menú y los de sesiones no activas
    dropMode();
    for (const s of todas) { s.turno = undefined; s.corriendo?.abort(); } // el comando corre en su propio grupo de procesos: sin esto queda huérfano al salir
    stopBusy();
    seguirDescifrado(false);
    parar();
    // Las conexiones extra se cierran acá; la principal la suelta quien llamó (`leave()`), después de esto.
    for (const s of todas) if (s !== sesion) s.client.close();
    hideWizard();
    sigil.settle();
    try {
      pantalla.salir();
      // La pantalla alternativa se lleva lo escrito: lo que el operador tiene que leer queda en la terminal.
      if (despedida && !enVivo && !panico) io.output.write(`${despedida}\r\n`);
    }
    finally {
      release();
      options.onExit?.(enVivo || panico);
    }
  };

  /** Los ids del registro de la sesión empiezan de cero: todas las ventanas que la muestran olvidan lo que sabían de ellos. */
  const reiniciar = (s: Sesion) => {
    for (const w of ventanas) if (w.sesion === s) {
      w.cachePublica = undefined;
      w.caches = new WeakMap();
      w.estados = w.pestanas.map(nuevoEstado);
      w.seleccion = undefined;
      w.fuente = undefined;
      w.expandidas.clear();
    }
  };
  /**
   * Cambia la sesión abierta en esta misma pantalla: el daemon adjunta la otra (o una nueva) y la conversación
   * vuelve de a tramos, como si se reescribiera; después un panel cuenta qué se abrió.
   */
  const switchSession = async (which: string, s: Sesion = ses): Promise<Panel> => {
    const title = t("sesiones", "sessions");
    if (s.client.status.running || s.activeTools.size) return { title, lines: [t("Detené el turno antes de cambiar de sesión.", "Stop the turn before switching sessions.")], tone: "warn" };
    if (s.corriendo) return { title, lines: [t("Esperá a que termine el «$ comando» (o cortalo con Ctrl+C) antes de cambiar de sesión.", "Wait for the «$ command» to finish (or cut it with Ctrl+C) before switching sessions.")], tone: "warn" };
    finishBoot();
    startBusy(which === "new" ? t("abriendo una sesión nueva", "opening a new session") : t(`retomando ${which.slice(0, 8)}`, `resuming ${which.slice(0, 8)}`));
    let snap: Snapshot;
    try { snap = await s.client.attach({ session: which }); } catch (error) { stopBusy(); return { title, lines: [(error as Error).message], tone: "warn" }; }
    stopBusy();
    s.pendientes.length = 0; // la salida de la sesión anterior no viaja a la nueva
    s.contadas.clear();
    if (enVivo) for (const m of snap.messages) proteccion.aprenderMensaje(m);
    reiniciar(s);
    s.subagentes = new Subagentes(); // la conversación cambió: los sub:N de la anterior ya no valen
    s.activeTools.clear();
    for (const [id, label] of Object.entries(snap.tools)) s.activeTools.set(id, label);
    const animado = options.animate ?? (!options.io && process.env.CYBER_ANIMATIONS !== "0");
    const steps = animado ? Math.min(12, snap.messages.length) : 0;
    for (let i = 1; i <= steps; i++) {
      s.registro = Registro.desdeSnapshot(snap.messages.slice(0, Math.ceil((snap.messages.length * i) / steps)));
      draw();
      await new Promise((resolve) => setTimeout(resolve, 35));
    }
    s.registro = Registro.desdeSnapshot(snap.messages);
    if (snap.partial) s.registro.evento({ type: "text", delta: snap.partial });
    s.hasContent = snap.messages.length > 0 || !!snap.partial || snap.status.running || Object.keys(snap.tools).length > 0;
    draw();
    const short = snap.sessionId.slice(0, 8);
    const spent = snap.status.cost.replace(/^API est\. /, "").replace(/ · proyecto .*/, "");
    const lines = which === "new"
      ? [t(`Sesión nueva ${short}. Lo que escribas arranca de cero, sin alcance; la memoria del proyecto sigue.`, `New session ${short}. What you write starts fresh, with no scope; project memory stays.`), ...(snap.avisos ?? [])]
      : [t(`Sesión ${short} retomada: ${snap.messages.length} mensajes · ${spent}${snap.status.title ? ` · ${snap.status.title.slice(0, 60)}` : ""}`, `Session ${short} resumed: ${snap.messages.length} messages · ${spent}${snap.status.title ? ` · ${snap.status.title.slice(0, 60)}` : ""}`), ...(snap.status.interrupted ? [t("Quedó un turno a medias: /continuar lo retoma.", "A turn was left unfinished: /continuar resumes it.")] : []), ...(snap.avisos ?? [])];
    return { title, lines, tone: "ok" };
  };

  const clearDisplay = (s: Sesion = ses) => {
    finishBoot();
    if (s.client.status.running || s.activeTools.size) {
      notice = "Detené el turno antes de limpiar la pantalla.";
      return;
    }
    s.registro = new Registro();
    s.contadas.clear();
    reiniciar(s); // los ids del registro nuevo empiezan de cero
    desmarcar();
    s.hasContent = false;
    notice = "";
  };

  /** Cambia la forma: las ventanas nuevas muestran la sesión de la activa con «Chat»; las que sobran se descartan. */
  const cambiarForma = (nueva: Forma) => {
    const n = cantidad(nueva);
    const base = vent.sesion;
    forma = nueva;
    ventanas.length = Math.min(ventanas.length, n);
    while (ventanas.length < n) { const w = nuevaVentana(base, [chat()]); ventanas.push(w); pedir(0, w); }
    fijar(Math.min(actual, n - 1));
    desmarcar();
    guardar();
    draw();
  };
  const cambiarVentana = (paso: number) => {
    if (ventanas.length < 2) return;
    fijar((actual + paso + ventanas.length) % ventanas.length);
    desmarcar();
  };

  /** Pide al daemon las sesiones del proyecto para la lista; si falla, queda lo que había (las abiertas siempre se ven). */
  const cargarLista = async () => {
    for (const s of todas) void s.harnesses.refrescar().then(() => { if (!closed) draw(); }, () => {});
    try { lista.sesiones = decodeRows(await sesion.client.ask("sesiones", { action: "list" })); } catch { /* sin daemon no hay nada que listar */ }
    if (!closed) draw();
  };
  /**
   * Abre una sesión del proyecto (o una nueva) en la ventana activa, con sus pestañas actuales. Una sesión ya abierta se
   * reusa; si no, se abre una conexión más al daemon, que sigue viva hasta salir aunque ninguna ventana la muestre.
   */
  const abrirSesion = async (id: string): Promise<Panel> => {
    const title = t("sesiones", "sessions");
    const w = vent;
    let s = id === "new" ? undefined : buscar(id);
    if (!s) {
      finishBoot();
      startBusy(id === "new" ? t("abriendo una sesión nueva", "opening a new session") : t(`abriendo ${id.slice(0, 8)}`, `opening ${id.slice(0, 8)}`));
      let c: Client | undefined;
      // Cada conexión extra registra sus manejadores de señales: se sube el tope para que Node no avise de más.
      process.setMaxListeners(process.getMaxListeners() + 1);
      try {
        c = await connectDaemon(options.cwd ?? options.project ?? process.cwd(), { spawn: false });
        const snap = await c.attach({ session: id });
        if (enVivo) for (const m of snap.messages) proteccion.aprenderMensaje(m);
        s = new Sesion(c, snap, options.harnesses);
      } catch (error) { c?.close(); process.setMaxListeners(Math.max(0, process.getMaxListeners() - 1)); stopBusy(); return { title, lines: [(error as Error).message], tone: "warn" }; }
      stopBusy();
      const ya = buscar(idDe(s));
      if (closed || ya) { c.close(); process.setMaxListeners(Math.max(0, process.getMaxListeners() - 1)); if (closed) return { title, lines: [], tone: "ok" }; s = ya!; } else {
        todas.push(s);
        enlazar(s);
        void reaplicar(s);
      }
    }
    if (closed || !ventanas.includes(w)) return { title, lines: [t(`Sesión ${idDe(s).slice(0, 8)} abierta.`, `Session ${idDe(s).slice(0, 8)} opened.`)], tone: "ok" };
    Object.assign(w, { sesion: s, fuente: undefined, estados: w.pestanas.map(nuevoEstado), caches: new WeakMap(), datos: new Map(), sinVer: new Set(), seleccion: undefined, expandidas: new Set() });
    w.cachePublica = undefined;
    w.pedidos.clear();
    pedir(w.activa, w);
    if (vent === w) fijar(ventanas.indexOf(w)); // si pasaste a otra ventana mientras conectaba, te quedás en ella
    desmarcar();
    draw();
    return { title, lines: [t(`Sesión ${idDe(s).slice(0, 8)} abierta en esta ventana.`, `Session ${idDe(s).slice(0, 8)} opened in this window.`)], tone: "ok" };
  };
  const elegirFila = async (f: FilaLista) => {
    if (f.tipo === "pestana") { if (ventanas.includes(f.w)) { fijar(ventanas.indexOf(f.w)); irA(f.i); } return; }
    if (f.tipo === "encabezado") return;
    if (f.tipo === "sub" || f.tipo === "harness") {
      if (f.s !== vent.sesion) await abrirSesion(idDe(f.s));
      const w = vent; // abrirSesion puede haber esperado: se usa la ventana actual de ahora
      if (!closed && ventanas.includes(w) && w.sesion === f.s) { if (f.tipo === "harness") finalesDe(f.s).delete(f.id); w.seleccion = undefined; w.fuente = f.tipo === "sub" ? { tipo: "sub", worker: f.worker } : { tipo: "harness", id: f.id }; }
      draw();
      if (f.tipo === "harness") tickHarness();
      return;
    }
    const panel = await abrirSesion(f.tipo === "nueva" ? "new" : f.id);
    if (panel.tone === "warn") notice = panel.lines[0] ?? "";
    void cargarLista();
    draw();
  };
  const enfocarLista = () => { lista.enfocada = true; void cargarLista(); };
  /** F2: la muestra y la enfoca; con ella a la vista la enfoca; con ella enfocada la esconde. */
  const alternarLista = () => {
    if (!listaCabe) { notice = t("La lista no entra: agrandá la terminal", "The list does not fit: enlarge the terminal"); return; }
    if (!conLista) { conLista = true; enfocarLista(); }
    else if (!lista.enfocada) enfocarLista();
    else { lista.enfocada = false; conLista = false; }
    guardar();
  };
  const teclaLista = (key: Key) => {
    const filas = filasLista();
    if (key.name === "escape") lista.enfocada = false;
    else if (key.name === "up" || key.name === "down") {
      const paso = key.name === "up" ? filas.length - 1 : 1;
      lista.at = (lista.at + paso) % filas.length;
      if (filas[lista.at]!.tipo === "encabezado") lista.at = (lista.at + paso) % filas.length;
    }
    else if (key.name === "home") lista.at = 0;
    else if (key.name === "end") lista.at = filas.length - 1;
    else if (key.name === "enter") { const f = filas[lista.at]; lista.enfocada = false; if (f) void elegirFila(f); }
  };

  /** Los pares de ventanas contiguas por el eje: la de la izquierda/arriba (`a`) y la otra (`b`). */
  const pares = (eje: "x" | "y") => {
    const out: Array<{ a: Rect; b: Rect }> = [];
    for (const a of rects) for (const b of rects) {
      if (!a || !b) continue;
      if (eje === "x" ? a.x + a.ancho === b.x && a.y < b.y + b.alto && b.y < a.y + a.alto : a.y + a.alto === b.y && a.x < b.x + b.ancho && b.x < a.x + a.ancho) out.push({ a, b });
    }
    return out;
  };
  const par = (eje: "x" | "y") => pares(eje)[0];
  const fijarDivisor = (eje: "x" | "y", celdas: number, total: number) => {
    const v = celdas / total;
    if (Number.isFinite(v)) divisores[eje] = Math.min(0.89, Math.max(0.11, v));
  };
  const ancho = (delta: number) => {
    const p = par("x");
    if (!p) return;
    fijarDivisor("x", p.a.ancho + delta, p.a.ancho + p.b.ancho);
    guardar();
    draw();
  };
  /** Pasa la pestaña activa a la ventana anterior/siguiente (circular); el origen sin pestañas recibe «Chat». */
  const moverPestana = (sentido: 1 | -1) => {
    if (ventanas.length < 2) return;
    const origen = vent, destino = ventanas[(actual + sentido + ventanas.length) % ventanas.length]!;
    const p = origen.pestanas[origen.activa]!;
    origen.fuente = undefined;
    destino.fuente = undefined;
    const resto = origen.pestanas.filter((x) => x !== p);
    aplicarPestanas(resto.length ? resto : [chat()], origen);
    aplicarPestanas([...destino.pestanas, p], destino);
    destino.activa = destino.pestanas.length - 1;
    pedir(destino.activa, destino);
    fijar(ventanas.indexOf(destino));
    desmarcar();
    draw();
  };

  /** Lo que un comando puede hacer con la interfaz. */
  const crearCio = (s: Sesion): CommandIO => ({
    ask: async (op, payload = {}) => {
      const lines = await s.client.ask(op, payload);
      // Un ajuste cambiado con éxito (por su comando o desde /config) queda recordado para este proyecto.
      const value = (payload as { value?: unknown }).value;
      if ((RECORDADOS as readonly string[]).includes(op) && typeof value === "string" && value) {
        const aviso = guardarAjuste(op as Recordado, value);
        if (aviso) { notice = aviso; draw(); }
      }
      return lines;
    },
    view: (name, arg = "") => s.client.view(name, arg),
    pick,
    input,
    confirm,
    status: () => ({ model: s.client.status.model, profile: s.client.status.profile, running: s.client.status.running, session: s.client.status.session, title: s.client.status.title }),
    tituloSesion: (titulo) => enVivo ? "Sesión reservada" : titulo,
    streamer: (arg) => {
      if (!arg) {
        enVivo = !enVivo;
        options.alCambiarStreamer?.(enVivo);
        desmarcar();
        if (enVivo) {
          for (const s of todas) for (const e of s.registro.entradas()) {
            if (e.tipo === "mensajes" || e.tipo === "resultados") proteccion.aprender(e.texto ?? "");
            if (e.tipo === "texto" && e.completo) proteccion.aprender(e.markdown);
            if (e.tipo === "acciones" && e.argumentos) proteccion.aprender(JSON.stringify(e.argumentos));
          }
          inicioVivo = Date.now();
          iniciarOBS();
        } else apagarOBS();
        for (const w of ventanas) w.cachePublica = undefined;
      } else if (arg === "hosts siempre" || arg === "hosts privados") proteccion.soloPrivados = arg === "hosts privados";
      else if (arg === "uso mostrar" || arg === "uso tapar") proteccion.mostrarUso = arg === "uso mostrar";
      else return { title: "streamer", lines: ["Usá /streamer, /streamer hosts siempre|privados o /streamer uso mostrar|tapar."] };
      return { title: "streamer", lines: [!enVivo && !arg ? "Modo apagado. Volvés a ver la sesión completa." : `Hosts ${proteccion.soloPrivados ? "privados" : "siempre tapados"} · consumo ${proteccion.mostrarUso ? "visible" : "tapado"}`] };
    },
    clear: () => clearDisplay(s),
    exit: () => void salirConAviso(),
    resume: () => ses.client.resume(), // la sesión de la ventana activa: `switchSession` pudo haber abierto otra
    notice: (view) => { panel(view, s); draw(); },
    send: (text) => { say([t("encargo enviado al agente", "task sent to the agent")], "dim", s); enviar(text, s); },
    interrupt: (text) => mandarYa(text, s),
    // Con una ventana y una sola sesión se reemplaza el attach como siempre; si no, se abre en la ventana activa.
    switchSession: (id) => (ventanas.length === 1 && todas.length === 1 ? switchSession(id, s) : abrirSesion(id)),
    inicio: () => runInicio(),
    // La ventana activa se resuelve al llamar: un comando largo (/config) puede haber cambiado la forma en el medio.
    pestanas: () => vent.pestanas,
    setPestanas: (lista) => aplicarPestanas(lista),
    moverPestana,
    ancho,
    forma: () => forma,
    setForma: cambiarForma,
    setMouse: (valor) => pantalla.mouse(valor),
    keys: () => {
      const tambien = (x: string) => dim(`(${t("también", "also")}: ${x})`);
      const sec = (titulo: string, ...ls: string[]) => [bold(titulo), ...ls.map((l) => `  ${l}`)];
      return [
        ...sec(t("Editor", "Editor"),
          `${t("Enter envía · Ctrl+J nueva línea", "Enter sends · Ctrl+J new line")} ${tambien("Alt+Enter")}`,
          t("Tab completa · ↑↓ historial o lista de /", "Tab completes · ↑↓ history or the / list"),
          t("«$ comando» lo corre en la terminal; el agente ve la salida en tu próximo mensaje", "«$ command» runs it in the terminal; the agent sees the output on your next message"),
          t("Durante un turno lo que escribís espera en cola (/cola); con «!» adelante le llega al modelo sin cortar el turno", "During a turn what you type waits in the queue (/cola); with «!» in front it reaches the model without stopping the turn"),
          t("Ctrl+Y (o /ya texto) corta el turno y manda ya tu mensaje, después de lo que esperaba en cola", "Ctrl+Y (or /ya text) stops the turn and sends your message now, after what was queued")),
        "",
        ...sec(t("Turno y salida", "Turn and exit"),
          `${t("Esc detiene el turno · Ctrl+C detiene; dos veces seguidas sale", "Esc stops the turn · Ctrl+C stops; twice in a row exits")} ${tambien(t("Ctrl+D con el editor vacío", "Ctrl+D with an empty editor"))}`,
          "F8 cubre la pantalla y OBS. Volvé a apretarla para seguir.",
          t("Ctrl+L limpia la pantalla; la sesión se conserva", "Ctrl+L clears the screen; the session is kept"),
          t("Al salir, un turno en curso sigue en segundo plano: cyber -c vuelve a él", "On exit, a running turn keeps going in the background: cyber -c returns to it")),
        "",
        ...sec(t("Pestañas", "Tabs"),
          `${t("Ctrl+N / Ctrl+P cambian de pestaña", "Ctrl+N / Ctrl+P switch tabs")} ${tambien("Alt+1…9, Alt+←→, Ctrl+PgUp/PgDn")}`,
          `${t("PgUp/PgDn recorren · Ctrl+Fin vuelve al final", "PgUp/PgDn scroll · Ctrl+End jumps to the end")} ${tambien(t("la rueda del mouse", "the mouse wheel"))}`,
          `${t("Alt+↑↓ elige una acción con el detalle Completo", "Alt+↑↓ picks an action with Full detail")} ${tambien("Tab/Shift+Tab")}`,
          t("/diseño edita las pestañas", "/diseño edits the tabs")),
        "",
        ...sec(t("Ventanas", "Windows"),
          t("F6 / Shift+F6 cambian de ventana · F2 muestra la lista de sesiones", "F6 / Shift+F6 switch window · F2 shows the session list"),
          `${t("Ctrl+Shift+←→ mueve la pestaña a otra ventana", "Ctrl+Shift+←→ moves the tab to another window")} ${tambien("/diseño")}`,
          `${t("Arrastrar el borde cambia el ancho", "Dragging the edge resizes")} ${tambien(t("/diseño, o Ctrl+Alt+←→ si tu escritorio no lo usa", "/diseño, or Ctrl+Alt+←→ if your desktop doesn't use it"))}`,
          ...(mouseGuardado() ? [t("Arrastrar con el mouse copia · En tmux, copiar con el mouse necesita `set -g allow-passthrough on`", "Drag with the mouse to copy · In tmux, mouse copy needs `set -g allow-passthrough on`")] : [])),
        "",
        ...sec(t("Menús", "Menus"), t("↑↓ o la primera letra mueven · un número elige · Enter acepta · Esc cancela", "↑↓ or the first letter move · a number picks · Enter accepts · Esc cancels")),
      ];
    },
  });

  const command = async (line: string) => {
    const [name = "", ...rest] = line.slice(1).split(/\s+/);
    const arg = rest.join(" ").trim();
    const s = ses;
    const io = crearCio(s);
    const spec = findCommand(name);
    if (!spec) {
      panel({ title: `/${name}`, lines: [t("Comando desconocido. Probá /ayuda.", "Unknown command. Try /help.")], tone: "warn" }, s);
      return draw();
    }
    startBusy(`/${spec.name}${arg ? ` ${arg}` : ""}`);
    try {
      const view = await spec.run(io, arg);
      stopBusy();
      if (view) panel(view, s);
    } catch (error) {
      stopBusy();
      panel({ title: `/${spec.name}`, lines: [(error as Error).message], tone: "warn" }, s);
    }
    draw();
  };

  /**
   * Sin clave: ofrece entrar por el sitio (código + llave) o pegar una clave; si queda vinculado, envía el
   * mensaje pendiente; si no, el próximo envío lo vuelve a ofrecer.
   */
  const askKey = async (text?: string) => {
    const s = ses, w = vent;
    let saved = false;
    const choice = await pick(t("Tu cuenta de orobas", "Your orobas account"), [
      { label: t("entrar por el sitio", "sign in on the site"), hint: t("te doy un código, lo aprobás con tu llave y la clave llega sola", "I give you a code, you approve it with your key and the key arrives on its own") },
      { label: t("pegar una clave", "paste a key"), hint: t("de cyber.elevateai.ar/cuenta", "from cyber.elevateai.ar/cuenta") },
    ], { footer: t("los modelos de la suscripción piden cuenta; los locales y tus claves propias, no", "subscription models need an account; local models and your own keys do not") });
    if (choice === 0) {
      startBusy(t("vinculando con el sitio", "linking with the site"));
      try { panel({ title: "orobas", lines: await deviceLink(menuIO(crearCio(s))), tone: "ok" }, s); saved = true; }
      catch (error) { panel({ title: "orobas", lines: [(error as Error).message], tone: "warn" }, s); }
      finally { stopBusy(); }
    } else if (choice === 1) {
      const key = await askHidden(t(`Pegá tu clave de ${link("https://cyber.elevateai.ar/cuenta")}`, `Paste your key from ${link("https://cyber.elevateai.ar/cuenta")}`));
      if (key) {
        try { say(await s.client.ask("account", { service: "orobas", action: "save", value: key }), "normal", s); saved = true; }
        catch (error) { say([(error as Error).message], "warn", s); }
      }
    }
    if (saved && text && !closed) { user(text, s); enviar(text, s); }
    else if (text) editor.set(text);
    draw();
  };

  const esPing = (text: string) => /c[oó]mo (vamos|va|venimos)|estado\??$/i.test(text);
  /** Único camino de envío: anexa lo que corrió el operador, salvo al «¿cómo vamos?» (el daemon solo lo reconoce sin bloque). */
  const enviar = (text: string, s: Sesion = ses) => {
    if (esPing(text)) return void s.client.send(text);
    s.client.send(text + bloqueTerminal(s.pendientes));
    s.pendientes.length = 0;
  };
  /** El mismo texto ya espera en cola (misma clave que usa el daemon): no se reenvía. */
  const yaEnCola = (text: string, s: Sesion = ses) => { const key = queueKey(text); return !!s.client.status.queue?.some((item) => item.key === key); };
  /**
   * «Mandalo ya» (Ctrl+Y o /ya): corta el turno en curso de forma ordenada y manda el texto, después de lo
   * que ya esperaba en cola; sin texto, manda la cola. Sin turno ni cola es un envío común.
   */
  const mandarYa = (raw: string, s: Sesion = ses) => {
    const text = raw.trim();
    if (!s.client.status.running && !s.client.status.queue?.length) {
      if (!text) return say([t("no hay turno en curso ni nada en cola", "no turn running and nothing queued")], "dim", s);
      if (s.client.status.needsKey) return void askKey(text);
      user(text, s);
      return enviar(text, s);
    }
    if (text && !yaEnCola(text, s)) user(text, s);
    say([s.client.status.running ? t("corto el turno: tu mensaje sale ya", "stopping the turn: your message goes out now") : t("mando ya lo que estaba en cola", "sending what was queued now")], "dim", s);
    s.client.interrupt(text ? text + bloqueTerminal(s.pendientes) : "");
    if (text) s.pendientes.length = 0;
  };
  const dolar = async (comando: string) => {
    const s = ses;
    if (s.corriendo) return say([t("ya hay un comando corriendo", "a command is already running")], "dim", s);
    const ctl = (s.corriendo = new AbortController());
    const inicio = Date.now();
    let vivo = "";
    let timer: ReturnType<typeof setTimeout> | undefined;
    const entrada = s.registro.aviso("", "normal") as Extract<Entrada, { tipo: "avisos" }>;
    novedad([entrada], s);
    try {
      const corrida = await correrComando(comando, {
        cwd: options.project ?? process.cwd(),
        signal: ctl.signal,
        onOutput: (chunk) => {
          // Solo la cola de lo que sale (el resto se perdería de vista igual) y un redibujo cada 50 ms como mucho.
          vivo = (vivo + stripAnsi(chunk).replace(/\r\n?/g, "\n")).slice(-4000);
          entrada.texto = vivo.length >= 4000 ? `…\n${vivo}` : vivo;
          timer ??= setTimeout(() => { timer = undefined; if (!closed) draw(); }, 50);
        },
      });
      s.pendientes.push(corrida);
      const seg = ((Date.now() - inicio) / 1000).toFixed(1);
      const fin = corrida.cortado ? t("cortado", "cut off") : t(`salió con ${corrida.codigo}`, `exited with ${corrida.codigo}`);
      say([`${fin} · ${seg} s · ${t("el agente la ve en tu próximo mensaje", "the agent sees it on your next message")}`], "dim", s);
    } finally { s.corriendo = undefined; clearTimeout(timer); }
    if (!closed) draw();
  };

  const submit = (raw: string) => {
    const text = raw.trim();
    if (!text) return;
    if (enVivo) proteccion.aprender(text);
    finishBoot();
    editor.remember(text);
    editor.set("");
    const comando = comandoDolar(text);
    if (comando) { user(text); return void dolar(comando); }
    // Con un permiso abierto, Enter sin texto no aplica; un texto se encola igual, pero avisamos.
    if (text.startsWith("/")) return void command(text);
    if (ses.client.status.needsKey) return void askKey(text);
    if (mode?.kind === "permiso") say(["hay un permiso esperando: el mensaje queda en cola"], "dim");
    // Durante un turno el mensaje espera a que termine (salvo «!…», que interrumpe al modelo, y «¿cómo vamos?»).
    const encola = ses.client.status.running && !text.startsWith("!") && !esPing(text);
    // Reenviar lo que ya espera no lo encola dos veces: se dice y no se repite en la conversación.
    if (encola && yaEnCola(text)) return say([t("ya está en cola: no lo mando de nuevo · Ctrl+Y lo manda ya", "already queued: not sent again · Ctrl+Y sends it now")], "dim");
    user(text);
    if (encola) say([t("en cola · sale cuando termine el turno · Ctrl+Y lo manda ya", "queued · goes out when the turn ends · Ctrl+Y sends it now")], "dim");
    enviar(text);
  };

  /** Fila de pantalla a índice en `todas`; fuera del área se recorta al borde (arriba: primera visible, abajo: última). */
  const aIndice = (f: number) => Math.max(0, Math.min(vent.ultimo.inicio + Math.max(0, Math.min(f - vent.ultimo.arriba, vent.ultimo.alto - 1)), vent.ultimo.todas.length - 1));
  const copiarMarcado = (enteras = false) => {
    const texto = marcado ? textoSeleccionado(vent.ultimo.todas, marcado.a, marcado.b, enteras) : "";
    if (!texto) return desmarcar();
    const r = copiar(texto, (s) => io.output.write(s));
    notice = r.aviso;
    copiado = r.ok ? r.aviso : "";
  };
  /** Divisor que se está arrastrando: `base` son las celdas de `a` al agarrarlo, `desde` dónde cayó el clic. */
  let arrastre: { eje: "x" | "y"; base: number; total: number; desde: number } | undefined;
  const agarrar = (c: number, f: number) => {
    for (const { a, b } of pares("x")) if (f >= Math.max(a.y, b.y) && f < Math.min(a.y + a.alto, b.y + b.alto) && (c === b.x || c === b.x - 1)) return { eje: "x" as const, base: a.ancho, total: a.ancho + b.ancho, desde: c };
    for (const { a, b } of pares("y")) if (c >= Math.max(a.x, b.x) && c < Math.min(a.x + a.ancho, b.x + b.ancho) && (f === b.y || f === b.y - 1)) return { eje: "y" as const, base: a.alto, total: a.alto + b.alto, desde: f };
    return undefined;
  };
  const mouse = (key: Key) => {
    if (arrastre) {
      if (key.name === "mouseDrag") { fijarDivisor(arrastre.eje, arrastre.base + ((arrastre.eje === "x" ? key.col : key.fila) ?? 0) - arrastre.desde, arrastre.total); draw(); }
      else if (key.name === "mouseUp") { arrastre = undefined; guardar(); }
      return;
    }
    if (key.name === "mouseDown" && rectLista && (key.col ?? 0) < rectLista.x + rectLista.ancho) {
      const filas = filasLista();
      const f = filas[lista.primera + (key.fila ?? 0) - rectLista.y - 1];
      if (f && (key.fila ?? 0) > rectLista.y && (key.fila ?? 0) < rectLista.y + rectLista.alto - 1) { desmarcar(); lista.at = filas.indexOf(f); void elegirFila(f); }
      return;
    }
    if (key.name === "mouseDown" && rects.length) {
      const g = agarrar(key.col ?? 0, key.fila ?? 0);
      if (g) { desmarcar(); arrastre = g; return; }
      // Un clic en otra ventana sólo la activa; el siguiente ya selecciona.
      const i = rects.findIndex((r) => r && (key.col ?? 0) >= r.x && (key.col ?? 0) < r.x + r.ancho && (key.fila ?? 0) >= r.y && (key.fila ?? 0) < r.y + r.alto);
      if (i >= 0 && i !== actual) { desmarcar(); fijar(i); return; }
    }
    // Con varias ventanas, las coordenadas se miden desde adentro del recuadro de la activa y no salen de él.
    const rect = rects[actual];
    const f = (key.fila ?? 0) - (rect ? rect.y + 1 : 0), col = Math.min(Math.max(0, (key.col ?? 0) - (rect ? rect.x + 1 : 0)), rect ? rect.ancho - 2 : Infinity);
    if (key.name === "mouseDown") {
      parar();
      marcado = undefined;
      if (!vent.ultimo.todas.length || f < vent.ultimo.arriba || f >= vent.ultimo.arriba + vent.ultimo.alto || vent.ultimo.inicio + f - vent.ultimo.arriba >= vent.ultimo.todas.length) return;
      const ahora = Date.now();
      clics = { n: clics.fila === f && clics.col === col && ahora - clics.t < 400 ? Math.min(3, clics.n + 1) : 1, t: ahora, fila: f, col };
      const fila = aIndice(f);
      const base = { ancho: anchoUtil, arrastro: false };
      if (clics.n === 1) marcado = { a: { fila, col }, b: { fila, col }, fijo: false, ...base };
      else if (clics.n === 2) {
        const p = palabraEn(vent.ultimo.todas, fila, col);
        if (p) marcado = { a: p[0], b: p[1], fijo: true, ...base };
      } else {
        const [i, z] = lineaLogica(vent.ultimo.todas, fila);
        marcado = { a: { fila: i, col: 0 }, b: { fila: z, col: anchoUtil }, fijo: true, ...base };
      }
      if (marcado?.fijo) copiarMarcado(clics.n === 3);
    } else if (key.name === "mouseDrag" && marcado && !marcado.fijo) {
      marcado.arrastro = true;
      // La terminal no informa filas fuera de la pantalla: el borde del área ya cuenta como «afuera».
      const fuera = f <= vent.ultimo.arriba ? 1 : f >= vent.ultimo.arriba + vent.ultimo.alto - 1 ? -1 : 0;
      marcado.b = { fila: aIndice(f), col };
      sentido = fuera;
      if (!fuera) parar();
      else if (!autoscroll) autoscroll = setInterval(() => {
        if (!marcado || mode) return parar();
        scrollar(sentido);
        draw();
        marcado.b = { fila: aIndice(sentido > 0 ? vent.ultimo.arriba : vent.ultimo.arriba + vent.ultimo.alto - 1), col: marcado.b.col };
        draw();
      }, 50);
    } else if (key.name === "mouseUp" && marcado && !marcado.fijo) {
      parar();
      marcado.fijo = true;
      if (!marcado.arrastro && marcado.a.fila === marcado.b.fila && marcado.a.col === marcado.b.col) marcado = undefined;
      else copiarMarcado();
    }
  };

  const onKey = (key: Key) => {
    if (key.name === "f8") {
      panico = !panico;
      options.alCambiarStreamer?.(enVivo || panico);
      if (!panico && desconectado) return exit();
      if (panico) pantalla.limpiar();
      pintar();
      actualizarOBS();
      return;
    }
    if (panico) return;
    if (enVivo && key.fila !== undefined) key = { ...key, fila: key.fila - 1 };
    // Cualquier entrada termina el arranque; la tecla se sigue procesando normalmente.
    finishBoot();
    if (key.name !== "ctrl+c") notice = "";
    if (key.name === "mouseDown" || key.name === "mouseDrag" || key.name === "mouseUp") return mode ? undefined : mouse(key);
    if (marcado && key.name !== "wheelUp" && key.name !== "wheelDown") desmarcar();
    if (mode) return modeKey(key);
    if (key.name === "f6" || key.name === "shift+f6") return cambiarVentana(key.name === "f6" ? 1 : -1);
    if (key.name === "ctrl+shift+left" || key.name === "ctrl+shift+right") return moverPestana(key.name === "ctrl+shift+right" ? 1 : -1);
    if (key.name === "ctrl+alt+left" || key.name === "ctrl+alt+right") return ancho(key.name === "ctrl+alt+right" ? 2 : -2);
    if (key.name === "f2") return alternarLista();
    // Con la lista enfocada las teclas son suyas (menos las que salen o desplazan).
    if (lista.enfocada && !["ctrl+c", "ctrl+d", "wheelUp", "wheelDown"].includes(key.name)) return teclaLista(key);
    if (vent.seleccion !== undefined) {
      if (key.name === "text" || key.name === "paste") vent.seleccion = undefined; // el texto sigue al editor
      else if (key.name === "escape") { vent.seleccion = undefined; return; }
      else if (key.name === "enter") {
        if (editor.text) vent.seleccion = undefined; // con texto, Enter sigue de largo y envía: la selección no se lo traga
        else {
          const r = ses.registro.entradas().find((e) => e.tipo === "resultados" && e.llamada === (ses.registro.entradas().find((a) => a.id === vent.seleccion) as { llamada?: string } | undefined)?.llamada);
          if (r && !vent.expandidas.delete(r.id)) vent.expandidas.add(r.id);
          return;
        }
      }
    }
    const vista = vent.pestanas[vent.activa]!;
    // Con una fuente a la vista las teclas de la pestaña oculta no hacen nada: ↑↓ recorren la fuente.
    if (vent.fuente && !editor.text && (key.name === "up" || key.name === "down")) { scrollar(key.name === "up" ? 1 : -1); return; }
    if (vista.tipo === "vista" && !vent.fuente && !editor.text && ["up", "down", "enter", "escape"].includes(key.name)) {
      const d = vent.datos.get(vent.activa);
      if (key.name === "escape") {
        if (d?.detalle) { d.detalle = undefined; d.ver = true; }
        else if (ses.client.status.running) ses.client.abort();
      } else if (d && !d.detalle && d.filas.length) {
        if (key.name === "enter") abrirDetalle(vent.activa);
        else { d.at = Math.max(0, Math.min(d.filas.length - 1, d.at + (key.name === "up" ? -1 : 1))); d.ver = true; }
      } else if (key.name === "up" || key.name === "down") scrollar(key.name === "up" ? 1 : -1); // sin filas que elegir, ↑↓ recorren de a una línea
      return;
    }
    const alt = /^alt\+([1-9])$/.exec(key.name);
    const enAcciones = !vent.fuente && vista.tipo === "conversacion" && vista.detalle === "completo" && vista.contenido.includes("resultados");
    // Sin Alt (Terminal.app, Windows Terminal): Tab/Shift+Tab eligen acción cuando no hay lista de «/» abierta.
    const sinLista = enAcciones && !completions().length;
    const sube = key.name === "alt+up" || (sinLista && key.name === "shiftTab");
    const baja = key.name === "alt+down" || (sinLista && key.name === "tab");
    if ((key.name === "alt+up" || key.name === "alt+down") && !enAcciones) editor.handle(key);
    else if (sube || baja) {
      const p = vista as Extract<Pestana, { tipo: "conversacion" }>;
      const visibles = ses.registro.entradas().filter((e) => e.tipo === "acciones" && muestra(p, e));
      if (!visibles.length) return;
      const i = visibles.findIndex((e) => e.id === vent.seleccion);
      const nuevo = visibles[i < 0 ? visibles.length - 1 : Math.max(0, Math.min(visibles.length - 1, i + (sube ? -1 : 1)))]!;
      vent.seleccion = nuevo.id;
      // Scrollea lo justo para que la acción quede dentro de la ventana.
      const linea = vent.ultimo.desde.get(nuevo.id);
      if (linea !== undefined) {
        const scroll = estadoDe(vent).scroll;
        if (linea < vent.ultimo.total - scroll - altoContenido) estadoDe(vent).scroll = Math.max(0, vent.ultimo.total - linea - altoContenido);
        else if (linea >= vent.ultimo.total - scroll) estadoDe(vent).scroll = Math.max(0, vent.ultimo.total - linea - 1);
      }
      return;
    }
    if (alt) irA(Number(alt[1]) - 1);
    else if (key.name === "ctrl+pageUp" || key.name === "ctrl+pageDown" || key.name === "ctrl+p" || key.name === "ctrl+n") irA((vent.activa + (key.name === "ctrl+pageUp" || key.name === "ctrl+p" ? -1 : 1) + vent.pestanas.length) % vent.pestanas.length);
    else if ((key.name === "alt+left" || key.name === "alt+right") && vent.pestanas.length === 1) editor.handle({ ...key, name: key.name === "alt+left" ? "wordLeft" : "wordRight" });
    else if (key.name === "alt+left" || key.name === "alt+right") irA((vent.activa + (key.name === "alt+left" ? -1 : 1) + vent.pestanas.length) % vent.pestanas.length);
    else if (key.name === "pageUp" || key.name === "pageDown") scrollar((key.name === "pageUp" ? 1 : -1) * Math.max(1, altoContenido - 2));
    else if (key.name === "wheelUp" || key.name === "wheelDown") {
      // La rueda recorre la ventana que está bajo el puntero, sin cambiar la activa.
      const bajo = rects.findIndex((r) => r && key.col !== undefined && key.fila !== undefined && key.col >= r.x && key.col < r.x + r.ancho && key.fila >= r.y && key.fila < r.y + r.alto);
      scrollar(key.name === "wheelUp" ? 3 : -3, bajo >= 0 ? ventanas[bajo]! : vent);
    }
    else if (key.name === "ctrl+home") scrollar(Number.MAX_SAFE_INTEGER / 2);
    else if (key.name === "ctrl+end") estadoDe(vent).scroll = 0;
    else if (key.name === "ctrl+l") clearDisplay();
    else if (key.name === "escape") {
      if (ses.client.status.running) ses.client.abort();
    } else if (key.name === "ctrl+y" || key.name === "ctrl+enter") {
      // Un comando («/…» o «$ …») no corta nada: sale como con Enter.
      const text = editor.text.trim();
      if (text.startsWith("/") || comandoDolar(text) || ses.client.status.needsKey) return submit(editor.text);
      finishBoot();
      if (text) { editor.remember(text); editor.set(""); }
      mandarYa(text);
    } else if (key.name === "ctrl+c") {
      if (ses.corriendo) ses.corriendo.abort();
      else if (ses.client.status.running) ses.client.abort();
      else if (editor.text) editor.set("");
      else if (Date.now() - lastCtrlC < 1500) return void salirConAviso();
      else {
        lastCtrlC = Date.now();
        notice = "Ctrl+C otra vez para salir";
      }
    } else if (key.name === "ctrl+d") {
      if (!editor.text) return void salirConAviso();
    } else if ((key.name === "up" || key.name === "down") && completions().length) {
      const count = completions().length;
      selected = (selected + (key.name === "up" ? count - 1 : 1)) % count;
    } else if (key.name === "enter") {
      const pick = completions()[selected];
      submit(pick ? `/${pick.word}` : editor.text);
    } else if (key.name === "tab") {
      const pick = completions()[selected];
      if (pick) editor.set(`/${pick.word} `);
    } else {
      editor.handle(key);
      selected = 0;
    }
  };

  /** Engancha una sesión: sus eventos se resuelven con ella, no con la de la ventana activa. */
  const enlazar = (s: Sesion) => {
    s.alTraer = agendar;
    s.on((event, nuevas, resuelto, nuevoSub) => {
      if (closed) return;
      if (enVivo && event.type === "message") proteccion.aprenderMensaje(event.message);
      if (nuevoSub && nuevoSub.estado === "trabajando") {
        if (arranco) clearTimeout(arranco.timer);
        arranco = { worker: nuevoSub.worker, de: s === ses ? "" : s.nombre(), timer: setTimeout(() => { arranco = undefined; agendar(); }, 5000) };
      }
      if (event.type === "tool_end" && event.name === "harness_run" && !event.isError && typeof event.details.id === "string") {
        void s.harnesses.refrescar().then(() => { if (!closed) draw(); }, () => {});
        if (arranco) clearTimeout(arranco.timer);
        arranco = { worker: `#${event.details.id} ${String(event.details.harness ?? "")}`.trim(), de: s === ses ? "" : s.nombre(), timer: setTimeout(() => { arranco = undefined; agendar(); }, 5000) };
      }
      // El daemon ya resolvió el permiso: la caja abierta (si es de esta sesión) se cierra sin responder.
      if (resuelto && mode?.kind === "permiso" && mode.s === s) mode = null;
      if (event.type !== "status") finishBoot();
      else seguirTurno(s);
      if (event.type === "notice") novedad(nuevas, s);
      else if (event.type === "confirm") {
        // Un pedido de la sesión que mirás interrumpe lo que haya abierto: el turno está frenado esperándolo.
        // Uno de otra sesión queda en `s.permiso` (aviso y ⚠) hasta que pases a su ventana.
        if (s === ses) { dropMode(); abrirPermiso(s); }
      } else {
        if (event.type === "tool_end" || event.type === "idle") refrescarVistas(s);
        novedad(nuevas, s);
        if (event.type === "disconnected" && panico) { desconectado = true; return; }
        if (event.type === "disconnected") return exit(avisoLinea(conSimboloAviso(t("Se perdió la conexión con el daemon.", "Lost the connection to the daemon."))));
      }
      agendar();
    });
  };
  enlazar(sesion);
  /** Lo recordado para este proyecto vuelve a aplicarse a la sesión, en orden; lo que vino por flag en esta corrida gana. */
  const reaplicar = async (s: Sesion) => {
    const recordados = ajustes();
    for (const op of RECORDADOS) {
      const value = recordados[op];
      if (value === undefined || options.explicit?.includes(op)) continue;
      try { await s.client.ask(op, { value }); }
      catch (error) { say([t(`No pude reaplicar el ajuste guardado (${op} ${value}): ${(error as Error).message}`, `Could not reapply the saved setting (${op} ${value}): ${(error as Error).message}`)], "warn", s); if (!closed) draw(); }
    }
  };

  const actualizarOBS = () => {
    if (!obs) return;
    try {
      if (panico || !enVivo) return obs.tapar();
      proteccion.actualizar();
      const tarea = ses.permiso ? "Esperando permiso" : ses.activeTools.size ? "Usando herramientas" : ses.client.status.running ? "Preparando respuesta" : "Esperando un mensaje";
      obs.mostrar(tarea, proteccion.modelo(ses.client.status.model ?? snapshot.model), Math.floor((Date.now() - inicioVivo) / 1000), proteccion.cantidad(idDe(ses)));
    } catch { apagarOBS(); avisoOBS = " · Falló la fuente de OBS"; }
  };
  const apagarOBS = () => {
    clearInterval(relojOBS);
    try { obs?.cerrar(); } catch { /* la fuente puede haber sido retirada */ }
    obs = undefined;
  };
  const iniciarOBS = () => {
    avisoOBS = "";
    if (!rutaOBS) return;
    try { obs = new FuenteOBS(rutaOBS); }
    catch { avisoOBS = " · OBS necesita un archivo nuevo y escribible"; return; }
    relojOBS = setInterval(actualizarOBS, 1000);
    actualizarOBS();
  };
  if (enVivo) iniciarOBS();

  const release = io.listen((data) => {
    for (const key of esPegadoConhost(data) ? [{ name: "paste", text: data.replace(/\r\n?/g, "\n") }] : parser.parse(data)) {
      onKey(key);
      if (closed) return;
    }
    draw();
  }, () => {
    draw();
  }, exit);
  for (const w of ventanas) pedir(w.activa, w);
  // Avisos del daemon al abrir (carpeta compartida, alcance de una sesión vieja): se ven, no bloquean.
  if (snapshot.avisos?.length) say(snapshot.avisos, "warn");
  seguirTurno(sesion); // shortcut: si se engancha a un turno ya en marcha, el reloj y el costo parten desde el enganche; mejorar si el daemon informa el inicio
  draw();
  void reaplicar(ses);
  // Primera vez en esta máquina: el inicio guiado (que incluye la cuenta). Si ya se hizo y falta la clave, sólo la cuenta.
  const wantsInicio = options.onboarding ?? !options.io;
  // Novedades: la primera vez en la máquina (inicio guiado pendiente, o sin historia en la configuración) se marcan todas vistas.
  const verNovedades = options.novedades ?? wantsInicio;
  const primeraVez = sinHistoria();
  const marcarTodas = () => { if (verNovedades) marcarNovedades(NOVEDADES.map((n) => n.id)); };
  const mostrarNovedades = () => {
    if (!verNovedades) return;
    const vistas = novedadesVistas();
    const nuevas = primeraVez ? [] : pendientes(vistas);
    const resto = NOVEDADES.filter((n) => !vistas.includes(n.id)).length - nuevas.length;
    if (nuevas.length) { panel(fromLines(t("Novedades", "What's new"), [...lineasDe(nuevas), ...(resto > 0 ? [t(`y ${resto} más en /novedades`, `and ${resto} more in /novedades`)] : [])], { footer: t("/novedades para verlas otra vez", "/novedades to see them again") })); draw(); }
    const aviso = verNovedades ? marcarNovedades(NOVEDADES.map((n) => n.id)) : undefined;
    if (aviso) { say([aviso], "warn"); draw(); }
  };
  if (wantsInicio && !ses.hasContent && !snapshot.resumed) {
    void ses.client.ask("inicio", {}).then((lines) => { if (lines[0] === "pendiente") { marcarTodas(); void runInicio(); } else { mostrarNovedades(); if (ses.client.status.needsKey) void askKey(); } }, () => { if (ses.client.status.needsKey) void askKey(); });
  } else { mostrarNovedades(); if (ses.client.status.needsKey) void askKey(); }
  sigil.start(draw, () => { finishBoot(); draw(); });
  return { submit: (text: string) => { submit(text); draw(); }, exit, pick: (title: string, options: string[]) => pick(title, options), askHidden };
}
