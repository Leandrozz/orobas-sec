import { BRANDS, modelName } from "./nombres-modelos.ts";
export { modelName } from "./nombres-modelos.ts";
// Comandos del operador en la TUI: un registro declarativo en vez de una cadena de if.
// Cada comando decide cómo se presenta: un panel con título y pie, un menú con flechas cuando hay
// opciones, una entrada cuando hace falta un valor, y confirmación cuando el paso no se deshace.
// La ejecución real vive en el daemon (ask/view); acá sólo está la interacción con la persona.
import { personalRow, selectablePersonal, connectPersonal, type Connection } from "./modelos-personales.ts";
import { lineasDe, NOVEDADES } from "./novedades.ts";
import { t } from "../idioma.ts";
import { TEMAS, buscarTema, temaActivo, usarTema, type Tema } from "./temas.ts";
import { selectorUltra, menuOrquesta, armarUltra, leerHarnesses, leerCorridas } from "./ultra.ts";
import { ultraGuardado, descifradoGuardado, elegirIdioma, guardarDescifrado, guardarMouse, guardarTema, guardarPestanas, idiomaGuardado, mouseGuardado, pestanasGuardadas, type Idioma } from "./ajustes.ts";
import { accent, bold, dim, warn } from "./text.ts";
import { etiquetarHallazgo } from "./vistas.ts";
import { TIPOS, type Pestana, type Tipo, type Vista } from "./pestanas.ts";
import { cantidad, FORMAS, type Forma } from "./ventanas.ts";
import { PROFILES } from "../perfil.ts";
import { accountMenu, mailMenu, platformMenu } from "../menu.ts";
import { SHARE_SENTENCE } from "../trayectorias.ts";
import { decodeRows, relative } from "../sesiones.ts";

export const PLATFORM_NAMES = ["github", "vercel", "supabase", "aws", "gcloud", "azure", "cloudflare", "kubernetes"];

export type Tone = "normal" | "warn" | "ok";
export interface Panel {
  title: string;
  lines: string[];
  /** Pie del panel: cómo seguir («Uso: …», teclas). */
  footer?: string;
  tone?: Tone;
}
export interface Row {
  label: string;
  hint?: string;
  /** Texto adicional para el buscador local. Nunca se dibuja. */
  busqueda?: string;
}

/** Lo que devuelve `cycle`: la fila nueva, o todas las filas con el cursor en `at` (mover filas). */
export type CycleResult = Row | { rows: Array<string | Row>; at: number } | undefined;

/** Lo que un comando puede hacer con la interfaz. La TUI y la terminal común lo implementan. */
export interface CommandIO {
  selectPersonal?(connection?: Connection): void;
  openClaudeModel?(model: string): void;
  personalActive?(): Connection | undefined;
  loginCLI?(client: "codex" | "claude" | "kimi" | "agy"): Promise<boolean>;
  ask(op: string, payload?: object): Promise<string[]>;
  view(name: string, arg?: string): Promise<string[]>;
  /**
   * Menú con flechas. Devuelve el índice elegido, o nada si se canceló. `search` agrega un buscador que
   * filtra mientras se escribe; `cycle` cambia la fila con ←→ sin cerrar el menú (devuelve la fila nueva).
   */
  pick(title: string, rows: Array<string | Row>, options?: { at?: number; footer?: string; search?: boolean; cycle?: (index: number, step: 1 | -1) => Promise<CycleResult>; move?: (index: number) => void }): Promise<number | undefined>;
  /** Una línea de entrada; `hidden` no muestra lo que se escribe. */
  input(label: string, options?: { hidden?: boolean }): Promise<string | undefined>;
  confirm(question: string): Promise<boolean>;
  /** Estado conocido del cliente: modelo, perfil y sesión, si el daemon los informa. */
  status(): { model?: string; profile?: string; running?: boolean; session?: string; title?: string };
  /** Los títulos pueden llegar recortados de otra sesión o proyecto. */
  tituloSesion?(titulo: string): string;
  streamer?(arg: string): Panel;
  clear(): void;
  exit(): void;
  resume(): void;
  /** Teclas de la interfaz, para /help. */
  keys(): string[];
  /** Mostrar un panel intermedio sin terminar el comando. */
  notice?(panel: Panel): void;
  /** Mandarle un mensaje al agente como si lo hubiera escrito el operador (sólo la TUI). */
  send?(text: string): void;
  /** Cortar el turno en curso y mandar ya el texto, después de lo que haya en cola; sin texto, la cola (sólo la TUI). */
  interrupt?(text: string): void;
  /** Cambiar la sesión abierta en esta misma pantalla («new» abre una nueva); devuelve el panel que lo cuenta (sólo la TUI). */
  switchSession?(id: string): Promise<Panel>;
  /** Correr el inicio guiado (sólo la TUI lo tiene). */
  inicio?(): Promise<void>;
  /** Pestañas abiertas y aplicarlas en vivo, y prender o apagar la rueda del mouse (sólo la TUI). */
  pestanas?(): Pestana[];
  setPestanas?(lista: Pestana[]): void;
  setMouse?(valor: boolean): void;
  /** Forma de las ventanas en paralelo y cambiarla (sólo la TUI). */
  forma?(): Forma;
  setForma?(forma: Forma): void;
  /** Pasa la pestaña activa a la ventana anterior/siguiente, y corre el divisor vertical `delta` columnas (sólo la TUI). */
  moverPestana?(sentido: 1 | -1): void;
  ancho?(delta: number): void;
}

export interface CommandSpec {
  name: string;
  aliases?: string[];
  description: string;
  /** Argumentos que acepta, para la lista de / y el pie del panel. */
  usage?: string;
  /** Grupo donde vive: queda fuera de la lista de / y se alcanza con «/grupo hijo». */
  parent?: string;
  /** Fuera de la lista de / sin pertenecer a un grupo. */
  hidden?: boolean;
  /** Sin argumento abre un menú: la fila «casa» (corre el run original) y después los hijos. */
  menu?: { casa?: string };
  /** Resuelve a un panel, o a nada si la persona canceló. */
  run(io: CommandIO, arg: string): Promise<Panel | null>;
}

/* ---------- Ayudas ---------- */

const USAGE = /^(Uso|Usage|Cambiar|Aprobar una propuesta|Fijarlo)\b/;

/**
 * Panel a partir de las líneas que devuelve el daemon: la primera línea en mayúsculas pasa a ser el
 * título y las de «Uso: …» van al pie, así el cuerpo queda limpio.
 */
export function fromLines(title: string, lines: string[], options: { footer?: string; tone?: Tone } = {}): Panel {
  const body = [...lines];
  let heading = title;
  const first = body[0] ?? "";
  if (first && first === first.toUpperCase() && /[A-ZÁÉÍÓÚÑ]{3}/.test(first) && body.length > 1) heading = body.shift()!.trim();
  const usage = body.filter((line) => USAGE.test(line.trim()));
  const rest = body.filter((line) => !USAGE.test(line.trim()));
  while (rest.length && !rest[rest.length - 1]!.trim()) rest.pop();
  const footer = [options.footer, ...usage.map((line) => line.trim())].filter(Boolean).join(" · ");
  return { title: heading, lines: rest.length ? rest : body.length ? [] : ["(nada que mostrar)"], ...(footer ? { footer } : {}), ...(options.tone ? { tone: options.tone } : {}) };
}

const warnPanel = (title: string, message: string): Panel => ({ title, lines: [message], tone: "warn" });

/** Elección entre valores fijos: con argumento va directo; sin argumento, menú con la opción vigente marcada. */
async function choose(io: CommandIO, spec: { name: string; op: string; title: string; options: (current: string) => Array<Row & { value: string; match: RegExp }>; footer?: string }, arg: string): Promise<Panel | null> {
  if (arg) return fromLines(spec.title, await io.ask(spec.op, { value: arg }));
  const current = await io.ask(spec.op, {});
  const text = current.join("\n");
  // Las opciones pueden depender de lo que contestó el daemon (los niveles del modelo de la sesión).
  const options = spec.options(text);
  const at = Math.max(0, options.findIndex((option) => option.match.test(text)));
  const rows = options.map((option, index) => ({ label: option.label, hint: `${option.hint ?? ""}${index === at ? (option.hint ? " · " : "") + t("Actual", "Current") : ""}` }));
  const choice = await io.pick(spec.title, rows, { at, footer: spec.footer });
  if (choice === undefined) return null;
  if (choice === at) return fromLines(spec.title, current);
  return fromLines(spec.title, await io.ask(spec.op, { value: options[choice]!.value }), { tone: "ok" });
}

/** Un número o «sin»: menú con valores usuales y «otro…» para escribirlo. */
async function amount(io: CommandIO, spec: { op: string; title: string; unit: string; presets: string[]; footer: string }, arg: string): Promise<Panel | null> {
  if (arg) return fromLines(spec.title, await io.ask(spec.op, { value: arg }));
  const current = await io.ask(spec.op, {});
  const rows: Row[] = [...spec.presets.map((value) => ({ label: `${spec.unit} ${value}` })), { label: t("sin tope", "no limit") }, { label: t("otro…", "other…") }];
  const choice = await io.pick(spec.title, rows, { footer: current[0] ?? "" });
  if (choice === undefined) return null;
  let value: string | undefined = choice < spec.presets.length ? spec.presets[choice] : choice === spec.presets.length ? "sin" : undefined;
  if (value === undefined) {
    value = await io.input(`${spec.title} (${spec.unit})`);
    if (!value) return null;
  }
  return fromLines(spec.title, await io.ask(spec.op, { value }), { tone: "ok" });
}

/* ---------- Opciones fijas (las usan su comando y /config) ---------- */

type Option = Row & { value: string; match: RegExp };
/** Cuándo corre solo el verificador (el valor de fábrica es «automática», como siempre). */
const verifyOptions = (): Option[] => [
  { label: t("automática", "automatic"), value: "automatica", hint: t("al cierre de cada turno, los candidatos nuevos o con evidencia nueva", "at the end of each turn, new candidates or ones with new evidence"), match: /Verificación automática:/ },
  { label: t("a pedido", "on request"), value: "a-pedido", hint: t("sólo con /verificar", "only with /verificar"), match: /Verificación a pedido/ },
  { label: t("con tope", "capped"), value: "tope 1", hint: t("automática hasta USD 1 por sesión (otro monto: /verificacion tope <USD>)", "automatic up to USD 1 per session (another amount: /verificacion tope <USD>)"), match: /Verificación automática con tope/ },
];
const scannerOptions = (): Option[] => [
  { label: t("sí", "yes"), value: "si", hint: t("Disponibles: nmap, ffuf, nuclei y compañía", "Available: nmap, ffuf, nuclei and friends"), match: /habilitados|enabled/ },
  { label: "no", value: "no", hint: t("sólo lo que hace el agente por su cuenta", "only what the agent does on its own"), match: /apagados|disabled/ },
];
const investigationOptions = (): Option[] => [
  { label: t("apagada", "off"), value: "no", hint: t("el agente propone; abrirla requiere un pedido citado", "the agent proposes; opening requires a quoted request"), match: /Investigación automática: apagada/ },
  { label: t("activa", "on"), value: "si", hint: t("abre con tope de USD 2 o mitad del presupuesto restante", "opens with USD 2 or half the remaining budget"), match: /Investigación automática: activa/ },
];
/** Niveles de razonamiento: cómo se muestran y con qué palabra de la respuesta del daemon se reconoce el vigente. */
const REASONING_LEVELS: Record<string, () => Option> = {
  bajo: () => ({ label: t("bajo", "low"), value: "bajo", hint: t("razona poco: rápido y barato", "thinks a little: fast and cheap"), match: /nivel bajo/i }),
  medio: () => ({ label: t("medio", "medium"), value: "medio", hint: t("un punto intermedio", "a middle ground"), match: /nivel medio/i }),
  alto: () => ({ label: t("alto", "high"), value: "alto", hint: t("razona más: más calidad, más salida", "thinks more: better quality, more output"), match: /nivel alto/i }),
  max: () => ({ label: "max", value: "max", hint: t("todo lo que da: lo más lento y caro", "all it has: slowest and priciest"), match: /nivel max/i }),
};
/**
 * Opciones de /razonamiento. Si el modelo de la sesión publica sus niveles (la frase «Niveles de este
 * modelo: …» de la respuesta del daemon), el menú son esos niveles; si no, prendido, apagado o por defecto.
 */
const reasoningOptions = (current = ""): Option[] => {
  const personal = /^Opciones personales: *(.*)$/m.exec(current);
  if (personal) {
    return ["default", ...personal[1]!.split(",").filter(Boolean)].map(value => ({
      label: ({ default: t("por defecto", "default"), on: t("activado", "on"), off: t("apagado", "off") } as Record<string, string>)[value] ?? value,
      value, hint: "", match: new RegExp("^Razonamiento: " + value + " ·"),
    }));
  }
  const off: Option = { label: "no", value: "no", hint: t("más rápido y barato", "faster and cheaper"), match: /apagado|desactivado|\boff\b/i };
  const auto: Option = { label: t("por defecto", "default"), value: "defecto", hint: t("lo que el modelo haga por su cuenta", "whatever the model does by default"), match: /defecto|default/i };
  const levels = /Niveles de este modelo: ([^;.\n]*)/.exec(current)?.[1];
  if (levels === undefined) return [
    // ~70%: medido el 16/11/2026 en deepseek-v4.1-flash, tres tareas cortas de seguridad: +73% en total (46–90% según la tarea).
    { label: t("sí", "yes"), value: "si", hint: t("Más calidad; ~70% más de salida", "Better quality; ~70% more output"), match: /prendido|encendido|activado|\bsí\b|\bon\b/i },
    off,
    auto,
  ];
  const minimum = /no se puede apagar/.test(current);
  return [
    { ...off, hint: minimum ? t("este modelo no se apaga: va su mínimo", "this model cannot turn it off: its minimum") : t("apagado: más rápido y barato", "off: faster and cheaper") },
    ...levels.split(",").map((name) => REASONING_LEVELS[name.trim()]?.()).filter((option): option is Option => !!option),
    auto,
  ];
};
const decoyOptions = (): Option[] => [
  { label: "bloquear", value: "bloquear", hint: t("no seguir sus rutas ni usar lo que regalan", "do not follow their paths nor use what they hand out"), match: /bloqueado|blocked/ },
  { label: "permitir", value: "permitir", hint: t("probarlos igual, bajo tu responsabilidad", "probe them anyway, on you"), match: /permitido|allowed/ },
];
/** /navegador: autorizado o no en este proyecto (la respuesta del daemon dice «Autorizado en este proyecto: sí|no»). */
const browserOptions = (): Option[] => [
  { label: t("sí", "yes"), value: "si", hint: t("el agente puede usar tu navegador en este proyecto", "the agent can use your browser in this project"), match: /(Autorizado en este proyecto|Allowed in this project): (sí|yes)/ },
  { label: "no", value: "no", hint: t("no lo toca hasta que lo autorices", "it does not touch it until you allow it"), match: /(Autorizado en este proyecto|Allowed in this project): no/ },
];
/** Modo de trazas elegido (la respuesta del daemon dice «elegido: <modo>»; en inglés, «chosen: <modo>»). */
const trazasOptions = (): Option[] => [
  { label: "compartir", value: "compartir", hint: t("van a Elevate AI, con los secretos tapados", "they go to Elevate AI, secrets masked"), match: /(elegido|chosen): compartir/ },
  { label: "local", value: "local", hint: t("sólo en tu PC", "only on your PC"), match: /(elegido|chosen): local/ },
  { label: "no", value: "no", hint: t("no se guardan", "not kept"), match: /(elegido|chosen): no\b/ },
];
const profileOptions = (): Option[] => PROFILES.map((profile) => ({ label: profile, value: profile, match: new RegExp(`\\b${profile}\\b`) }));

/* ---------- Configuración ---------- */

/** Un ajuste de /config: su valor actual y cómo se cambia (←→ entre opciones fijas, o Enter abre su menú). */
interface Setting { diseno?: true; label: string; current(io: CommandIO): Promise<string>; cycle?(io: CommandIO, step: 1 | -1): Promise<void>; open?(io: CommandIO): Promise<unknown> }

/** Ajuste de opciones fijas que vive en el daemon: el valor se lee de su respuesta y se cambia con la misma operación. */
const fixed = (label: string, op: string, options: (current: string) => Option[]): Setting => {
  const read = async (io: CommandIO) => { const text = (await io.ask(op, {})).join("\n"); const list = options(text); return { list, at: list.findIndex((option) => option.match.test(text)) }; };
  return {
    label,
    current: async (io) => { const { list, at } = await read(io); return list[at]?.label ?? "—"; },
    cycle: async (io, step) => { const { list, at } = await read(io); await io.ask(op, { value: list[(Math.max(0, at) + step + list.length) % list.length]!.value }); },
  };
};
/** Ajuste que se cambia con su comando de siempre; `show` resume la respuesta del daemon en un valor corto. */
const viaCommand = (label: string, name: string, current: (io: CommandIO) => Promise<string>): Setting => ({ label, current, open: (io) => findCommand(name)!.run(io, "") });
const first = async (io: CommandIO, op: string, payload: object = {}) => (await io.ask(op, payload))[0] ?? "";

/* ---------- Ventanas ---------- */

const formaLabel = (): Record<Forma, string> => ({ una: t("Una", "One"), lado: t("Lado a lado", "Side by side"), lateral: t("Con lateral", "With sidebar"), tres: t("Tres", "Three"), cuatro: t("Cuatro (2×2)", "Four (2×2)") });
const formaExplica = (): Record<Forma, string> => ({ una: t("como siempre", "as usual"), lado: t("dos iguales", "two equal"), lateral: t("una ancha y una angosta", "one wide, one narrow"), tres: t("una y dos apiladas", "one and two stacked"), cuatro: t("cuatro iguales", "four equal") });
/** Mini-dibujo de una línea de cada forma. */
const FORMA_DIBUJO: Record<Forma, string> = { una: "[      ]", lado: "[  |  ]", lateral: "[    | ]", tres: "[  |--]", cuatro: "[--+--]" };

async function ventanasCommand(io: CommandIO): Promise<null> {
  if (!io.setForma) return null;
  const actual = io.forma?.() ?? "una";
  const formas = FORMAS.map((f) => ({ label: formaLabel()[f], hint: `${FORMA_DIBUJO[f]}  ${formaExplica()[f]}` }));
  // Con más de una ventana, dos filas más: mover la pestaña y el ancho (←→ lo cicla sin cerrar el menú).
  const extra = cantidad(actual) > 1 && io.moverPestana && io.ancho
    ? [{ label: t("mover pestaña a la ventana siguiente", "move tab to the next window"), hint: "Ctrl+Shift+←→" }, { label: t("ancho: más / menos", "width: more / less"), hint: "‹ ›  Ctrl+Alt+←→" }]
    : [];
  const choice = await io.pick(t("ventanas", "windows"), [...formas, ...extra], {
    at: FORMAS.indexOf(actual),
    cycle: async (index, step) => {
      if (index !== FORMAS.length + 1) return undefined;
      io.ancho!(step * 2);
      return extra[1]!;
    },
  });
  if (choice === FORMAS.length) io.moverPestana!(1);
  else if (choice !== undefined && choice < FORMAS.length) io.setForma(FORMAS[choice]!);
  return null;
}

/* ---------- Pestañas ---------- */

const tipoLabel = (): Record<Tipo, string> => ({ mensajes: t("Mensajes", "Messages"), texto: t("Texto del modelo", "Model text"), acciones: t("Acciones", "Actions"), resultados: t("Resultados", "Results"), comandos: t("Comandos /", "Commands /"), avisos: t("Avisos", "Notices") });
const detalles = ["minimo", "normal", "completo"] as const;
type Conv = Pestana & { tipo: "conversacion" };
const detalleLabel = () => ({ minimo: t("Mínimo", "Minimal"), normal: "Normal", completo: t("Completo", "Full") });
const vistaLabel = (): Record<Vista, string> => ({ hallazgos: t("Hallazgos", "Findings"), artefactos: t("Artefactos", "Artifacts"), cobertura: t("Cobertura", "Coverage"), costos: t("Costos", "Costs"), trabajos: t("Trabajos", "Jobs") });
const resumen = (p: Pestana) => (p.tipo === "vista" ? t(`Vista: ${vistaLabel()[p.vista]}`, `View: ${vistaLabel()[p.vista]}`) : `${p.contenido.length === TIPOS.length ? t("Todo", "All") : p.contenido.map((x) => tipoLabel()[x]).join(", ") || t("Nada", "Nothing")} · ${detalleLabel()[p.detalle]}`);

/** Muestra el aviso de una escritura que falló (el cambio se aplicó igual en la sesión). */
const avisar = (io: CommandIO, aviso: string | undefined) => { if (aviso) io.notice?.(fromLines("config", [aviso], { tone: "warn" })); };

/** Editor de pestañas de /config: cada cambio se guarda y se aplica en vivo; todo vuelve a la misma fila. */
async function pestanasCommand(io: CommandIO): Promise<void> {
  let lista = io.pestanas?.() ?? pestanasGuardadas();
  const aplicar = (nueva: Pestana[]) => { lista = nueva; avisar(io, guardarPestanas(nueva)); io.setPestanas?.(nueva); };
  const fila = (p: Pestana): Row => ({ label: p.nombre, hint: resumen(p) });
  const editar = async (i: number): Promise<void> => {
    let at = 0;
    for (;;) {
      const p = lista[i]!;
      const conv = p.tipo === "conversacion";
      const rows: Row[] = [{ label: t("Nombre", "Name"), hint: p.nombre }];
      if (conv) {
        rows.push(...TIPOS.map((x) => ({ label: tipoLabel()[x], hint: p.contenido.includes(x) ? "[x]" : "[ ]" })));
        rows.push({ label: t("Detalle", "Detail"), hint: `‹ ${detalleLabel()[p.detalle]} ›` });
      }
      if (lista.length > 1) rows.push({ label: t("Borrar pestaña", "Delete tab") });
      const hasta = conv ? TIPOS.length + 1 : 0;
      // Cada manejador lee la pestaña vigente: `p` quedó vieja si un cycle o una casilla la cambió después de armar el menú.
      const cambiar = (cambio: (actual: Conv) => Conv) => aplicar(lista.map((x, k) => (k === i ? cambio(x as Conv) : x)));
      const siguiente = (actual: Conv, paso: number) => detalles[(detalles.indexOf(actual.detalle) + paso + detalles.length) % detalles.length]!;
      const choice = await io.pick(p.nombre, rows, {
        at,
        cycle: async (index, step) => {
          if (!conv || index !== hasta) return undefined;
          const nuevo = siguiente(lista[i] as Conv, step);
          cambiar((actual) => ({ ...actual, detalle: nuevo }));
          return { label: rows[index]!.label, hint: `‹ ${detalleLabel()[nuevo]} ›` };
        },
      });
      if (choice === undefined) return;
      at = choice;
      if (choice === 0) {
        const nombre = (await io.input(t("Nombre de la pestaña", "Tab name")))?.trim().slice(0, 24);
        if (nombre) aplicar(lista.map((x, k) => (k === i ? { ...x, nombre } : x)));
      } else if (conv && choice <= TIPOS.length) {
        const tipo = TIPOS[choice - 1]!;
        cambiar((actual) => ({ ...actual, contenido: TIPOS.filter((x) => (x === tipo ? !actual.contenido.includes(x) : actual.contenido.includes(x))) }));
      } else if (conv && choice === hasta) {
        cambiar((actual) => ({ ...actual, detalle: siguiente(actual, 1) }));
      } else if (await io.confirm(t(`¿Borrar la pestaña «${p.nombre}»?`, `Delete the tab "${p.nombre}"?`))) {
        aplicar(lista.filter((_, k) => k !== i));
        return;
      }
    }
  };
  const nueva = async (): Promise<void> => {
    const opciones: Array<Tipo | Vista | "conversacion"> = ["conversacion", "hallazgos", "artefactos", "cobertura", "costos", "trabajos"];
    const choice = await io.pick(t("Tipo de pestaña", "Tab type"), [t("Conversación", "Conversation"), ...Object.values(vistaLabel())]);
    if (choice === undefined) return;
    const tipo = opciones[choice]!;
    const base = tipo === "conversacion" ? t("Conversación", "Conversation") : vistaLabel()[tipo as Vista];
    const escrito = await io.input(t("Nombre de la pestaña (vacío: el del tipo)", "Tab name (empty: the type's)"));
    if (escrito === undefined) return;
    const nombre = escrito.trim().slice(0, 24) || base;
    aplicar([...lista, tipo === "conversacion" ? { nombre, tipo, contenido: [], detalle: "normal" } : { nombre, tipo: "vista", vista: tipo as Vista }]);
    if (tipo === "conversacion") await editar(lista.length - 1);
  };
  let at = 0;
  for (;;) {
    const choice = await io.pick(t("Pestañas · ←→ las mueve", "Tabs · ←→ moves them"), [...lista.map(fila), t("+ Nueva pestaña", "+ New tab")], {
      at,
      cycle: async (index, step) => {
        const otro = index + step;
        if (index >= lista.length || otro < 0 || otro >= lista.length) return undefined;
        const copia = [...lista];
        [copia[index], copia[otro]] = [copia[otro]!, copia[index]!];
        aplicar(copia);
        return { rows: [...copia.map(fila), t("+ Nueva pestaña", "+ New tab")], at: otro };
      },
    });
    if (choice === undefined) return;
    at = choice;
    if (choice === lista.length) await nueva(); else await editar(choice);
    at = Math.min(at, lista.length);
  }
}

/** Aplica el tema ya y lo recuerda; devuelve el aviso si no se pudo guardar. */
const aplicarTema = (tema: Tema): string | undefined => { usarTema(tema.id); return guardarTema(tema.id); };

async function temaCommand(io: CommandIO, arg = ""): Promise<Panel | null> {
  const previo = temaActivo();
  let tema: Tema | undefined;
  if (arg.trim()) {
    tema = buscarTema(arg);
    if (!tema) return fromLines("tema", [t(`Uso: /tema <nombre>. Hay: ${TEMAS.map((x) => x.nombre()).join(", ")}`, `Usage: /tema <name>. Available: ${TEMAS.map((x) => x.nombre()).join(", ")}`)], { tone: "warn" });
  } else {
    const choice = await io.pick(t("tema", "theme"), TEMAS.map((x) => ({ label: x.nombre(), hint: x.descripcion() })), { at: TEMAS.indexOf(previo), move: (i) => usarTema(TEMAS[i]!.id) });
    if (choice === undefined) { usarTema(previo.id); return null; }
    tema = TEMAS[choice]!;
  }
  const aviso = aplicarTema(tema);
  return fromLines("tema", [t(`Tema: ${tema.nombre()}.`, `Theme: ${tema.nombre()}.`), ...(aviso ? [aviso] : [])], { tone: aviso ? "warn" : "ok" });
}

function settings(): Setting[] {
  const idiomas: Array<{ label: string; value: Idioma | undefined }> = [{ label: "Español", value: "es" }, { label: "English", value: "en" }, { label: t("El del sistema", "System default"), value: undefined }];
  return [
    { label: t("Idioma", "Language"), current: async () => idiomas.find((option) => option.value === idiomaGuardado())!.label, cycle: async (io, step) => { const at = idiomas.findIndex((option) => option.value === idiomaGuardado()); avisar(io, elegirIdioma(idiomas[(at + step + idiomas.length) % idiomas.length]!.value)); } },
    { diseno: true, label: t("Pestañas", "Tabs"), current: async (io) => (io.pestanas?.() ?? pestanasGuardadas()).map((p) => p.nombre).join(" · "), open: pestanasCommand },
    { diseno: true, label: t("Ventanas", "Windows"), current: async (io) => formaLabel()[io.forma?.() ?? "una"], open: ventanasCommand },
    { diseno: true, label: t("Mouse (rueda y seleccionar)", "Mouse (wheel and select)"), current: async () => (mouseGuardado() ? t("Sí", "Yes") : "No"), cycle: async (io) => { const nuevo = !mouseGuardado(); avisar(io, guardarMouse(nuevo)); io.setMouse?.(nuevo); } },
    { diseno: true, label: t("Tema", "Theme"), current: async () => temaActivo().nombre(), cycle: async (io, step) => { const at = TEMAS.indexOf(temaActivo()); avisar(io, aplicarTema(TEMAS[(at + step + TEMAS.length) % TEMAS.length]!)); }, open: async (io) => { const panel = await temaCommand(io); if (panel?.tone === "warn") io.notice?.(panel); } },
    { diseno: true, label: t("Efecto descifrado", "Decrypt effect"), current: async () => (descifradoGuardado() ? t("Sí", "Yes") : "No"), cycle: async (io) => avisar(io, guardarDescifrado(!descifradoGuardado())) },
    viaCommand(t("Modelo", "Model"), "modelo", async (io) => modelName(io.status().model ?? "")),
    { label: t("Modelo fuerte", "Strong model"), current: async (io) => modelName(strongOf(await io.ask("strong", {}))), open: (io) => strongCommand(io, "") },
    fixed(t("Razonamiento", "Reasoning"), "reasoning", reasoningOptions),
    // ←→ alterna auto y fijo; Enter abre /router (estado, modelo medio).
    { ...fixed(t("Router de modelos", "Model router"), "router", routerOptions), open: async (io) => { const panel = await routerCommand(io, ""); if (panel) io.notice?.(panel); } },
    fixed(t("Perfil", "Profile"), "perfil", profileOptions),
    fixed(t("Escáneres externos", "External scanners"), "scanners", scannerOptions),
    fixed(t("Verificación automática", "Automatic verification"), "verificacion", verifyOptions),
    fixed(t("Investigación automática", "Automatic investigation"), "investigation_auto", investigationOptions),
    fixed(t("Señuelos", "Decoys"), "decoys", decoyOptions),
    viaCommand(t("Presupuesto de la sesión", "Session budget"), "presupuesto", async (io) => { const usd = /USD (\d+(?:\.\d+)?)/.exec(await first(io, "budget")); return usd ? `USD ${usd[1]}` : t("Sin tope", "No limit"); }),
    viaCommand(t("Tope de peticiones HTTP", "HTTP request cap"), "peticiones", async (io) => /Tope de peticiones HTTP: (\d+)/.exec(await first(io, "requests"))?.[1] ?? t("Sin tope", "No limit")),
    viaCommand(t("Ritmo máximo", "Max rate"), "ritmo", async (io) => { const rate = /Ritmo máximo: (\d+(?:\.\d+)?)/.exec(await first(io, "rate")); return rate ? t(`${rate[1]} por segundo`, `${rate[1]} per second`) : t("Sin ritmo", "No limit"); }),
    viaCommand("User-Agent", "agente", async (io) => /User-Agent: (.+?)\. Uso/.exec(await first(io, "agent"))?.[1] ?? "—"),
    viaCommand(t("Permisos de shell", "Shell permissions"), "permisos", async (io) => { const lines = await io.ask("permisos", {}); if (lines.some((line) => line.startsWith("Modo: autoaprobar todo"))) return t("Todo autoaprobado", "Everything auto-approved"); const saved = lines.filter((line) => line.startsWith("permitido siempre")).length; return saved ? t(`${saved} guardado${saved > 1 ? "s" : ""}`, `${saved} saved`) : t("Ninguno; cada comando pregunta", "None; every command asks"); }),
    viaCommand(t("Cuenta de orobas", "orobas account"), "orobas", (io) => first(io, "account", { service: "orobas", action: "status" })),
    viaCommand("HackerOne", "hackerone", (io) => first(io, "account", { service: "hackerone", action: "status" })),
    fixed(t("Navegador del operador", "Operator browser"), "navegador", browserOptions),
    viaCommand(t("Correo de prueba", "Test mail"), "correo", async (io) => { const boxes = await io.ask("mail_account", { action: "status" }); return /sin vincular|not linked/.test(boxes[0] ?? "") ? t("Sin vincular", "Not linked") : t(`${boxes.length} casilla${boxes.length > 1 ? "s" : ""}`, `${boxes.length} mailbox(es)`); }),
    viaCommand(t("Servidores MCP", "MCP servers"), "mcp", async (io) => { const servers = (await io.ask("mcp", { action: "status" })).filter(Boolean).length; return servers ? String(servers) : t("Ninguno", "None"); }),
    // ←→ alterna compartir, local y no (se guarda en la configuración, vale para todos los proyectos); Enter abre /datos.
    { ...fixed(t("Trazas", "Traces"), "trazas", trazasOptions), open: (io) => findCommand("datos")!.run(io, "") },
    viaCommand(t("Inicio guiado", "Onboarding"), "inicio", async () => t("Repetirlo", "Run again")),
  ];
}

/** /config: todos los ajustes con su valor, buscador, ←→ para las opciones fijas y Enter para abrir el resto. */
async function configCommand(io: CommandIO, solo: (s: Setting) => boolean = () => true, titulo = t("Configuración", "Settings")): Promise<Panel | null> {
  const show = async (io2: CommandIO, setting: Setting): Promise<Row> => {
    const raw = await setting.current(io2).catch(() => "—");
    const value = raw.charAt(0).toUpperCase() + raw.slice(1);
    return { label: setting.label, hint: setting.cycle ? `‹ ${value} ›` : value };
  };
  let at = 0;
  for (;;) {
    const list = settings().filter(solo);
    const rows = await Promise.all(list.map((setting) => show(io, setting)));
    const choice = await io.pick(titulo, rows, {
      at,
      search: true,
      footer: t("se guarda al cambiarlo; ventanas, pestañas, tema e idioma general valen para todos los proyectos", "saved as you change it; windows, tabs, theme and general language apply to every project"),
      cycle: async (index, step) => { const setting = list[index]!; if (!setting.cycle) return undefined; await setting.cycle(io, step); return show(io, setting); },
    });
    if (choice === undefined) return null;
    at = choice;
    const setting = list[choice]!;
    // Enter abre el menú de la fila si lo tiene (Tema: la lista); si no, avanza como →. Vuelve a la lista con el valor nuevo.
    if (setting.open) await setting.open(io);
    else await setting.cycle!(io, 1);
  }
}

/* ---------- Modelo ---------- */

export interface ModelRow { spec: string; name?: string; kind?: string; context?: string; price?: string; status?: string }
/** Filas del daemon (op «models»): current, model y other separados por tabuladores. */
export function parseModels(lines: string[]): { current: string; models: ModelRow[]; others: string[] } {
  let current = "";
  const models: ModelRow[] = [];
  const others: string[] = [];
  for (const line of lines) {
    const [kind, ...cells] = line.split("\t");
    if (kind === "current") current = cells[0] ?? "";
    else if (kind === "model") models.push({ spec: cells[0] ?? "", name: cells[1] || undefined, kind: cells[2] || undefined, context: cells[3] || undefined, price: cells[4] || undefined, status: cells[5] || undefined });
    else if (kind === "other") others.push(cells[0] ?? "");
  }
  return { current, models, others };
}
/** Para qué conviene cada modelo de la suscripción, en pocas palabras (por id, sin proveedor). */
const modelUse = (id: string): string | undefined => ({
  auto: t("Elige solo; cambia si un proveedor falla", "Picks for you; switches if a provider fails"),
  "deepseek-v4.1-flash": t("El más rápido; uso general", "Fastest; general use"),
  "deepseek-v4.1-flash-estandar": t("Más lento", "Slower"),
  "glm-5.3-flash": t("Barato y rápido: el base por defecto", "Cheap and fast: the default base"),
  "cyber-ultra-1.0": t("Fuerte y caro: el que razona por defecto", "Strong and expensive: the default reasoner"),
  "cyber-zero-1.5": t("Fuerte y caro", "Strong and expensive"),
  "qwen3.8-27b": t("Contexto más chico (512k)", "Smaller context (512k)"),
} as Record<string, string>)[id];
export function modelRow(model: ModelRow, current: string): Row {
  const parts = [modelUse(model.spec.slice(model.spec.indexOf("/") + 1)), model.kind && (BRANDS[model.kind.toLowerCase()] ?? model.kind), model.context ? `${model.context}k` : "", model.price ? `USD ${model.price}` : "", model.status && model.status !== "ok" ? model.status.toUpperCase() : ""].filter(Boolean);
  if (model.spec === current) parts.push(t("Actual", "Current"));
  return { label: model.name || modelName(model.spec), hint: parts.join(" · ") };
}

/** «Modelo fuerte: orobas/x · base …» (op «strong» del daemon) → «orobas/x». */
export const strongOf = (lines: string[]): string => /^Modelo fuerte: (\S+)/.exec(lines[0] ?? "")?.[1] ?? "";

/**
 * Menú de modelos: la lista de la cuenta con el actual marcado y «otro…» para escribirlo. Devuelve el
 * elegido, o nada si no cambió. Lo usan /modelo (el base, el del bucle: el actual lo dice el daemon) y
 * /modelo fuerte (el actual es el fuerte).
 */
async function pickModelSpec(io: CommandIO, title: string, strong?: string): Promise<string | undefined> {
  const parsed = parseModels(await io.ask("models", {}));
  const { models, others } = parsed;
  const current = strong ?? parsed.current;
  // Sin lista del proveedor (simulado o uno propio) igual se abre el menú, con «otro…» para escribirlo.
  // El actual va siempre, aunque el proveedor no lo liste (p. ej. «auto»): si no, nada queda marcado y elegirlo no hace nada.
  const list = !current || models.some((model) => model.spec === current) ? models : [{ spec: current }, ...models];
  let at = Math.max(0, list.findIndex((model) => model.spec === current));
  const rows = [...list.map((model) => modelRow(model, current)), { label: t("otro…", "other…"), hint: t("escribir proveedor/modelo", "type provider/model") }];
  const footer = others.length ? t(`otros proveedores: ${others.join(", ")}`, `other providers: ${others.join(", ")}`) : models.some((model) => model.price) ? t("tarifas en USD por millón: entrada / caché / salida", "USD per million: input / cache / output") : current;
  const personal = strong === undefined ? await selectablePersonal(Boolean(io.openClaudeModel)) : [];
  if (strong === undefined) {
    rows.pop();
    const selected = io.personalActive?.();
    for (const entry of personal) {
      const active = selected?.provider === entry.provider && selected?.model === entry.model && selected?.base === entry.base && selected?.subscription === entry.subscription;
      if (active) at = rows.length;
      const row = personalRow(entry);
      rows.push({ ...row, hint: row.hint + (active ? " · ✓" : "") });
    }
    rows.push({ label: t("Otros", "Other"), hint: t("conectar modelo o escribir proveedor/modelo", "connect model or type provider/model") });
  }
  const choice = await io.pick(title, rows, { at, footer, search: true });
  if (choice !== undefined && strong === undefined && choice >= list.length) {
    if (choice < rows.length - 1) {
      const entry = personal[choice - list.length]!;
      if (entry.nativeClaude) io.openClaudeModel?.(entry.model);
      else io.selectPersonal?.(entry);
      return;
    }
    const action = await io.pick(t("Otros", "Other"), [t("Conectar modelo…", "Connect model…"), t("Escribir proveedor/modelo", "Type provider/model")]);
    if (action === undefined) return;
    if (action === 0) {
      const connection = await connectPersonal(io);
      if (connection?.nativeClaude) io.openClaudeModel?.(connection.model);
      else if (connection) io.selectPersonal?.(connection);
      return;
    }
  }
  if (choice === undefined || (!io.personalActive?.() && choice === at && list[at]?.spec === current)) return undefined;
  const value = choice === rows.length - 1 ? (await io.input(t("proveedor/modelo", "provider/model")))?.trim() : list[choice]!.spec;
  return value || undefined;
}

async function modelCommand(io: CommandIO, arg: string): Promise<Panel | null> {
  const title = t("modelo", "model");
  // «/modelo fuerte [nombre]»: el modelo fuerte, el que razona a pedido del base.
  const [first = "", ...rest] = arg.trim().split(/\s+/);
  if (/^(fuerte|strong)$/i.test(first)) return strongCommand(io, rest.join(" "));
  const value = arg || await pickModelSpec(io, title);
  if (value === undefined) return null;
  const lines = await io.ask("model", { value });
  io.selectPersonal?.();
  return fromLines(title, lines, { tone: "ok" });
}

/** /modelo fuerte: ver o cambiar el modelo que consultan deep_reason y delegate con strong. */
async function strongCommand(io: CommandIO, arg: string): Promise<Panel | null> {
  const title = t("modelo fuerte", "strong model");
  if (arg.trim()) return fromLines(title, await io.ask("strong", { value: arg.trim() }), { tone: "ok" });
  const value = await pickModelSpec(io, title, strongOf(await io.ask("strong", {})));
  if (value === undefined) return null;
  return fromLines(title, await io.ask("strong", { value }), { tone: "ok" });
}

/* ---------- Router ---------- */

/** Modos del router: cómo se muestran y con qué línea de /router estado se reconoce el vigente («Modo  auto · …»). */
const routerOptions = (): Option[] => [
  { label: "auto", value: "auto", hint: t("el ejecutor trabaja; el fuerte decide sobre un traspaso", "the executor works; the strong decides on a handoff"), match: /^(Modo|Mode)\s+auto\b/m },
  { label: t("fijo", "fixed"), value: "fijo", hint: t("todo con el modelo de la sesión, sin encargos", "everything on the session model, no handoffs"), match: /^(Modo|Mode)\s+(fijo|fixed)\b/m },
];

/** /router: sin argumento, un menú como /razonamiento (auto, fijo, estado, modelo medio); «estado» abre el panel. */
async function routerCommand(io: CommandIO, arg: string): Promise<Panel | null> {
  const title = "router";
  const [verb = "", ...rest] = arg.trim().split(/\s+/);
  if (/^(medio|mid)$/i.test(verb)) return routerMedio(io, rest.join(" "));
  if (/^(estado|status)$/i.test(verb)) return fromLines(title, await io.ask("router", {}));
  if (verb) return fromLines(title, await io.ask("router", { value: verb }), { tone: "ok" });
  const current = await io.ask("router", {});
  const text = current.join("\n");
  const options = routerOptions();
  const at = Math.max(0, options.findIndex((option) => option.match.test(text)));
  const rows: Row[] = [
    ...options.map((option, index) => ({ label: option.label, hint: `${option.hint}${index === at ? ` · ${t("Actual", "Current")}` : ""}` })),
    { label: t("estado", "status"), hint: t("roles, decisiones, gasto y ahorro", "roles, decisions, spend and savings") },
    { label: t("modelo medio…", "mid model…"), hint: t("opcional: lee código sobre un traspaso", "optional: reads code on a handoff") },
  ];
  const choice = await io.pick(title, rows, { at, footer: t("el ejecutor es /modelo; el fuerte, /modelo fuerte", "the executor is /modelo; the strong one, /modelo fuerte") });
  if (choice === undefined) return null;
  if (choice === options.length + 1) return routerMedio(io, "");
  if (choice === options.length || choice === at) return fromLines(title, current);
  return fromLines(title, await io.ask("router", { value: options[choice]!.value }), { tone: "ok" });
}

/* ---------- Investigar ---------- */

/**
 * /investigar: el modo investigación. Sin argumento (o «estado»), el panel; «pausa», «seguir [usd]» y
 * «cerrar» (con confirmación: no se reabre); cualquier otra cosa abre una sobre ese objetivo, con el tope
 * opcional al final.
 */
async function investigarCommand(io: CommandIO, arg: string): Promise<Panel | null> {
  const title = t("investigación", "investigation");
  const texto = arg.trim();
  if (!texto || /^(estado|status|ver)$/i.test(texto)) return fromLines(title, await io.ask("investigar", {}));
  if (/^(cerrar|terminar|close)$/i.test(texto) && !(await io.confirm(t("¿Cerrar la investigación? El diario y los hallazgos quedan, pero no se retoma.", "Close the investigation? The journal and findings stay, but it cannot be resumed.")))) return null;
  return fromLines(title, await io.ask("investigar", { value: texto }), { tone: "ok" });
}

/** /router medio: el modelo que lee código sobre un traspaso (opcional); «no» lo saca. */
async function routerMedio(io: CommandIO, arg: string): Promise<Panel | null> {
  const title = t("modelo medio", "mid model");
  if (arg.trim()) return fromLines(title, await io.ask("router_medio", { value: arg.trim() }), { tone: "ok" });
  const current = /: (\S+?)\.(\s|$)/.exec((await io.ask("router_medio", {}))[0] ?? "")?.[1];
  const value = await pickModelSpec(io, title, current ?? "");
  if (value === undefined) return null;
  return fromLines(title, await io.ask("router_medio", { value }), { tone: "ok" });
}

/* ---------- MCP ---------- */

export interface McpRow { name: string; command: string; state: string; tools?: string; error?: string }
export const parseMcp = (lines: string[]): McpRow[] => lines.filter(Boolean).map((line) => {
  const [name = "", command = "", state = "", tools = "", error = ""] = line.split("\t");
  return { name, command, state, ...(tools ? { tools } : {}), ...(error ? { error } : {}) };
});

async function mcpCommand(io: CommandIO, arg: string): Promise<Panel | null> {
  const title = "MCP";
  const [verb = "", ...rest] = arg.split(/\s+/).filter(Boolean);
  if (verb === "quitar" && rest[0]) return fromLines(title, await io.ask("mcp", { action: "remove", name: rest[0] }), { tone: "ok" });
  if (verb === "probar" && rest[0]) return fromLines(title, await io.ask("mcp", { action: "probe", name: rest[0] }));
  if (verb === "agregar" && rest.length >= 2) return fromLines(title, await io.ask("mcp", { action: "add", name: rest[0], command: rest[1], args: rest.slice(2) }), { tone: "ok" });
  if (verb) return warnPanel(title, t("Uso: /mcp · /mcp agregar <nombre> <comando> [args] · /mcp probar <nombre> · /mcp quitar <nombre>", "Usage: /mcp · /mcp agregar <name> <command> [args] · /mcp probar <name> · /mcp quitar <name>"));
  const servers = parseMcp(await io.ask("mcp", { action: "status" }));
  const rows: Row[] = [
    ...servers.map((server) => ({ label: server.name, hint: `${server.state}${server.tools ? ` · ${server.tools} ${t("herramientas", "tools")}` : ""}${server.error ? ` · ${server.error}` : ""} · ${server.command}` })),
    { label: t("agregar…", "add…"), hint: t("un servidor MCP por stdio: nombre, comando y argumentos", "a stdio MCP server: name, command and arguments") },
  ];
  const choice = await io.pick(title, rows, { footer: t("Enter en un servidor: probar o quitar · los servidores corren en tu máquina, fuera del alcance HTTP", "Enter on a server: probe or remove") });
  if (choice === undefined) return null;
  if (choice === servers.length) {
    const name = await io.input(t("Nombre del servidor (letras, números, - y _)", "Server name"));
    if (!name) return null;
    const command = await io.input(t("Comando (p. ej. npx)", "Command (e.g. npx)"));
    if (!command) return null;
    const args = (await io.input(t("Argumentos, separados por espacio (Enter si no hay)", "Arguments, space-separated (Enter for none)"))) ?? "";
    return fromLines(title, await io.ask("mcp", { action: "add", name, command, args: args.split(/\s+/).filter(Boolean) }), { tone: "ok" });
  }
  const server = servers[choice]!;
  const action = await io.pick(server.name, [{ label: t("probar", "probe"), hint: t("conectar y contar sus herramientas", "connect and count its tools") }, { label: t("quitar", "remove"), hint: t("sacarlo de la configuración y cerrarlo", "remove from config and close it") }]);
  if (action === undefined) return null;
  if (action === 0) return fromLines(title, await io.ask("mcp", { action: "probe", name: server.name }));
  if (!(await io.confirm(t(`¿Quitar el servidor MCP «${server.name}»?`, `Remove MCP server “${server.name}”?`)))) return null;
  return fromLines(title, await io.ask("mcp", { action: "remove", name: server.name }), { tone: "ok" });
}

/* ---------- Alcance, identidades, consentimientos ---------- */

async function scopeCommand(io: CommandIO, arg: string): Promise<Panel | null> {
  const title = t("alcance", "scope");
  if (arg) return fromLines(title, await io.view("scope", arg), { tone: "ok" });
  const current = await io.view("scope");
  const choice = await io.pick(title, [
    { label: t("ver", "view"), hint: t("el alcance autorizado hoy", "what is authorized today") },
    { label: t("agregar", "add"), hint: t("reglas que entran (dominios, URLs, redes)", "rules that go in") },
    { label: t("excluir", "exclude"), hint: t("reglas que quedan afuera", "rules kept out") },
    { label: t("quitar", "remove"), hint: t("sacar una regla", "drop a rule") },
    { label: t("limpiar", "clear"), hint: t("borrar todo el alcance", "erase the whole scope") },
    { label: t("por sesión", "per session"), hint: t("el alcance de cada sesión del proyecto", "each session's scope in this project") },
    { label: t("fuentes de lectura", "reading sources"), hint: t("documentación o código público que el agente sólo lee, nunca prueba", "public docs or code the agent only reads, never tests") },
    { label: t("cabeceras fijas", "fixed headers"), hint: t("identificación enviada al objetivo", "identification sent to the target") },
  ], { footer: current[0] ?? "" });
  if (choice === undefined) return null;
  if (choice === 0) return fromLines(title, current);
  if (choice === 7) {
    const linea = await io.input(t("Nombre: valor · o quitar Nombre", "Name: value · or quitar Name"));
    return linea ? fromLines(title, await io.view("scope", `cabecera ${linea}`), { tone: "ok" }) : fromLines(title, current);
  }
  if (choice === 5) return fromLines(title, await io.view("scope", "sesiones"));
  if (choice === 6) {
    const sources = await io.input(t("Hosts o URLs de documentación o código público, separados por espacio (GitHub ya está)", "Docs or public code hosts or URLs, space-separated (GitHub is already there)"));
    return sources ? fromLines(title, await io.view("scope", `referencia ${sources}`), { tone: "ok" }) : null;
  }
  if (choice === 4) {
    if (!(await io.confirm(t("¿Borrar todo el alcance? El agente no va a poder tocar nada hasta que cargues otro.", "Erase the whole scope?")))) return null;
    return fromLines(title, await io.view("scope", "limpiar"), { tone: "warn" });
  }
  const verb = ["", "add", "excluir", "quitar"][choice]!;
  const rules = await io.input(t(`Reglas a ${["", "agregar", "excluir", "quitar"][choice]}, separadas por espacio`, "Rules, space-separated"));
  if (!rules) return null;
  return fromLines(title, await io.view("scope", `${verb} ${rules}`), { tone: "ok" });
}

async function identityCommand(io: CommandIO, arg: string): Promise<Panel | null> {
  const title = t("identidades", "identities");
  if (arg) return fromLines(title, await io.ask("identity", { value: arg }), { tone: "ok" });
  const current = await io.ask("identity", {});
  const pending = current.filter((line) => line.startsWith("Pendiente:")).map((line) => line.replace(/^Pendiente:\s*/, "").split(" · ")[0]!.trim());
  const rows: Row[] = [
    ...pending.map((name) => ({ label: name, hint: t("propuesta del agente: aprobar", "proposed by the agent: approve") })),
    { label: t("agregar…", "add…"), hint: t("una identidad con su cabecera (el valor queda oculto)", "an identity with its header (value stays hidden)") },
  ];
  const choice = await io.pick(title, rows, { footer: current[0] ?? "" });
  if (choice === undefined) return null;
  if (choice < pending.length) return fromLines(title, await io.ask("identity", { value: `aprobar ${pending[choice]}` }), { tone: "ok" });
  const name = await io.input(t("Nombre de la identidad (p. ej. comprador)", "Identity name"));
  if (!name) return null;
  const header = await io.input(t("Cabecera (p. ej. Cookie o Authorization)", "Header (e.g. Cookie)"));
  if (!header) return null;
  const value = await io.input(t(`Valor de ${header}`, `Value of ${header}`), { hidden: true });
  if (!value) return null;
  return fromLines(title, await io.ask("identity", { value: `${name} ${header}: ${value}` }), { tone: "ok" });
}

async function consentCommand(io: CommandIO, arg: string): Promise<Panel | null> {
  const title = t("consentimientos", "consents");
  if (arg) return fromLines(title, await io.ask("consent", { value: arg }), { tone: "ok" });
  const current = await io.ask("consent", {});
  const choice = await io.pick(title, [
    { label: t("ver", "view"), hint: t("lo otorgado y lo revocado", "granted and revoked") },
    { label: t("otorgar", "grant"), hint: t("borrar-ajeno: exige citar tu mensaje con la autorización", "borrar-ajeno: requires quoting your authorization") },
    { label: t("revocar", "revoke"), hint: t("borrar-ajeno vuelve a la guarda normal", "borrar-ajeno back to the normal guard") },
  ]);
  if (choice === undefined) return null;
  if (choice === 0) return fromLines(title, current);
  if (choice === 2) return fromLines(title, await io.ask("consent", { value: "borrar-ajeno no" }), { tone: "ok" });
  const quote = await io.input(t("Cita textual de tu mensaje con la autorización", "Quote your authorizing message"));
  if (!quote) return null;
  if (!(await io.confirm(t("Esto habilita borrar recursos ajenos dentro del alcance. ¿Confirmás?", "This allows deleting third-party resources within scope. Confirm?")))) return null;
  return fromLines(title, await io.ask("consent", { value: `borrar-ajeno si «${quote}»` }), { tone: "warn" });
}

/* ---------- El registro ---------- */

const panelOf = (title: string, op: () => Promise<string[]>, tone?: Tone) => async () => fromLines(title, await op(), tone ? { tone } : {});

/**
 * /sesiones: menú con buscador de las sesiones del proyecto (la más reciente primero, la actual marcada) y,
 * elegida una, qué hacer con ella: retomarla en esta pantalla, continuar su turno cortado, ramificarla,
 * renombrarla o ver su detalle. Al final, las sesiones de otros proyectos y cómo abrirlas.
 */
async function sessionsCommand(io: CommandIO, arg: string): Promise<Panel | null> {
  const title = t("sesiones", "sessions");
  const trimmed = arg.trim();
  if (/^(nueva|new)$/i.test(trimmed)) return io.switchSession ? io.switchSession("new") : fromLines(title, [t("Sólo en la TUI; en la terminal: cyber", "TUI only; in the terminal: cyber")]);
  if (/^(todos|all)$/i.test(trimmed)) return otherProjects(io);
  const rows = decodeRows(await io.ask("sesiones", { action: "list" }));
  if (trimmed) {
    const found = rows.find((r) => r.id.startsWith(trimmed));
    if (!found) return fromLines(title, [t(`No hay una sesión que empiece con «${trimmed}».`, `No session starts with "${trimmed}".`)], { tone: "warn" });
    return sessionActions(io, found);
  }
  const mark = (r: (typeof rows)[number]) => (r.current ? accent("▶") : r.state === "en curso" ? accent("●") : r.state === "interrumpida" ? warn("◌") : dim("·"));
  const menu: Row[] = [
    { label: t("＋ nueva sesión", "＋ new session"), hint: t("empezar de cero en este proyecto", "start fresh in this project") },
    ...rows.map((r) => ({ busqueda: r.title, label: `${mark(r)} ${relative(r.lastAt).padEnd(11)} ${(io.tituloSesion?.(r.title) ?? r.title).slice(0, 48)}`, hint: `${r.id.slice(0, 8)} · ${r.messages} msj · USD ${r.usd}${r.findings ? ` · ${r.findings} ${r.findings === 1 ? t("hallazgo", "finding") : t("hallazgos", "findings")}` : ""} · ${r.current ? t("esta", "this one") : r.state}` })),
    { label: t("⋯ otros proyectos", "⋯ other projects"), hint: t("sesiones de todos tus proyectos", "sessions across your projects") },
  ];
  const choice = await io.pick(title, menu, { at: rows.length ? 1 : 0, search: true, footer: t("Enter elige · escribí para buscar · Esc vuelve", "Enter picks · type to search · Esc goes back") });
  if (choice === undefined) return null;
  if (choice === 0) return io.switchSession ? io.switchSession("new") : fromLines(title, [t("Sólo en la TUI.", "TUI only.")]);
  if (choice === menu.length - 1) return otherProjects(io);
  return sessionActions(io, rows[choice - 1]!);
}

async function sessionActions(io: CommandIO, row: ReturnType<typeof decodeRows>[number]): Promise<Panel | null> {
  const short = row.id.slice(0, 8);
  const title = `${t("sesión", "session")} ${short}`;
  const actions: Array<{ row: Row; run: () => Promise<Panel | null> }> = [];
  if (!row.current) actions.push({ row: { label: t("retomar acá", "resume here"), hint: t(`${row.messages} mensajes · ${row.state}`, `${row.messages} messages · ${row.state}`) }, run: () => (io.switchSession ? io.switchSession(row.id) : Promise.resolve(fromLines(title, [`cyber -s ${short}`]))) });
  if (row.state === "interrumpida") actions.push({ row: { label: t("continuar el turno cortado", "continue the interrupted turn"), hint: t("retoma y sigue donde quedó", "resumes and picks up where it stopped") }, run: async () => { const panel = row.current ? null : await io.switchSession?.(row.id); io.resume(); return panel ?? fromLines(title, [t("Turno retomado.", "Turn resumed.")], { tone: "ok" }); } });
  actions.push(
    { row: { label: t("ramificar", "fork"), hint: t("una sesión nueva que arranca con esta conversación", "a new session starting from this conversation") }, run: async () => { const [fresh] = await io.ask("sesiones", { action: "fork", session: row.id }); return io.switchSession && fresh ? io.switchSession(fresh) : fromLines(title, [t(`Rama creada: cyber -s ${(fresh ?? "").slice(0, 8)}`, `Fork created: cyber -s ${(fresh ?? "").slice(0, 8)}`)], { tone: "ok" }); } },
    { row: { label: t("renombrar", "rename"), hint: (io.tituloSesion?.(row.title) ?? row.title).slice(0, 40) }, run: async () => { const value = await io.input(t("Título", "Title")); if (!value?.trim()) return null; return fromLines(title, await io.ask("sesiones", { action: "rename", session: row.id, title: value }), { tone: "ok" }); } },
    { row: { label: t("detalle", "details"), hint: t("último intercambio, gasto, hallazgos", "last exchange, spend, findings") }, run: async () => fromLines(title, await io.ask("sesiones", { action: "detalle", session: row.id })) },
    { row: { label: t("volver", "back") }, run: () => sessionsCommand(io, "") },
  );
  const choice = await io.pick(`${title} · ${(io.tituloSesion?.(row.title) ?? row.title).slice(0, 40)}`, actions.map((a) => a.row), { footer: `${relative(row.lastAt)} · USD ${row.usd} · ${row.current ? t("esta sesión", "this session") : row.state}` });
  if (choice === undefined) return null;
  return actions[choice]!.run();
}

async function otherProjects(io: CommandIO): Promise<Panel | null> {
  const title = t("otros proyectos", "other projects");
  const rows = (await io.ask("sesiones", { action: "list", todos: true })).map((l) => l.split("	")).filter((f) => f.length >= 7);
  if (!rows.length) return fromLines(title, [t("No hay sesiones guardadas en otros proyectos.", "No saved sessions in other projects.")]);
  const choice = await io.pick(title, rows.map(([, , nombre, session, fecha, estado, titulo]) => ({ busqueda: titulo, label: `${relative(fecha!).padEnd(11)} ${bold(nombre!)}  ${(io.tituloSesion?.(titulo!) ?? titulo!).slice(0, 40)}`, hint: `${session!.slice(0, 8)} · ${estado}` })), { search: true, footer: t("Enter muestra cómo abrirla · Esc vuelve", "Enter shows how to open it · Esc goes back") });
  if (choice === undefined) return null;
  const [, ruta, nombre, session] = rows[choice]!;
  return fromLines(title, [t(`La sesión ${session!.slice(0, 8)} es del proyecto ${nombre}. Abrila en otra terminal:`, `Session ${session!.slice(0, 8)} belongs to project ${nombre}. Open it in another terminal:`), `cyber -C ${ruta} -s ${session!.slice(0, 8)}`], { footer: t("Cada proyecto tiene su daemon: no se cambia desde acá.", "Each project has its own daemon: it cannot be switched from here.") });
}

/** Nombres de las categorías de cobertura tal como se leen (el daemon los manda como identificadores, sin tildes). */
const COVERAGE_NAMES: Record<string, string> = { reconocimiento: "Reconocimiento", autenticacion: "Autenticación", "control de acceso": "Control de acceso", inyeccion: "Inyección", "logica de negocio": "Lógica de negocio", configuracion: "Configuración", deteccion: "Detección" };
const COVERAGE_MARK: Record<string, (text: string) => string> = { "✓": accent, "~": warn, "–": dim, "○": dim };
/**
 * /cobertura: cada categoría en su línea (marca y nombre) y lo que abarca debajo, con sangría; el daemon la
 * manda como una sola línea larga por categoría, que cortada al ancho se volvía un bloque difícil de leer.
 */
export function coverageLines(lines: string[]): string[] {
  const out: string[] = [];
  for (const line of lines) {
    const row = /^\s*([○✓~–]) ([^:]+): (.+)$/.exec(line);
    if (!row) { out.push(line); continue; }
    const [, mark, name, text] = row as unknown as [string, string, string, string];
    out.push(`${COVERAGE_MARK[mark]!(mark)} ${bold(COVERAGE_NAMES[name] ?? name.charAt(0).toUpperCase() + name.slice(1))}`, `    ${text.charAt(0).toUpperCase()}${text.slice(1)}`, "");
  }
  return out;
}

export function buildCommands(): CommandSpec[] {
  const commands: CommandSpec[] = [
    { name: "streamer", description: "Prender o apagar el modo streamer · F8 cubre la pantalla", usage: "[hosts siempre|privados · uso mostrar|tapar]", run: async (io, arg) => io.streamer?.(arg) ?? null },
    { name: "limpiar", aliases: ["clear"], description: "Limpiar la pantalla y volver al sello; conserva la sesión (Ctrl+L)", run: async (io) => { io.clear(); return null; } },
    { name: "costos", aliases: ["cost"], description: "Detalle del gasto de API", run: (io) => panelOf("costos", () => io.view("costos"))() },
    { name: "memory", aliases: ["memoria"], description: "Buscar o listar la memoria del proyecto", usage: "[palabras]", run: (io, arg) => panelOf("memoria", () => io.view("memoria", arg))() },
    { name: "evidence", aliases: ["evidencia"], description: "Artefactos guardados; con hash, su contenido", usage: "[hash]", run: (io, arg) => panelOf("evidencia", () => io.view("evidencia", arg))() },
    { name: "presupuesto", aliases: ["budget"], description: "Tope de gasto de la sesión en USD", usage: "<USD> | sin", run: (io, arg) => amount(io, { op: "budget", title: t("tope de la sesión", "session budget"), unit: "USD", presets: ["1", "2", "5", "10", "20"], footer: "" }, arg) },
    { name: "peticiones", aliases: ["requests"], description: "Tope de peticiones HTTP de la sesión", usage: "<N> | sin", run: (io, arg) => amount(io, { op: "requests", title: t("tope de peticiones", "request cap"), unit: "", presets: ["100", "300", "1000", "3000"], footer: "" }, arg) },
    { name: "ritmo", aliases: ["rate"], description: "Peticiones por segundo como máximo", usage: "<N> | sin", run: (io, arg) => amount(io, { op: "rate", title: t("ritmo máximo", "max rate"), unit: "", presets: ["1", "2", "5", "10"], footer: "" }, arg) },
    { name: "verificacion", aliases: ["verificación", "verification"], description: "Cuándo corre solo el verificador: automática, a pedido o con tope de gasto por sesión", usage: "automatica | a-pedido | tope <USD>", run: (io, arg) => (/^tope\s+\S/i.test(arg.trim()) ? io.ask("verificacion", { value: arg.trim() }).then((lines) => fromLines(t("verificación", "verification"), lines, { tone: "ok" })) : choose(io, { name: "verificacion", op: "verificacion", title: t("verificación automática", "automatic verification"), options: verifyOptions }, arg)) },
    { name: "investigacion-auto", aliases: ["investigation-auto"], description: "Apertura automática de investigación de código, apagada por defecto", usage: "si | no", run: (io, arg) => choose(io, { name: "investigacion-auto", op: "investigation_auto", title: t("investigación automática", "automatic investigation"), options: investigationOptions }, arg) },
    { name: "escaneres", aliases: ["scanners", "escáneres"], description: "Escáneres externos: habilitar o apagar", usage: "si | no", run: (io, arg) => choose(io, { name: "escaneres", op: "scanners", title: t("escáneres externos", "external scanners"), options: scannerOptions }, arg) },
    { name: "perfil", aliases: ["profile"], description: "Perfil de capacidades: qué arsenal hay disponible", usage: PROFILES.join(" | "), run: (io, arg) => choose(io, { name: "perfil", op: "perfil", title: t("perfil", "profile"), options: profileOptions }, arg) },
    { name: "permisos", aliases: ["permissions"], description: "Permisos de shell: autoaprobar todo, o ver, permitir, quitar o limpiar prefijos", usage: "todo | normal | permitir <prefijo> | quitar <prefijo> | limpiar", run: async (io, arg) => {
      const [accion, ...resto] = (arg ?? "").split(/\s+/).filter(Boolean);
      const prefix = resto.join(" ");
      if (accion === "todo" || accion === "normal") return fromLines("permisos", await io.ask("permisos", { value: accion }), { tone: "ok" });
      if (accion === "limpiar") return fromLines("permisos", await io.ask("permisos", { value: "limpiar" }), { tone: "ok" });
      if (accion === "quitar" && prefix) return fromLines("permisos", await io.ask("permisos", { value: `quitar ${prefix}` }), { tone: "ok" });
      if (accion === "permitir" && prefix) return fromLines("permisos", await io.ask("permisos", { value: `permitir ${prefix}` }), { tone: "ok" });
      const escrito = await io.input(t("prefijo a permitir siempre (p. ej. git push)", "prefix to always allow (e.g. git push)"));
      if (!escrito) return fromLines("permisos", await io.ask("permisos"));
      return fromLines("permisos", await io.ask("permisos", { value: `permitir ${escrito}` }), { tone: "ok" });
    } },
    { name: "deteccion", aliases: ["detection", "detección"], description: "Modo purple: señales esperadas vs detectadas, y gaps por acción", run: (io) => panelOf("detección", () => io.ask("deteccion"))() },
    { name: "razonamiento", aliases: ["reasoning", "effort"], description: "Razonamiento previo del modelo: prenderlo, apagarlo o elegir cuánto razona", usage: "si | no | defecto | bajo | medio | alto | max", run: (io, arg) => choose(io, { name: "razonamiento", op: "reasoning", title: t("razonamiento", "reasoning"), options: reasoningOptions }, arg) },
    { name: "senuelos", aliases: ["decoys", "señuelos"], description: t("Señuelos del objetivo: permitir o bloquear los detectados; marcar, quitar o listar los que ya sabés que son trampas", "Target decoys: allow or block detected ones; mark, remove or list the ones you know are traps"), usage: "permitir | bloquear | marcar <host|URL|/ruta> [motivo] | quitar <patrón|n> | lista", run: async (io, arg) => /^(marcar|mark|agregar|add|quitar|sacar|desmarcar|unmark|remove|lista|listar|ver|list|marcados)\b/i.test(arg.trim()) ? fromLines(t("señuelos marcados", "marked decoys"), await io.ask("decoy_marks", { value: arg.trim() }), { tone: "ok" }) : choose(io, { name: "senuelos", op: "decoys", title: t("señuelos", "decoys"), options: decoyOptions }, arg) },
    { name: "modelo", aliases: ["model", "modelos", "models"], description: "Ver los modelos disponibles o cambiar el de la sesión (el base) o el fuerte", usage: "[nombre] | fuerte [nombre]", run: modelCommand },
    { name: "router", aliases: ["ruteo"], description: t("Router de modelos: el ejecutor hace el bucle y el fuerte decide sobre traspasos; modo, estado y ahorro", "Model router: the executor runs the loop and the strong decides on handoffs; mode, status and savings"), usage: "auto | fijo | estado | medio <modelo>|no", run: routerCommand },
    { name: "agente", aliases: ["agent"], description: "User-Agent con el que me identifico", usage: "<texto> | defecto", run: async (io, arg) => {
      const title = "User-Agent";
      if (arg) return fromLines(title, await io.ask("agent", { value: arg }), { tone: "ok" });
      const current = await io.ask("agent", {});
      const choice = await io.pick(title, [{ label: t("ver", "view") }, { label: t("por defecto", "default"), hint: t("el del harness", "the harness one") }, { label: t("otro…", "other…"), hint: t("escribirlo", "type it") }], { footer: current[0] ?? "" });
      if (choice === undefined) return null;
      if (choice === 0) return fromLines(title, current);
      const value = choice === 1 ? "defecto" : await io.input("User-Agent");
      if (!value) return null;
      return fromLines(title, await io.ask("agent", { value }), { tone: "ok" });
    } },
    { name: "cobertura", aliases: ["coverage"], description: "Cobertura de la evaluación: categorías, peticiones y superficie", run: async (io) => fromLines(t("cobertura", "coverage"), coverageLines(await io.view("cobertura")), { footer: t("✓ cubierta · ~ limitada · – no aplica · ○ pendiente", "✓ covered · ~ limited · – not applicable · ○ pending") }) },
    { name: "grafo", aliases: ["graph"], description: t("Grafo de hechos: lo observado del objetivo, qué falta probar, vecinos, caminos, la cadena de un hallazgo; exportar a JSON, DOT o Mermaid", "Fact graph: what was observed on the target, what is left to test, neighbors, paths, a finding's chain; export to JSON, DOT or Mermaid"), usage: "[faltantes|vecinos <nodo>|caminos <a> → <b>|hallazgo <id>|exportar json|dot|mermaid]", run: async (io, arg) => fromLines(t("grafo", "graph"), await io.view("grafo", arg)) },
    { name: "jobs", aliases: ["trabajos"], description: "Sesiones del proyecto y su estado", run: (io) => panelOf("trabajos", () => io.view("jobs"))() },
    { name: "cves", aliases: ["cve"], description: t("CVEs nuevos críticos y altos (Zero Wire): estado del feed, los que podrían aplicar a esta sesión y los últimos", "New critical and high CVEs (Zero Wire): feed status, those that could apply to this session and the latest"), usage: "[actualizar] [N]", run: (io, arg) => panelOf("cves", () => io.view("cves", arg))() },
    { name: "sesiones", aliases: ["resume", "retomar", "sesion", "sessions"], description: "Sesiones del proyecto: retomar acá, nueva, ramificar, renombrar o ver el detalle; también las de otros proyectos", usage: "[<id>|nueva|todos]", run: sessionsCommand },
    { name: "continuar", aliases: ["continue"], description: "Retomar un turno interrumpido", run: async (io) => { io.resume(); return null; } },
    { name: "orquesta", aliases: ["harnesses"], description: "Otros harnesses (Claude Code, Codex, pi, OpenCode, Orobas) corriendo sobre worktrees: ver, parar, limpiar", usage: "[ver|parar|limpiar <id> [rama]|harnesses]", run: async (io, arg) => {
      if (!arg.trim() || (/^(ver|view|parar|stop|limpiar|clean)$/i.test(arg.trim()))) return menuOrquesta(io);
      const [verb = "", id = ""] = arg.trim().split(/\s+/);
      if (/^(ver|view)$/i.test(verb) && id) return fromLines(`orquesta #${id}`, await io.ask("orquesta", { action: "ver", run: id }));
      if (/^(parar|stop)$/i.test(verb) && id) return fromLines("orquesta", await io.ask("orquesta", { action: "parar", run: id }), { tone: "ok" });
      if (/^(limpiar|clean)$/i.test(verb) && id) return fromLines("orquesta", await io.ask("orquesta", { action: "limpiar", run: id, rama: /\b(rama|branch)\b/i.test(arg) }), { tone: "ok" });
      if (/^harnesses$/i.test(verb)) return fromLines("harnesses", await io.ask("orquesta", { action: "harnesses" }));
      return fromLines("orquesta", [t(`No conozco «${verb}». Opciones: ver (view), parar (stop), limpiar (clean) <id> [rama|branch], harnesses`, `Unknown "${verb}". Options: view, stop, clean <id> [branch], harnesses`)], { tone: "warn" });
    } },
    { name: "ultra", description: "Modo ultra: reparte una tarea entre varios harnesses en paralelo, cada uno en su worktree; con --objetivo, varios frentes sobre el objetivo", usage: "[<tarea>] [--objetivo] [--partes N] [--con claude,codex,pi,opencode,cyber]", run: async (io, arg) => {
      if (!arg.trim()) return selectorUltra(io);
      const harnesses = leerHarnesses(await io.ask("orquesta", { action: "harnesses" }));
      const enCurso = leerCorridas(await io.ask("orquesta", {})).filter((c) => c.enCurso).length;
      const armado = armarUltra(arg, ultraGuardado(), harnesses, enCurso);
      io.notice?.(fromLines("ultra", [armado.linea]));
      arg = armado.arg;
      const [prompt] = await io.ask("orquesta", { action: "ultra", tarea: arg });
      if (!io.send || !prompt) return fromLines("ultra", [prompt ?? ""]);
      io.send(prompt);
      return null;
    } },
    { name: "cola", aliases: ["queue"], description: "Mensajes que esperan a que termine el turno: ver, mandar ya o vaciar", usage: "[ya|vaciar]", run: async (io, arg) => {
      const title = t("cola", "queue");
      if (/^(vaciar|clear)$/i.test(arg)) return fromLines(title, await io.ask("queue", { action: "clear" }), { tone: "ok" });
      if (/^(ya|now)$/i.test(arg)) return fromLines(title, await io.ask("queue", { action: "ya" }), { tone: "ok" });
      const current = await io.ask("queue", { action: "list" });
      if (!/^\d+ mensaje/.test(current[0] ?? "")) return fromLines(title, current);
      const choice = await io.pick(title, [
        { label: t("ver", "view"), hint: t("dejarlos como están", "leave them") },
        { label: t("mandar ya", "send now"), hint: t("corta el turno en curso y salen enseguida (Ctrl+Y)", "stops the running turn and they go out right away (Ctrl+Y)") },
        { label: t("vaciar", "clear"), hint: t("descartar todos los mensajes en cola", "drop every queued message") },
      ], { footer: current[0] ?? "" });
      if (choice === undefined) return null;
      if (choice === 0) return fromLines(title, current);
      if (choice === 1) return fromLines(title, await io.ask("queue", { action: "ya" }), { tone: "ok" });
      if (!(await io.confirm(t("¿Descartar lo que está en cola?", "Drop the queued messages?")))) return null;
      return fromLines(title, await io.ask("queue", { action: "clear" }), { tone: "ok" });
    } },
    { name: "investigar", aliases: ["investigacion", "investigación", "investigate"], description: t("Modo investigación: mapa, hipótesis y harnesses ejecutables en tres niveles, con diario y tope de USD; estado, pausa, seguir o cerrar", "Investigation mode: map, hypotheses and executable harnesses on three levels, with a journal and a USD cap; status, pause, resume or close"), usage: "<objetivo> [usd] | estado | pausa | seguir [usd] | cerrar", run: investigarCommand },
    { name: "ya", aliases: ["now"], description: "Cortar el turno en curso y mandar ya el mensaje (y lo que haya en cola)", usage: "[texto]", run: async (io, arg) => {
      if (io.interrupt) { io.interrupt(arg); return null; }
      // Sin TUI no hay editor: lo que esté en cola sale ya.
      return fromLines(t("cola", "queue"), await io.ask("queue", { action: "ya" }), { tone: "ok" });
    } },
    { name: "hallazgos", aliases: ["findings"], description: "Hallazgos de esta sesión («todos»: del proyecto), detalle por id, o cambiar estado", usage: "[todos | id] [estado]", run: (io, arg) => panelOf("hallazgos", async () => (await io.view("findings", arg)).map(etiquetarHallazgo))() },
    { name: "informe", aliases: ["report"], description: "Generar el informe Markdown de esta sesión («proyecto»: de todas)", usage: "[en] [proyecto]", run: async (io, arg) => {
      const title = t("informe", "report");
      if (arg) return fromLines(title, await io.view("informe", arg), { tone: "ok" });
      const choice = await io.pick(title, [{ label: "castellano", hint: t("el informe en castellano", "report in Spanish") }, { label: "english", hint: t("el informe en inglés", "report in English") }]);
      if (choice === undefined) return null;
      return fromLines(title, await io.view("informe", choice === 1 ? "en" : ""), { tone: "ok" });
    } },
    { name: "datos", aliases: ["data", "trazas", "traces"], description: "Trazas: compartirlas con Elevate AI, guardarlas sólo en tu PC o no guardarlas; ver qué incluyen y dónde quedan", usage: "[compartir | local | no | subir]", run: async (io, arg) => {
      const title = t("trazas", "traces");
      const pedido = arg.trim().toLowerCase();
      if (/^(compartir|local|no)$/.test(pedido)) return fromLines(title, await io.ask("datos", { action: "modo", value: pedido }), { tone: pedido === "compartir" ? "ok" : "warn" });
      if (/^revocar$/.test(pedido)) return fromLines(title, await io.ask("datos", { action: "revoke" }), { tone: "warn" });
      if (/^subir$/.test(pedido)) return fromLines(title, await io.ask("datos", { action: "share" }), { tone: "ok" });
      const status = await io.ask("datos", { action: "status" });
      const choice = await io.pick(title, [
        { label: t("ver", "view"), hint: t("qué incluyen, qué rige y dónde quedan las locales", "what they include, what is in effect and where local ones are") },
        { label: "compartir", hint: t("el material va a Elevate AI para entrenar el agente (con los secretos tapados)", "the material goes to Elevate AI to train the agent (secrets masked)") },
        { label: "local", hint: t("nada sale al servicio; el material queda en tu PC, en JSONL", "nothing goes to the service; the material stays on your PC, as JSONL") },
        { label: "no", hint: t("nada sale al servicio y no se arma material", "nothing goes to the service and no material is built") },
        { label: t("subir lo anterior", "upload past sessions"), hint: t("sólo en compartir: sube las sesiones anteriores de este proyecto, anónimas", "compartir only: uploads this project's past sessions, anonymized") },
      ], { footer: status[0] ?? "" });
      if (choice === undefined) return null;
      if (choice === 0) return fromLines(title, status);
      if (choice === 4) return fromLines(title, await io.ask("datos", { action: "share" }), { tone: "ok" });
      const modo = (["compartir", "local", "no"] as const)[choice - 1]!;
      return fromLines(title, await io.ask("datos", { action: "modo", value: modo }), { tone: modo === "compartir" ? "ok" : "warn" });
    } },
    { name: "trayectorias", aliases: ["trajectories"], description: "Exportar las sesiones completas (JSONL tachado) para evaluar o entrenar", usage: "[anonimo] [sesión…]", run: async (io, arg) => {
      const title = t("trayectorias", "trajectories");
      if (arg) return fromLines(title, await io.view("trayectorias", arg), { tone: "ok" });
      const choice = await io.pick(title, [
        { label: t("con hosts", "with hosts"), hint: t("credenciales tachadas; los hosts del alcance quedan", "credentials redacted; scope hosts kept") },
        { label: t("anónimo", "anonymous"), hint: t("además reemplaza los hosts por host-1, host-2…", "also replaces hosts with host-1, host-2…") },
      ], { footer: t("una línea JSON por sesión en cyber-informes/; no sale de tu máquina", "one JSON line per session in cyber-informes/; stays on your machine") });
      if (choice === undefined) return null;
      return fromLines(title, await io.view("trayectorias", choice === 1 ? "anonimo" : ""), { tone: "ok" });
    } },
    { name: "verificar", aliases: ["verify"], description: "Verificador independiente: un candidato o todos", usage: "[id]", run: async (io, arg) => {
      const title = t("verificación", "verification");
      if (arg) return fromLines(title, await io.ask("verify", { value: arg }));
      if (!(await io.confirm(t("¿Verificar todos los candidatos pendientes? Usa el modelo y tarda.", "Verify every pending candidate? It uses the model and takes a while.")))) return null;
      return fromLines(title, await io.ask("verify", { value: "todos" }));
    } },
    { name: "alcance", aliases: ["scope"], description: "Alcance de la sesión y cabeceras fijas del proyecto", usage: "[add|excluir|quitar|referencia <reglas>|limpiar|recuperar <rev>|sesiones|cabecera Nombre: valor|cabecera quitar Nombre]", run: scopeCommand },
    { name: "h1", description: "HackerOne: programas, o alcance de un programa", usage: "[programas | alcance <programa>]", run: async (io, arg) => {
      const title = "HackerOne";
      if (arg) { const [action, handle] = arg.split(/\s+/); return fromLines(title, await io.ask("h1", { action, handle })); }
      const choice = await io.pick(title, [{ label: t("programas", "programs"), hint: t("los que tenés a mano", "the ones at hand") }, { label: t("alcance…", "scope…"), hint: t("de un programa, por su nombre", "of one program, by handle") }]);
      if (choice === undefined) return null;
      if (choice === 0) return fromLines(title, await io.ask("h1", { action: "programas" }));
      const handle = await io.input(t("Nombre del programa en HackerOne", "HackerOne program handle"));
      if (!handle) return null;
      return fromLines(title, await io.ask("h1", { action: "alcance", handle }));
    } },
    { name: "orobas", description: "Clave de orobas: iniciar sesión, actualizar o revocar", run: async (io) => fromLines("orobas", await accountMenu("orobas", menuIO(io))) },
    { name: "hackerone", description: "Cuenta de HackerOne: iniciar sesión, actualizar o revocar", run: async (io) => fromLines("HackerOne", await accountMenu("hackerone", menuIO(io))) },
    { name: "correo", aliases: ["mail"], description: "Casillas de correo de prueba: agregar o quitar", run: async (io) => fromLines(t("correo de prueba", "test mail"), await mailMenu(menuIO(io))) },
    { name: "navegador", aliases: ["browser", "chrome"], description: t("Tu navegador (extensión de Orobas): ver si está conectado, y autorizarlo o revocarlo en este proyecto", "Your browser (Orobas extension): see whether it is connected, and allow or revoke it in this project"), usage: "si | no", run: async (io, arg) => fromLines(t("navegador", "browser"), await io.ask("navegador", arg.trim() ? { value: arg.trim() } : {}), arg.trim() ? { tone: "ok" } : {}) },
    ...PLATFORM_NAMES.map((name): CommandSpec => ({ name, description: `Cuenta de ${name}: iniciar sesión o revocar`, run: async (io) => fromLines(name, await platformMenu(name, name, menuIO(io))) })),
    { name: "identity", aliases: ["identidad"], description: "Identidades: ver propuestas, aprobar o agregar", usage: "[aprobar <nombre> | <nombre> <cabecera>: <valor>]", run: identityCommand },
    { name: "consent", aliases: ["consentimiento"], description: "Consentimientos de doble efecto: ver, otorgar o revocar", usage: "[borrar-ajeno si «cita» | borrar-ajeno no]", run: consentCommand },
    { name: "mcp", description: "Servidores MCP: estado, probar, agregar o quitar", usage: "[agregar <nombre> <comando> [args] | probar <nombre> | quitar <nombre>]", run: mcpCommand },
    { name: "herramientas", aliases: ["toolbox"], description: "Qué escáneres están instalados", run: (io) => panelOf("caja de herramientas", () => io.ask("toolbox"))() },
    { name: "inicio", aliases: ["onboarding"], description: "Inicio guiado: cuenta, perfil, herramientas, navegador, cuentas y alcance, paso a paso", run: async (io) => {
      if (!io.inicio) return fromLines(t("inicio", "setup"), await io.ask("inicio", {}));
      await io.inicio();
      return null;
    } },
    { name: "novedades", aliases: ["news"], description: t("Lo nuevo de la TUI", "What's new in the TUI"), run: async () => fromLines(t("Novedades", "What's new"), lineasDe(NOVEDADES)) },
    { name: "conexiones", menu: {}, description: t("Cuentas y servicios conectados: nubes, orobas, HackerOne, correo de prueba y tu navegador", "Connected accounts and services: clouds, orobas, HackerOne, test mail and your browser"), run: async () => warnPanel("conexiones", `${t("Uso", "Usage")}: /conexiones [${hijos("conexiones").map((h) => h.name).join("|")}]`) },
    { name: "limites", menu: {}, description: t("Topes de gasto, peticiones y ritmo, y cuánto llevás gastado", "Spend, request and rate caps, and what you've spent"), run: async () => warnPanel("limites", `${t("Uso", "Usage")}: /limites [${hijos("limites").map((h) => h.name).join("|")}]`) },
    { name: "diseño", aliases: ["diseno", "layout"], description: t("Cómo se ve: ventanas, pestañas, tema, mouse y efectos", "How it looks: windows, tabs, theme, mouse and effects"), run: (io) => configCommand(io, (s) => !!s.diseno, t("Diseño", "Layout")) },
    { name: "pestañas", aliases: ["pestanas", "tabs"], description: t("Editar las pestañas: cuáles, en qué orden y qué muestran", "Edit tabs: which, in what order and what they show"), run: async (io) => { await pestanasCommand(io); return null; } },
    { name: "ventanas", aliases: ["windows"], description: t("Varias ventanas a la vez", "Several windows at once"), run: (io) => ventanasCommand(io) },
    { name: "config", aliases: ["configuracion", "configuración", "settings"], description: "Todos los ajustes del proyecto en un lugar: buscar, cambiar con ←→ o abrir con Enter", run: (io) => configCommand(io) },
    { name: "idioma", aliases: ["lang", "language"], description: "Idioma de la interfaz: español, inglés o el del sistema", usage: "es | en | sistema", run: async (io, arg) => {
      const options: Array<{ label: string; value: Idioma | undefined }> = [{ label: "español", value: "es" }, { label: "English", value: "en" }, { label: t("el del sistema", "system default"), value: undefined }];
      const current = idiomaGuardado();
      let choice: number | undefined = arg ? ["es", "en", "sistema"].indexOf(arg.trim().toLowerCase().replace(/^system$/, "sistema")) : undefined;
      if (choice === -1) return fromLines(t("idioma", "language"), [t("Uso: /idioma es | en | sistema", "Usage: /idioma es | en | sistema")], { tone: "warn" });
      choice ??= await io.pick(t("idioma", "language"), options.map((option) => ({ label: option.label, hint: option.value === current ? t("Actual", "Current") : "" })), { at: options.findIndex((option) => option.value === current) });
      if (choice === undefined) return null;
      const { label, value } = options[choice]!;
      const aviso = elegirIdioma(value);
      return fromLines(t("idioma", "language"), [value ? t(`Interfaz en ${label}.`, `Interface in ${label}.`) : t("Interfaz en el idioma del sistema.", "Interface follows the system language."), ...(aviso ? [aviso] : [])], { tone: aviso ? "warn" : "ok" });
    } },
    { name: "tema", aliases: ["theme"], description: t("Tema de colores: Orobas, Elevate AI, Hacker, Filete porteño, Hornero o Hacker argentino", "Color theme: Orobas, Elevate AI, Hacker, Filete porteño, Hornero or Argentine hacker"), usage: "[nombre]", run: (io, arg) => temaCommand(io, arg) },
    { name: "ayuda", aliases: ["help"], description: "Teclas y comandos", run: async (io) => helpPanel(io.keys()) },
    { name: "salir", aliases: ["quit"], description: "Salir", run: async (io) => { io.exit(); return null; } },
  ];
  return agrupar(commands);
}

/** Los comandos que muestra la lista de /, en este orden; el resto vive en un grupo o está oculto. */
export const VISIBLES = ["sesiones", "hallazgos", "informe", "alcance", "limites", "modelo", "razonamiento", "ultra", "conexiones", "herramientas", "diseño", "config", "inicio", "novedades", "ayuda", "streamer", "limpiar", "salir"];

const PADRE: Record<string, string[]> = {
  sesiones: ["jobs", "continuar"], modelo: ["router"], hallazgos: ["verificar", "verificacion", "evidence", "cobertura", "grafo", "cves", "memory"], informe: ["trayectorias", "datos"],
  alcance: ["senuelos", "identity", "consent", "permisos", "agente", "deteccion"], limites: ["presupuesto", "peticiones", "ritmo", "costos"],
  conexiones: [...PLATFORM_NAMES, "orobas", "hackerone", "h1", "correo", "navegador"], herramientas: ["perfil", "escaneres", "mcp"], diseño: ["ventanas", "pestañas", "tema"], config: ["idioma", "investigacion-auto"],
};
const CASA: Record<string, string> = { hallazgos: t("Lista de hallazgos", "Findings list"), informe: t("Generar el informe", "Generate the report"), alcance: t("Ver y editar el alcance", "View and edit the scope"), herramientas: t("Qué hay instalado", "What's installed") };

/** Pone cada comando en su grupo, envuelve el run de los grupos (hijo, run propio o menú) y ordena según VISIBLES. */
function agrupar(commands: CommandSpec[]): CommandSpec[] {
  const padre = (name: string) => Object.keys(PADRE).find((p) => PADRE[p]!.includes(name));
  const marcados = commands.map((c) => ({ ...c, ...(padre(c.name) ? { parent: padre(c.name) } : {}), ...(c.name === "cola" || c.name === "ya" || c.name === "orquesta" || c.name === "investigar" ? { hidden: true } : {}), ...(CASA[c.name] ? { menu: { casa: CASA[c.name] } } : {}) }));
  const lista = marcados.map((c) => {
    const hs = (PADRE[c.name] ?? []).map((n) => marcados.find((m) => m.name === n)!);
    if (!hs.length) return c;
    const propio = c.run;
    const run: CommandSpec["run"] = async (io, arg) => {
      const texto = arg.trim();
      const first = (/^\S*/.exec(texto)?.[0] ?? "").toLowerCase();
      const hijo = first ? hs.find((h) => h.name === first || h.aliases?.includes(first)) : undefined;
      if (hijo) return hijo.run(io, texto.slice(first.length).trim());
      if (arg.trim() || !c.menu) return propio(io, arg);
      const casa = c.menu.casa;
      const choice = await io.pick(`/${c.name}`, [...(casa ? [{ label: casa }] : []), ...hs.map((h) => ({ label: `/${h.name}`, hint: h.description }))]);
      if (choice === undefined) return null;
      if (casa && choice === 0) return propio(io, "");
      return hs[choice - (casa ? 1 : 0)]!.run(io, "");
    };
    return { ...c, run };
  });
  const orden = (c: CommandSpec) => { const i = VISIBLES.indexOf(c.name); return i < 0 ? VISIBLES.length : i; };
  return lista.sort((a, b) => orden(a) - orden(b));
}

export const menuIO = (io: CommandIO) => ({
  ask: (op: string, payload: object) => io.ask(op, payload),
  pick: (title: string, options: string[]) => io.pick(title, options),
  askHidden: (label: string) => io.input(label, { hidden: true }),
  notice: (lines: string[]) => io.notice?.({ title: "orobas", lines, footer: t("esperando tu aprobación en el sitio · Esc cancela", "waiting for your approval on the site · Esc cancels") }),
});

export function helpPanel(keys: string[]): Panel {
  const lines = [...keys, ""];
  for (const name of VISIBLES) {
    const command = COMMANDS.find((c) => c.name === name)!;
    lines.push(`  /${name.padEnd(13)} ${command.description}${command.usage ? `  ·  ${command.usage}` : ""}`);
    const hs = hijos(name);
    if (hs.length) lines.push(dim(`      ${hs.map((h) => h.name).join(", ")}`));
  }
  return { title: t("ayuda", "help"), lines, footer: t("Tab completa un comando · ↑↓ recorre la lista de /", "Tab completes a command · ↑↓ walks the / list") };
}

export const COMMANDS: CommandSpec[] = buildCommands();

/** Miembros de un grupo, en el orden en que se registraron. */
export const hijos = (name: string): CommandSpec[] => (PADRE[name] ?? []).map((n) => COMMANDS.find((c) => c.name === n)!);

/** Lista plana para el manual y el autocompletado: nombre, alias y descripción. */
export const TUI_COMMANDS: Array<{ name: string; aliases: string[]; description: string; parent?: string }> = COMMANDS.map(({ name, aliases = [], description, parent }) => ({ name, aliases, description, ...(parent ? { parent } : {}) }));

export function findCommand(name: string): CommandSpec | undefined {
  return COMMANDS.find((command) => command.name === name || command.aliases?.includes(name));
}

/** Lista de «/»: vacía, sólo los visibles; con letras, todos (también ocultos y miembros de grupo, con «en /grupo»). Por nombre y alias; la fila muestra lo tipeado y, entre paréntesis, su par. */
export function sugerencias(typed: string): Array<{ word: string; label: string; description: string }> {
  const plain = (word: string) => word.normalize("NFD").replace(/\p{M}/gu, "");
  return COMMANDS.flatMap((item) => {
    if (!typed && (item.parent || item.hidden)) return [];
    const names = [item.name, ...(item.aliases ?? [])];
    const word = names.find((name) => name.startsWith(typed));
    if (!word) return [];
    const other = names.find((name) => plain(name) !== plain(word));
    return [{ word, label: other ? `/${word} (/${other})` : `/${word}`, description: `${item.parent ? `en /${item.parent} · ` : ""}${item.description}` }];
  });
}
