import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { t } from "../idioma.ts";
import { guardarUltra, ultraGuardado, type UltraGuardado } from "./ajustes.ts";
import { fromLines, type CommandIO, type Panel } from "./comandos.ts";
import { correrComando } from "./dolar.ts";

export interface Harness { id: string; label: string; instalado: boolean }
export interface CorridaFila { id: string; harness: string; estado: string; rama?: string; tarea: string; enCurso: boolean; anterior: boolean }

// Comandos fijos: nunca se arman con texto del modelo ni de afuera. `cyber` no tiene.
export const INSTALAR: Readonly<Record<string, string>> = {
  claude: "npm i -g @anthropic-ai/claude-code",
  codex: "npm i -g @openai/codex",
  pi: "npm i -g @mariozechner/pi-coding-agent",
  opencode: "npm i -g opencode-ai",
};

/** Sólo ids propios de INSTALAR: un id del daemon como «constructor» no hereda nada del prototipo. */
export const comandoInstalar = (id: string): string | undefined => (Object.hasOwn(INSTALAR, id) ? INSTALAR[id] : undefined);

export function leerHarnesses(lineas: string[]): Harness[] {
  const out: Harness[] = [];
  for (const l of lineas) {
    const m = /^(\w+)\s+(✓|✗).*· (.+)$/.exec(l);
    if (m) out.push({ id: m[1]!, label: m[3]!, instalado: m[2] === "✓" });
  }
  return out;
}

export function leerCorridas(lineas: string[]): CorridaFila[] {
  const out: CorridaFila[] = [];
  let anterior = false;
  for (const l of lineas) {
    if (l === "anteriores:") anterior = true;
    // [\s\S]: view() corta la tarea cruda, que puede traer saltos de línea.
    const m = /^#(\S+)\s+(\S+)\s+(\S+)\s+(\d\d-\d\d \d\d:\d\d)  (.{34}) ?([\s\S]*)$/.exec(l);
    if (!m) continue;
    const rama = m[5]!.trim();
    out.push({ id: m[1]!, harness: m[2]!, estado: m[3]!, rama: rama === "sin worktree" ? undefined : rama, tarea: m[6]!.replace(/\s+/g, " ").trim(), enCurso: m[3] === "corriendo" || m[3] === "esperando", anterior });
  }
  return out;
}

export function dentroDeDocker(archivo?: string): boolean {
  return existsSync(archivo ?? "/.dockerenv");
}

export function armarUltra(texto: string, guardado: UltraGuardado, harnesses: Harness[], enCurso: number): { arg: string; linea: string } {
  // Mismas regex que el daemon (src/daemon.ts, action "ultra").
  const objetivo = /--objetivo\b/.test(texto) || guardado.modo === "objetivo";
  const escritoPartes = /--partes\s+(\d+)/.exec(texto)?.[1];
  const escritoCon = /--con\s+([a-z,]+)/.exec(texto)?.[1];
  const conocidos = ["claude", "codex", "pi", "opencode", "cyber"];
  const instalados = new Set(harnesses.filter((h) => h.instalado).map((h) => h.id));
  const marcados = (guardado.harnesses ?? []).filter((h) => instalados.has(h));
  const van = escritoCon ? escritoCon.split(",").filter((h) => conocidos.includes(h)) : marcados;
  // El daemon acota lo escrito a 2–6 y toma 0 como auto.
  const partes: number | "auto" = escritoPartes ? (Number(escritoPartes) ? Math.min(6, Math.max(2, Number(escritoPartes))) : "auto") : guardado.partes;

  let arg = texto.trim();
  if (!/--objetivo\b/.test(arg) && objetivo) arg += " --objetivo";
  if (!escritoCon && !objetivo && marcados.length) arg += ` --con ${marcados.join(",")}`;
  if (!escritoPartes && partes !== "auto") arg += ` --partes ${partes}`;

  const nPartes = partes === "auto" ? Math.min(4, Math.max(2, van.length || instalados.size)) : partes;
  const txtPartes = partes === "auto" ? t("partes auto", "auto parts") : t(`${partes} partes`, `${partes} parts`);
  const quien = van.length ? van.join(", ") : t("todos los instalados", "all installed");
  const modo = objetivo ? t("objetivo", "target") : t("repositorio", "repository");
  const medio = objetivo ? txtPartes : `${quien} · ${txtPartes} · ${modo}`;
  const aviso = enCurso > 0 && nPartes + enCurso > 6
    ? t(` · hay ${enCurso} en curso: algunas partes esperarán`, ` · ${enCurso} running: some parts will wait`) : "";
  const linea = `ultra · ${objetivo ? `${modo} · ` : ""}${medio}   ${t("(/ultra para cambiar)", "(/ultra to change)")}${aviso}`;
  return { arg, linea };
}

export interface DepsUltra { correr?: typeof correrComando; docker?: boolean; windows?: boolean }

const PARTES: Array<number | "auto"> = ["auto", 2, 3, 4, 5, 6];

/** Selector de /ultra: marca harnesses, partes y modo; instala el que falta; guarda sólo en «listo». */
export async function selectorUltra(io: CommandIO, deps: DepsUltra = {}): Promise<Panel | null> {
  const correr = deps.correr ?? correrComando;
  const docker = deps.docker ?? dentroDeDocker();
  const windows = deps.windows ?? process.platform === "win32";
  const leer = async () => leerHarnesses(await io.ask("orquesta", { action: "harnesses" }));
  let harnesses = await leer();
  const guardado = ultraGuardado();
  const marcados = new Set((guardado.harnesses ?? harnesses.filter((h) => h.instalado).map((h) => h.id)));
  for (const h of harnesses) if (!h.instalado) marcados.delete(h.id);
  // Lo guardado es la lista de marcados, instalados o no: los que hoy no se ven se conservan al guardar.
  const ausentes = () => (guardado.harnesses ?? []).filter((id) => !harnesses.some((h) => h.id === id && h.instalado));
  let partes = guardado.partes;
  let modo = guardado.modo;
  const notas = new Map<string, string>();
  const n = () => harnesses.length;
  let at = 0;
  for (;;) {
    const objetivo = modo === "objetivo";
    const rows = [
      ...harnesses.map((h) => {
        const marca = !h.instalado ? "↓" : marcados.has(h.id) ? "✓" : "·";
        const hint = objetivo ? t("no aplica en modo objetivo", "does not apply in target mode")
          : notas.get(h.id) ?? (h.instalado ? (marcados.has(h.id) ? t("marcado · Enter para quitar", "marked · Enter to unmark") : t("sin marcar · Enter para marcar", "unmarked · Enter to mark"))
            : docker ? t("no disponible dentro de Docker", "not available inside Docker")
              : !comandoInstalar(h.id) ? t("no instalado", "not installed")
                : windows ? t(`instalalo a mano: ${comandoInstalar(h.id)}`, `install it manually: ${comandoInstalar(h.id)}`)
                  : t("no instalado · Enter para instalar", "not installed · Enter to install"));
        return { label: `${marca} ${h.label}`, hint };
      }),
      { label: t(`partes: ${partes === "auto" ? "auto" : partes}`, `parts: ${partes === "auto" ? "auto" : partes}`), hint: t("Enter para cambiar", "Enter to change") },
      { label: t(`modo: ${objetivo ? "objetivo" : "repositorio"}`, `mode: ${objetivo ? "target" : "repository"}`), hint: t("Enter para alternar", "Enter to toggle") },
      { label: t("listo", "done"), hint: t("guardar y cerrar", "save and close") },
    ];
    const choice = await io.pick("ultra", rows, { at });
    if (choice === undefined) return null;
    at = choice;
    if (choice === n()) { partes = PARTES[(PARTES.indexOf(partes) + 1) % PARTES.length]!; continue; }
    if (choice === n() + 1) { modo = objetivo ? "repo" : "objetivo"; continue; }
    if (choice === n() + 2) {
      if (!objetivo && !marcados.size) { io.notice?.(fromLines("ultra", [t("Marcá al menos uno.", "Mark at least one.")], { tone: "warn" })); continue; }
      const nuevo: UltraGuardado = { harnesses: [...new Set([...marcados, ...ausentes()])], partes, modo };
      const aviso = guardarUltra(nuevo);
      if (aviso) io.notice?.(fromLines("ultra", [aviso], { tone: "warn" }));
      return fromLines("ultra", [armarUltra("", nuevo, harnesses, 0).linea], { tone: "ok" });
    }
    const h = harnesses[choice]!;
    if (objetivo) continue;
    if (h.instalado) { if (!marcados.delete(h.id)) marcados.add(h.id); continue; }
    const cmd = comandoInstalar(h.id);
    if (docker || windows || !cmd) continue;
    if (!(await io.confirm(t(`¿Instalar ${h.label} con «${cmd}»?`, `Install ${h.label} with "${cmd}"?`)))) continue;
    io.notice?.(fromLines("ultra", [t(`instalando ${h.label}… (puede tardar unos minutos)`, `installing ${h.label}… (may take a few minutes)`)]));
    // shortcut: sin salida en vivo ni cancelación, hace falta una capacidad nueva en CommandIO; agregarla si las instalaciones tardan
    const r = await correr(cmd, { cwd: homedir() });
    const cola = r.salida.split("\n").map((l) => l.trimEnd()).filter(Boolean).slice(-8);
    if (r.codigo !== 0) {
      const que = r.codigo === null ? t("No se pudo ejecutar la instalación.", "Could not run the install.") : t(`Falló la instalación (código ${r.codigo}).`, `Install failed (code ${r.codigo}).`);
      io.notice?.(fromLines("ultra", [que, ...cola], { tone: "warn" }));
      continue;
    }
    if (cola.length) io.notice?.(fromLines("ultra", cola));
    harnesses = await leer();
    if (harnesses.find((x) => x.id === h.id)?.instalado) marcados.add(h.id);
    else notas.set(h.id, t("instalado; reiniciá cyber para que lo vea", "installed; restart cyber so it can see it"));
  }
}

/** Menú de /orquesta: elegir una corrida y la acción que su estado permite. */
export async function menuOrquesta(io: CommandIO): Promise<Panel | null> {
  const titulo = "orquesta";
  const actual = await io.ask("orquesta", {});
  const corridas = leerCorridas(actual);
  const rows = [
    // Las «anteriores» no están en memoria: ver/parar/limpiar fallarían, así que sólo se leen.
    ...corridas.map((c) => ({ label: `#${c.id}  ${c.harness}  ${c.estado}`, hint: [c.rama ?? t("sin worktree", "no worktree"), c.tarea, c.anterior && t("de otra sesión: sólo lectura", "from another session: read-only")].filter(Boolean).join(" · ") })),
    { label: t("harnesses instalados", "installed harnesses"), hint: t("marcar, instalar y elegir cuántas partes", "mark, install and choose how many parts") },
  ];
  let at = 0;
  for (;;) {
    const choice = await io.pick(titulo, rows, { footer: actual[0] ?? "", at });
    if (choice === undefined) return null;
    at = choice;
    const c = corridas[choice];
    if (!c) return selectorUltra(io);
    if (c.anterior) continue;
    return accionesCorrida(io, c);
  }
}

async function accionesCorrida(io: CommandIO, c: CorridaFila): Promise<Panel | null> {
  const titulo = "orquesta";
  const filasAcc = [{ label: t("ver", "view"), hint: t("ver el detalle", "see details") },
    ...(c.enCurso ? [{ label: t("parar", "stop"), hint: t("parar la corrida", "stop the run") }]
      : c.rama ? [{ label: t("limpiar", "clean"), hint: t("borrar el worktree y dejar la rama", "delete the worktree, keep the branch") },
        { label: t("limpiar todo", "clean all"), hint: t("borrar el worktree y la rama", "delete the worktree and the branch") }] : [])];
  const accion = await io.pick(`#${c.id}`, filasAcc);
  if (accion === undefined) return null;
  if (accion === 0) return fromLines(`orquesta #${c.id}`, await io.ask("orquesta", { action: "ver", run: c.id }));
  if (c.enCurso) {
    if (!(await io.confirm(t(`¿Parar #${c.id}?`, `Stop #${c.id}?`)))) return null;
    return fromLines(titulo, await io.ask("orquesta", { action: "parar", run: c.id }), { tone: "ok" });
  }
  const rama = accion === 2;
  if (!(await io.confirm(rama ? t(`¿Borrar el worktree y la rama de #${c.id}?`, `Delete the worktree and the branch of #${c.id}?`) : t(`¿Borrar el worktree de #${c.id}?`, `Delete the worktree of #${c.id}?`)))) return null;
  const r = await io.ask("orquesta", { action: "limpiar", run: c.id, rama });
  return r.length ? fromLines(titulo, r, { tone: "ok" }) : fromLines(titulo, [t("No quedaba worktree.", "No worktree left.")], { tone: "warn" });
}
