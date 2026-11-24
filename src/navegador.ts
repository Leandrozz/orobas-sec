// Navegador del operador: la autorización para usarlo y lo que el proyecto recuerda de la extensión.
// La autorización es una por proyecto y sólo la da el operador: con /navegador si, o pidiéndolo con
// sus palabras («usá mi navegador», «te autorizo el browser»). Lo que diga una herramienta, una página
// o lo que el operador pegó (comillas, bloques, la salida de un «$ comando») nunca cuenta. El puente
// con la extensión y las herramientas chrome_* viven en chrome.ts.
import type { DatabaseSync } from "node:sqlite";
import { t } from "./idioma.ts";
import { isShortConfirmation, ownWords } from "./operador.ts";

export interface BrowserGrant {
  /** Cuándo se autorizó (ISO). */
  at: string;
  /** Lo que dijo o tecleó el operador. */
  pedido: string;
  via: "comando" | "mensaje";
  /** Sesión donde lo dijo. */
  sesion?: string;
}

/** Estado de la extensión visto desde este agente. */
export type BrowserState = "conectado" | "dormido" | "sin-emparejar";

const read = (db: DatabaseSync, key: string) => (db.prepare("select value from meta where key=?").get(key) as { value: string } | undefined)?.value;
const write = (db: DatabaseSync, key: string, value: string) => db.prepare("insert into meta(key,value) values(?,?) on conflict(key) do update set value=excluded.value").run(key, value);

/** Autorización del navegador del operador y última vez que se vio la extensión, en la tabla meta del proyecto. */
export class BrowserAccess {
  private readonly db: DatabaseSync;
  /** Última marca escrita: «visto» se guarda de a ratos, no en cada /poll. */
  private written = 0;

  constructor(db: DatabaseSync) {
    this.db = db;
  }

  grant(): BrowserGrant | undefined {
    try {
      const saved = JSON.parse(read(this.db, "navegador") ?? "null") as BrowserGrant | null;
      return saved?.at ? saved : undefined;
    } catch {
      return undefined;
    }
  }

  /** Cuándo la revocó por última vez (ISO): lo que el operador dijo antes no la devuelve. */
  revokedAt(): string | undefined {
    return read(this.db, "navegador_revocado");
  }

  /** Autoriza; si ya estaba autorizado, deja la autorización original y devuelve `nueva: false`. */
  allow(pedido: string, via: BrowserGrant["via"], sesion?: string): { grant: BrowserGrant; nueva: boolean } {
    const current = this.grant();
    if (current) return { grant: current, nueva: false };
    const grant: BrowserGrant = { at: new Date().toISOString(), pedido: pedido.replace(/\s+/g, " ").trim().slice(0, 300), via, ...(sesion ? { sesion } : {}) };
    write(this.db, "navegador", JSON.stringify(grant));
    return { grant, nueva: true };
  }

  /** Revoca; devuelve la autorización que había, o nada si no había. */
  revoke(): BrowserGrant | undefined {
    const current = this.grant();
    this.db.prepare("delete from meta where key='navegador'").run();
    write(this.db, "navegador_revocado", new Date().toISOString());
    return current;
  }

  /** Última vez que este proyecto vio la extensión (ms; 0 si nunca). */
  seen(): number {
    return Number(read(this.db, "navegador_visto") ?? 0) || 0;
  }

  saw(at: number): void {
    if (at - this.written < 30_000) return;
    this.written = at;
    if (at > this.seen()) write(this.db, "navegador_visto", String(at));
  }
}

/* ---------- Lo que dice el operador ---------- */

const NOUN = /^(navegador(es)?|browser|chrome|chromium|brave|extension|extensiones)$/;
/** Pedirle que lo use: «usá», «usalo», «te autorizo», «podés usar», «reconectá», «ya te conecté», «estoy logueado». */
const GRANT = /^(us(a|as|ar|e|en|alo|ala|alos|emos|ame|arlo|arla|ando)|utiliz\w*|autoriz\w*|habilit\w*|permit\w*|conect\w*|reconect\w*|manej(a|alo|ar)|tom(a|alo|ala|ar)|agarr(a|alo|ala|ar)|aprovech\w*|entr(a|ar)|prob(a|alo|ar)|loguead\w*|logead\w*|use|using|authoriz\w*|allow\w*|enable\w*|connect\w*|logged|try)$/;
/** Verbos que, negados, prohíben: «no uses», «no toques», «no abras», «no te autorizo». */
const FORBID = /^(us\w*|toc\w*|toqu\w*|abr\w*|agarr\w*|manej\w*|entr\w*|autoriz\w*|habilit\w*|permit\w*|conect\w*|use|using|touch|open)$/;
const NEGATION = new Set(["no", "nunca", "jamas", "ni", "sin", "dont", "never", "not"]);
/** Entre la negación y el verbo, cambian el sentido: «no puedo usar», «no sé si podés usar». */
const AMBIGUOUS = new Set(["puedo", "pude", "podia", "pudo", "se", "sabia", "tengo", "anda", "funciona", "andaba", "funcionaba", "si"]);
const POLITE = new Set(["podes", "puedes", "podrias", "podria", "podras", "could", "can", "would"]);
const REVOKE = /^(revoc\w*|desautoriz\w*|revoke\w*)$/;
/** «tu navegador» es el del agente (browser_open), no el del operador. */
const OWN_AGENT = /^(tu|tus|your)$/;
const AGENT_KIND = /^(headless|propio|tuyo|interno|integrado|playwright)$/;

type Word = { word: string; segment: number };

/** Palabras sin acentos ni mayúsculas, con el tramo (entre signos) al que pertenecen y si ese tramo es una pregunta. */
function words(text: string): { list: Word[]; questions: Set<number> } {
  const plain = text.normalize("NFKD").replace(/\p{M}/gu, "").toLowerCase().replace(/['’`]/g, "");
  const list: Word[] = [];
  const questions = new Set<number>();
  let segment = 0;
  for (const part of plain.split(/([,.;:!?¡¿()\n]|\s[-–—]\s)/)) {
    if (/^([,.;:!?¡¿()\n]|\s[-–—]\s)$/.test(part)) {
      if (part === "?") questions.add(segment);
      segment++;
      continue;
    }
    for (const word of part.split(/[^\p{L}\p{N}]+/u)) if (word) list.push({ word, segment });
  }
  return { list, questions };
}

/** Lo que el operador escribió con sus palabras: sin lo que pegó, sin la salida de un «$ comando» ni las notas del harness. */
function ownText(text: string): string {
  return ownWords(text.replace(/<terminal>[\s\S]*?(<\/terminal>|$)/g, " ").replace(/\[sistema\][^\n]*/g, " "));
}

/**
 * ¿El operador autoriza (o prohíbe) usar su navegador? Pide un sustantivo (navegador, browser, chrome,
 * extensión) cerca de un verbo de uso, en lo que escribió con sus palabras. Una negación justo antes del
 * verbo, con el navegador como objeto, lo prohíbe («no uses mi navegador»); «no, usá mi navegador» no.
 * Una pregunta no autoriza salvo que sea un pedido («¿podés usar mi navegador?»). Un sí corto vale si
 * contesta una pregunta del agente que proponía usarlo (`asked`: lo último que el agente le escribió).
 */
export function browserIntent(text: string, asked?: string): { intent: "si" | "no"; quote: string } | undefined {
  const own = ownText(text);
  const quote = own.replace(/\s+/g, " ").trim().slice(0, 200);
  const { list, questions } = words(own);
  // «tu navegador», «el navegador headless»: el del agente, no el del operador.
  const nouns = list.flatMap((item, index) => (NOUN.test(item.word) && !OWN_AGENT.test(list[index - 1]?.word ?? "") && !AGENT_KIND.test(list[index + 1]?.word ?? "") ? [index] : []));
  const near = (at: number, span: number, after = false) => nouns.some((index) => (after ? index > at && index - at <= span : Math.abs(index - at) <= span));
  /** La negación que hay justo antes del verbo, en el mismo tramo: «negada», o «ambigua» si en el medio hay un «puedo» o un «sé». */
  const negatedBefore = (at: number, span: number) => {
    for (let back = 1; back <= span && at - back >= 0; back++) {
      const item = list[at - back]!;
      if (item.segment !== list[at]!.segment) return undefined;
      if (NEGATION.has(item.word) || (item.word === "de" && /^(deja|deje|dejes|para|pare|stop)$/.test(list[at - back - 1]?.word ?? ""))) {
        const between = list.slice(at - back + 1, at).map((entry) => entry.word);
        return { kind: between.some((word) => AMBIGUOUS.has(word)) ? "ambigua" : "negada", word: item.word };
      }
    }
    return undefined;
  };
  let yes = false;
  let no = false;
  let blocked = false;
  // Cada tramo, una vez (un mensaje largo pegado sin comillas no se recorre al cuadrado).
  const segments = new Map<number, string[]>();
  for (const item of list) {
    const words = segments.get(item.segment);
    if (words) words.push(item.word);
    else segments.set(item.segment, [item.word]);
  }
  if (nouns.length) list.forEach((item, at) => {
    const question = questions.has(item.segment);
    const segment = segments.get(item.segment)!;
    if (REVOKE.test(item.word) && near(at, 6) && !question) no = true;
    if (FORBID.test(item.word)) {
      const negation = negatedBefore(at, 3);
      // Prohíbe si el navegador es lo que sigue («no uses mi navegador», «no te autorizo a usar el browser»);
      // «probá sin usar mi navegador» no autoriza, pero tampoco revoca.
      if (negation?.kind === "negada" && (near(at, 4, true) || (/^(lo|la)$/.test(list[at - 1]?.word ?? "") && near(at, 6)))) {
        if (negation.word !== "sin" && !question) no = true;
        else if (!segment.join(" ").includes("por que no")) blocked = true;
      }
    }
    if (!GRANT.test(item.word) || !near(at, 6)) return;
    if (negatedBefore(at, 4)) {
      // «¿Por qué no usás mi navegador?» es un pedido.
      if (question && segment.join(" ").includes("por que no")) yes = true;
      return;
    }
    if (question && !segment.some((word) => POLITE.has(word)) && !segment.join(" ").includes("por que no")) return;
    yes = true;
  });
  if (no) return { intent: "no", quote };
  if (yes && !blocked) return { intent: "si", quote };
  // «¿Uso tu navegador?» → «sí». Una pregunta con opciones («¿uso tu navegador o el headless?») no se contesta con un sí pelado.
  if (asked && isShortConfirmation(own)) {
    const proposal = asked.split(/(?<=[.!?\n])\s+/).filter((part) => part.includes("?")).find((part) => {
      const parsed = words(part).list;
      if (parsed.some((entry) => entry.word === "o" || entry.word === "or")) return false;
      return parsed.some((entry, at) => (GRANT.test(entry.word) || FORBID.test(entry.word)) && parsed.some((other, index) => NOUN.test(other.word) && !AGENT_KIND.test(parsed[index + 1]?.word ?? "") && Math.abs(index - at) <= 6));
    });
    if (proposal) return { intent: "si", quote: `${quote} (a «${proposal.trim().slice(0, 160)}»)` };
  }
  return undefined;
}

/* ---------- Para mostrar ---------- */

const ago = (ms: number, now: number) => {
  const s = Math.max(0, Math.round((now - ms) / 1000));
  if (s < 60) return t(`hace ${s} s`, `${s} s ago`);
  const m = Math.round(s / 60);
  if (m < 60) return t(`hace ${m} min`, `${m} min ago`);
  const h = Math.round(m / 60);
  return h < 48 ? t(`hace ${h} h`, `${h} h ago`) : t(`hace ${Math.round(h / 24)} días`, `${Math.round(h / 24)} days ago`);
};

/** Etiqueta corta para el pie de la TUI; nada si el operador no usa la extensión ni la autorizó. */
export function browserBadge(info: { authorized: boolean; state: BrowserState }): string | undefined {
  if (!info.authorized) return info.state === "sin-emparejar" ? undefined : t("nav: no autorizado", "browser: not allowed");
  if (info.state === "conectado") return t("nav: conectado", "browser: connected");
  if (info.state === "dormido") return t("nav: dormido", "browser: asleep");
  return t("nav: sin emparejar", "browser: not paired");
}

/** Respuesta de /navegador: autorización, estado de la extensión y qué hacer. */
export function browserLines(info: { grant?: BrowserGrant; state: BrowserState; seen: number; cmd: string; listening: boolean; now?: number }): string[] {
  const now = info.now ?? Date.now();
  const { grant } = info;
  const lines = [t("NAVEGADOR DEL OPERADOR", "OPERATOR BROWSER")];
  lines.push(grant
    ? t(`Autorizado en este proyecto: sí, desde ${new Date(grant.at).toLocaleString("es-AR")} (${grant.via === "comando" ? "con /navegador si" : `por tu mensaje «${grant.pedido.slice(0, 120)}»`}).`, `Allowed in this project: yes, since ${new Date(grant.at).toLocaleString("en-US")} (${grant.via === "comando" ? "with /navegador si" : `by your message «${grant.pedido.slice(0, 120)}»`}).`)
    : t("Autorizado en este proyecto: no. El agente no toca tu navegador hasta que lo autorices.", "Allowed in this project: no. The agent does not touch your browser until you allow it."));
  const seen = info.seen ? t(` (visto por última vez ${ago(info.seen, now)})`, ` (last seen ${ago(info.seen, now)})`) : "";
  if (info.state === "conectado") lines.push(t(`Extensión: conectada${seen}.`, `Extension: connected${seen}.`));
  else if (info.state === "dormido") lines.push(t(`Extensión: dormida o Chromium cerrado${seen}. Se despierta sola cada 30 s mientras Chromium esté abierto, y el agente la espera hasta 35 s.`, `Extension: asleep or Chromium closed${seen}. It wakes up by itself every 30 s while Chromium is open, and the agent waits up to 35 s for it.`));
  else lines.push(t("Extensión: nunca se conectó a un agente en esta máquina (sin emparejar).", "Extension: never connected to an agent on this machine (not paired)."));
  lines.push("");
  if (!grant) lines.push(t("Qué hacer: /navegador si (o decile «usá mi navegador»). Vale para todas las sesiones de este proyecto; /navegador no lo revoca.", "What to do: /navegador si (or tell it \"use my browser\"). It covers every session of this project; /navegador no revokes it."));
  if (info.state === "sin-emparejar") lines.push(t(`Qué hacer: corré «${info.cmd}» y seguí los pasos (una sola vez por máquina): cargar la carpeta en chrome://extensions y pegar el código en el ícono de Orobas.`, `What to do: run "${info.cmd}" and follow the steps (once per machine): load the folder in chrome://extensions and paste the code in the Orobas icon.`));
  else if (info.state === "dormido") lines.push(t("Qué hacer: nada, si Chromium está abierto. Si no vuelve, abrí Chromium o tocá el ícono de Orobas (eso la despierta); si el ícono dice «código incorrecto», corré de nuevo «" + info.cmd + "».", "What to do: nothing, if Chromium is open. If it does not come back, open Chromium or click the Orobas icon (that wakes it up); if the icon says \"wrong code\", run \"" + info.cmd + "\" again."));
  else if (grant) lines.push(t("Listo: el agente puede usar tus pestañas de sitios del alcance (no completa contraseñas ni hace clic en borrar, pagar o transferir).", "Ready: the agent can use your tabs on in-scope sites (it does not fill in passwords nor click delete, pay or transfer)."));
  if (grant && !info.listening) lines.push(t("(Este agente todavía no abrió el puerto para la extensión: lo abre al usar el navegador.)", "(This agent has not opened the port for the extension yet: it does when it uses the browser.)"));
  lines.push(t("Uso: /navegador si | no", "Usage: /navegador si | no"));
  return lines;
}
