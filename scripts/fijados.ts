// Versiones y sumas fijadas de lo que la imagen baja de terceros (distro/fijados.txt), y la propuesta de subirlas.
// Lo usa scripts/actualizar-fijados.sh; distro/bajar-fijado.sh lee el mismo archivo durante el build.
//
// Formato de distro/fijados.txt (líneas vacías y las que empiezan con # no cuentan):
//   @ NOMBRE origen=FUENTE sumas=SUMAS[,SUMAS…]   cómo buscar la última versión y dónde publica sus sumas el autor
//   NOMBRE VERSION ARQ SHA256 URL                  un archivo; ARQ es amd64, arm64 o all
// FUENTE: github:DUEÑO/REPO (último release), github-tags:DUEÑO/REPO:PREFIJO (último tag con ese prefijo),
//         url:URL (un texto con la versión, como el stable.txt de Kubernetes).
// SUMAS:  lista:URL (archivo «suma  nombre» del autor), sha256:URL (archivo con la suma sola), github (el digest que
//         GitHub calcula al subir el archivo al release), gpg:URL (firma GPG: se baja y se avisa, se verifica a mano).
//         En las URL, {v} es la versión y {url} la del archivo.
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { parseArgs } from "node:util";

export interface Fuente { nombre: string; origen: string; sumas: string[]; linea: number }
export interface Artefacto { nombre: string; version: string; arq: string; sha256: string; url: string; linea: number }
export interface Fijados { lineas: string[]; fuentes: Map<string, Fuente>; artefactos: Artefacto[] }

const ARQS = new Set(["amd64", "arm64", "all"]);
// https siempre; http sólo hacia esta máquina (pruebas).
export const urlValida = (u: string) => /^https:\/\//.test(u) || /^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?\//.test(u);

export function leerFijados(texto: string): Fijados {
  const lineas = texto.split("\n");
  const fuentes = new Map<string, Fuente>();
  const artefactos: Artefacto[] = [];
  lineas.forEach((cruda, i) => {
    const linea = cruda.trim();
    if (!linea || linea.startsWith("#")) return;
    const campos = linea.split(/\s+/);
    if (campos[0] === "@") {
      const [, nombre, ...resto] = campos;
      const kv = Object.fromEntries(resto.map((c) => [c.slice(0, c.indexOf("=")), c.slice(c.indexOf("=") + 1)]));
      if (!nombre || !kv.origen || !kv.sumas || resto.some((c) => !c.includes("="))) throw new Error(`fijados.txt:${i + 1}: se espera «@ NOMBRE origen=… sumas=…»`);
      if (fuentes.has(nombre)) throw new Error(`fijados.txt:${i + 1}: ${nombre} tiene dos líneas @`);
      fuentes.set(nombre, { nombre, origen: kv.origen, sumas: kv.sumas.split(","), linea: i });
      return;
    }
    if (campos.length !== 5) throw new Error(`fijados.txt:${i + 1}: se esperan 5 campos (NOMBRE VERSION ARQ SHA256 URL) y hay ${campos.length}`);
    const [nombre, version, arq, sha256, url] = campos as [string, string, string, string, string];
    artefactos.push({ nombre, version, arq, sha256, url, linea: i });
  });
  return { lineas, fuentes, artefactos };
}

/** Lo que está mal en un archivo leído: vacío si está bien. */
export function revisar(f: Fijados): string[] {
  const errores: string[] = [];
  const vistos = new Set<string>();
  for (const a of f.artefactos) {
    const donde = `fijados.txt:${a.linea + 1} (${a.nombre} ${a.arq})`;
    if (!f.fuentes.has(a.nombre)) errores.push(`${donde}: falta la línea «@ ${a.nombre} …»`);
    if (!ARQS.has(a.arq)) errores.push(`${donde}: arquitectura desconocida`);
    if (!/^[0-9a-f]{64}$/.test(a.sha256)) errores.push(`${donde}: la suma no es SHA-256 en hexadecimal`);
    if (!/^https:\/\//.test(a.url)) errores.push(`${donde}: la URL no es https`);
    if (!a.url.includes(a.version)) errores.push(`${donde}: la URL no nombra la versión ${a.version}`);
    if (vistos.has(`${a.nombre} ${a.arq}`)) errores.push(`${donde}: repetido`);
    vistos.add(`${a.nombre} ${a.arq}`);
  }
  for (const [nombre, fuente] of f.fuentes) {
    const suyos = f.artefactos.filter((a) => a.nombre === nombre);
    if (!suyos.length) errores.push(`fijados.txt:${fuente.linea + 1}: ${nombre} no tiene archivos`);
    if (new Set(suyos.map((a) => a.version)).size > 1) errores.push(`${nombre}: versiones distintas según la arquitectura`);
    const arqs = new Set(suyos.map((a) => a.arq));
    if (!arqs.has("all") && !(arqs.has("amd64") && arqs.has("arm64"))) errores.push(`${nombre}: falta amd64 o arm64`);
    if (!/^(github:[\w.-]+\/[\w.-]+|github-tags:[\w.-]+\/[\w.-]+:[\w.-]*|url:\S+)$/.test(fuente.origen)) errores.push(`${nombre}: origen desconocido (${fuente.origen})`);
    for (const s of fuente.sumas) if (!/^(lista:\S+|sha256:\S+|gpg:\S+|github)$/.test(s)) errores.push(`${nombre}: sumas desconocidas (${s})`);
  }
  return errores;
}

const plantilla = (s: string, v: string, url = "") => s.replaceAll("{v}", v).replaceAll("{url}", url);

// --- Red ---
const API = (process.env.GITHUB_API_URL ?? "https://api.github.com").replace(/\/$/, "");
async function traer(url: string, json = false): Promise<any> {
  if (!urlValida(url)) throw new Error(`sólo https: ${url}`);
  const cabeceras: Record<string, string> = { "user-agent": "orobas-sec-actualizar-fijados" };
  if (url.startsWith(API) && process.env.GITHUB_TOKEN) cabeceras.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const r = await fetch(url, { headers: cabeceras, redirect: "follow" });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  if (!urlValida(r.url)) throw new Error(`redirigido fuera de https: ${r.url}`);
  return json ? r.json() : Buffer.from(await r.arrayBuffer());
}

interface Candidata { version: string; fecha?: string; aviso?: string }
const sinV = (t: string) => t.replace(/^v/, "");
const comparar = (a: string, b: string) => {
  const x = a.split(/[.-]/).map(Number);
  const y = b.split(/[.-]/).map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
  return 0;
};

/** La versión más nueva publicada hace al menos `minDias` días (las recién salidas se esperan: si alguien comprometió un release, suele notarse en días). */
async function ultima(origen: string, minDias: number): Promise<Candidata> {
  const limite = Date.now() - minDias * 86_400_000;
  if (origen.startsWith("github:")) {
    const releases = (await traer(`${API}/repos/${origen.slice(7)}/releases?per_page=40`, true)) as { tag_name: string; draft: boolean; prerelease: boolean; published_at: string }[];
    const estables = releases.filter((r) => !r.draft && !r.prerelease && /^v?\d+\.\d+\.\d+$/.test(r.tag_name)).sort((a, b) => comparar(sinV(b.tag_name), sinV(a.tag_name)));
    const elegida = estables.find((r) => Date.parse(r.published_at) <= limite);
    if (!elegida) throw new Error(`${origen}: ningún release estable con ${minDias} días`);
    const aviso = estables[0] !== elegida ? `hay ${estables[0]!.tag_name}, más nueva que ${minDias} días: se espera` : undefined;
    return { version: sinV(elegida.tag_name), fecha: elegida.published_at.slice(0, 10), aviso };
  }
  if (origen.startsWith("github-tags:")) {
    const [repo, prefijo] = [origen.slice(12, origen.lastIndexOf(":")), origen.slice(origen.lastIndexOf(":") + 1)];
    const tags = (await traer(`${API}/repos/${repo}/tags?per_page=100`, true)) as { name: string; commit: { sha: string } }[];
    const ordenadas = tags.filter((t) => t.name.startsWith(prefijo) && /^v?\d+\.\d+\.\d+$/.test(t.name)).sort((a, b) => comparar(sinV(b.name), sinV(a.name)));
    for (const t of ordenadas.slice(0, 15)) {
      const c = (await traer(`${API}/repos/${repo}/commits/${t.commit.sha}`, true)) as { commit: { committer: { date: string } } };
      if (Date.parse(c.commit.committer.date) <= limite) return { version: sinV(t.name), fecha: c.commit.committer.date.slice(0, 10), aviso: t !== ordenadas[0] ? `hay ${ordenadas[0]!.name}, más nueva que ${minDias} días: se espera` : undefined };
    }
    throw new Error(`${origen}: ningún tag con ${minDias} días`);
  }
  if (origen.startsWith("url:")) {
    const texto = String(await traer(origen.slice(4))).trim();
    if (!/^v?\d+\.\d+\.\d+$/.test(texto)) throw new Error(`${origen}: no es una versión: ${texto.slice(0, 40)}`);
    return { version: sinV(texto), aviso: "la fuente no da fecha: revisá a mano cuándo salió" };
  }
  throw new Error(`origen desconocido: ${origen}`);
}

/** Compara la suma calculada con las que publica el autor; devuelve qué se comprobó, o tira si alguna no coincide. */
async function contrastar(fuente: Fuente, version: string, url: string, sha: string, dir: string): Promise<string[]> {
  const hechas: string[] = [];
  for (const s of fuente.sumas) {
    if (s === "github") {
      const m = /^https:\/\/github\.com\/([^/]+\/[^/]+)\/releases\/download\/([^/]+)\/([^/]+)$/.exec(url);
      if (!m) throw new Error(`${url}: «github» sólo sirve para archivos de un release de GitHub`);
      const rel = (await traer(`${API}/repos/${m[1]}/releases/tags/${m[2]}`, true)) as { assets: { name: string; digest?: string | null }[] };
      const digest = rel.assets.find((a) => a.name === decodeURIComponent(m[3]!))?.digest;
      if (!digest) throw new Error(`${url}: GitHub no publica el digest de ese archivo`);
      if (digest !== `sha256:${sha}`) throw new Error(`${url}: la suma no coincide con el digest de GitHub (${digest})`);
      hechas.push("digest de GitHub");
    } else if (s.startsWith("lista:")) {
      const fuenteUrl = plantilla(s.slice(6), version, url);
      const texto = String(await traer(fuenteUrl));
      const linea = texto.split("\n").find((l) => l.trim().split(/\s+/)[1]?.replace(/^\*/, "") === basename(url));
      const publicada = linea?.trim().split(/\s+/)[0]?.toLowerCase();
      if (!publicada) throw new Error(`${fuenteUrl} no nombra ${basename(url)}`);
      if (publicada !== sha) throw new Error(`${basename(url)}: la suma no coincide con ${fuenteUrl}`);
      hechas.push(basename(fuenteUrl));
    } else if (s.startsWith("sha256:")) {
      const fuenteUrl = plantilla(s.slice(7), version, url);
      const publicada = String(await traer(fuenteUrl)).trim().split(/\s+/)[0]?.toLowerCase();
      if (publicada !== sha) throw new Error(`${basename(url)}: la suma no coincide con ${fuenteUrl}`);
      hechas.push(basename(fuenteUrl));
    } else if (s.startsWith("gpg:")) {
      const fuenteUrl = plantilla(s.slice(4), version, url);
      writeFileSync(join(dir, basename(fuenteUrl)), await traer(fuenteUrl));
      hechas.push(`firma GPG bajada (${basename(fuenteUrl)}): verificala a mano con la clave del autor`);
    }
  }
  return hechas;
}

export interface Propuesta { nombre: string; de: string; a: string; fecha?: string; aviso?: string; archivos: { arq: string; sha256: string; url: string; comprobado: string[] }[] }

/** Busca versiones nuevas, baja cada archivo a `dir`, calcula su suma y la contrasta; no cambia nada. */
export async function proponer(f: Fijados, opciones: { dir: string; minDias: number; versiones?: Record<string, string>; nombres?: string[] }): Promise<{ propuestas: Propuesta[]; al_dia: string[]; errores: string[] }> {
  const propuestas: Propuesta[] = [];
  const alDia: string[] = [];
  const errores: string[] = [];
  for (const fuente of f.fuentes.values()) {
    if (opciones.nombres?.length && !opciones.nombres.includes(fuente.nombre)) continue;
    const suyos = f.artefactos.filter((a) => a.nombre === fuente.nombre);
    const actual = suyos[0]!.version;
    try {
      const c: Candidata = opciones.versiones?.[fuente.nombre] ? { version: opciones.versiones[fuente.nombre]! } : await ultima(fuente.origen, opciones.minDias);
      if (c.version === actual) {
        alDia.push(`${fuente.nombre} ${actual}${c.aviso ? ` (${c.aviso})` : ""}`);
        continue;
      }
      const p: Propuesta = { nombre: fuente.nombre, de: actual, a: c.version, fecha: c.fecha, aviso: c.aviso, archivos: [] };
      for (const a of suyos) {
        const url = a.url.replaceAll(actual, c.version);
        const dir = join(opciones.dir, a.nombre, c.version, a.arq);
        mkdirSync(dir, { recursive: true });
        const datos = (await traer(url)) as Buffer;
        writeFileSync(join(dir, basename(url)), datos);
        const sha256 = createHash("sha256").update(datos).digest("hex");
        p.archivos.push({ arq: a.arq, sha256, url, comprobado: await contrastar(fuente, c.version, url, sha256, dir) });
      }
      propuestas.push(p);
    } catch (e) {
      errores.push(`${fuente.nombre}: ${(e as Error).message}`);
    }
  }
  return { propuestas, al_dia: alDia, errores };
}

/** El texto del archivo con las propuestas aplicadas (sólo cambian las líneas de esos archivos). */
export function aplicar(f: Fijados, propuestas: Propuesta[]): string {
  const lineas = [...f.lineas];
  for (const p of propuestas) {
    for (const a of f.artefactos.filter((x) => x.nombre === p.nombre)) {
      const nuevo = p.archivos.find((x) => x.arq === a.arq)!;
      const vieja = lineas[a.linea]!;
      lineas[a.linea] = vieja.replace(a.version, p.a).replace(a.sha256, nuevo.sha256).replace(a.url, nuevo.url);
    }
  }
  return lineas.join("\n");
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      archivo: { type: "string", default: "distro/fijados.txt" },
      dir: { type: "string" },
      "min-dias": { type: "string", default: "7" },
      version: { type: "string", multiple: true },
      revisar: { type: "boolean" },
      ayuda: { type: "boolean", short: "h" },
    },
  });
  if (values.ayuda) {
    console.log(`scripts/actualizar-fijados.sh [--archivo distro/fijados.txt] [--dir DIR] [--min-dias 7] [--version NOMBRE=VERSION]… [NOMBRE…]
  Busca versiones nuevas de lo que fija distro/fijados.txt (las publicadas hace al menos --min-dias días), baja cada
  archivo a DIR, calcula su SHA-256, lo contrasta con las sumas que publica el autor y reescribe el archivo. No
  commitea nada: revisá «git diff distro/fijados.txt» y probá el build antes de commitear.
scripts/actualizar-fijados.sh --revisar   sólo revisa el formato del archivo.`);
    return;
  }
  const f = leerFijados(readFileSync(values.archivo!, "utf8"));
  const errores = revisar(f);
  if (errores.length) throw new Error(`${values.archivo} tiene errores:\n  ${errores.join("\n  ")}`);
  if (values.revisar) return console.log(`${values.archivo}: ${f.fuentes.size} herramientas, ${f.artefactos.length} archivos, bien.`);
  if (!values.dir) throw new Error("falta --dir: dónde bajar los archivos para calcular sus sumas (fuera de /tmp si es RAM)");
  const versiones = Object.fromEntries((values.version ?? []).map((v) => v.split("=") as [string, string]));
  const r = await proponer(f, { dir: values.dir, minDias: Number(values["min-dias"]), versiones, nombres: positionals });
  for (const linea of r.al_dia) console.log(`al día   ${linea}`);
  for (const p of r.propuestas) {
    console.log(`nueva    ${p.nombre} ${p.de} → ${p.a}${p.fecha ? ` (publicada el ${p.fecha})` : ""}${p.aviso ? `; ${p.aviso}` : ""}`);
    for (const a of p.archivos) console.log(`           ${a.arq.padEnd(5)} ${a.sha256}  ${a.url}\n                 contrastada con: ${a.comprobado.join("; ") || "nada (el autor no publica sumas)"}`);
  }
  for (const e of r.errores) console.error(`error    ${e}`);
  if (r.propuestas.length) {
    writeFileSync(values.archivo!, aplicar(f, r.propuestas));
    console.log(`\nReescribí ${values.archivo}. Revisá el diff y construí la imagen antes de commitear.`);
  }
  if (r.errores.length) process.exitCode = 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e: Error) => {
    console.error(`actualizar-fijados: ${e.message}`);
    process.exit(1);
  });
}
