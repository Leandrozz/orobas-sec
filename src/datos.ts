// Carpeta de datos por usuario, una subcarpeta por proyecto; socket y log fuera de cualquier montaje.
import { createHash, randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, cpSync, lstatSync, existsSync, linkSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, utimesSync, unlinkSync, writeFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { homedir, hostname, tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { t } from "./idioma.ts";
import { credentialsDir, readSecret, secretState, writeSecret } from "./secretos.ts";

export function dataDir(): string {
  if (process.env.CYBER_DATA_DIR) return process.env.CYBER_DATA_DIR;
  if (process.platform === "darwin") return join(homedir(), "Library", "Application Support", "elevate-cyber");
  if (process.platform === "win32") return join(process.env.LOCALAPPDATA || join(homedir(), "AppData", "Local"), "elevate-cyber");
  return join(process.env.XDG_DATA_HOME || join(homedir(), ".local", "share"), "elevate-cyber");
}

function normalize(path: string): string {
  const slashed = path.replace(/\\/g, "/").replace(/\/+$/, "");
  return /^[A-Za-z]:/.test(slashed) ? slashed.toLowerCase() : slashed;
}

export function projectId(host: string): string {
  const norm = normalize(host);
  const name = (basename(norm).replace(/[^A-Za-z0-9._-]/g, "_") || "proyecto").slice(0, 40);
  return `${name}-${createHash("sha256").update(norm).digest("hex").slice(0, 8)}`;
}

/** Ruta del proyecto en el host: dentro del contenedor el montaje es /proyecto y el lanzador pasa la real. */
export function hostPath(cwd: string): string {
  return process.env.CYBER_PROYECTO_HOST && cwd === "/proyecto" ? process.env.CYBER_PROYECTO_HOST : resolve(cwd);
}

/**
 * El home del usuario en la máquina donde está la carpeta. En Docker no es el del contenedor: se
 * deduce de la carpeta de datos que monta el lanzador (CYBER_DATOS_HOST), o lo dice CYBER_HOME_HOST.
 */
function hostHome(): string {
  if (process.env.CYBER_HOME_HOST) return process.env.CYBER_HOME_HOST;
  const datos = process.env.CYBER_DATOS_HOST;
  const derived = datos && /^(.+?)[\\/](?:\.local[\\/]share|Library[\\/]Application Support|AppData[\\/]Local)[\\/]elevate-cyber[\\/]?$/.exec(datos)?.[1];
  return derived || homedir();
}

/**
 * ¿La carpeta del proyecto es la máquina del operador y no un lugar para el objetivo? Sí si es la raíz del disco,
 * su carpeta personal o una carpeta que la contiene (/home). Lo usan las herramientas que leen archivos del
 * proyecto (código, REA) para decidir la procedencia de lo que leen (src/secretos-sesion.ts): en una carpeta por
 * programa, lo que hay es del objetivo (su repositorio clonado, su APK, su bundle); en el home, del operador.
 */
export function carpetaDelOperador(cwd: string, home: string = hostHome()): boolean {
  const here = normalize(hostPath(cwd));
  if (here === "" || /^[a-z]:$/.test(here)) return true;
  const casa = normalize(home);
  return casa === here || casa.startsWith(`${here}/`);
}

/**
 * Aviso si el proyecto es el home del usuario o la raíz: todo lo que se abra ahí comparte daemon,
 * memoria, artefactos y hallazgos, y los programas se mezclan. No bloquea; lo muestran la TUI y -p.
 */
export function sharedFolderWarning(cwd: string, home: string = hostHome()): string | undefined {
  const here = normalize(hostPath(cwd));
  const root = here === "" || /^[a-z]:$/.test(here);
  if (!root && here !== normalize(home)) return undefined;
  const where = root ? t("la raíz del disco", "the root of the disk") : t("tu carpeta personal", "your home folder");
  const how = existsSync("/.dockerenv")
    ? t("abrí cyber desde una carpeta por programa (por ejemplo ~/bb/<programa>)", "open cyber from one folder per program (for example ~/bb/<program>)")
    : t("orobas-sec -C ~/bb/<programa>", "orobas-sec -C ~/bb/<program>");
  return t(
    `Este proyecto es ${where} (${hostPath(cwd)}): todas las sesiones que abras acá comparten daemon, memoria, artefactos y hallazgos, y los programas se mezclan. Conviene una carpeta por programa: ${how}.`,
    `This project is ${where} (${hostPath(cwd)}): every session you open here shares the daemon, memory, artifacts and findings, and programs get mixed. Use one folder per program: ${how}.`,
  );
}

const idOf = (cwd: string) => projectId(hostPath(cwd));

/** Crea (si falta) y verifica un directorio privado: nuestro, sin enlaces y 0700; en un /tmp compartido otro usuario podría haberlo adelantado. */
function privateDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (process.platform === "win32") return;
  const info = lstatSync(dir);
  if (info.isSymbolicLink() || !info.isDirectory() || info.uid !== process.getuid?.() || (info.mode & 0o777) !== 0o700)
    throw new Error(t(`${dir} no es una carpeta privada tuya (dueño, enlace o permisos distintos de 0700): borrala o corregila y reintentá.`, `${dir} is not a private folder of yours (owner, symlink or permissions other than 0700): remove or fix it and retry.`));
}

/** Corta (hash de 16 hex) para que el socket entre en los 104 bytes de macOS, y por usuario para no compartir /tmp. */
export function runtimeDir(cwd: string): string {
  const parent = join(process.env.XDG_RUNTIME_DIR || tmpdir(), `elevate-cyber-${process.getuid?.() ?? "u"}`);
  const dir = join(parent, createHash("sha256").update(idOf(cwd)).digest("hex").slice(0, 16));
  privateDir(parent);
  privateDir(dir);
  return dir;
}

export function registerProject(cwd: string): void {
  const file = join(dataDir(), "proyectos.json");
  let all: Record<string, unknown> = {};
  try {
    all = JSON.parse(readFileSync(file, "utf8"));
  } catch {}
  const ruta = hostPath(cwd);
  all[idOf(cwd)] = { ruta, nombre: basename(normalize(ruta)), ultimoUso: new Date().toISOString() };
  mkdirSync(dataDir(), { recursive: true, mode: 0o700 });
  try {
    chmodSync(dataDir(), 0o700); // en un montaje ajeno puede no dejar: no es motivo para no arrancar
  } catch {}
  mkdirSync(join(dataDir(), "proyectos", idOf(cwd)), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(all, null, 1));
  renameSync(tmp, file);
}

const STALE_MS = 30_000;
const alive = (pid: number) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
};

export class ProjectLocked extends Error {}

/** Candado del proyecto con latido (mtime): otro daemon vivo, aunque sea en otro contenedor, lo respeta. */
export function lockProject(cwd: string, link: (from: string, to: string) => void = linkSync): () => void {
  const dir = join(dataDir(), "proyectos", idOf(cwd));
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = join(dir, "daemon.lock");
  const body = JSON.stringify({ host: hostname(), pid: process.pid, desde: new Date().toISOString() });
  const tmp = `${file}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  writeFileSync(tmp, body, { mode: 0o600 });
  try {
    for (let attempt = 0; ; attempt++) {
      try {
        try {
          link(tmp, file); // atómico y con el contenido completo: nadie lee un candado a medio escribir
        } catch (error) {
          // Los montajes de Docker Desktop (Windows, macOS) no tienen enlaces duros: se publica con creación exclusiva.
          if (!["EPERM", "ENOTSUP", "EXDEV"].includes((error as NodeJS.ErrnoException).code ?? "")) throw error;
          writeFileSync(file, body, { flag: "wx", mode: 0o600 });
        }
        break;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
      let mtime: number;
      try {
        mtime = statSync(file).mtimeMs;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT" && attempt < 3) continue; // lo soltaron entre medio
        throw error;
      }
      let held: { host?: string; pid?: number } | undefined;
      try {
        held = JSON.parse(readFileSync(file, "utf8"));
      } catch {} // vacío o ilegible: cuenta como tomado mientras el latido sea reciente
      const stale = Date.now() - mtime >= STALE_MS;
      const dead = held?.host === hostname() && typeof held.pid === "number" && !alive(held.pid);
      if (!stale && !dead) throw new ProjectLocked(t("Este proyecto ya está abierto en otra terminal.", "This project is already open in another terminal."));
      if (attempt >= 1) throw new Error(t("No se pudo tomar el candado del proyecto.", "Could not take the project lock."));
      // shortcut: la carrera entre dos que toman un candado vencido se reduce, no se elimina; alcanza con el latido de 30 s.
      const aside = `${file}.stale.${process.pid}`;
      try {
        renameSync(file, aside);
        unlinkSync(aside);
      } catch {}
    }
  } finally {
    try {
      unlinkSync(tmp);
    } catch {}
  }
  // Solo se toca el archivo mientras siga siendo nuestro: si otro lo tomó, su candado no se borra ni se renueva.
  const mine = () => {
    try {
      const now = JSON.parse(readFileSync(file, "utf8"));
      const own = JSON.parse(body);
      return now.host === own.host && now.pid === own.pid && now.desde === own.desde;
    } catch {
      return false;
    }
  };
  const beat = setInterval(() => {
    try {
      if (!mine()) return;
      const now = new Date();
      utimesSync(file, now, now);
    } catch {}
  }, 10_000);
  beat.unref();
  return () => {
    clearInterval(beat);
    try {
      if (mine()) unlinkSync(file);
    } catch {}
  };
}

// Latido del candado durante una mudanza larga (sincrónica): el intervalo del daemon no corre mientras tanto.
let pulse = () => {};
const sha = (file: string) => {
  pulse();
  return createHash("sha256").update(readFileSync(file)).digest("hex");
};
const files = (dir: string): string[] =>
  !existsSync(dir) ? [] : readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(join(dir, e.name)).map((f) => join(e.name, f)) : [e.name]));
const sameTree = (from: string, to: string) => files(from).every((f) => existsSync(join(to, f)) && sha(join(from, f)) === sha(join(to, f)));
const count = (db: DatabaseSync, table: string) => {
  try {
    return (db.prepare(`select count(*) n from ${table}`).get() as { n: number }).n;
  } catch {
    return -1; // la tabla no existía en la base vieja
  }
};

/** Todo lo que hay en la .cyber (ids de sesiones y hallazgos, artefactos, memoria) ya está en el destino. */
function alreadyThere(legacy: string, root: string, db: string): boolean {
  if (!sameTree(join(legacy, "artifacts"), join(root, "artifacts")) || !sameTree(join(legacy, "memory"), join(root, "memory"))) return false;
  const source = join(legacy, "cyber.db");
  if (!existsSync(source)) return true;
  if (!existsSync(db)) return false;
  const a = new DatabaseSync(source, { readOnly: true });
  const b = new DatabaseSync(db, { readOnly: true });
  try {
    for (const table of ["sessions", "findings"]) {
      let ids: Array<{ id: string }>;
      try {
        ids = a.prepare(`select id from ${table}`).all() as Array<{ id: string }>;
      } catch {
        continue;
      }
      const have = new Set((b.prepare(`select id from ${table}`).all() as Array<{ id: string }>).map((r) => r.id));
      if (ids.some((r) => !have.has(r.id))) return false;
    }
    return true;
  } catch {
    return false;
  } finally {
    a.close();
    b.close();
  }
}

/** Copia sin perder nada del destino: un archivo distinto que ya esté se aparta con sufijo en vez de pisarse. */
function copyTree(from: string, to: string): void {
  for (const f of files(from)) {
    pulse();
    const target = join(to, f);
    mkdirSync(join(target, ".."), { recursive: true });
    if (existsSync(target)) {
      if (sha(target) === sha(join(from, f))) continue;
      renameSync(target, `${target}.parcial-${Date.now()}`);
    }
    copyFileSync(join(from, f), target);
  }
}
const probeSocket = (sock: string): number | null =>
  spawnSync(process.execPath, ["-e", `require("net").connect(process.argv[1]).on("connect",()=>process.exit(0)).on("error",()=>process.exit(3));setTimeout(()=>process.exit(4),2000)`, sock], { timeout: 5000 }).status;
const tablesOf = (db: DatabaseSync) => (db.prepare("select name from sqlite_master where type='table' and name not like 'sqlite_%'").all() as Array<{ name: string }>).map((r) => r.name);
const KNOWN = [/^cyber\.db(-wal|-shm)?$/, /^memory\//, /^artifacts\//, /^plataformas\//, /^informes\/.*\.md$/, /^uso-[^/]*\.json$/, /^config\/elevate-cyber\/hackerone\.json$/, /^daemon\.(sock|pid|log)$/];

/** Mueve <cwd>/.cyber a la carpeta de datos: copia, verifica y recién entonces borra. Ante cualquier duda deja todo como estaba y pendiente=true: el daemon no abre la base nueva. */
export function migrateLegacy(cwd: string, afterCopy?: (root: string) => void, probe: (sock: string) => number | null = probeSocket): { moved: boolean; notice?: string; pendiente?: boolean } {
  const file = join(dataDir(), "proyectos", idOf(cwd), "daemon.lock");
  pulse = () => {
    try {
      const now = new Date();
      utimesSync(file, now, now);
    } catch {}
  };
  try {
    return migrate(cwd, afterCopy, probe);
  } finally {
    pulse = () => {};
  }
}

// Solo para los avisos: muestra la ruta como la ve el usuario en el host (dentro del contenedor las rutas reales son otras).
export function shown(p: string, cwd: string = process.cwd()): string {
  for (const [from, to] of [[dataDir(), process.env.CYBER_DATOS_HOST], [credentialsDir(), process.env.CYBER_CREDENCIALES_HOST], [resolve(cwd), hostPath(cwd)]] as [string, string | undefined][]) {
    if (!to || (p !== from && !p.startsWith(from + "/") && !p.startsWith(from + "\\"))) continue;
    const sep = to.includes("\\") ? "\\" : "/";
    return [to.replace(/[\\/]+$/, ""), ...p.slice(from.length).split(/[\\/]/).filter(Boolean)].join(sep);
  }
  return p;
}

function migrate(cwd: string, afterCopy: ((root: string) => void) | undefined, probe: (sock: string) => number | null): { moved: boolean; notice?: string; pendiente?: boolean } {
  const legacy = join(cwd, ".cyber");
  if (!existsSync(legacy)) return { moved: false };
  const root = join(dataDir(), "proyectos", idOf(cwd));
  const ok = join(root, "mudanza.ok");
  const parcial = join(root, "mudanza.parcial");
  const db = join(root, "cyber.db");
  const notices: string[] = [];
  const sh = (p: string) => shown(p, cwd);
  const fail = (why: string, step: string) => ({ moved: false, pendiente: true, notice: [t(`No se mudó .cyber: ${why}. Qué hacer: ${step} Nada se borró (tus datos siguen en ${sh(legacy)}; la base nueva, si hay, en ${sh(root)}).`, `.cyber was not moved: ${why}. What to do: ${step} Nothing was deleted (your data is still in ${sh(legacy)}; any new database is in ${sh(root)}).`), ...notices].join(" ") });
  const aside = (why: string) => {
    const stamp = Date.now();
    for (const x of ["", "-wal", "-shm"]) if (existsSync(db + x)) renameSync(db + x, `${db}.${why}-${stamp}${x}`);
    notices.push(t(`Se apartó la base anterior del destino como ${sh(db)}.${why}-${stamp}.`, `The previous destination database was set aside as ${sh(db)}.${why}-${stamp}.`));
  };
  const sock = join(legacy, "daemon.sock");
  if (existsSync(sock)) {
    // Un daemon viejo vivo seguiría escribiendo en .cyber: solo se sigue ante «rechazó» (3) o «sin respuesta» (4); cualquier otra cosa bloquea.
    const status = probe(sock);
    if (status !== 3 && status !== 4) return fail(t("hay un daemon viejo corriendo o no se pudo comprobar", "an old daemon is running or could not be checked"), t("cerrá la otra sesión de cyber (o esperá 10 minutos a que el daemon viejo se apague) y volvé a abrir.", "close the other cyber session (or wait 10 minutes for the old daemon to exit) and open again."));
  }
  if (!existsSync(ok)) {
    mkdirSync(root, { recursive: true });
    try {
      if (existsSync(db)) {
        if (existsSync(parcial)) aside("parcial"); // copia nuestra interrumpida: se aparta, no se borra
        else {
          let own: DatabaseSync;
          let empty: boolean;
          try {
            own = new DatabaseSync(db, { readOnly: true });
          } catch {
            return fail(t(`la base del destino ${sh(db)} está corrupta o bloqueada`, `the destination database ${sh(db)} is corrupt or locked`), t(`renombrala (por ejemplo a cyber.db.mala) y volvé a abrir.`, `rename it (for example to cyber.db.bad) and open again.`));
          }
          try {
            tablesOf(own); // lanza si la base está corrupta: ahí no se adivina, se avisa
            empty = ["sessions", "findings", "events"].every((table) => count(own, table) <= 0) && files(join(root, "artifacts")).length === 0;
          } catch {
            return fail(t(`la base del destino ${sh(db)} está corrupta o bloqueada`, `the destination database ${sh(db)} is corrupt or locked`), t(`renombrala (por ejemplo a cyber.db.mala) y volvé a abrir.`, `rename it (for example to cyber.db.bad) and open again.`));
          } finally {
            own.close();
          }
          if (!empty) return fail(t(`${sh(legacy)} y ${sh(db)} tienen datos`, `${sh(legacy)} and ${sh(db)} both contain data`), t(`mové ${sh(db)} a otro lado (por ejemplo renombrándola) y volvé a abrir para que se mude .cyber.`, `move ${sh(db)} aside (for example rename it) and open again so .cyber can be migrated.`));
          aside("vacia");
        }
      }
      writeFileSync(parcial, "");
      const source = join(legacy, "cyber.db");
      if (existsSync(source)) {
        const old = new DatabaseSync(source);
        try {
          old.prepare("vacuum into ?").run(db); // copia consistente aunque haya filas en el -wal
        } finally {
          old.close();
        }
        pulse();
      }
      for (const dir of ["memory", "artifacts"]) if (existsSync(join(legacy, dir))) copyTree(join(legacy, dir), join(root, dir));
      afterCopy?.(root);
      if (existsSync(source)) {
        const a = new DatabaseSync(source, { readOnly: true });
        const b = new DatabaseSync(db, { readOnly: true });
        try {
          for (const table of tablesOf(a)) if (count(a, `"${table}"`) !== count(b, `"${table}"`)) return fail(t(`no coinciden los conteos de ${table}`, `${table} counts differ`), t("reintentá; si persiste, copiá .cyber a otro lado, renombrá la carpeta nueva y volvé a abrir.", "retry; if it persists, copy .cyber elsewhere, rename the new folder and open again."));
        } finally {
          a.close();
          b.close();
        }
      }
      for (const dir of ["memory", "artifacts"]) if (!sameTree(join(legacy, dir), join(root, dir))) return fail(t(`falló la verificación de ${dir}`, `${dir} verification failed`), t("reintentá; si persiste, copiá .cyber a otro lado, renombrá la carpeta nueva y volvé a abrir.", "retry; if it persists, copy .cyber elsewhere, rename the new folder and open again."));
      // Informes y exportaciones de uso vuelven a la carpeta del proyecto; si el nombre ya existe con otro contenido, se conserva con prefijo.
      const out = join(cwd, "cyber-informes");
      const exportable = [
        ...files(join(legacy, "informes")).filter((f) => f.endsWith(".md")).map((f) => join("informes", f)),
        ...readdirSync(legacy).filter((f) => /^uso-.*\.json$/.test(f)),
      ];
      for (const rel of exportable) {
        mkdirSync(out, { recursive: true });
        let to = join(out, basename(rel));
        if (existsSync(to) && sha(to) !== sha(join(legacy, rel))) to = join(out, `legacy-${basename(rel)}`);
        copyFileSync(join(legacy, rel), to);
        if (sha(to) !== sha(join(legacy, rel))) return fail(t("falló la verificación de los informes", "report verification failed"), t("reintentá; si persiste, copiá .cyber a otro lado, renombrá la carpeta nueva y volvé a abrir.", "retry; if it persists, copy .cyber elsewhere, rename the new folder and open again."));
      }
      const h1 = join(legacy, "config", "elevate-cyber", "hackerone.json");
      if (existsSync(h1)) {
        if (secretState("hackerone") === "locked") return fail(t("las credenciales de HackerOne guardadas están cifradas y no hay llave del llavero", "the stored HackerOne credentials are encrypted and the keyring key is unavailable"), t("desbloqueá el llavero y volvé a abrir.", "unlock the keyring and open again."));
        if (readSecret("hackerone") !== undefined) notices.push(t("HackerOne ya tenía credenciales guardadas: se conservan esas y se descartó el archivo viejo.", "HackerOne already had stored credentials: those are kept and the old file was discarded."));
        else {
          const raw = readFileSync(h1, "utf8");
          writeSecret("hackerone", raw);
          if (readSecret("hackerone") !== raw) return fail(t("no se pudo guardar la clave de HackerOne", "could not store the HackerOne key"), t("reintentá; si persiste, copiá .cyber a otro lado, renombrá la carpeta nueva y volvé a abrir.", "retry; if it persists, copy .cyber elsewhere, rename the new folder and open again."));
          notices.push(t("Las credenciales de HackerOne pasaron al almacén de credenciales.", "HackerOne credentials were moved to the credentials store."));
        }
      }
      if (existsSync(join(legacy, "plataformas"))) {
        const to = join(credentialsDir(), "plataformas");
        cpSync(join(legacy, "plataformas"), to, { recursive: true, force: false, errorOnExist: false });
        if (!files(join(legacy, "plataformas")).every((f) => existsSync(join(to, f)))) return fail(t("falló la mudanza de plataformas", "platform sessions move failed"), t("reintentá; si persiste, copiá .cyber a otro lado, renombrá la carpeta nueva y volvé a abrir.", "retry; if it persists, copy .cyber elsewhere, rename the new folder and open again."));
      }
      // Todo lo demás que hubiera en .cyber se conserva aparte, verificado, antes de borrar.
      const rest = files(legacy).filter((f) => !KNOWN.some((re) => re.test(f.replace(/\\/g, "/"))));
      for (const rel of rest) {
        let to = join(root, "legacy-sobrante", rel);
        mkdirSync(join(to, ".."), { recursive: true });
        if (existsSync(to) && sha(to) !== sha(join(legacy, rel))) to = `${to}-${Date.now()}`; // mismo nombre, otro contenido: se guarda con sufijo
        if (!existsSync(to)) copyFileSync(join(legacy, rel), to);
        if (sha(to) !== sha(join(legacy, rel))) return fail(t("falló la verificación de los archivos sobrantes", "leftover files verification failed"), t("reintentá; si persiste, copiá .cyber a otro lado, renombrá la carpeta nueva y volvé a abrir.", "retry; if it persists, copy .cyber elsewhere, rename the new folder and open again."));
      }
      if (rest.length) notices.push(t(`Archivos desconocidos de .cyber guardados en ${join(root, "legacy-sobrante")}.`, `Unknown files from .cyber were kept in ${join(root, "legacy-sobrante")}.`));
      writeFileSync(ok, new Date().toISOString());
      rmSync(parcial, { force: true });
    } catch (error) {
      return fail((error as Error).message, t("reintentá; si persiste, copiá .cyber a otro lado, renombrá la carpeta nueva y volvé a abrir.", "retry; if it persists, copy .cyber elsewhere, rename the new folder and open again."));
    }
  } else {
    let there = false;
    try {
      there = alreadyThere(legacy, root, db);
    } catch {}
    if (!there) return fail(t("la .cyber que reapareció tiene datos que el destino no tiene", "the reappeared .cyber has data the destination lacks"), t("reintentá; si persiste, copiá .cyber a otro lado, renombrá la carpeta nueva y volvé a abrir.", "retry; if it persists, copy .cyber elsewhere, rename the new folder and open again."));
  }
  rmSync(legacy, { recursive: true, force: true });
  return { moved: true, notice: notices.join(" ") || undefined };
}

/** Respaldo de cyber.db la primera vez que un build nuevo abre el proyecto; quedan los 3 últimos. */
export function backupOnNewVersion(cwd: string, build: string): string | undefined {
  const root = join(dataDir(), "proyectos", idOf(cwd));
  const version = join(root, "version");
  const db = join(root, "cyber.db");
  let previous: string | undefined;
  try {
    previous = readFileSync(version, "utf8");
  } catch {}
  if (previous === build) return undefined;
  let made: string | undefined;
  if (existsSync(db)) {
    const dir = join(root, "respaldos");
    mkdirSync(dir, { recursive: true });
    // El sello tiene que ser único: varios respaldos seguidos caen en el mismo milisegundo y con
    // sellos repetidos la poda elegía al azar cuál borrar.
    const base = join(dir, `cyber-${(previous ?? "previo").replace(/[^A-Za-z0-9._-]/g, "_")}`);
    let ts = Date.now();
    while (existsSync(`${base}-${ts}.db`)) ts++;
    made = `${base}-${ts}.db`;
    const source = new DatabaseSync(db);
    try {
      source.prepare("vacuum into ?").run(made);
    } finally {
      source.close();
    }
    const stamp = (f: string) => Number(/-(\d+)\.db$/.exec(f)?.[1]);
    // En empate de sello (mismo milisegundo), el nombre desempata: el orden no puede ser arbitrario.
    const newer = (x: string, y: string) => stamp(y) - stamp(x) || y.localeCompare(x);
    for (const old of readdirSync(dir).filter((f) => f.startsWith("cyber-")).sort(newer).slice(3)) rmSync(join(dir, old), { force: true });
  }
  mkdirSync(root, { recursive: true });
  writeFileSync(version, build);
  return made;
}
