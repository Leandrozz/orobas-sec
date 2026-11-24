// Modo «sólo lo que cambió» para PRs: de los archivos que tocó el PR se infieren las rutas HTTP afectadas, para
// concentrar la evaluación ahí (y, si se pide, acotar el alcance a ellas). La inferencia es honesta: lo que sale de
// una definición de ruta reconocible se usa; lo que no, se dice («no pude inferir rutas de estos archivos»).
//
// Reconoce rutas declaradas en las líneas agregadas o cambiadas (Express/Fastify/Koa/Hono, Flask, FastAPI, Django,
// Spring, Laravel, Rails, ASP.NET, Go net/http, chi, gin, echo) y el enrutado por archivos (Next.js pages/ y app/,
// SvelteKit, Nuxt, Remix, Astro).
import { execFileSync } from "node:child_process";

export interface RutaInferida {
  ruta: string;
  archivo: string;
  linea?: number;
  /** De dónde salió: una declaración en el código o el nombre del archivo. */
  como: "declaracion" | "archivo";
}

export interface Cambios {
  activo: boolean;
  /** Por qué está activo o no. */
  motivo: string;
  base?: string;
  archivos: string[];
  rutas: RutaInferida[];
  /** Archivos de código cambiados de los que no salió ninguna ruta. */
  sinRuta: string[];
  error?: string;
}

const CODIGO = /\.(ts|tsx|js|jsx|mjs|cjs|py|rb|php|java|kt|go|cs|rs|ex|exs|svelte|vue|astro)$/i;

/** Declaraciones de rutas: el grupo con nombre «ruta» es el camino. */
const DECLARACIONES: RegExp[] = [
  // Express, Fastify, Koa, Hono, Elysia: app.get("/x"), router.post('/x'), fastify.route({ url: "/x" })
  /\b(?:app|router|api|server|fastify|route|routes|r|v1|admin)\s*\.\s*(?:get|post|put|patch|delete|del|options|head|all|use|route)\s*\(\s*["'`](?<ruta>\/[^"'`\s]*)["'`]/i,
  /\burl\s*:\s*["'`](?<ruta>\/[^"'`\s]*)["'`]/,
  // Flask y FastAPI: @app.route("/x"), @router.get("/x"), @bp.post("/x")
  /@\w+\s*\.\s*(?:route|get|post|put|patch|delete|api_route|websocket)\s*\(\s*["'](?<ruta>\/[^"'\s]*)["']/i,
  // Django: path("x/", vista), re_path(r"^x/$", vista)
  /\b(?:path|re_path)\s*\(\s*r?["'](?<ruta>[^"']*)["']/,
  // Spring: @GetMapping("/x"), @RequestMapping(value = "/x")
  /@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*["'](?<ruta>\/[^"']*)["']/,
  // Laravel: Route::get('/x', …)
  /\bRoute::(?:get|post|put|patch|delete|any|match|resource|apiResource)\s*\(\s*["'](?<ruta>\/?[^"']*)["']/,
  // Rails: get "/x", post 'x' (dentro de routes.rb)
  /^\s*(?:get|post|put|patch|delete|resources?|namespace)\s+["':](?<ruta>\/?[\w/:.-]+)/,
  // ASP.NET: [HttpGet("x")], [Route("x")], app.MapGet("/x", …)
  /\[(?:Http(?:Get|Post|Put|Patch|Delete)|Route)\s*\(\s*"(?<ruta>[^"]*)"/,
  /\.Map(?:Get|Post|Put|Patch|Delete|Methods)\s*\(\s*"(?<ruta>\/[^"]*)"/,
  // Go: http.HandleFunc("/x", …), mux.Handle("/x"), r.Get("/x") (chi), e.GET("/x") (echo/gin)
  /\b(?:HandleFunc|Handle)\s*\(\s*"(?:[A-Z]+ )?(?<ruta>\/[^"]*)"/,
  /\b\w+\s*\.\s*(?:GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete|Group)\s*\(\s*"(?<ruta>\/[^"]*)"/,
];

/** Ruta pública de un archivo con enrutado por carpetas, o undefined. */
export function rutaDeArchivo(archivo: string): string | undefined {
  const a = archivo.replace(/\\/g, "/");
  const limpiar = (partes: string[]) => {
    const ruta = partes
      .filter((p) => p && !/^\(.*\)$/.test(p) && !p.startsWith("@") && p !== "index" && p !== "page" && p !== "route" && p !== "+page" && p !== "+server" && p !== "+page.server" && p !== "_index")
      .map((p) => p.replace(/^\[\.\.\.(\w+)\]$/, "{$1*}").replace(/^\[\[\.\.\.(\w+)\]\]$/, "{$1*}").replace(/^\[(\w+)\]$/, "{$1}").replace(/^\$(\w+)$/, "{$1}"))
      .join("/");
    return `/${ruta}`.replace(/\/+$/, "") || "/";
  };
  // Next.js app router: app/**/route.ts (API) y app/**/page.tsx
  let m = /(?:^|\/)(?:src\/)?app\/(.*?)\/?(?:route|page)\.(?:ts|tsx|js|jsx|mjs)$/.exec(a);
  if (m) return limpiar(m[1]!.split("/"));
  // Next.js pages router: pages/api/x.ts, pages/x.tsx
  m = /(?:^|\/)(?:src\/)?pages\/(.*?)\.(?:ts|tsx|js|jsx|mjs)$/.exec(a);
  if (m && !/(^|\/)_(app|document|error)$/.test(m[1]!)) return limpiar(m[1]!.split("/"));
  // SvelteKit: src/routes/**/+page.svelte, +server.ts
  m = /(?:^|\/)src\/routes\/(.*?)\/?\+(?:page|server|page\.server|layout)\.(?:svelte|ts|js)$/.exec(a);
  if (m) return limpiar(m[1]!.split("/"));
  // Nuxt: pages/**/x.vue, server/api/x.ts
  m = /(?:^|\/)server\/api\/(.*?)(?:\.(?:get|post|put|patch|delete))?\.(?:ts|js)$/.exec(a);
  if (m) return limpiar(["api", ...m[1]!.split("/")]);
  m = /(?:^|\/)pages\/(.*?)\.vue$/.exec(a);
  if (m) return limpiar(m[1]!.split("/"));
  // Remix: app/routes/a.b.$id.tsx
  m = /(?:^|\/)app\/routes\/(.*?)\.(?:tsx|ts|jsx|js)$/.exec(a);
  if (m) return limpiar(m[1]!.split(/[./]/));
  // Astro: src/pages/**/x.astro|ts
  m = /(?:^|\/)src\/pages\/(.*?)\.(?:astro|ts|js|md)$/.exec(a);
  if (m) return limpiar(m[1]!.split("/"));
  return undefined;
}

/** Normaliza una ruta declarada: parámetros de cada framework como {nombre}. */
export function normalizarDeclarada(ruta: string): string | undefined {
  let r = ruta.trim().replace(/^\^/, "").replace(/\$$/, "");
  if (!r) return undefined;
  r = r.replace(/\(\?P<(\w+)>[^)]*\)/g, "{$1}").replace(/<(?:\w+:)?(\w+)>/g, "{$1}").replace(/:(\w+)/g, "{$1}").replace(/\{(\w+)(?::[^}]*)?\}/g, "{$1}");
  if (!r.startsWith("/")) r = `/${r}`;
  r = r.replace(/\/+/g, "/").replace(/\/+$/, "") || "/";
  if (/[\s*]/.test(r.replace(/\{\w+\*?\}/g, "")) || r.length > 200) return undefined;
  return r;
}

/** Las rutas que aparecen en las líneas agregadas de un diff unificado (git diff -U0). */
export function rutasDelDiff(diff: string): RutaInferida[] {
  const salida: RutaInferida[] = [];
  let archivo = "";
  let linea = 0;
  for (const fila of diff.split("\n")) {
    if (fila.startsWith("+++ ")) {
      archivo = fila.slice(4).replace(/^b\//, "").trim();
      continue;
    }
    const h = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(fila);
    if (h) {
      linea = Number(h[1]);
      continue;
    }
    if (!fila.startsWith("+") || fila.startsWith("+++")) continue;
    const texto = fila.slice(1);
    if (archivo && CODIGO.test(archivo)) {
      for (const patron of DECLARACIONES) {
        const ruta = patron.exec(texto)?.groups?.ruta;
        const limpia = ruta === undefined ? undefined : normalizarDeclarada(ruta);
        if (limpia) {
          salida.push({ ruta: limpia, archivo, linea, como: "declaracion" });
          break;
        }
      }
    }
    linea++;
  }
  return salida;
}

/** ¿Es un PR o un MR? (Para el modo «auto».) */
export function enPullRequest(env: NodeJS.ProcessEnv): boolean {
  return /^pull_request(_target)?$/.test(env.GITHUB_EVENT_NAME ?? "") || !!env.CI_MERGE_REQUEST_IID;
}

/** La base contra la que se compara: la de la configuración, la del PR o la del MR. */
export function baseDeComparacion(configurada: string | undefined, env: NodeJS.ProcessEnv): string | undefined {
  if (configurada) return configurada;
  if (env.CI_MERGE_REQUEST_DIFF_BASE_SHA) return env.CI_MERGE_REQUEST_DIFF_BASE_SHA;
  if (env.GITHUB_BASE_REF) return `origin/${env.GITHUB_BASE_REF}`;
  return undefined;
}

const git = (cwd: string, args: string[]) => execFileSync("git", ["-C", cwd, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 64 << 20 });

/** Archivos y rutas que cambió el PR respecto de la base. Nunca lanza: lo que falla queda en `error`. */
export function inferirCambios(cwd: string, modo: "auto" | "si" | "no", base: string | undefined, env: NodeJS.ProcessEnv, rutasSiempre: string[] = []): Cambios {
  const vacio = (activo: boolean, motivo: string, extra: Partial<Cambios> = {}): Cambios => ({ activo, motivo, archivos: [], rutas: [], sinRuta: [], ...extra });
  if (modo === "no") return vacio(false, "apagado en la configuración");
  if (modo === "auto" && !enPullRequest(env)) return vacio(false, "no es un PR: se evalúa todo el alcance");
  const contra = baseDeComparacion(base, env);
  if (!contra) return vacio(false, "no sé contra qué comparar (definí evaluacion.solo_cambios.base): se evalúa todo el alcance", { error: "sin base" });
  let archivos: string[];
  let diff: string;
  try {
    archivos = git(cwd, ["diff", "--name-only", "--diff-filter=ACMR", `${contra}...HEAD`]).split("\n").map((f) => f.trim()).filter(Boolean);
    diff = git(cwd, ["diff", "-U0", "--no-color", "--diff-filter=ACMR", `${contra}...HEAD`]);
  } catch (error) {
    const detalle = String((error as { stderr?: string }).stderr ?? (error as Error).message).split("\n")[0];
    return vacio(false, `no pude comparar con ${contra} (${detalle}): se evalúa todo el alcance. En GitHub hace falta actions/checkout con fetch-depth: 0 (o traer la base)`, { base: contra, error: detalle });
  }
  const rutas: RutaInferida[] = [...rutasDelDiff(diff)];
  for (const archivo of archivos) {
    const ruta = rutaDeArchivo(archivo);
    if (ruta) rutas.push({ ruta, archivo, como: "archivo" });
  }
  const vistas = new Set<string>();
  const unicas = rutas.filter((r) => (vistas.has(r.ruta) ? false : vistas.add(r.ruta)));
  for (const ruta of rutasSiempre) if (!vistas.has(ruta)) unicas.push({ ruta, archivo: "(rutas_siempre)", como: "archivo" });
  const conRuta = new Set(rutas.map((r) => r.archivo));
  const sinRuta = archivos.filter((a) => CODIGO.test(a) && !conRuta.has(a));
  if (!archivos.length) return vacio(false, `el PR no cambió archivos respecto de ${contra}: se evalúa todo el alcance`, { base: contra });
  if (!rutas.length) return vacio(false, `no pude inferir rutas HTTP de los ${archivos.length} archivo(s) que cambió el PR: se evalúa todo el alcance`, { base: contra, archivos, sinRuta });
  return { activo: true, motivo: `${unicas.length} ruta(s) inferida(s) de ${archivos.length} archivo(s) cambiado(s) respecto de ${contra}`, base: contra, archivos, rutas: unicas, sinRuta };
}
