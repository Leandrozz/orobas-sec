// Catálogo de herramientas con carga por demanda. El modelo ve un núcleo chico; el resto lo busca
// por intención con tool_search y lo carga con tools_load. Evita el problema de los harnesses que
// mandan 100+ herramientas en cada solicitud (timeouts, contexto lleno, elecciones peores).
import type { DatabaseSync } from "node:sqlite";
import type { McpManager, McpOferta } from "./mcp.ts";
import type { Tool, ToolResult } from "./agent.ts";
import { formatManual, manualEntries, searchManual } from "./manual.ts";

const str = (extra: object = {}) => ({ type: "string", ...extra });
const list = (items: object) => ({ type: "array", items });
const obj = (properties: Record<string, object>, required: string[]) => ({ type: "object", properties, required });

/** Grupos para que el resumen del catálogo en el prompt sea legible. */
export const GROUPS: Record<string, string[]> = {
  "análisis web": ["web_source_pull", "ids_harvest", "grafo_anotar", "graphql_probe", "outbound_probe", "race_probe", "csrf_check", "ws_probe", "upload_probe", "sourcemap_recover", "js_wayback_diff", "openapi_import", "jwt_inspect", "secrets_scan", "tech_fingerprint", "har_import", "postman_import", "payload_list", "payload_get"],
  "recon pasivo": ["wayback_cdx", "crt_sh", "github_search", "url_dedupe", "takeover_check"],
  "post-explotación (lab)": ["postex_persist", "postex_exfil", "postex_cleanup"],
  "detección (purple)": ["detection_expect", "detection_hit", "detection_view"],
  navegador: ["browser_open", "browser_act", "browser_capture"],
  "correo de prueba": ["mail_address", "mail_wait", "reset_probe"],
  canarios: ["canary_new", "canary_list"],
  "navegador del operador": ["chrome_tabs", "chrome_open", "chrome_read", "chrome_act", "chrome_session", "chrome_traffic", "chrome_capture"],
  escáneres: ["nmap_scan", "ffuf_fuzz", "sqlmap_scan", "httpx_probe", "nuclei_scan", "subfinder_enum", "katana_crawl", "dns_resolve"],
  "banco de CVE/CWE": ["cve_search", "cve_detail", "cwe_detail", "vuln_graph", "vuln_ask", "cve_recent"],
  "pedidos del operador": ["h1_programs", "h1_scope_load", "bb_programs", "bb_scope_load", "cyber_bounty_programs", "cyber_bounty_scope", "cyber_bounty_submit", "cyber_bounty_status", "scope_edit", "profile_set", "session_settings", "report_generate", "h1_report_submit", "decoy_mark"],
  "plataformas y nube": ["platform_status", "platform_link", "platform_cli"],
  código: ["code_list", "code_search", "code_read", "code_crypto", "hash_crack", "code_semgrep", "code_gitleaks", "reference_read", "shell"],
  móvil: ["apk_analyze"],
  // REA, incorporado sólo en la caja: las principales; el resto aparece con tool_search rea.
  "ingeniería inversa": ["rea.analyze_javascript_application", "rea.inspect_web_network_capture", "rea.export_environment_bundle", "rea.capture_browser_scenario", "rea.open_binary", "rea.inspect_artifact", "rea.inspect_apk_signature", "rea.decode_android_resources", "rea.inspect_analysis_view"],
  orquestación: ["harness_run", "harness_wait", "harness_status", "harness_result", "harness_stop", "harness_cleanup"],
  // Sólo en la caja (src/fuzzing.ts): afuera no se registran y el grupo no aparece.
  "harness y fuzzing": ["harness_build", "fuzz_run", "poc_run"],
};

/**
 * En el catálogo (tool_search y help_search las encuentran) pero fuera del resumen largo: el prompt
 * ya indica cuándo proponer el modo y cuándo se permite abrirlo. La descripción completa se lee a pedido.
 */
export const FUERA_DEL_RESUMEN = new Set(["investigation_start"]);

export class Catalog {
  readonly db: DatabaseSync;
  readonly sessionId: string;
  /** Herramientas disponibles por demanda, por nombre. */
  readonly available = new Map<string, Tool>();
  private readonly active: Tool[];
  private readonly mcp?: McpManager;
  private restoredMcp = false;
  private readonly wrap: (tool: Tool) => Tool;

  constructor(db: DatabaseSync, sessionId: string, active: Tool[], wrap: (tool: Tool) => Tool, mcp?: McpManager) {
    this.db = db;
    this.sessionId = sessionId;
    this.active = active;
    this.wrap = wrap;
    this.mcp = mcp;
    db.exec("create table if not exists tools_loaded(session_id text not null, name text not null, at text not null, primary key(session_id, name))");
    // Los incorporados (REA en la caja) están en el catálogo desde el arranque sin arrancar su proceso.
    if (mcp) this.register(mcp.offers().map((offer) => this.placeholder(offer)));
  }

  /** Lugar de una herramienta de un incorporado hasta que arranque: al primer uso lo descubre y le pasa la llamada. */
  private placeholder(offer: McpOferta & { server: string }): Tool {
    const name = `${offer.server}.${offer.name}`;
    const tool: Tool = {
      name,
      label: offer.label,
      description: offer.description,
      parameters: offer.parameters ?? { type: "object", properties: {}, additionalProperties: true },
      replay: "never",
      execute: async (args, signal) => {
        const errors = await this.discover([offer.server], signal);
        const real = this.available.get(name);
        if (!real || real === tool) throw new Error(errors.join("; ") || `${offer.server} no ofrece ${offer.name} en esta versión.`);
        return real.execute(args, signal);
      },
    };
    return tool;
  }

  register(tools: Tool[]): void {
    for (const tool of tools) {
      this.available.set(tool.name, tool);
      const at = this.active.findIndex((item) => item.name === tool.name);
      if (at >= 0) this.active[at] = this.wrap(tool);
    }
  }

  private async discover(servers: string[], signal?: AbortSignal): Promise<string[]> {
    const results = await Promise.allSettled(servers.map(async (server) => {
      const tools = await this.mcp!.tools(server, signal);
      const names = new Set(tools.map((tool) => tool.name));
      for (const name of this.available.keys()) if (name.startsWith(`${server}.`) && !names.has(name)) {
        this.available.delete(name);
        const at = this.active.findIndex((tool) => tool.name === name);
        if (at >= 0) this.active.splice(at, 1);
      }
      this.register(tools);
    }));
    return results.flatMap((result, index) => result.status === "rejected" ? [`MCP ${servers[index]}: ${(result.reason as Error).message}`] : []);
  }

  async restoreMcp(signal?: AbortSignal): Promise<void> {
    if (this.restoredMcp || !this.mcp) return;
    this.restoredMcp = true;
    const rows = this.db.prepare("select name from tools_loaded where session_id=?").all(this.sessionId) as Array<{ name: string }>;
    // Un incorporado no arranca al retomar: su herramienta cargada lo arranca cuando se use.
    const servers = this.mcp.names().filter((server) => !this.mcp!.lazy(server) && rows.some((row) => row.name.startsWith(`${server}.`)));
    await this.discover(servers, signal);
    this.restore();
    // Un proceso fallido no se relanza en cada paso: el operador puede corregirlo en otra sesión.
  }

  /**
   * Vuelve a cargar lo que la sesión ya había pedido (al retomarla), en el orden en que se cargó: con el orden de
   * la clave (alfabético) la lista de herramientas salía distinta y el prefijo cacheado no servía.
   */
  restore(): string[] {
    const rows = this.db.prepare("select name from tools_loaded where session_id=? order by rowid").all(this.sessionId) as Array<{ name: string }>;
    return rows.map((row) => row.name).filter((name) => this.load(name, false));
  }

  loaded(): string[] {
    return this.active.map((tool) => tool.name);
  }

  load(name: string, persist = true): boolean {
    const tool = this.available.get(name);
    if (!tool) return false;
    if (!this.active.some((item) => item.name === name)) this.active.push(this.wrap(tool));
    if (persist) this.db.prepare("insert or ignore into tools_loaded(session_id,name,at) values(?,?,?)").run(this.sessionId, name, new Date().toISOString());
    return true;
  }

  /**
   * Carga por nombre; antes descubre los servidores MCP que esos nombres piden (un incorporado arranca acá,
   * cuando se pide una herramienta suya, no antes).
   */
  async loadAll(names: string[], signal?: AbortSignal): Promise<{ ok: string[]; missing: string[]; errors: string[] }> {
    const servers = (this.mcp?.names() ?? []).filter((name) => names.some((tool) => tool.startsWith(`${name}.`)));
    const errors = await this.discover(servers, signal);
    const ok: string[] = [];
    const missing: string[] = [];
    for (const name of names) (this.load(name) ? ok : missing).push(name);
    return { ok, missing, errors };
  }

  /** Por qué no está: REA fuera de la caja no es «no existe», es «acá no se ofrece». */
  whyMissing(missing: string[]): string {
    const reasons: string[] = [];
    if (missing.some((name) => name.startsWith("rea.")) && !this.mcp?.builtins().includes("rea")) reasons.push("REA (rea.*) corre sólo dentro de la caja de Orobas (el contenedor del proyecto): acá no se ofrece. Seguí con web_source_pull, code_crypto, js_endpoints, apk_analyze o har_import.");
    if (missing.some((name) => GROUPS["harness y fuzzing"]!.includes(name))) reasons.push("harness_build, fuzz_run y poc_run corren sólo dentro de la caja de Orobas (clang con sanitizers y libFuzzer): acá no se ofrecen ni se compila nada. Seguí con code_search y code_read, y si hace falta ejecutar la hipótesis, pedile al operador que abra la caja.");
    return reasons.join(" ") || "Buscá con tool_search.";
  }

  search(query: string): Tool[] {
    const terms = query.toLowerCase().split(/[\s,]+/).filter(Boolean);
    const score = (tool: Tool) => {
      const haystack = `${tool.name} ${tool.label} ${tool.description}`.toLowerCase();
      return terms.reduce((sum, term) => sum + (tool.name.includes(term) ? 3 : haystack.includes(term) ? 1 : 0), 0);
    };
    return [...this.available.values()]
      .map((tool) => ({ tool, score: score(tool) }))
      .filter((item) => item.score > 0 || !terms.length)
      .sort((a, b) => b.score - a.score)
      .map((item) => item.tool);
  }

  /** Resumen para el prompt: nombre y media línea por herramienta, agrupadas. */
  summary(): string {
    const lines: string[] = [];
    for (const [group, names] of Object.entries(GROUPS)) {
      const items = names.filter((name) => this.available.has(name)).map((name) => `${name} (${this.available.get(name)!.label})`);
      if (items.length) lines.push(`${group}: ${items.join(", ")}`);
    }
    const grouped = new Set(Object.values(GROUPS).flat());
    const rest = [...this.available.keys()].filter((name) => !grouped.has(name) && !FUERA_DEL_RESUMEN.has(name));
    const builtins = this.mcp?.builtins() ?? [];
    const own = rest.filter((name) => !builtins.some((server) => name.startsWith(`${server}.`)));
    if (own.length) lines.push(`otras: ${own.join(", ")}`);
    for (const server of builtins) {
      const more = rest.filter((name) => name.startsWith(`${server}.`)).length;
      if (more) lines.push(`${server}: ${more} herramientas más (tool_search ${server}).`);
    }
    const external = (this.mcp?.names() ?? []).filter((name) => !builtins.includes(name));
    if (external.length) lines.push(`MCP local (fuera del alcance HTTP; sólo binarios, archivos y código): ${external.join(", ")}. Buscá con tool_search para descubrir sus herramientas.`);
    return lines.join("\n");
  }

  tools(): Tool[] {
    const help: Tool = {
      name: "help_search",
      label: "Buscar en el manual",
      description:
        "Busca en la documentación del propio harness: comandos del operador (CLI y /comandos de la TUI), herramientas disponibles y cargadas, servidores MCP configurados y las guías del repositorio. " +
        "Usala antes de responder qué podés hacer, qué comandos tiene el operador, si existe una integración (HackerOne, plataformas y nubes, MCP, navegador) o cómo se usa algo.",
      parameters: obj({ query: str({ description: "Palabras clave; vacío lista las primeras entradas" }) }, []),
      replay: "safe",
      execute: async (params): Promise<ToolResult> => {
        const loaded = new Set(this.loaded());
        const tools = [...this.active, ...this.available.values()].map((tool) => ({ name: tool.name, label: tool.label, description: tool.description, loaded: loaded.has(tool.name) }));
        const builtins = this.mcp?.builtins() ?? [];
        const hits = searchManual(manualEntries({ tools, mcp: (this.mcp?.names() ?? []).filter((name) => !builtins.includes(name)), incorporados: builtins }), String(params.query ?? ""));
        return { text: formatManual(hits), details: { resultados: hits.length } };
      },
    };
    const search: Tool = {
      name: "tool_search",
      label: "Buscar herramientas",
      description: "Busca en el catálogo de herramientas disponibles por demanda (análisis web, escáneres, pedidos del operador, plataformas y nube, código, apps móviles) por palabra clave o intención. Devuelve nombre y descripción; después cargalas con tools_load.",
      parameters: obj({ query: str({ description: "Palabras clave; vacío lista todo" }) }, []),
      replay: "safe",
      execute: async (params, signal): Promise<ToolResult> => {
        // Buscar no arranca los incorporados: su oferta ya está en el catálogo.
        const servers = (this.mcp?.names() ?? []).filter((name) => !this.mcp!.lazy(name));
        const named = servers.filter((name) => String(params.query ?? "").includes(name));
        const errors = await this.discover(named.length ? named : servers, signal);
        const hits = this.search(params.query ?? "").slice(0, 12);
        const text = hits.length ? hits.map((tool) => `${tool.name}${this.loaded().includes(tool.name) ? " (cargada)" : ""} — ${tool.name.includes(".") ? tool.description.split(/\r?\n/).filter(Boolean).slice(0, 2).map((line) => line.slice(0, 320)).join("\n") : tool.description.split(". ")[0] + "."}`).join("\n") : "Nada coincide. Sin consulta lista todo el catálogo.";
        return { text: [text, ...errors].join("\n"), details: { resultados: hits.length } };
      },
    };
    const load: Tool = {
      name: "tools_load",
      label: "Cargar herramientas",
      description: "Carga una o más herramientas del catálogo para usarlas en esta sesión (quedan cargadas si la sesión se retoma).",
      parameters: obj({ names: list(str()) }, ["names"]),
      replay: "safe",
      execute: async (params, signal): Promise<ToolResult> => {
        const { ok, missing, errors } = await this.loadAll(params.names as string[], signal);
        const text = [ok.length ? `Cargadas: ${ok.join(", ")}. Ya podés llamarlas.` : "", missing.length ? `No existen: ${missing.join(", ")}. ${this.whyMissing(missing)}` : ""].filter(Boolean).join(" ");
        const complete = ok.filter((name) => name.includes(".")).map((name) => `${name}: ${this.available.get(name)!.description}`);
        return { text: [text, ...complete, ...errors].join("\n"), details: { cargadas: ok.length } };
      },
    };
    return [help, search, load];
  }
}
