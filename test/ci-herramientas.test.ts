import "./datos-tmp.ts";
// Qué herramientas tiene el agente en una corrida de CI. La corrida las saca por nombre (HERRAMIENTAS_FUERA_DE_CI):
// una herramienta nueva del harness entraría sola a CI sin que nadie lo decida. Esta prueba lo impide: toda
// herramienta disponible con la configuración de CI tiene que estar en la lista revisada de abajo. Si agregás una
// herramienta y esto falla, decidí: si no ejecuta comandos en el runner, no usa cuentas del operador, no cambia el
// alcance y no sale a servicios de terceros por fuera del cliente HTTP, sumala a REVISADAS; si no, a
// HERRAMIENTAS_FUERA_DE_CI (src/ci/corrida.ts).
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { HERRAMIENTAS_DE_ESCRITURA, HERRAMIENTAS_FUERA_DE_CI } from "../src/ci/corrida.ts";
import { Engine } from "../src/engine.ts";
import { resolveProvider } from "../src/providers.ts";

/** Revisadas para CI: dentro del alcance sellado (cliente HTTP, navegador propio, escáneres), locales o de la sesión. */
const REVISADAS = new Set([
  // Sesión, memoria, hallazgos y catálogo.
  "memory_search", "memory_read", "memory_write", "artifact_read", "fixture_run", "scope_check", "finding_record", "finding_update", "finding_list",
  "delegate", "deep_reason", "help_search", "tool_search", "tools_load", "skill_load",
  // Cliente HTTP y sondas: todo destino pasa por el alcance sellado.
  "http_request", "http_probe", "http_replay", "http_identities", "coverage_mark", "coverage_view", "site_map", "js_endpoints", "access_matrix",
  "auth_probe", "param_probe", "body_probe", "path_probe", "graphql_probe", "csrf_check", "race_probe", "upload_probe", "ws_probe", "outbound_probe",
  "ids_harvest", "web_source_pull", "sourcemap_recover", "tech_fingerprint", "jwt_inspect", "secrets_scan", "url_dedupe", "dns_resolve",
  "canary_new", "canary_list", "payload_list", "payload_get", "har_import", "postman_import", "openapi_import",
  // Navegador propio del harness (no el del operador) y escáneres: con el alcance del cliente HTTP y `evaluacion.escaneres`.
  "browser_open", "browser_read", "browser_act", "browser_capture", "browser_tabs", "browser_close",
  "nmap_scan", "httpx_probe", "nuclei_scan", "ffuf_fuzz", "katana_crawl", "sqlmap_scan", "subfinder_enum",
  // Lectura del código del repositorio y análisis locales.
  "code_list", "code_read", "code_search", "code_crypto", "code_gitleaks", "code_semgrep", "hash_crack", "apk_analyze",
  // Banco local de CVE y CWE; detección (purple).
  "cve_search", "cve_detail", "cwe_detail", "vuln_ask", "vuln_graph", "detection_expect", "detection_hit", "detection_view",
  // Grafo de hechos (base local del proyecto).
  "grafo", "grafo_anotar",
]);

function disponibles(disabled: string[]): string[] {
  const cwd = mkdtempSync(join(tmpdir(), "ci-herramientas-"));
  const engine = new Engine({ cwd, provider: resolveProvider("faux"), disabled, autoVerify: false, cveFeed: false, mcp: {}, investigacion: false, router: "fijo" });
  try {
    return [...new Set([...engine.agent.tools.map((tool) => tool.name), ...engine.catalog.available.keys()])].sort();
  } finally {
    void engine.close().finally(() => rmSync(cwd, { recursive: true, force: true }));
  }
}

test("CI: ninguna herramienta entra sin revisar, y las que se sacan no están (ni en el núcleo ni en el catálogo)", () => {
  const nombres = disponibles([...HERRAMIENTAS_FUERA_DE_CI]);
  // La lista sale del motor de verdad (núcleo y catálogo): si viniera vacía, lo de abajo pasaría sin mirar nada.
  for (const esperada of ["http_request", "finding_record", "nuclei_scan", "code_read"]) assert.ok(nombres.includes(esperada), `falta ${esperada}`);
  const sinRevisar = nombres.filter((nombre) => !REVISADAS.has(nombre));
  assert.deepEqual(sinRevisar, [], `herramientas disponibles en CI sin revisar: ${sinRevisar.join(", ")} (ver el comentario de arriba)`);
  const coladas = HERRAMIENTAS_FUERA_DE_CI.filter((nombre) => nombres.includes(nombre));
  assert.deepEqual(coladas, [], `herramientas que CI saca y siguen disponibles: ${coladas.join(", ")}`);
  // Una lista no puede revisar y sacar lo mismo.
  assert.deepEqual(HERRAMIENTAS_FUERA_DE_CI.filter((nombre) => REVISADAS.has(nombre)), []);
});

test("CI en sólo lectura: además salen las sondas que escriben", () => {
  const nombres = disponibles([...HERRAMIENTAS_FUERA_DE_CI, ...HERRAMIENTAS_DE_ESCRITURA]);
  assert.deepEqual(HERRAMIENTAS_DE_ESCRITURA.filter((nombre) => nombres.includes(nombre)), []);
});
