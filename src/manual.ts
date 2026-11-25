// El manual del harness, generado desde el código: comandos del operador (CLI y TUI), herramientas,
// servidores MCP y las guías del repositorio. El agente lo consulta con help_search para responder
// sobre sí mismo sin adivinar, y la ayuda de la CLI y la TUI salen de acá para que no diverjan.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { configPath } from "./providers.ts";

export function cliHelp(): string {
  // Títulos en mayúscula y sin sangría: manualEntries sólo toma las líneas con sangría («  cyber …», «  -x, --…»).
  return `☀️ Orobas · orobas-sec, de Elevate AI

Uso: cyber [comando] [opciones]

SESIONES
  cyber                        abre la TUI con una sesión nueva
  cyber -c                     retoma la última sesión (aunque siga trabajando)
  cyber -s <id>                retoma una sesión por ID
  cyber -s <id> --continuar    retoma un turno interrumpido (caída o reinicio)
  cyber --resumen              sesiones recientes de todos tus proyectos; abre la elegida
  cyber -p "texto"             un turno sin TUI; la respuesta va a stdout
  cyber -p "texto" --detach    lo deja trabajando en segundo plano y vuelve
  cyber jobs                   sesiones del proyecto y su estado
  cyber sesiones               lo mismo, con título, actividad y gasto; en la TUI, /sesiones retoma, ramifica o renombra

ALCANCE Y HALLAZGOS
  cyber scope [add|excluir|quitar <reglas>|limpiar|recuperar <rev>|sesiones|cabecera Nombre: valor]   alcance de la sesión y cabeceras fijas del proyecto
  cyber findings [todos | id [estado motivo]]         hallazgos del proyecto (con -s, de esa sesión)
  cyber informe [en] [proyecto]  informe Markdown del proyecto (con -s, de esa sesión); «en»: textos fijos en inglés
  cyber mejoras [N] [--modelo]  diagnóstico local de las últimas N sesiones; --modelo redacta propuestas con el modelo fuerte y le manda sólo tipo, sesión, pasos, conteos y herramienta (con secretos tapados), nunca errores, motivos ni rutas
  cyber cobertura              cobertura de la evaluación de la última sesión
  cyber grafo [faltantes|vecinos <nodo>|caminos <a> → <b>|hallazgo <id>|exportar json|dot|mermaid]  grafo de hechos de la última sesión (o la de -s)
  cyber cves [actualizar] [N]  CVEs nuevos críticos y altos (Zero Wire): estado del feed, cruces de la sesión, últimos N
  cyber memoria [consulta]     busca en la memoria del proyecto
  cyber evidencia [hash]       artefactos guardados
  cyber permisos [todo|normal|permitir|quitar <prefijo>|limpiar]  shell: autoaprobar todo o prefijos «siempre»

CUENTAS
  cyber orobas                 vincula, renueva o revoca tu clave de orobas
  cyber hackerone              vincula, actualiza o revoca tu cuenta de HackerOne
  cyber chatgpt                estado, uso y cuentas de ChatGPT (Continue with ChatGPT)
  cyber login|logout chatgpt   autoriza tu plan con OpenAI o revoca la sesión
  cyber h1 [buscar <texto>|todos|alcance <programa>]  programas de HackerOne; carga el alcance de uno
  cyber <plataforma>           vincula o revoca github, vercel, supabase, aws, gcloud, azure, cloudflare o kubernetes
  cyber login <plataforma>     lo mismo, con el login de la CLI de la plataforma (también hackerone)
  cyber extension              instala y empareja la extensión de Chromium: el agente usa tu navegador
  cyber navegador [si|no]      tu navegador en este proyecto: estado de la extensión, autorizarlo o revocarlo

GASTO
  cyber costos                 gasto de API del proyecto
  cyber tope [USD|sin]         tope de gasto del proyecto, sumando todas sus sesiones
  cyber uso                    uso completo del proyecto; lo exporta a cyber-informes/ para enviar

INTEGRACIÓN CONTINUA
  cyber ci                     evaluación no interactiva con .orobas/ci.yml: alcance autorizado y sellado, topes de gasto y tiempo, sólo verificados bloquean
  cyber ci --retest            vuelve a probar los hallazgos verificados de la corrida anterior (--anterior) y dice cuáles quedaron arreglados
  cyber ci validar | huella | ejemplo | comentar   valida la configuración, muestra la huella del alcance, un ejemplo, o comenta en el PR

SISTEMA
  cyber toolbox                escáneres, navegador, plataformas y modelo; cómo instalar lo que falta
  cyber daemon [stop]          corre el daemon en primer plano, o lo detiene
  cyber --actualizar           instala el último release, verificando su firma (y baja la imagen)
  cyber --version              la versión instalada
  cyber --instalar             copia el lanzador al PATH del usuario
  cyber --cerrar-docker si|no  cerrar Docker Desktop al salir si lo abrió cyber (CYBER_CERRAR_DOCKER=0|1)

OPCIONES
  -m, --model proveedor/modelo   modelo base; si falta, $CYBER_MODEL, "defaultModel" u orobas/glm-5.3-flash; «faux» simula
  -b, --presupuesto USD          tope de gasto por sesión (2.00 por defecto; «sin» lo quita)
  -r, --peticiones N             tope de peticiones HTTP (sin tope; 2000 con un programa de HackerOne)
      --ritmo N                  peticiones por segundo como máximo (sin ritmo; 5 con un programa de HackerOne)
      --agente texto             User-Agent propio (ElevateAICyber/0.1, con tu usuario de HackerOne si aplica)
      --cabecera "Nombre: valor"  Cabecera fija para el objetivo; repetible y guardada en el proyecto
      --streamer                 abrir la TUI en modo streamer (también CYBER_STREAMER=1)
      --no-streamer              abrir la TUI con la vista completa aunque CYBER_STREAMER esté activo
      --obs archivo              abrir en modo streamer y crear la fuente de texto para OBS
  -C, --dir carpeta              carpeta del proyecto (la actual por defecto)

NOTAS
  Todo se puede pedir hablando: «vamos con el programa X», «subí el presupuesto a 5», «armá el informe».
  En la TUI, «$ comando» corre el comando en tu terminal y el agente ve la salida en tu próximo mensaje.
  El agente corre en un daemon por proyecto: cerrar la TUI no detiene un turno en curso.
  Los CVEs nuevos críticos y altos (Zero Wire) se cruzan solos con lo que el agente vio en el alcance (/cves); "cveFeed": false en la configuración o CYBER_CVE_FEED=no lo apaga.
  Los datos de trabajo quedan en tu carpeta de datos, fuera del proyecto; en él solo se escribe cyber-informes/.
  Las credenciales quedan cifradas en tu carpeta de credenciales (/orobas, /hackerone y /<plataforma> en la TUI).
  La cuenta de orobas es obligatoria con cualquier modelo; con claves o modelos propios se pide verificación
  (el nivel se ve en cyber.elevateai.ar/cuenta).
  Los flags --actualizar, --instalar y --cerrar-docker son del lanzador de Docker; CYBER_IMAGE cambia la imagen
  y CYBER_NO_UPDATE=1 omite la búsqueda de actualizaciones.
  Proveedores y tarifas: ${configPath()}`;
}

// Los comandos de la TUI y las plataformas viven con la TUI (src/tui/comandos.ts): acá sólo se reexportan para el manual.
export { PLATFORM_NAMES, TUI_COMMANDS } from "./tui/comandos.ts";
import { TUI_COMMANDS } from "./tui/comandos.ts";

export interface ManualEntry {
  kind: "cli" | "tui" | "herramienta" | "mcp" | "guia";
  name: string;
  text: string;
}

const GUIDES = ["README.md", "docs/herramientas.md"];

/** Raíz del repositorio: este archivo vive en src/. */
export const ROOT = join(import.meta.dirname, "..");

/** Secciones de las guías Markdown del repositorio, una entrada por encabezado. */
function guideEntries(root: string): ManualEntry[] {
  const entries: ManualEntry[] = [];
  for (const file of GUIDES) {
    const path = join(root, file);
    if (!existsSync(path)) continue;
    let heading = file;
    let body: string[] = [];
    const flush = () => {
      const text = body.join("\n").trim();
      if (text) entries.push({ kind: "guia", name: `${file} › ${heading}`, text: text.slice(0, 1200) });
      body = [];
    };
    for (const line of readFileSync(path, "utf8").split("\n")) {
      const match = /^#{1,3}\s+(.+)/.exec(line);
      if (match) {
        flush();
        heading = match[1]!.trim();
      } else body.push(line);
    }
    flush();
  }
  return entries;
}

export function manualEntries(extra: { tools?: Array<{ name: string; label: string; description: string; loaded: boolean }>; mcp?: string[]; incorporados?: string[]; root?: string } = {}): ManualEntry[] {
  const entries: ManualEntry[] = [];
  for (const line of cliHelp().split("\n")) {
    const match = /^\s+(cyber [^ ]+(?: [^ ]+)?|-\w, --\S+|--\S+)\s+(.+)$/.exec(line);
    if (match) entries.push({ kind: "cli", name: match[1]!.trim(), text: match[2]!.trim() });
  }
  for (const command of TUI_COMMANDS) entries.push({ kind: "tui", name: `/${command.name}`, text: `${command.parent ? `en /${command.parent} · ` : ""}${command.description}` });
  for (const tool of extra.tools ?? []) entries.push({ kind: "herramienta", name: `${tool.name}${tool.loaded ? " (cargada)" : ""}`, text: `${tool.label}: ${tool.description}` });
  for (const server of extra.mcp ?? []) entries.push({ kind: "mcp", name: server, text: "servidor MCP configurado por el operador; sus herramientas se descubren con tool_search y se cargan con tools_load" });
  for (const server of extra.incorporados ?? []) entries.push({ kind: "mcp", name: server, text: `servidor MCP incorporado en la caja${server === "rea" ? " (REA, ingeniería inversa: habilidad ingenieria-inversa)" : ""}; sus herramientas ya están en el catálogo y arranca al primer uso` });
  entries.push(...guideEntries(extra.root ?? ROOT));
  return entries;
}

const plain = (text: string) => text.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase();

export function searchManual(entries: ManualEntry[], query: string, limit = 10): ManualEntry[] {
  const terms = plain(query).split(/[\s,]+/).filter((term) => term.length > 1);
  if (!terms.length) return entries.slice(0, limit);
  const score = (entry: ManualEntry) => {
    const name = plain(entry.name);
    const text = plain(entry.text);
    return terms.reduce((sum, term) => sum + (name.includes(term) ? 3 : text.includes(term) ? 1 : 0), 0);
  };
  return entries
    .map((entry) => ({ entry, score: score(entry) }))
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, limit)
    .map((item) => item.entry);
}

/** Texto para el agente: una línea por entrada, con su clase. */
export function formatManual(entries: ManualEntry[]): string {
  if (!entries.length) return "Nada en el manual coincide. Probá con otras palabras, o decile al operador que no está documentado.";
  return entries.map((entry) => `[${entry.kind}] ${entry.name} — ${entry.text.replace(/\s+/g, " ").slice(0, 400)}`).join("\n");
}
