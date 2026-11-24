// Apps móviles: apk_analyze. Muchos programas de bug bounty ponen la app en el alcance, y lo que trae
// adentro (hosts, rutas, claves, banderas del manifest) suele pegarle al mismo backend que la web. La
// herramienta lee el APK que dejó el operador (o uno que se baja de una URL del alcance), sin salir a
// ningún otro lado: si la caja tiene jadx o apktool, decompila ahí; si no, lee lo que se puede sin
// ellas (cadenas de los dex, resources.arsc, assets, res/raw, el manifest y la configuración de red).
// Los secretos que trae la app son material del objetivo: vuelven enteros al modelo (y tapados en las
// trazas, src/secretos-sesion.ts). Esta herramienta no los valida contra ningún servicio ni los usa.
import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, relative } from "node:path";
import { isIP } from "node:net";
import type { Tool, ToolResult } from "./agent.ts";
import type { Artifacts } from "./artifacts.ts";
import { arscStrings, axmlStrings, decodeAxml, dexStrings, looksLikeZip, parseTextXml, printableStrings, type XmlNode, type ZipEntry, zipEntries, zipRead } from "./apk.ts";
import { pacer } from "./ceder.ts";
import { insideProject } from "./codigo.ts";
import { exec, which } from "./exec.ts";
import type { FindingInput } from "./findings.ts";
import { type HttpClient, isStaticAsset } from "./http.ts";
import { enCaja } from "./instalar-herramientas.ts";
import { reaDisponible } from "./rea.ts";
import { extractApi } from "./jsanalisis.ts";
import { SECRET_PATTERNS } from "./probes.ts";
import { decide } from "./scope.ts";

export interface MobileContext {
  artifacts: Artifacts;
  http: HttpClient;
  /** Carpeta del proyecto: de acá salen los APK locales y acá se deja lo decompilado si se pide. */
  cwd: string;
  /** Registra una pista y devuelve su id corto; tira si ya hay una igual (mismo activo y clase). */
  findingRecord?: (input: FindingInput) => string;
  /** Decompiladores disponibles; por defecto, los de la caja si están en el PATH. Las pruebas pasan dobles. */
  decompilers?: () => { jadx?: string; apktool?: string };
  run?: (options: { argv: string[]; timeoutMs: number; signal?: AbortSignal }) => Promise<{ exitCode: number | null; stdout: string; stderr: string; timedOut?: boolean; cancelled?: boolean }>;
  /** ¿Hay REA en esta sesión (dentro de la caja)? Entonces el resumen sugiere seguir con él. Por defecto, reaDisponible(). */
  rea?: () => boolean;
}

/** Tope de un APK local y de uno bajado (la descarga queda además como evidencia del intercambio). */
export const MAX_LOCAL = 400 * 1024 * 1024;
export const MAX_DOWNLOAD = 150 * 1024 * 1024;
/** Topes de lectura: por dex, por archivo de texto, por binario y en total. */
const MAX_DEX = 160 * 1024 * 1024;
const MAX_TEXT = 32 * 1024 * 1024;
const MAX_BINARY = 64 * 1024 * 1024;
const MAX_TOTAL = 700 * 1024 * 1024;

const str = (extra: object = {}) => ({ type: "string", ...extra });
const int = (extra: object = {}) => ({ type: "integer", ...extra });
const bool = (description: string) => ({ type: "boolean", description });
const obj = (properties: Record<string, object>, required: string[]) => ({ type: "object", properties, required });

// ─── Secretos ──────────────────────────────────────────────────────────────────────────────────

type Confianza = "alta" | "media";
interface SecretRule {
  tipo: string;
  pattern: RegExp;
  confianza: Confianza;
  /** Grupo de la expresión con el valor; por defecto, la coincidencia entera. */
  group?: number;
  check?: (value: string) => boolean;
  nota?: string;
}

const jwtValid = (value: string) => {
  try {
    return typeof JSON.parse(Buffer.from(value.split(".")[0]!, "base64url").toString("utf8")).alg === "string";
  } catch {
    return false;
  }
};
const basicValid = (value: string) => /^[\x21-\x7e]{1,100}:[\x20-\x7e]{1,100}$/.test(Buffer.from(value, "base64").toString("latin1"));
/** Valores de ejemplo, plantillas y relleno: no son secretos. */
const PLACEHOLDER = /x{5,}|\*{4,}|your[_-]|<[^>]{0,40}>|%[sd]|\$\{|\{\{|example|placeholder|changeme|dummy|sample|insert[_-]|replace[_-]?me|0{12,}|1234567890|abcdefghij/i;

/** Patrones de secrets_scan que ya tienen versión propia acá (con tope de largo y más formatos). */
const COVERED = new Set(["clave de acceso AWS", "token de GitHub", "clave privada", "JWT", "clave de Stripe", "clave de Google", "token de Slack", "URL con credenciales"]);

/** Formatos conocidos primero (más específicos); después los patrones generales del harness (probes.ts). */
// Cada patrón tiene tope de largo y, si la clase admite «-», no arranca detrás de otro «-» o letra: un asset
// armado («eyJ-eyJ-…», «xoxb-xoxb-…») volvía cuadrática la búsqueda.
const SECRET_RULES: SecretRule[] = [
  { tipo: "clave de acceso AWS", pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, confianza: "alta" },
  { tipo: "clave secreta AWS", pattern: /(?:aws.{0,3}secret.{0,3}(?:access.{0,3})?key|secretAccessKey)["'\s:=,]{1,8}([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi, confianza: "alta", group: 1 },
  { tipo: "clave de API de Google", pattern: /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g, confianza: "alta", nota: "las claves de Google van embebidas por diseño: sólo pesan si no tienen restricciones de API o de app, y saberlo exige usarla contra Google" },
  { tipo: "secreto OAuth de Google", pattern: /(?<![\w-])GOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_-])/g, confianza: "alta" },
  { tipo: "clave de servidor de FCM", pattern: /(?<![\w-])AAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{120,400}/g, confianza: "alta" },
  { tipo: "clave secreta de Stripe", pattern: /\b[sr]k_live_[A-Za-z0-9]{16,250}\b/g, confianza: "alta" },
  { tipo: "clave de prueba de Stripe", pattern: /\b[sr]k_test_[A-Za-z0-9]{16,250}\b/g, confianza: "media" },
  { tipo: "token de Slack", pattern: /(?<![\w-])xox[abposr]-[A-Za-z0-9-]{10,250}\b/g, confianza: "alta" },
  { tipo: "webhook de Slack", pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,}\/B[A-Z0-9]{6,}\/[A-Za-z0-9]{20,64}/g, confianza: "alta" },
  { tipo: "token de Twilio", pattern: /twilio.{0,20}?(?:auth.{0,3})?token["'\s:=,]{1,8}([0-9a-f]{32})\b/gi, confianza: "alta", group: 1 },
  { tipo: "clave de API de Twilio", pattern: /\bSK[0-9a-f]{32}\b/g, confianza: "alta" },
  { tipo: "SID de cuenta de Twilio", pattern: /\bAC[0-9a-f]{32}\b/g, confianza: "media", nota: "identificador: sin el token no autentica" },
  { tipo: "clave de Algolia", pattern: /algolia.{0,20}?key["'\s:=,]{1,8}([0-9a-f]{32})\b/gi, confianza: "alta", group: 1, nota: "si es la de búsqueda es pública por diseño; la de administración no" },
  { tipo: "DSN de Sentry con secreto", pattern: /\bhttps?:\/\/[0-9a-f]{32}:[0-9a-f]{32}@[a-z0-9.-]+(?::\d+)?\/\d+/g, confianza: "alta" },
  { tipo: "DSN de Sentry", pattern: /\bhttps?:\/\/[0-9a-f]{32}@[a-z0-9.-]+(?::\d+)?\/\d+/g, confianza: "media", nota: "público por diseño en una app: sirve para mandar eventos, no para leerlos" },
  { tipo: "JWT", pattern: /(?<![\w-])eyJ[A-Za-z0-9_-]{10,1000}\.eyJ[A-Za-z0-9_-]{10,8000}\.[A-Za-z0-9_-]{10,4000}/g, confianza: "alta", check: jwtValid },
  { tipo: "clave privada", pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]{20,8000}?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g, confianza: "alta" },
  { tipo: "token de GitHub", pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g, confianza: "alta" },
  { tipo: "token de GitLab", pattern: /(?<![\w-])glpat-[A-Za-z0-9_-]{20,80}\b/g, confianza: "alta" },
  { tipo: "clave de SendGrid", pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, confianza: "alta" },
  { tipo: "clave de Mailgun", pattern: /\bkey-[0-9a-f]{32}\b/g, confianza: "alta" },
  { tipo: "token secreto de Mapbox", pattern: /(?<![\w.-])sk\.eyJ[A-Za-z0-9_-]{20,2000}\.[A-Za-z0-9_-]{20,2000}/g, confianza: "alta" },
  { tipo: "token de Facebook", pattern: /\bEAA[A-Za-z0-9]{60,400}/g, confianza: "alta" },
  { tipo: "token de Square", pattern: /(?<![\w-])sq0(?:atp|csp)-[A-Za-z0-9_-]{22,60}\b/g, confianza: "alta" },
  { tipo: "token de Shopify", pattern: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g, confianza: "alta" },
  { tipo: "credencial Basic", pattern: /\bBasic\s{1,4}([A-Za-z0-9+/]{8,500}={0,2})(?![A-Za-z0-9+/=])/g, confianza: "alta", group: 1, check: basicValid },
  { tipo: "token Bearer", pattern: /\bBearer\s{1,4}([A-Za-z0-9._~+/-]{20,2000}={0,2})(?![A-Za-z0-9._~+/=-])/g, confianza: "alta", group: 1 },
  { tipo: "cabecera Authorization", pattern: /["']?Authorization["']?\s*[:=,]\s*["'](?:(?:Bearer|Basic|Token)\s+)?([^"'\s]{12,200})["']/gi, confianza: "alta", group: 1 },
  // Los del harness (secrets_scan) que no están arriba con topes de largo (sobre texto del APK un patrón sin tope
  // puede volverse cuadrático): hoy, los generales «password/secret/token = valor», con confianza media.
  ...SECRET_PATTERNS.filter((rule) => !COVERED.has(rule.name)).map((rule): SecretRule => {
    const general = /campo|asignación/.test(rule.name);
    // En código minificado «token:e.token» no es un secreto: se descartan referencias a variables y llamadas.
    const check = (value: string) => value.length >= 6 && !/^(?:password|secret|token|null|undefined|true|false|string)$/i.test(value) && !/^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$|\($/.test(value);
    return { tipo: rule.name, pattern: rule.pattern, confianza: general ? "media" : "alta", ...(general ? { check } : {}) };
  }),
];

/** Valor de una coincidencia de los patrones generales: lo que está después del «=» o «:». */
const generalValue = (match: string) => {
  const at = match.search(/[=:]/);
  return (at >= 0 ? match.slice(at + 1) : match).trim().replace(/^["']|["']$/g, "");
};

/** Primeros y últimos caracteres y el largo: alcanza para reconocerlo, no para usarlo. */
export function redactSecret(value: string): string {
  const flat = value.replace(/\s+/g, " ");
  if (flat.length >= 24) return `${flat.slice(0, 6)}…${flat.slice(-4)} (${flat.length})`;
  if (flat.length >= 12) return `${flat.slice(0, 4)}…${flat.slice(-2)} (${flat.length})`;
  return `${flat.slice(0, 2)}… (${flat.length})`;
}

interface SecretHit {
  id: string;
  tipo: string;
  confianza: Confianza;
  valor: string;
  archivos: string[];
  nota?: string;
}

// ─── URLs, hosts y rutas ───────────────────────────────────────────────────────────────────────

const URL_STOP = new Set([..." \t\r\n\"'<>`\\^{}|"]);
const SCHEME_CHAR = /[A-Za-z0-9+.-]/;

/** URLs de un texto, en tiempo lineal: se parte de cada «://» y se busca el esquema hacia atrás. */
export function findUrls(text: string, limit = 50_000): string[] {
  const out: string[] = [];
  for (let from = 0, at: number; out.length < limit && (at = text.indexOf("://", from)) >= 0; ) {
    from = at + 3;
    let start = at;
    while (start > 0 && at - start < 32 && SCHEME_CHAR.test(text[start - 1]!)) start--;
    while (start < at && !/[A-Za-z]/.test(text[start]!)) start++;
    if (start === at) continue;
    let end = at + 3;
    while (end < text.length && end - at < 2048 && !URL_STOP.has(text[end]!)) end++;
    const url = text.slice(start, end).replace(/[),.;:\]]+$/, "");
    if (url.length > at - start + 3) out.push(url);
    from = end;
  }
  return out;
}

/** Esquemas que no son de la app (sistema, web, documentos): no son deep links propios. */
const SYSTEM_SCHEMES = new Set(["http", "https", "ws", "wss", "ftp", "ftps", "file", "content", "android.resource", "android-app", "jar", "data", "about", "blob", "chrome", "chrome-extension", "javascript", "market", "intent", "package", "mailto", "tel", "sms", "smsto", "mms", "geo", "rtsp", "rtmp", "smb", "ldap", "ldaps", "jdbc", "urn", "xmlns", "res", "asset", "assets", "app", "local", "ws+unix", "unix", "socks", "socks4", "socks5", "git", "ssh", "svn", "sftp", "s3", "gs", "hdfs", "redis", "mongodb", "mysql", "postgres", "postgresql", "amqp", "mqtt", "fb", "fbconnect", "whatsapp", "tg", "twitter", "spotify", "comgooglemaps", "maps", "itms-apps", "itms-services"]);
/** Hosts de documentación, esquemas XML y bibliotecas: ruido que no es superficie del objetivo. */
const NOISE_HOSTS = /(^|\.)(schemas\.android\.com|w3\.org|xmlpull\.org|apache\.org|ns\.adobe\.com|purl\.org|xml\.org|json-schema\.org|example\.(com|org|net)|schemas\.microsoft\.com|schemas\.xmlsoap\.org|openxmlformats\.org|developer\.android\.com|issuetracker\.google\.com|googlesource\.com|slf4j\.org|oracle\.com|unicode\.org|ietf\.org|iana\.org|reactnative\.dev|fb\.me|facebook\.github\.io|goo\.gl|bit\.ly|xmlsoap\.org|jsonschema\.net|ogp\.me|schema\.org|mozilla\.org|whatwg\.org|ecma-international\.org|localhost|10\.0\.2\.2|127\.0\.0\.1)$/i;
/** Rutas del sistema de archivos de Android: no son de la API. */
const SYSTEM_PATH = /^\/(?:system|proc|data|sdcard|dev|etc|storage|mnt|sys|vendor|res|assets|android_asset|android_res|META-INF|usr|bin|sbin|tmp|cache|acct|apex|odm|product|oem|lib|lib64|debug_ramdisk|linkerconfig|config\/sdcardfs)(?:\/|$)/i;
const API_FIRST = /^(?:api|apis|v\d+(?:\.\d+)?|rest|graphql|gql|auth|oauth2?|login|logout|signin|signup|register|token|tokens|session|sessions|account|accounts|user|users|me|profile|profiles|customer|customers|client|clients|order|orders|payment|payments|checkout|cart|carts|admin|internal|private|mobile|app|apps|service|services|backend|gateway|bff|public|upload|uploads|file|files|media|search|notification|notifications|device|devices|config|settings|webhook|webhooks|health|status|debug|reset|password|otp|verify|kyc|wallet|wallets|transfer|transfers|card|cards|product|products|message|messages|chat|feed|graph)$/i;
/** Primeros segmentos de lo que parece una ruta y no lo es: paquetes, tipos MIME, formatos. */
const NOT_API_FIRST = /^(?:com|org|net|io|android|androidx|kotlin|kotlinx|java|javax|dalvik|sun|okhttp3|okio|retrofit2|google|application|text|image|audio|video|multipart|font|model|message\/rfc822|dd|mm|yyyy|hh)$/i;
/** Lo que merece mirarse primero: administración, depuración, identidad, dinero, subidas. */
export const INTERESTING = /admin|internal|debug|staging|\btest|\bdev\b|backup|export|import|graphql|upload|private|secret|token|passw|reset|webhook|actuator|swagger|openapi|config|management|console|impersonat|sudo|role|permission|kyc|wallet|transfer|payment|refund|invite|otp/i;
const NON_PROD_HOST = /(^|[.-])(dev|develop|stag|staging|stg|qa|uat|test|testing|sandbox|preprod|pre|internal|admin|beta|demo)\d*([.-]|$)/i;

/** ¿Es una ruta de API? Devuelve la ruta limpia (sin consulta) o undefined. */
export function apiPath(value: string): { path: string; relative: boolean } | undefined {
  const text = value.trim();
  if (text.length < 2 || text.length > 200 || /\s/.test(text) || text.startsWith("//")) return undefined;
  if (!/^[A-Za-z0-9_\-{}.~%:@/$?=&]+$/.test(text) || /^L[\w/$]+;$/.test(text)) return undefined;
  const path = text.split("?")[0]!.replace(/\/+$/, "");
  const relative = !path.startsWith("/");
  const segments = path.split("/").filter(Boolean);
  if (!segments.length || segments.length > 12 || !segments.some((segment) => /[A-Za-z]{2}/.test(segment.replace(/\{[^}]*\}/g, "")))) return undefined;
  if (isStaticAsset(`/${segments.join("/")}`) && !/\{/.test(path)) return undefined;
  if (NOT_API_FIRST.test(segments[0]!) || /\$/.test(path)) return undefined;
  if (relative) {
    if (segments.length < 2 && !/\{/.test(path)) return undefined;
    if (!API_FIRST.test(segments[0]!) && !/\{[A-Za-z_]\w*\}/.test(path)) return undefined;
    return { path, relative: true };
  }
  if (SYSTEM_PATH.test(path)) return undefined;
  if (!API_FIRST.test(segments[0]!) && !/\{[A-Za-z_]\w*\}/.test(path) && !(segments.length >= 2 && /api/i.test(path))) return undefined;
  return { path, relative: false };
}

interface HostInfo {
  host: string;
  schemes: Set<string>;
  paths: Map<string, Set<string>>;
  files: Set<string>;
  urls: number;
  allowed?: boolean;
  reason?: string;
}

interface PathInfo {
  path: string;
  methods: Set<string>;
  files: Set<string>;
  relative: boolean;
}

// ─── Manifest y configuración de red ───────────────────────────────────────────────────────────

const attr = (node: XmlNode, name: string): string | undefined => node.attrs[`android:${name}`] ?? node.attrs[name];
const flag = (value: string | undefined): boolean | undefined => (value === "true" ? true : value === "false" ? false : undefined);
const kids = (node: XmlNode | undefined, name: string) => (node?.children ?? []).filter((child) => child.name === name);
const PROTECTION = ["normal", "dangerous", "signature", "signatureOrSystem"];

export interface Component {
  tipo: string;
  nombre: string;
  exportado: boolean;
  /** Exportado sin declararlo (por tener intent-filter, o provider en apps muy viejas). */
  implicito: boolean;
  permiso?: string;
  lanzador: boolean;
  acciones: string[];
  authorities?: string;
  grantUriPermissions?: boolean;
}

export interface ManifestInfo {
  paquete?: string;
  version?: string;
  versionCode?: string;
  minSdk?: number;
  targetSdk?: number;
  debuggable?: boolean;
  allowBackup?: boolean;
  usesCleartextTraffic?: boolean;
  networkSecurityConfig?: string;
  permisos: string[];
  permisosPropios: Array<{ nombre: string; proteccion: string }>;
  componentes: Component[];
  deepLinks: Array<{ link: string; componente: string; autoVerify: boolean; exportado: boolean }>;
  metadatos: Array<{ nombre: string; valor: string }>;
}

export function manifestInfo(root: XmlNode): ManifestInfo {
  const sdk = kids(root, "uses-sdk")[0];
  const app = kids(root, "application")[0];
  const number = (value: string | undefined) => (value && /^-?\d+$/.test(value) ? Number(value) : undefined);
  const target = number(sdk && attr(sdk, "targetSdkVersion"));
  const info: ManifestInfo = {
    paquete: root.attrs.package,
    version: attr(root, "versionName"),
    versionCode: attr(root, "versionCode"),
    minSdk: number(sdk && attr(sdk, "minSdkVersion")),
    targetSdk: target,
    debuggable: app && flag(attr(app, "debuggable")),
    allowBackup: app && flag(attr(app, "allowBackup")),
    usesCleartextTraffic: app && flag(attr(app, "usesCleartextTraffic")),
    networkSecurityConfig: app && attr(app, "networkSecurityConfig"),
    permisos: [...new Set([...kids(root, "uses-permission"), ...kids(root, "uses-permission-sdk-23")].map((node) => attr(node, "name") ?? "").filter(Boolean))],
    permisosPropios: kids(root, "permission").map((node) => {
      const level = attr(node, "protectionLevel") ?? "normal";
      const numeric = /^(0x)?[0-9a-f]+$/i.test(level) ? Number(level) & 0xf : undefined;
      return { nombre: attr(node, "name") ?? "", proteccion: numeric !== undefined ? PROTECTION[numeric] ?? level : level };
    }),
    componentes: [],
    deepLinks: [],
    metadatos: [],
  };
  const appPermission = app && attr(app, "permission");
  for (const node of app?.children ?? []) {
    if (node.name === "meta-data") {
      const value = attr(node, "value");
      if (value && !/^[@?]0x/.test(value)) info.metadatos.push({ nombre: attr(node, "name") ?? "", valor: value });
      continue;
    }
    if (!["activity", "activity-alias", "service", "receiver", "provider"].includes(node.name)) continue;
    const filters = kids(node, "intent-filter");
    const declared = flag(attr(node, "exported"));
    const exported = declared ?? (node.name === "provider" ? (target ?? 1) < 17 : filters.length > 0);
    const actions = filters.flatMap((filter) => kids(filter, "action").map((action) => attr(action, "name") ?? ""));
    const categories = filters.flatMap((filter) => kids(filter, "category").map((category) => attr(category, "name") ?? ""));
    const name = attr(node, "name") ?? "?";
    const component: Component = {
      tipo: node.name,
      nombre: name.startsWith(".") && info.paquete ? `${info.paquete}${name}` : name,
      exportado: exported,
      implicito: declared === undefined && exported,
      permiso: attr(node, "permission") ?? (node.name === "provider" ? attr(node, "readPermission") ?? attr(node, "writePermission") : undefined) ?? appPermission,
      lanzador: actions.includes("android.intent.action.MAIN") && categories.includes("android.intent.category.LAUNCHER"),
      acciones: [...new Set(actions)].slice(0, 8),
      ...(node.name === "provider" ? { authorities: attr(node, "authorities"), grantUriPermissions: flag(attr(node, "grantUriPermissions")) } : {}),
    };
    info.componentes.push(component);
    for (const filter of filters) {
      if (!kids(filter, "action").some((action) => attr(action, "name") === "android.intent.action.VIEW")) continue;
      const data = kids(filter, "data");
      const schemes = [...new Set(data.map((item) => attr(item, "scheme")).filter((value): value is string => !!value))];
      const hosts = [...new Set(data.map((item) => { const host = attr(item, "host"); const port = attr(item, "port"); return host ? `${host}${port ? `:${port}` : ""}` : undefined; }).filter((value): value is string => !!value))];
      const paths = [...new Set(data.flatMap((item) => [attr(item, "path"), attr(item, "pathPrefix") && `${attr(item, "pathPrefix")}*`, attr(item, "pathPattern")]).filter((value): value is string => !!value))];
      for (const scheme of schemes) for (const host of hosts.length ? hosts : [""]) for (const path of paths.length ? paths : [""]) {
        if (info.deepLinks.length < 60) info.deepLinks.push({ link: `${scheme}://${host}${path}`, componente: component.nombre, autoVerify: flag(attr(filter, "autoVerify")) === true, exportado: exported });
      }
    }
  }
  return info;
}

export interface NetworkConfig {
  archivo: string;
  cleartextBase?: boolean;
  confiaCAsDelUsuario: boolean;
  /** Dominios con reglas propias: cleartext, pines y CAs. */
  dominios: Array<{ dominios: string[]; cleartext?: boolean; pines: number; vence?: string; casDelUsuario: boolean }>;
  depuracionConfiaCAsDelUsuario: boolean;
}

export function networkConfig(root: XmlNode, archivo: string): NetworkConfig {
  const userCAs = (node: XmlNode | undefined) => kids(node, "trust-anchors").some((anchors) => kids(anchors, "certificates").some((cert) => attr(cert, "src") === "user"));
  const base = kids(root, "base-config")[0];
  const config: NetworkConfig = { archivo, cleartextBase: base && flag(attr(base, "cleartextTrafficPermitted")), confiaCAsDelUsuario: userCAs(base), dominios: [], depuracionConfiaCAsDelUsuario: userCAs(kids(root, "debug-overrides")[0]) };
  const walk = (node: XmlNode) => {
    for (const domain of kids(node, "domain-config")) {
      const pins = kids(domain, "pin-set");
      config.dominios.push({
        dominios: kids(domain, "domain").map((item) => (item.text ?? "").trim()).filter(Boolean),
        cleartext: flag(attr(domain, "cleartextTrafficPermitted")),
        pines: pins.reduce((sum, set) => sum + kids(set, "pin").length, 0),
        vence: pins.map((set) => attr(set, "expiration")).find(Boolean),
        casDelUsuario: userCAs(domain),
      });
      if (config.dominios.length < 100) walk(domain);
    }
  };
  walk(root);
  return config;
}

// ─── Lectura del APK ───────────────────────────────────────────────────────────────────────────

const SKIP_EXT = /\.(png|jpe?g|gif|webp|bmp|ico|svg|9\.png|ogg|mp3|mp4|m4a|aac|wav|webm|mkv|avi|flac|ttf|otf|woff2?|eot|pb|tflite|onnx|bin\.gz|gz|zip|jar|apk|obb|kotlin_builtins|kotlin_module|version|RSA|DSA|EC|SF|MF)$/i;
const TEXT_EXT = /\.(json|xml|properties|txt|js|mjs|cjs|bundle|html?|ya?ml|cfg|conf|ini|env|plist|config|csv|graphql|gql|toml|md|java|kt|smali)$/i;
/** Bibliotecas comunes en lo que decompila jadx: no son código de la app y meten ruido. */
const LIBRARY_DIRS = /^sources\/(?:android|androidx|kotlin|kotlinx|java|javax|dalvik|j\$|com\/google\/(?:android\/(?:gms|material|play|datatransport)|firebase|gson|protobuf|common|crypto|errorprone|j2objc|thirdparty|zxing)|com\/squareup|okhttp3|okio|retrofit2|io\/reactivex|rx|org\/(?:jetbrains|intellij|json|apache|slf4j|bouncycastle|greenrobot|reactivestreams|checkerframework)|com\/facebook|com\/bumptech|io\/flutter|dagger|com\/airbnb\/lottie|com\/fasterxml|net\/sqlcipher|com\/crashlytics|io\/sentry|com\/amplitude|com\/appsflyer|com\/adjust|com\/onesignal|com\/braze|io\/branch|com\/mixpanel|com\/segment|coil|io\/ktor|io\/grpc|com\/github\/(?:mikephil|bumptech)|org\/conscrypt)\//;

interface Source {
  file: string;
  kind: "dex" | "recursos" | "texto" | "binario" | "codigo";
  /** Cadenas sueltas (dex, tablas de recursos, binarios) o el texto entero en un solo elemento. */
  strings: string[];
}

interface ApkRead {
  label: string;
  bytes: number;
  sha256: string;
  manifest?: ManifestInfo;
  /** El manifest no se pudo decodificar (ofuscado o roto). */
  manifestIlegible?: boolean;
  nsc: NetworkConfig[];
  sources: Source[];
  leidos: number;
  omitidos: string[];
  dex: number;
}

const isDex = (name: string) => /\.dex$/i.test(name);

/** Lee un APK (zip en memoria): manifest, configuración de red y las fuentes de texto a revisar. */
async function readApk(label: string, buf: Buffer, pause: () => Promise<void>): Promise<ApkRead> {
  const entries = zipEntries(buf);
  const result: ApkRead = { label, bytes: buf.length, sha256: createHash("sha256").update(buf).digest("hex"), nsc: [], sources: [], leidos: 0, omitidos: [], dex: 0 };
  let total = 0;
  const take = (entry: ZipEntry, max: number) => {
    if (total >= MAX_TOTAL) {
      result.omitidos.push(`${entry.name} (tope total de lectura)`);
      return undefined;
    }
    const data = zipRead(buf, entry, Math.min(max, MAX_TOTAL - total));
    if (!data) {
      result.omitidos.push(`${entry.name} (${entry.size > max ? "más grande que el tope" : `no se pudo abrir (método ${entry.method})`})`);
      return undefined;
    }
    total += data.length;
    result.leidos++;
    return data;
  };
  const manifestEntry = entries.find((entry) => entry.name === "AndroidManifest.xml");
  if (manifestEntry) {
    const data = take(manifestEntry, 8 * 1024 * 1024);
    const root = data && (decodeAxml(data) ?? (data[0] === 0x3c ? parseTextXml(data.toString("utf8")) : undefined));
    if (root?.name === "manifest") result.manifest = manifestInfo(root);
    else result.manifestIlegible = true;
    if (data) result.sources.push({ file: "AndroidManifest.xml", kind: "recursos", strings: axmlStrings(data) });
  }
  let flutter = false;
  for (const entry of entries) {
    await pause();
    const name = entry.name;
    if (name.endsWith("/") || name === "AndroidManifest.xml") continue;
    if (isDex(name)) {
      const data = take(entry, MAX_DEX);
      if (!data) continue;
      result.dex++;
      result.sources.push({ file: name, kind: "dex", strings: dexStrings(data) ?? printableStrings(data, 6) });
      continue;
    }
    if (name === "resources.arsc") {
      const data = take(entry, MAX_TEXT * 2);
      if (data) result.sources.push({ file: name, kind: "recursos", strings: arscStrings(data) ?? printableStrings(data, 6) });
      continue;
    }
    if (/^res\/.*\.xml$/i.test(name)) {
      // Layouts, dibujos y animaciones no traen secretos; sí la configuración (res/xml) y lo crudo (res/raw).
      // Con nombres ofuscados (res/a1.xml) no se sabe: se mira la raíz para encontrar la configuración de red.
      const visual = /^res\/(?:layout|drawable|anim|animator|color|menu|mipmap|navigation|font|transition|interpolator)[^/]*\//i.test(name);
      if (visual) continue;
      const data = take(entry, 4 * 1024 * 1024);
      if (!data) continue;
      const root = decodeAxml(data) ?? (data[0] === 0x3c ? parseTextXml(data.toString("utf8")) : undefined);
      if (root?.name === "network-security-config") result.nsc.push(networkConfig(root, name));
      result.sources.push({ file: name, kind: "recursos", strings: data[0] === 0x3c ? [data.toString("utf8")] : axmlStrings(data) });
      continue;
    }
    if (/^lib\/[^/]+\/libapp\.so$/.test(name)) {
      // Flutter: el código Dart compilado; alcanza con una arquitectura.
      if (flutter) continue;
      const data = take(entry, MAX_BINARY);
      if (data) {
        flutter = true;
        result.sources.push({ file: name, kind: "binario", strings: printableStrings(data, 8) });
      }
      continue;
    }
    if (/global-metadata\.dat$/.test(name) && name.startsWith("assets/")) {
      const data = take(entry, MAX_BINARY);
      if (data) result.sources.push({ file: name, kind: "binario", strings: printableStrings(data, 8) });
      continue;
    }
    if (name.startsWith("META-INF/") || name.startsWith("lib/") || name.startsWith("res/") && !name.startsWith("res/raw/") || SKIP_EXT.test(name)) continue;
    if (!(name.startsWith("assets/") || name.startsWith("res/raw/") || TEXT_EXT.test(name) || !name.includes("/"))) continue;
    const data = take(entry, MAX_TEXT);
    if (!data) continue;
    const head = data.subarray(0, 8192);
    if (head.includes(0) || (data[0] === 0x03 && data[1] === 0x00)) {
      const root = decodeAxml(data);
      if (root?.name === "network-security-config") result.nsc.push(networkConfig(root, name));
      result.sources.push({ file: name, kind: "binario", strings: root ? axmlStrings(data) : printableStrings(data.subarray(0, MAX_BINARY), 8) });
    } else result.sources.push({ file: name, kind: "texto", strings: [data.toString("utf8")] });
  }
  return result;
}

/** Un .apks o .xapk es un zip de APKs: se abren los de adentro (base y splits). */
function innerApks(buf: Buffer): Array<{ label: string; buf: Buffer }> | undefined {
  const entries = zipEntries(buf);
  if (entries.some((entry) => entry.name === "AndroidManifest.xml")) return undefined;
  const apks = entries.filter((entry) => /\.apk$/i.test(entry.name)).slice(0, 8);
  if (!apks.length) return undefined;
  return apks.flatMap((entry) => {
    const data = zipRead(buf, entry, 300 * 1024 * 1024);
    return data && looksLikeZip(data) ? [{ label: entry.name, buf: data }] : [];
  });
}

/** Archivos de texto de lo decompilado (jadx o apktool), sin bibliotecas y con topes. */
function decompiledSources(dir: string, own?: string): { sources: Source[]; manifest?: XmlNode; nsc: Array<{ root: XmlNode; file: string }>; files: number } {
  const sources: Source[] = [];
  const nsc: Array<{ root: XmlNode; file: string }> = [];
  let manifest: XmlNode | undefined;
  let files = 0;
  let bytes = 0;
  const ownDir = own ? `sources/${own.replace(/\./g, "/")}/` : undefined;
  const stack = [dir];
  while (stack.length && files < 40_000 && bytes < 300 * 1024 * 1024) {
    const current = stack.pop()!;
    let entries: string[];
    try { entries = readdirSync(current); } catch { continue; }
    for (const entry of entries) {
      const path = join(current, entry);
      const rel = relative(dir, path).split("\\").join("/");
      let info;
      try { info = statSync(path); } catch { continue; }
      if (info.isDirectory()) {
        // Una biblioteca no se recorre, salvo que sea (o contenga) el paquete de la propia app.
        const dirRel = `${rel}/`;
        const own = ownDir && (ownDir.startsWith(dirRel) || dirRel.startsWith(ownDir));
        if (!LIBRARY_DIRS.test(dirRel) || own) stack.push(path);
        continue;
      }
      if (!TEXT_EXT.test(entry) || info.size > 4 * 1024 * 1024 || /\/(?:layout|drawable|anim|animator|color|menu|mipmap|navigation|font)[^/]*\//.test(`/${rel}`)) continue;
      const text = readFileSync(path, "utf8");
      files++;
      bytes += text.length;
      if (/(^|\/)AndroidManifest\.xml$/.test(rel)) manifest ??= parseTextXml(text);
      if (/\.xml$/.test(rel) && text.includes("network-security-config")) {
        const root = parseTextXml(text);
        if (root?.name === "network-security-config") nsc.push({ root, file: rel });
      }
      sources.push({ file: `decompilado/${rel}`, kind: /\.(java|kt|smali)$/.test(rel) ? "codigo" : "texto", strings: [text] });
    }
  }
  return { sources, manifest, nsc, files };
}

// ─── Análisis ──────────────────────────────────────────────────────────────────────────────────

interface Findings {
  secrets: Map<string, SecretHit>;
  hosts: Map<string, HostInfo>;
  paths: Map<string, PathInfo>;
  schemes: Map<string, string>;
  firebase: { bases: Set<string>; buckets: Set<string> };
  pins: Set<string>;
  pinning: Set<string>;
  named: Array<{ nombre: string; valor: string; archivo: string }>;
}

const newFindings = (): Findings => ({ secrets: new Map(), hosts: new Map(), paths: new Map(), schemes: new Map(), firebase: { bases: new Set(), buckets: new Set() }, pins: new Set(), pinning: new Set(), named: [] });

const RETROFIT = /@(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\(\s*"([^"\n]{1,200})"\s*\)/g;
const RETROFIT_HTTP = /@HTTP\([^)\n]{0,200}?method\s*=\s*"([A-Z]+)"[^)\n]{0,200}?path\s*=\s*"([^"\n]{1,200})"/g;
const QUOTED_PATH = /["'`](\/[A-Za-z0-9_\-{}.~%:@/]{2,200})["'`]/g;
/** Indicios de pinning. Los de código (último campo true) sólo valen sobre lo decompilado sin bibliotecas: en las cadenas de un dex aparecen igual por OkHttp o Conscrypt aunque la app no los use. */
const PINNING_CLUES: Array<[RegExp, string, boolean]> = [
  [/TrustKit/, "TrustKit", false],
  [/react-native-ssl-pinning|SSLPinning|sslPinning|ssl_pinning/, "pinning declarado por una biblioteca o configuración", false],
  [/setTrustedCertificatesBytes|badCertificateCallback/, "Flutter con certificados propios", false],
  [/\.certificatePinner\(|CertificatePinner\.Builder|new CertificatePinner/, "OkHttp CertificatePinner en uso", true],
  [/checkServerTrusted/, "TrustManager propio (checkServerTrusted)", true],
];

function addSecret(found: Findings, rule: SecretRule, value: string, file: string): void {
  const clean = value.trim();
  if (!clean || clean.length > 9000 || PLACEHOLDER.test(clean) || (rule.check && !rule.check(clean))) return;
  const existing = found.secrets.get(clean);
  if (existing) {
    if (existing.archivos.length < 5 && !existing.archivos.includes(file)) existing.archivos.push(file);
    return;
  }
  if (found.secrets.size >= 300) return;
  found.secrets.set(clean, { id: `s${found.secrets.size + 1}`, tipo: rule.tipo, confianza: rule.confianza, valor: clean, archivos: [file], ...(rule.nota ? { nota: rule.nota } : {}) });
}

function addPath(found: Findings, path: string, relative: boolean, file: string, method?: string): void {
  let entry = found.paths.get(path);
  if (!entry) {
    if (found.paths.size >= 3000) return;
    entry = { path, methods: new Set(), files: new Set(), relative };
    found.paths.set(path, entry);
  }
  if (method) entry.methods.add(method.toUpperCase());
  if (entry.files.size < 4) entry.files.add(file);
}

function addUrl(found: Findings, raw: string, file: string): void {
  const scheme = raw.slice(0, raw.indexOf("://")).toLowerCase();
  if (!["http", "https", "ws", "wss"].includes(scheme)) {
    if (!SYSTEM_SCHEMES.has(scheme) && /^[a-z][a-z0-9+.-]{1,30}$/.test(scheme) && found.schemes.size < 200 && !found.schemes.has(scheme)) found.schemes.set(scheme, raw.slice(0, 120));
    return;
  }
  let url: URL;
  try { url = new URL(raw); } catch { return; }
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!host || /[%${}]/.test(host) || (!host.includes(".") && host !== "localhost" && !isIP(host))) return;
  if (/\.firebaseio\.com$|\.firebasedatabase\.app$/.test(host)) found.firebase.bases.add(`https://${host}`);
  if (host === "firebasestorage.googleapis.com") {
    const bucket = /^\/v0\/b\/([^/]+)/.exec(url.pathname)?.[1];
    if (bucket) found.firebase.buckets.add(decodeURIComponent(bucket));
  }
  let entry = found.hosts.get(host);
  if (!entry) {
    if (found.hosts.size >= 2000) return;
    entry = { host, schemes: new Set(), paths: new Map(), files: new Set(), urls: 0 };
    found.hosts.set(host, entry);
  }
  entry.urls++;
  entry.schemes.add(scheme);
  if (entry.files.size < 4) entry.files.add(file);
  let path = url.pathname.replace(/\/+$/, "");
  try { path = decodeURI(path); } catch {}
  if (path && path !== "/" && !(isStaticAsset(path) && !/\{/.test(path)) && entry.paths.size < 400) {
    const methods = entry.paths.get(path) ?? new Set<string>();
    entry.paths.set(path, methods);
  }
}

/** Revisa una fuente: secretos, URLs, rutas, esquemas, Firebase y pistas de pinning. */
function scan(found: Findings, source: Source): void {
  const text = source.strings.length === 1 ? source.strings[0]! : source.strings.join("\n");
  for (const rule of SECRET_RULES) {
    rule.pattern.lastIndex = 0;
    for (const match of text.matchAll(rule.pattern)) {
      const value = rule.group ? match[rule.group] : /campo|asignación/.test(rule.tipo) ? generalValue(match[0]) : match[0];
      if (value) addSecret(found, rule, value, source.file);
    }
  }
  for (const raw of findUrls(text)) {
    addUrl(found, raw, source.file);
    // Usuario y contraseña en la URL (https://usuario:clave@host): secreto con formato válido.
    try {
      const url = new URL(raw);
      if (url.password && /^https?:|^wss?:|^ftp/.test(url.protocol)) addSecret(found, { tipo: "URL con credenciales", pattern: /$^/, confianza: "alta" }, `${url.protocol}//${url.username}:${url.password}@${url.host}`, source.file);
    } catch {}
  }
  if (source.kind === "dex" || source.kind === "recursos" || source.kind === "binario") {
    for (const value of source.strings) {
      if (value.length > 220) continue;
      if (/^[a-z0-9][a-z0-9.-]{2,}\.(?:appspot\.com|firebasestorage\.app)$/.test(value)) found.firebase.buckets.add(value);
      if (/^sha(?:256|1)\/[A-Za-z0-9+/]{27,43}=$/.test(value) && !/^sha(?:256|1)\/A+=$/.test(value)) found.pins.add(value);
      const path = apiPath(value);
      if (path) addPath(found, path.path, path.relative, source.file);
    }
  } else {
    for (const match of text.matchAll(RETROFIT)) addRelativeOrUrl(found, match[2]!, source.file, match[1]!);
    for (const match of text.matchAll(RETROFIT_HTTP)) addRelativeOrUrl(found, match[2]!, source.file, match[1]!);
    for (const match of text.matchAll(QUOTED_PATH)) {
      const path = apiPath(match[1]!);
      if (path) addPath(found, path.path, false, source.file);
    }
    for (const match of text.matchAll(/["'](?:sha256|sha1)\/[A-Za-z0-9+/]{27,43}=["']/g)) if (!/\/A+=/.test(match[0])) found.pins.add(match[0].slice(1, -1));
    if (/\.(js|bundle|html?|mjs|cjs)$/i.test(source.file) && text.length < 40 * 1024 * 1024) {
      for (const op of extractApi(text).operations.slice(0, 400)) for (const method of op.methods.length ? op.methods : [undefined]) addPath(found, op.path, false, source.file, method);
    }
    // Recursos con nombre de secreto (strings.xml decodificado): el valor no tiene formato conocido pero el nombre lo delata.
    if (/strings\.xml$/.test(source.file)) {
      for (const match of text.matchAll(/<string name="([^"<>]{0,60}?(?:api[_-]?key|secret|token|password|passwd|client[_-]?id|private)[^"<>]{0,60})"[^>]{0,200}>([^<]{6,300})<\/string>/gi)) {
        if (found.named.length < 100 && !PLACEHOLDER.test(match[2]!)) found.named.push({ nombre: match[1]!, valor: match[2]!.trim(), archivo: source.file });
      }
    }
  }
  for (const [pattern, clue, code] of PINNING_CLUES) if ((!code || source.kind === "codigo") && found.pinning.size < 10 && pattern.test(text)) found.pinning.add(clue);
}

function addRelativeOrUrl(found: Findings, value: string, file: string, method: string): void {
  if (/^https?:\/\//i.test(value)) {
    addUrl(found, value, file);
    try { addPath(found, new URL(value).pathname, false, file, method); } catch {}
    return;
  }
  const clean = value.split("?")[0]!.replace(/\/+$/, "");
  if (!clean || clean.length > 200) return;
  addPath(found, clean, !clean.startsWith("/"), file, method);
}

// ─── Herramienta ───────────────────────────────────────────────────────────────────────────────

/** Mirrors y tiendas: de ahí no se baja nada (APKs de terceros, sin garantía de origen). */
const MIRRORS = ["apkpure", "apkmirror", "apkcombo", "uptodown", "aptoide", "apkmonk", "apk-dl", "apkdl", "apksfull", "apkfab", "apkgk", "evozi", "apkpremier", "happymod", "softonic", "malavida", "apk4fun", "apkplz", "9apps", "apk20", "apkmody", "liteapks", "apkflash", "apkcafe", "apksupport"];
const STORES = /(^|\.)(play\.google\.com|market\.android\.com|galaxystore\.samsung\.com|appgallery\.huawei\.com|apps\.apple\.com)$/i;

function refuseSource(target: URL): void {
  const host = target.hostname.toLowerCase();
  if (STORES.test(host) || target.protocol === "market:") throw new Error(`No bajo apps de una tienda (${host}): la app de Google Play no se descarga desde acá. Pedile al operador que deje el APK en la carpeta del proyecto (por ejemplo con adb pull desde un dispositivo suyo) y pasame la ruta con path.`);
  if (host.split(".").some((label) => MIRRORS.includes(label)) || /apk\.support|apk-dl\.com/.test(host)) throw new Error(`${host} es un mirror de APKs de terceros: no se usa aunque esté en el alcance (no hay garantía de que el archivo sea el del programa). Pedile al operador que deje el APK en la carpeta del proyecto.`);
}

async function download(http: HttpClient, url: string, identity: string | undefined): Promise<{ buf: Buffer; id: string; url: string }> {
  let current = url;
  for (let hop = 0; hop < 6; hop++) {
    let target: URL;
    try { target = new URL(current); } catch { throw new Error(`URL inválida: ${current}`); }
    if (!/^https?:$/.test(target.protocol)) throw new Error(`Sólo se baja por HTTP o HTTPS (${target.protocol}).`);
    refuseSource(target);
    const decision = decide(http.scope(), current);
    if (!decision.allowed) throw new Error(`Fuera del alcance de esta sesión: ${current}. ${decision.reason}. No se baja: pedile al operador que deje el APK en la carpeta del proyecto, o que agregue el host al alcance si el programa lo cubre.`);
    // Mismo camino que el resto del tráfico: alcance por nombre y por IP, señuelos, ritmo, tope y evidencia.
    const { exchange, body, rawHeaders } = await http.forward({ url: current, timeoutMs: 300_000, maxBodyBytes: MAX_DOWNLOAD }, identity);
    if (exchange.error || !exchange.response) throw new Error(`No se pudo bajar ${current}: ${exchange.error ?? "sin respuesta"} (${exchange.id}).`);
    const status = exchange.response.status;
    const location = rawHeaders.location;
    if (status >= 300 && status < 400 && location) {
      current = new URL(location, current).href;
      continue;
    }
    if (status !== 200) throw new Error(`${current} respondió ${status} (${exchange.id}): no hay APK para analizar.`);
    if (!looksLikeZip(body)) throw new Error(`Lo que devolvió ${current} no es un APK (no empieza como zip; ${exchange.id}).`);
    return { buf: body, id: exchange.id, url: current };
  }
  throw new Error("Demasiadas redirecciones bajando el APK.");
}

const yesNo = (value: boolean | undefined, unknown = "no declarado") => (value === true ? "sí" : value === false ? "no" : unknown);
const list = (items: string[], max: number) => `${items.slice(0, max).join(", ")}${items.length > max ? `, … (${items.length - max} más)` : ""}`;

export function createMobileTools(context: MobileContext): Tool[] {
  const { http, artifacts } = context;
  const run = context.run ?? ((options) => exec({ ...options, maxOutputBytes: 1_000_000 }));
  const tools = context.decompilers ?? (() => ({ jadx: which("jadx"), apktool: which("apktool") }));

  const apkAnalyze: Tool = {
    name: "apk_analyze",
    label: "Analizar APK",
    description:
      "Analiza una app Android: un APK (o .apks/.xapk, o una carpeta con base.apk y splits) que el operador dejó en la carpeta del proyecto, o una URL de descarga directa que esté dentro del alcance de la sesión (nunca tiendas ni mirrors). " +
      "Saca hosts (marcando cuáles están en el alcance), rutas de API, deep links y esquemas, permisos y componentes exportados, debuggable/allowBackup/cleartext, configuración de red y pinning, Firebase y secretos con formato válido (con su valor: lo que trae la app es material del objetivo). " +
      "Con jadx o apktool en la caja decompila; sin ellos lee cadenas de los dex, resources.arsc, assets y res/raw. Registra pistas, no valida ni usa ninguna clave. Si el programa sólo nombra un paquete de Google Play, pedile el APK al operador.",
    parameters: obj({
      path: str({ description: "Ruta dentro de la carpeta del proyecto: .apk, .apks, .xapk o carpeta con los .apk" }),
      url: str({ description: "Descarga directa, dentro del alcance de la sesión" }),
      identity: str({ description: "Identidad aprobada para la descarga, si hace falta" }),
      decompilar: bool("Decompilar con jadx/apktool si la caja los tiene; por defecto sí"),
      conservar: bool("Dejar lo decompilado en apk-decompilado/<paquete> para leerlo con code_search y code_read; por defecto no"),
      timeoutSec: int({ minimum: 30, maximum: 1200, description: "Tope para decompilar; por defecto 300" }),
    }, []),
    execute: async (params, signal): Promise<ToolResult> => {
      if (!!params.path === !!params.url) throw new Error("Pasá path (un APK en la carpeta del proyecto) o url (descarga directa del alcance), uno solo.");
      const pause = pacer(signal);
      // 1. Conseguir los bytes.
      const inputs: Array<{ label: string; buf: Buffer; file?: string }> = [];
      let origin: Record<string, unknown>;
      if (params.path) {
        const real = insideProject(context.cwd, String(params.path));
        const info = statSync(real);
        const files = info.isDirectory() ? readdirSync(real).filter((name) => /\.(apk|apks|xapk)$/i.test(name)).sort().slice(0, 8).map((name) => join(real, name)) : [real];
        if (!files.length) throw new Error(`En ${params.path} no hay archivos .apk, .apks ni .xapk.`);
        for (const file of files) {
          const size = statSync(file).size;
          if (size > MAX_LOCAL) throw new Error(`${basename(file)} pesa ${Math.round(size / 1048576)} MB: el tope es ${MAX_LOCAL / 1048576} MB.`);
          const buf = readFileSync(file);
          if (!looksLikeZip(buf)) throw new Error(`${basename(file)} no parece un APK (no empieza como zip).`);
          inputs.push({ label: relative(context.cwd, file) || basename(file), buf, file });
        }
        origin = { archivo: params.path };
      } else {
        const got = await download(http, String(params.url), params.identity);
        inputs.push({ label: basename(new URL(got.url).pathname) || "descarga.apk", buf: got.buf });
        origin = { url: got.url, intercambio: got.id };
      }
      // 2. Bundles (.apks, .xapk): los APK de adentro.
      const apks: Array<{ label: string; buf: Buffer; file?: string }> = [];
      for (const input of inputs) {
        const inner = innerApks(input.buf);
        if (inner) apks.push(...inner.map((item) => ({ label: `${input.label}!${item.label}`, buf: item.buf })));
        else apks.push(input);
      }
      if (!apks.length) throw new Error("No encontré ningún APK adentro del archivo.");
      // 3. Leer cada APK.
      const reads: ApkRead[] = [];
      for (const apk of apks) reads.push(await readApk(apk.label, apk.buf, pause));
      const baseIndex = Math.max(0, reads.findIndex((read) => read.manifest && read.manifest.componentes.length));
      const base = reads[baseIndex]!;
      let manifest = base.manifest;
      const nsc = reads.flatMap((read) => read.nsc);
      const found = newFindings();
      for (const read of reads) for (const source of read.sources) {
        await pause();
        scan(found, { ...source, file: reads.length > 1 ? `${read.label}:${source.file}` : source.file });
      }
      // 4. Decompilar, si se puede y se pidió.
      const available = params.decompilar === false ? {} : tools();
      let modo = "sin decompilar";
      let decompilerNote = params.decompilar === false ? "no se pidió decompilar" : enCaja() ? "jadx y apktool no están en la caja: /toolbox_install jadx (versión fija, sha256 verificado)" : "jadx y apktool no están en esta máquina y en el host no se instalan (sólo en la caja)";
      let kept: string | undefined;
      if (available.jadx || available.apktool) {
        const work = mkdtempSync(join(tmpdir(), "orobas-apk-"));
        try {
          const apkFile = apks[baseIndex]!.file ?? join(work, "base.apk");
          if (!apks[baseIndex]!.file) writeFileSync(apkFile, apks[baseIndex]!.buf);
          const out = join(work, "salida");
          const timeoutMs = Math.min(1200, params.timeoutSec ?? 300) * 1000;
          const argv = available.jadx
            ? [available.jadx, "-d", out, "-j", "2", "--log-level", "error", apkFile]
            : [available.apktool!, "d", "-f", "-s", "--no-assets", "-p", join(work, "marco"), "-o", out, apkFile];
          const tool = available.jadx ? "jadx" : "apktool";
          const result = await run({ argv, timeoutMs, signal });
          if (existsSync(out)) {
            const decompiled = decompiledSources(out, manifest?.paquete);
            for (const source of decompiled.sources) {
              await pause();
              scan(found, source);
            }
            if (!manifest && decompiled.manifest?.name === "manifest") manifest = manifestInfo(decompiled.manifest);
            for (const item of decompiled.nsc) if (!nsc.some((config) => config.archivo.endsWith(basename(item.file)))) nsc.push(networkConfig(item.root, `decompilado/${item.file}`));
            modo = `con ${tool}`;
            decompilerNote = `${tool}: ${decompiled.files} archivos de texto revisados${result.exitCode === 0 ? "" : result.timedOut ? ` (cortado a los ${timeoutMs / 1000} s: resultado parcial)` : ` (terminó con ${result.exitCode}: resultado parcial)`}`;
            if (params.conservar && decompiled.files) {
              const name = `${(manifest?.paquete ?? "app").replace(/[^\w.-]/g, "_")}${manifest?.version ? `-${manifest.version.replace(/[^\w.-]/g, "_")}` : ""}`;
              kept = join("apk-decompilado", name);
              const target = join(context.cwd, kept);
              rmSync(target, { recursive: true, force: true });
              mkdirSync(join(context.cwd, "apk-decompilado"), { recursive: true });
              cpSync(out, target, { recursive: true });
            }
          } else decompilerNote = `${tool} no dejó salida (${result.timedOut ? "tiempo agotado" : result.cancelled ? "cancelado" : `salida ${result.exitCode}`}): ${(result.stderr || result.stdout).trim().split("\n").at(-1)?.slice(0, 160) ?? ""}. Sigue sin decompilar.`;
        } finally {
          rmSync(work, { recursive: true, force: true });
        }
      }
      // 5. Alcance de cada host (por URL: una regla con prefijo de ruta cuenta).
      const scope = http.scope();
      for (const host of found.hosts.values()) {
        const scheme = (host.schemes.has("https") ? "https" : [...host.schemes][0] ?? "https").replace(/^ws/, "http");
        const probes = ["/", ...[...host.paths.keys()].slice(0, 20)].map((path) => `${scheme}://${host.host}${path}`);
        const decisions = probes.map((probe) => ({ probe, decision: decide(scope, probe) }));
        const hit = decisions.find((item) => item.decision.allowed && http.inScope(item.probe));
        host.allowed = !!hit;
        host.reason = (hit ?? decisions[0]!).decision.reason;
      }
      // Hosts sin esquema que sólo aparecen como texto (p. ej. «api.objetivo.com» para String.format): sólo los del alcance.
      for (const read of reads) for (const source of read.sources) {
        if (source.kind !== "dex" && source.kind !== "recursos") continue;
        for (const value of source.strings) {
          if (value.length > 120 || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(value) || found.hosts.has(value)) continue;
          if (!decide(scope, value).allowed || !http.inScope(`https://${value}/`)) continue;
          found.hosts.set(value, { host: value, schemes: new Set(["https"]), paths: new Map(), files: new Set([source.file]), urls: 0, allowed: true, reason: "nombre suelto en las cadenas" });
        }
      }
      const inside = [...found.hosts.values()].filter((host) => host.allowed).sort((a, b) => b.paths.size - a.paths.size || a.host.localeCompare(b.host));
      const outside = [...found.hosts.values()].filter((host) => !host.allowed && !NOISE_HOSTS.test(host.host)).sort((a, b) => b.urls - a.urls || a.host.localeCompare(b.host));
      const noise = [...found.hosts.values()].filter((host) => !host.allowed && NOISE_HOSTS.test(host.host)).length;
      // Rutas sueltas («/api/…» sin host): si la app usa un solo host del alcance, se le asignan; si no, quedan listadas.
      const soleHost = inside.length === 1 ? inside[0]! : undefined;
      const paths = [...found.paths.values()].sort((a, b) => Number(INTERESTING.test(b.path)) - Number(INTERESTING.test(a.path)) || b.methods.size - a.methods.size || a.path.localeCompare(b.path));
      // 6. Firebase.
      const firebase = [
        ...[...found.firebase.bases].map((url) => ({ tipo: "base de datos", url, prueba: `${url}/.json?shallow=true` })),
        ...[...found.firebase.buckets].map((bucket) => ({ tipo: "bucket de Storage", url: bucket, prueba: `https://firebasestorage.googleapis.com/v0/b/${encodeURIComponent(bucket)}/o?maxResults=1` })),
      ].map((item) => ({ ...item, enAlcance: decide(scope, item.prueba).allowed && http.inScope(item.prueba) }));
      // 7. Pinning y red.
      const pinnedDomains = nsc.flatMap((config) => config.dominios.filter((domain) => domain.pines > 0).flatMap((domain) => domain.dominios));
      const pinning = pinnedDomains.length
        ? `sí: pin-set en la configuración de red para ${list(pinnedDomains, 4)}`
        : found.pins.size
          ? `probable: ${found.pins.size} pin(es) sha256/… en el código${found.pinning.size ? ` (${[...found.pinning].join(", ")})` : ""}`
          : found.pinning.size
            ? `indicios: ${[...found.pinning].join(", ")}${modo === "sin decompilar" ? " (sin decompilar no se sabe si se usan)" : ""}`
            : `no se ven indicios${modo === "sin decompilar" ? " (sin decompilar no se descarta un TrustManager propio)" : ""}`;
      const cleartextDomains = nsc.flatMap((config) => config.dominios.filter((domain) => domain.cleartext).flatMap((domain) => domain.dominios));
      const cleartextGlobal = nsc.some((config) => config.cleartextBase === true) || (manifest?.usesCleartextTraffic === true && !nsc.some((config) => config.cleartextBase === false));
      const userCAs = nsc.some((config) => config.confiaCAsDelUsuario || config.dominios.some((domain) => domain.casDelUsuario));
      // 8. Secretos. Lo que trae el APK es material del objetivo (decisión de Lean del 22/11): el modelo ve cada
      // valor entero, en el resumen y en el artefacto del análisis; las trazas lo tapan (src/secretos-sesion.ts).
      for (const named of found.named) addSecret(found, { tipo: `recurso «${named.nombre.slice(0, 40)}»`, pattern: /$^/, confianza: "media" }, named.valor, named.archivo);
      const allSecrets = [...found.secrets.values()].sort((a, b) => Number(b.confianza === "alta") - Number(a.confianza === "alta") || Number(a.id.slice(1)) - Number(b.id.slice(1)));
      // Las pistas que se guardan como hallazgo pasan por acá: cada secreto (y la ruta o la contraseña de los que
      // son URL, como un webhook) se acorta también donde reaparezca. El informe que sale de los hallazgos no lleva
      // la clave entera; el modelo y el artefacto del análisis, sí.
      const scrubbers = allSecrets
        .flatMap((secret) => {
          const parts = [secret.valor];
          try {
            const url = new URL(secret.valor);
            if (url.pathname.length >= 12) parts.push(url.pathname);
            if (url.password) parts.push(url.password);
          } catch {}
          return parts.filter((part) => part.length >= 6);
        })
        .sort((a, b) => b.length - a.length);
      const scrub = (text: string) => {
        let result = text;
        for (const value of scrubbers) {
          if (result.includes(value)) result = result.split(value).join(redactSecret(value));
          const escaped = JSON.stringify(value).slice(1, -1);
          if (escaped !== value && result.includes(escaped)) result = result.split(escaped).join(redactSecret(value));
        }
        return result;
      };
      const pkg = manifest?.paquete ?? base.label;
      const secretsArtifact = allSecrets.length
        ? artifacts.put(JSON.stringify({ paquete: pkg, aviso: "Valores completos encontrados en la app. Son pistas sin validar: no se usan ni se prueban sin pedido explícito del operador.", secretos: allSecrets }, null, 1), "application/json", `apk_analyze:secretos:${pkg}`)
        : undefined;
      // 9. Cobertura: lo del alcance queda como superficie vista (no probada) y como enlaces por visitar.
      let observed = 0;
      const linkable: string[] = [];
      for (const host of inside) {
        const scheme = host.schemes.has("https") || host.schemes.has("wss") ? "https" : "http";
        const own = [...host.paths.keys()].map((path) => ({ path, methods: found.paths.get(path)?.methods ?? new Set<string>() }));
        const loose = host === soleHost ? paths.filter((path) => !path.relative && !host.paths.has(path.path)).map((path) => ({ path: path.path, methods: path.methods })) : [];
        for (const { path, methods } of [...own, ...loose]) {
          if (observed >= 300) break;
          // Una ruta que es parte de un secreto (el camino de un webhook) no entra a la superficie de la sesión.
          if (scrubbers.some((value) => value.includes(path) || path.includes(value))) continue;
          const url = `${scheme}://${host.host}${path.replace(/\{[^}]+\}/g, "1")}`;
          try {
            for (const method of methods.size ? methods : new Set(["GET"])) http.observe({ url, method });
            observed++;
            if (linkable.length < 60 && (INTERESTING.test(path) || linkable.length < 30)) linkable.push(new URL(url).pathname);
          } catch {}
        }
      }
      for (const link of linkable) http.linked.add(link);
      // 10. Credenciales de cabecera: se proponen como identidad; sólo el operador las aprueba.
      const proposals: string[] = [];
      const headerSecrets = allSecrets.filter((secret) => ["token Bearer", "credencial Basic", "cabecera Authorization"].includes(secret.tipo));
      const soleOrigin = inside.filter((host) => host.schemes.has("https")).length === 1 ? `https://${inside.find((host) => host.schemes.has("https"))!.host}` : undefined;
      if (soleOrigin) for (const secret of headerSecrets.slice(0, 3)) {
        const value = secret.tipo === "credencial Basic" ? `Basic ${secret.valor}` : /^(?:Bearer|Basic|Token)\s/i.test(secret.valor) ? secret.valor : `Bearer ${secret.valor}`;
        proposals.push(`${http.proposeIdentity({ name: "apk", headers: { authorization: value } }, soleOrigin, "objetivo")} (${secret.id}, Authorization para ${soleOrigin})`);
      }
      // 11. Artefacto del análisis (con los valores).
      const analysis = {
        origen: origin,
        apks: reads.map((read) => ({ archivo: read.label, bytes: read.bytes, sha256: read.sha256, dex: read.dex, leidos: read.leidos, omitidos: read.omitidos.slice(0, 50), manifestIlegible: read.manifestIlegible ?? false })),
        modo,
        decompilador: decompilerNote,
        conservado: kept,
        manifest,
        red: { cleartextGlobal, cleartextDominios: cleartextDomains, confiaCAsDelUsuario: userCAs, pinning, pines: [...found.pins].slice(0, 20), configuraciones: nsc },
        hosts: [...inside, ...outside].map((host) => ({ host: host.host, enAlcance: !!host.allowed, motivo: host.reason, urls: host.urls, rutas: [...host.paths.keys()].slice(0, 200), archivos: [...host.files] })),
        hostsRuido: noise,
        rutas: paths.slice(0, 1500).map((path) => ({ ruta: path.path, relativa: path.relative, metodos: [...path.methods], archivos: [...path.files] })),
        esquemas: [...found.schemes.entries()].map(([scheme, sample]) => ({ esquema: scheme, ejemplo: sample })),
        firebase,
        secretos: allSecrets.map((secret) => ({ id: secret.id, tipo: secret.tipo, confianza: secret.confianza, valor: secret.valor, archivos: secret.archivos, ...(secret.nota ? { nota: secret.nota } : {}) })),
        identidadesPropuestas: proposals,
      };
      const analysisArtifact = artifacts.put(JSON.stringify(analysis, null, 1), "application/json", `apk_analyze:${pkg}`);
      // 12. Pistas: secretos con formato válido, hosts del alcance con algo que mirar, configuración del manifest.
      const leads: string[] = [];
      const record = (input: FindingInput) => {
        if (!context.findingRecord) return;
        try {
          const clean = { ...input, title: scrub(input.title), summary: scrub(input.summary) };
          leads.push(`${context.findingRecord({ ...clean, state: "pista", evidence: [analysisArtifact.hash] })} ${clean.title.slice(0, 70)}`);
        } catch (error) {
          const existing = /Ya existe (\w{8})/.exec((error as Error).message)?.[1];
          leads.push(existing ? `${existing} (ya estaba) ${input.title.slice(0, 60)}` : `no se registró «${input.title.slice(0, 50)}»: ${(error as Error).message.slice(0, 100)}`);
        }
      };
      const asset = `android:${pkg}`;
      const byType = new Map<string, SecretHit[]>();
      for (const secret of allSecrets.filter((item) => item.confianza === "alta")) byType.set(secret.tipo, [...(byType.get(secret.tipo) ?? []), secret]);
      for (const [tipo, hits] of [...byType].slice(0, 8)) {
        record({
          title: `${tipo} en la app ${pkg}`.slice(0, 120),
          kind: `secreto en app móvil: ${tipo}`.slice(0, 60),
          severity: tipo === "clave de API de Google" ? "informativa" : "baja",
          asset,
          summary: `Observado: ${hits.length} valor(es) con formato válido de ${tipo} (${hits.slice(0, 3).map((hit) => `${hit.id} ${redactSecret(hit.valor)} en ${hit.archivos[0]}`).join("; ")}). Inferido: nada todavía; no se validó contra el servicio ni se usó contra el objetivo.${hits[0]!.nota ? ` Nota: ${hits[0]!.nota}.` : ""} El valor completo está en el artefacto de secretos del análisis, para el operador.`,
          limits: "Sin validar: puede ser de prueba, estar revocada o restringida. Validarla o usarla exige pedido explícito del operador.",
        });
      }
      for (const host of inside.slice(0, 5)) {
        const interesting = [...host.paths.keys()].filter((path) => INTERESTING.test(path));
        const nonProd = NON_PROD_HOST.test(host.host);
        const isFirebase = firebase.some((item) => item.enAlcance && item.url.includes(host.host));
        if (!interesting.length && !nonProd && !isFirebase) continue;
        record({
          title: `La app ${pkg} usa ${host.host}${nonProd ? " (no productivo)" : ""}: ${interesting.length ? list(interesting, 3) : `${host.paths.size} rutas`}`.slice(0, 120),
          kind: "superficie de app móvil",
          severity: "informativa",
          asset: host.host,
          summary: `Observado en el APK (${[...host.files].slice(0, 2).join(", ")}): ${host.paths.size} ruta(s) de ${host.host}${interesting.length ? `, entre ellas ${list(interesting, 6)}` : ""}.${nonProd ? " El nombre del host sugiere un entorno no productivo." : ""}${isFirebase ? " Es una base o bucket de Firebase del alcance: probar lectura pública con un GET de sólo lectura." : ""} Inferido: la app le habla a este host; falta probar las rutas con las herramientas HTTP.`,
          limits: "Rutas sacadas del binario: pueden ser viejas o de otra variante de la app.",
        });
      }
      const exposedProviders = manifest?.componentes.filter((component) => component.tipo === "provider" && component.exportado && !component.permiso) ?? [];
      if (manifest?.debuggable || cleartextGlobal || exposedProviders.length) {
        const parts = [
          manifest?.debuggable ? "android:debuggable=true (se puede adjuntar un depurador y leer la memoria del proceso en un dispositivo)" : "",
          cleartextGlobal ? "tráfico en claro permitido para todos los hosts" : "",
          exposedProviders.length ? `content provider exportado sin permiso: ${list(exposedProviders.map((item) => `${item.nombre}${item.authorities ? ` (${item.authorities})` : ""}`), 3)}` : "",
          manifest?.allowBackup ? "allowBackup=true" : "",
        ].filter(Boolean);
        record({
          title: `Configuración de la app ${pkg}: ${parts.map((part) => part.split(" (")[0]).join("; ")}`.slice(0, 120),
          kind: "configuración de app móvil",
          severity: manifest?.debuggable || exposedProviders.length ? "baja" : "informativa",
          asset,
          summary: `Observado en el AndroidManifest.xml${nsc.length ? " y la configuración de red" : ""}: ${parts.join("; ")}. Inferido: su impacto depende de qué expone la app en el dispositivo; probarlo exige un dispositivo o emulador con la app instalada.`,
          limits: "Análisis estático del APK; no se probó en un dispositivo.",
        });
      }
      // 13. Resumen para el modelo.
      const lines: string[] = [];
      const read0 = reads[0]!;
      lines.push(`APK ${pkg}${manifest?.version ? ` ${manifest.version}` : ""}${manifest?.versionCode ? ` (code ${manifest.versionCode})` : ""} · minSdk ${manifest?.minSdk ?? "?"} · targetSdk ${manifest?.targetSdk ?? "?"} · ${reads.length > 1 ? `${reads.length} APKs (base y splits)` : `${(read0.bytes / 1048576).toFixed(1)} MB · sha256 ${read0.sha256.slice(0, 12)}…`}${origin.intercambio ? ` · bajado en ${origin.intercambio}` : ""}`);
      lines.push(`Modo: ${modo}. ${decompilerNote}. Leídos: ${reads.reduce((sum, read) => sum + read.dex, 0)} dex y ${reads.reduce((sum, read) => sum + read.leidos, 0)} archivos${reads.some((read) => read.omitidos.length) ? `; omitidos ${reads.reduce((sum, read) => sum + read.omitidos.length, 0)} (en el artefacto)` : ""}.`);
      if (manifest) {
        lines.push(`Manifest: debuggable ${yesNo(manifest.debuggable)}${manifest.debuggable ? " ⚠" : ""} · allowBackup ${yesNo(manifest.allowBackup, "no declarado (sí por defecto)")} · usesCleartextTraffic ${yesNo(manifest.usesCleartextTraffic, (manifest.targetSdk ?? 0) >= 28 ? "no declarado (no por defecto)" : "no declarado (sí por defecto)")} · networkSecurityConfig ${manifest.networkSecurityConfig ? "sí" : "no"}.`);
        const exported = manifest.componentes.filter((component) => component.exportado && !component.permiso && !component.lanzador);
        if (exported.length) lines.push(`Exportados sin permiso (${exported.length}): ${list(exported.map((component) => `${component.tipo} ${component.nombre.replace(`${pkg}.`, ".")}${component.implicito ? " (implícito)" : ""}${component.authorities ? ` [${component.authorities}]` : ""}`), 6)}.`);
        const notable = manifest.permisos.filter((name) => /SMS|CONTACTS|LOCATION|CAMERA|RECORD_AUDIO|STORAGE|INSTALL_PACKAGES|SYSTEM_ALERT|QUERY_ALL|PHONE_STATE|CALL_LOG|ACCESSIBILITY|BIOMETRIC|ACCOUNTS/.test(name)).map((name) => name.replace(/^android\.permission\./, ""));
        lines.push(`Permisos: ${manifest.permisos.length}${notable.length ? ` (a mirar: ${list(notable, 8)})` : ""}${manifest.permisosPropios.some((item) => item.proteccion === "normal" || item.proteccion === "dangerous") ? ` · permisos propios débiles: ${list(manifest.permisosPropios.filter((item) => item.proteccion === "normal" || item.proteccion === "dangerous").map((item) => `${item.nombre} (${item.proteccion})`), 3)}` : ""}.`);
        if (manifest.deepLinks.length) lines.push(`Deep links (${manifest.deepLinks.length}): ${list(manifest.deepLinks.map((link) => `${link.link}${link.autoVerify ? " (verificado)" : ""}`), 8)}.`);
      } else lines.push(base.manifestIlegible ? "Manifest: no se pudo decodificar (ofuscado o dañado); el resto del análisis sigue." : "Manifest: no hay AndroidManifest.xml en el APK (¿es sólo un split?); el resto del análisis sigue.");
      const deepSchemes = new Set(manifest?.deepLinks.map((link) => link.link.split("://")[0]!) ?? []);
      const otherSchemes = [...found.schemes.keys()].filter((scheme) => !deepSchemes.has(scheme));
      if (otherSchemes.length) lines.push(`Otros esquemas en el código (no declarados como deep link): ${list(otherSchemes.map((scheme) => `${scheme}://`), 8)}.`);
      lines.push(`Red: cleartext ${cleartextGlobal ? "permitido para todo ⚠" : cleartextDomains.length ? `permitido para ${list(cleartextDomains, 4)}` : "no permitido"}${userCAs ? " · confía en CAs instaladas por el usuario (interceptar es fácil)" : ""} · pinning ${pinning}.`);
      lines.push(inside.length ? `Hosts del alcance (${inside.length}): ${list(inside.map((host) => `${host.host} (${host.paths.size} rutas${NON_PROD_HOST.test(host.host) ? ", no productivo" : ""})`), 8)}.` : "Hosts del alcance: ninguno de los que usa la app está en el alcance de esta sesión.");
      if (outside.length) lines.push(`Fuera del alcance (${outside.length}; no se tocan. Si el programa los cubre, proponé al operador agregarlos): ${list(outside.map((host) => host.host), 12)}${noise ? ` · ${noise} de documentación o bibliotecas omitidos` : ""}.`);
      const hostPaths = inside.flatMap((host) => [...host.paths.keys()].map((path) => ({ path, label: `${host.host}${path}` }))).sort((a, b) => Number(INTERESTING.test(b.path)) - Number(INTERESTING.test(a.path)) || a.label.localeCompare(b.label));
      if (hostPaths.length) lines.push(`Rutas de hosts del alcance (${hostPaths.length}, primero las de administración, identidad, dinero y depuración): ${list(hostPaths.map((item) => { const methods = found.paths.get(item.path)?.methods; return `${methods?.size ? `${[...methods].join("/")} ` : ""}${item.label}`; }), 20)}.`);
      const loosePaths = paths.filter((path) => !inside.some((host) => host.paths.has(path.path)));
      if (loosePaths.length) {
        const shown = loosePaths.map((path) => `${path.methods.size ? `${[...path.methods].join("/")} ` : ""}${path.path}${path.relative ? " (relativa)" : ""}`);
        lines.push(`Rutas sin host en el código (${loosePaths.length}${soleHost ? `; las absolutas se asignaron a ${soleHost.host}, el único host del alcance` : ""}): ${list(shown, 20)}.`);
      }
      if (observed) lines.push(`Superficie: ${observed} ruta(s) de hosts del alcance quedaron vistas (no probadas) en site_map y cobertura.`);
      if (firebase.length) lines.push(`Firebase: ${firebase.map((item) => `${item.tipo} ${item.url} ${item.enAlcance ? `(EN alcance: lectura pública con http_request GET ${item.prueba})` : "(FUERA del alcance: no se prueba; proponé al operador agregarlo si el programa lo cubre)"}`).join(" · ")}.`);
      const entero = (valor: string) => valor.length > 300 ? `${valor.slice(0, 300)}… (${valor.length} caracteres; entero en el artefacto)` : valor;
      if (allSecrets.length) lines.push(`Secretos (${allSecrets.length}): ${allSecrets.slice(0, 12).map((secret) => `${secret.id} ${secret.tipo} ${entero(secret.valor)} [${secret.confianza}] en ${secret.archivos[0]}`).join(" · ")}${allSecrets.length > 12 ? " · … (el resto en el artefacto)" : ""}.`);
      if (proposals.length) lines.push(`Identidades propuestas (no se usan hasta que el operador las apruebe con /identity aprobar <nombre>): ${proposals.join("; ")}.`);
      if (leads.length) lines.push(`Pistas: ${leads.join(" · ")}.`);
      if (kept) lines.push(`Código decompilado en ${kept}: code_search y code_read sobre esa carpeta.`);
      if (params.path && (context.rea ?? reaDisponible)()) lines.push(`Para profundizar en la caja (firma, recursos con apktool, inventario completo, librerías .so, Flutter): habilidad ingenieria-inversa, con REA sobre ${String(params.path)}.`);
      lines.push("No se validó ni se usó ninguna clave: probarla contra un servicio o contra el objetivo lo decide el operador. Siguiente: cruzar los hosts y rutas del alcance con lo que ya viste de la web (http_probe con GET primero).");
      lines.push(`Artefacto: ${analysisArtifact.hash}`);
      return {
        text: lines.join("\n"),
        details: { artefacto: analysisArtifact.hash, ...(secretsArtifact ? { secretos: secretsArtifact.hash } : {}), modo, hosts_alcance: inside.length, rutas: paths.length, pistas: leads.length },
      };
    },
  };
  return [apkAnalyze];
}
