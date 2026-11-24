import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { crc32, deflateRawSync } from "node:zlib";
import { decodeAxml, dexStrings, parseTextXml, printableStrings, zipEntries, zipExtract, zipRead } from "../src/apk.ts";
import { Artifacts } from "../src/artifacts.ts";
import { which } from "../src/exec.ts";
import { Findings } from "../src/findings.ts";
import { HttpClient } from "../src/http.ts";
import { INSTALLABLE, installTool, MOVIL, movilStatus, planesMovil, type Runner } from "../src/instalar-herramientas.ts";
import { apiPath, createMobileTools, findUrls, redactSecret, type MobileContext } from "../src/movil.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

const tmp = () => mkdtempSync(join(tmpdir(), "cyber-movil-"));
const abort = new AbortController().signal;

// ─── Constructores de un APK de prueba (nada se baja de internet) ──────────────────────────────

/** Zip mínimo: cabeceras locales, directorio central y fin; deflate salvo que se pida guardado. */
function zip(files: Array<{ name: string; data: Buffer | string; store?: boolean }>): Buffer {
  const locals: Buffer[] = [];
  const central: Buffer[] = [];
  let offset = 0;
  for (const file of files) {
    const raw = Buffer.isBuffer(file.data) ? file.data : Buffer.from(file.data);
    const body = file.store ? raw : deflateRawSync(raw);
    const name = Buffer.from(file.name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(file.store ? 0 : 8, 8);
    local.writeUInt32LE(crc32(raw), 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(name.length, 26);
    const cen = Buffer.alloc(46);
    cen.writeUInt32LE(0x02014b50, 0);
    cen.writeUInt16LE(20, 4);
    cen.writeUInt16LE(20, 6);
    cen.writeUInt16LE(file.store ? 0 : 8, 10);
    cen.writeUInt32LE(crc32(raw), 16);
    cen.writeUInt32LE(body.length, 20);
    cen.writeUInt32LE(raw.length, 24);
    cen.writeUInt16LE(name.length, 28);
    cen.writeUInt32LE(offset, 42);
    locals.push(local, name, body);
    central.push(cen, name);
    offset += 30 + name.length + body.length;
  }
  const directory = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

type Value = string | boolean | number | { ref: number };
interface Node { name: string; attrs?: Array<[string, Value, number?]>; children?: Node[]; text?: string }
const ANDROID = "http://schemas.android.com/apk/res/android";

/** XML binario de Android (AXML) desde un árbol: tabla de cadenas, mapa de ids de recurso y elementos. */
function axml(root: Node, utf8 = false): Buffer {
  const ids: number[] = [];
  const idNames: string[] = [];
  const walk = (node: Node, fn: (node: Node) => void) => { fn(node); node.children?.forEach((child) => walk(child, fn)); };
  walk(root, (node) => node.attrs?.forEach(([name, , id]) => { if (id !== undefined && !ids.includes(id)) { ids.push(id); idNames.push(name.replace(/^android:/, "")); } }));
  const strings: string[] = [...idNames];
  const index = (value: string) => { let at = strings.indexOf(value); if (at < 0) { at = strings.length; strings.push(value); } return at; };
  index(ANDROID);
  index("android");
  walk(root, (node) => { index(node.name); node.attrs?.forEach(([name, value, id]) => { if (id === undefined) index(name.replace(/^android:/, "")); if (typeof value === "string") index(value); }); if (node.text) index(node.text); });
  // Tabla de cadenas.
  const encoded = strings.map((value) => {
    if (utf8) {
      const bytes = Buffer.from(value, "utf8");
      return Buffer.concat([Buffer.from([value.length, bytes.length]), bytes, Buffer.from([0])]);
    }
    const head = Buffer.alloc(2);
    head.writeUInt16LE(value.length);
    return Buffer.concat([head, Buffer.from(value, "utf16le"), Buffer.alloc(2)]);
  });
  const offsets = Buffer.alloc(4 * strings.length);
  let at = 0;
  encoded.forEach((item, i) => { offsets.writeUInt32LE(at, i * 4); at += item.length; });
  let data = Buffer.concat(encoded);
  if (data.length % 4) data = Buffer.concat([data, Buffer.alloc(4 - (data.length % 4))]);
  const poolHeader = Buffer.alloc(28);
  poolHeader.writeUInt16LE(0x0001, 0);
  poolHeader.writeUInt16LE(28, 2);
  poolHeader.writeUInt32LE(28 + offsets.length + data.length, 4);
  poolHeader.writeUInt32LE(strings.length, 8);
  poolHeader.writeUInt32LE(utf8 ? 0x100 : 0, 16);
  poolHeader.writeUInt32LE(28 + offsets.length, 20);
  const pool = Buffer.concat([poolHeader, offsets, data]);
  const resmap = Buffer.alloc(8 + 4 * ids.length);
  resmap.writeUInt16LE(0x0180, 0);
  resmap.writeUInt16LE(8, 2);
  resmap.writeUInt32LE(resmap.length, 4);
  ids.forEach((id, i) => resmap.writeUInt32LE(id, 8 + i * 4));
  const chunks: Buffer[] = [];
  const node16 = (type: number, size: number) => {
    const chunk = Buffer.alloc(size);
    chunk.writeUInt16LE(type, 0);
    chunk.writeUInt16LE(16, 2);
    chunk.writeUInt32LE(size, 4);
    chunk.writeUInt32LE(0xffffffff, 12);
    return chunk;
  };
  const ns = node16(0x0100, 24);
  ns.writeUInt32LE(strings.indexOf("android"), 16);
  ns.writeUInt32LE(strings.indexOf(ANDROID), 20);
  chunks.push(ns);
  const emit = (node: Node) => {
    const attrs = node.attrs ?? [];
    const start = node16(0x0102, 36 + 20 * attrs.length);
    start.writeUInt32LE(0xffffffff, 16);
    start.writeUInt32LE(strings.indexOf(node.name), 20);
    start.writeUInt16LE(20, 24);
    start.writeUInt16LE(20, 26);
    start.writeUInt16LE(attrs.length, 28);
    attrs.forEach(([name, value, id], i) => {
      const a = 36 + 20 * i;
      const android = id !== undefined || name.startsWith("android:");
      start.writeUInt32LE(android ? strings.indexOf(ANDROID) : 0xffffffff, a);
      start.writeUInt32LE(id !== undefined ? ids.indexOf(id) : strings.indexOf(name.replace(/^android:/, "")), a + 4);
      start.writeUInt16LE(8, a + 12);
      if (typeof value === "string") {
        start.writeUInt32LE(strings.indexOf(value), a + 8);
        start.writeUInt8(0x03, a + 15);
        start.writeUInt32LE(strings.indexOf(value), a + 16);
      } else {
        start.writeUInt32LE(0xffffffff, a + 8);
        if (typeof value === "boolean") { start.writeUInt8(0x12, a + 15); start.writeUInt32LE(value ? 0xffffffff : 0, a + 16); }
        else if (typeof value === "number") { start.writeUInt8(0x10, a + 15); start.writeInt32LE(value, a + 16); }
        else { start.writeUInt8(0x01, a + 15); start.writeUInt32LE(value.ref, a + 16); }
      }
    });
    chunks.push(start);
    if (node.text) {
      const cdata = node16(0x0104, 28);
      cdata.writeUInt32LE(strings.indexOf(node.text), 16);
      cdata.writeUInt16LE(8, 20);
      cdata.writeUInt8(0x03, 23);
      cdata.writeUInt32LE(strings.indexOf(node.text), 24);
      chunks.push(cdata);
    }
    node.children?.forEach(emit);
    const end = node16(0x0103, 24);
    end.writeUInt32LE(0xffffffff, 16);
    end.writeUInt32LE(strings.indexOf(node.name), 20);
    chunks.push(end);
  };
  emit(root);
  const body = Buffer.concat([pool, resmap, ...chunks]);
  const header = Buffer.alloc(8);
  header.writeUInt16LE(0x0003, 0);
  header.writeUInt16LE(8, 2);
  header.writeUInt32LE(8 + body.length, 4);
  return Buffer.concat([header, body]);
}

/** Dex mínimo: cabecera y tabla de cadenas (string_ids), que es lo único que se lee. */
function dex(strings: string[]): Buffer {
  const header = Buffer.alloc(0x70);
  header.write("dex\n035\0", 0, "latin1");
  header.writeUInt32LE(strings.length, 0x38);
  header.writeUInt32LE(0x70, 0x3c);
  const table = Buffer.alloc(4 * strings.length);
  const datas: Buffer[] = [];
  let at = 0x70 + table.length;
  strings.forEach((value, i) => {
    table.writeUInt32LE(at, i * 4);
    const bytes = Buffer.from(value, "utf8");
    const item = Buffer.concat([Buffer.from([Math.min(127, value.length)]), bytes, Buffer.from([0])]);
    datas.push(item);
    at += item.length;
  });
  return Buffer.concat([header, table, ...datas]);
}

/** resources.arsc con sólo la tabla global de cadenas (UTF-8). */
function arsc(strings: string[]): Buffer {
  const encoded = strings.map((value) => { const bytes = Buffer.from(value); return Buffer.concat([Buffer.from([value.length, bytes.length]), bytes, Buffer.from([0])]); });
  const offsets = Buffer.alloc(4 * strings.length);
  let at = 0;
  encoded.forEach((item, i) => { offsets.writeUInt32LE(at, i * 4); at += item.length; });
  let data = Buffer.concat(encoded);
  if (data.length % 4) data = Buffer.concat([data, Buffer.alloc(4 - (data.length % 4))]);
  const head = Buffer.alloc(28);
  head.writeUInt16LE(0x0001, 0);
  head.writeUInt16LE(28, 2);
  head.writeUInt32LE(28 + offsets.length + data.length, 4);
  head.writeUInt32LE(strings.length, 8);
  head.writeUInt32LE(0x100, 16);
  head.writeUInt32LE(28 + offsets.length, 20);
  const table = Buffer.alloc(12);
  table.writeUInt16LE(0x0002, 0);
  table.writeUInt16LE(12, 2);
  table.writeUInt32LE(12 + 28 + offsets.length + data.length, 4);
  return Buffer.concat([table, head, offsets, data]);
}

// Valores con formato válido, armados por partes para que ningún escáner los tome por secretos reales.
const AWS = "AKIA" + "Z7Q4N2XWJ8R5T3VL";
const GOOGLE = "AIza" + "SyD3f9Kq2LmN8pRt5VwX1yZa4Bc7De0FgHi";
const BEARER = "mT9vQ2" + "xL7pR4sW8nK3jH6gF1dZ";
const BASIC = Buffer.from("admin:" + "Clave2024!").toString("base64");
const SLACK = "https://hooks.slack.com/services/" + "T0123ABCD/B0456EFGH/" + "Qx7mZp2KvL9nWc4RtY8sJd3F";
const ALGOLIA = "9f8e7d6c5b4a3f2e" + "1d0c9b8a7f6e5d4c";
const SENTRY = "https://" + "0123456789abcdef0123456789abcdef" + "@o12345.ingest.sentry.io/678";
const PIN = "sha256/" + "r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E=";

function manifest(): Buffer {
  const A = (name: string, value: Value, id?: number): [string, Value, number?] => [name, value, id];
  return axml({
    name: "manifest",
    attrs: [A("package", "com.ejemplo.billetera"), A("android:versionCode", 420, 0x0101021b), A("android:versionName", "4.2.0", 0x0101021c)],
    children: [
      { name: "uses-sdk", attrs: [A("android:minSdkVersion", 24, 0x0101020c), A("android:targetSdkVersion", 33, 0x01010270)] },
      { name: "uses-permission", attrs: [A("android:name", "android.permission.INTERNET", 0x01010003)] },
      { name: "uses-permission", attrs: [A("android:name", "android.permission.READ_SMS", 0x01010003)] },
      { name: "uses-permission", attrs: [A("android:name", "android.permission.CAMERA", 0x01010003)] },
      { name: "permission", attrs: [A("android:name", "com.ejemplo.billetera.PERMISO", 0x01010003), A("android:protectionLevel", 0, 0x01010009)] },
      {
        name: "application",
        // debuggable con el nombre vaciado (como dejan algunos ofuscadores): se reconoce por el id de recurso.
        attrs: [A("", true, 0x0101000f), A("android:allowBackup", true, 0x01010280), A("android:networkSecurityConfig", { ref: 0x7f150001 }, 0x01010527)],
        children: [
          { name: "meta-data", attrs: [A("android:name", "com.google.android.geo.API_KEY", 0x01010003), A("android:value", GOOGLE, 0x01010024)] },
          { name: "activity", attrs: [A("android:name", ".MainActivity", 0x01010003), A("android:exported", true, 0x01010010)], children: [{ name: "intent-filter", children: [{ name: "action", attrs: [A("android:name", "android.intent.action.MAIN", 0x01010003)] }, { name: "category", attrs: [A("android:name", "android.intent.category.LAUNCHER", 0x01010003)] }] }] },
          {
            name: "activity",
            attrs: [A("android:name", ".DeepLinkActivity", 0x01010003)],
            children: [{
              name: "intent-filter",
              attrs: [A("android:autoVerify", true, 0x010104ee)],
              children: [
                { name: "action", attrs: [A("android:name", "android.intent.action.VIEW", 0x01010003)] },
                { name: "category", attrs: [A("android:name", "android.intent.category.BROWSABLE", 0x01010003)] },
                { name: "data", attrs: [A("android:scheme", "billetera", 0x01010027), A("android:host", "pagar", 0x01010028)] },
              ],
            }],
          },
          { name: "provider", attrs: [A("android:name", ".ArchivosProvider", 0x01010003), A("android:exported", true, 0x01010010), A("android:authorities", "com.ejemplo.billetera.archivos", 0x01010018), A("android:grantUriPermissions", true, 0x0101001b)] },
          { name: "service", attrs: [A("android:name", ".SyncService", 0x01010003), A("android:exported", false, 0x01010010)] },
          { name: "receiver", attrs: [A("android:name", ".PushReceiver", 0x01010003), A("android:exported", true, 0x01010010), A("android:permission", "com.google.android.c2dm.permission.SEND", 0x01010006)] },
        ],
      },
    ],
  });
}

function networkSecurity(): Buffer {
  return axml({
    name: "network-security-config",
    children: [
      { name: "base-config", attrs: [["cleartextTrafficPermitted", false]], children: [{ name: "trust-anchors", children: [{ name: "certificates", attrs: [["src", "system"]] }, { name: "certificates", attrs: [["src", "user"]] }] }] },
      { name: "domain-config", attrs: [["cleartextTrafficPermitted", true]], children: [{ name: "domain", attrs: [["includeSubdomains", true]], text: "dev.ejemplo.com" }] },
    ],
  }, true);
}

function testApk(extra: Array<{ name: string; data: Buffer | string; store?: boolean }> = []): Buffer {
  return zip([
    { name: "AndroidManifest.xml", data: manifest() },
    { name: "classes.dex", data: dex(["Lcom/ejemplo/billetera/Api;", "https://api.ejemplo.com/v2/", "https://staging-api.ejemplo.com/internal/debug/config", "/api/v2/admin/usuarios/{id}", "users/{userId}/wallets", "https://tracker.terceros.io/collect?id=1", AWS, `Bearer ${BEARER}`, ANDROID, "billetera://pagar/confirmar", "/system/bin/su", "application/json", "dd/MM/yyyy", PIN]) },
    { name: "classes2.dex", data: "no es un dex: texto suelto con https://cdn.ejemplo.com/assets/app.css y relleno" },
    { name: "resources.arsc", data: arsc(["https://ejemplo-prod.firebaseio.com", "ejemplo-prod.appspot.com", GOOGLE, "1:1234567890:android:abc123"]) },
    { name: "assets/config.json", data: JSON.stringify({ apiBase: "https://api.ejemplo.com", sentry: SENTRY, algoliaApiKey: ALGOLIA, password: "Sup3rS3cr3t!" }) },
    { name: "res/raw/backend.properties", data: `admin.auth=Basic ${BASIC}\nslack.webhook=${SLACK}\n` },
    { name: "res/xml/network_security_config.xml", data: networkSecurity() },
    { name: "res/layout/main.xml", data: Buffer.from([3, 0, 8, 0, 0, 0, 0, 0]) },
    { name: "assets/index.android.bundle", data: 'var a=1;fetch("/api/v2/pagos/transferir",{method:"POST",body:JSON.stringify({monto:1,destino:2})});fetch("https://api.ejemplo.com/v2/cuentas")' },
    { name: "res/drawable/icono.png", data: Buffer.alloc(64, 1), store: true },
    ...extra,
  ]);
}

function setup(rules: string[], extra: Partial<MobileContext> = {}) {
  const cwd = tmp();
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const scope: Scope = { rev: 1, source: "manual", notes: "", at: "", include: rules.map((rule) => parseRule(rule)), exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  const findings = new Findings(db, (hash) => artifacts.find(hash), (hash) => { try { return artifacts.read(hash); } catch { return undefined; } });
  const context: MobileContext = { artifacts, http, cwd, findingRecord: (input) => findings.record({ ...input, state: "pista" }, "s1").id.slice(0, 8), decompilers: () => ({}), ...extra };
  const [tool] = createMobileTools(context);
  return { cwd, artifacts, http, findings, tool: tool!, scope };
}

// ─── Pruebas ───────────────────────────────────────────────────────────────────────────────────

// Decisión de Lean del 22/11: lo que trae la app es material del objetivo. El modelo ve cada secreto entero (en el
// resumen y en el artefacto del análisis); las pistas que se guardan como hallazgo siguen acortadas.
test("apk_analyze sin jadx: manifest, red, hosts en y fuera del alcance, rutas, Firebase y secretos enteros para el modelo", async () => {
  const { cwd, artifacts, http, findings, tool } = setup(["*.ejemplo.com", "https://firebasestorage.googleapis.com/v0/b/ejemplo-prod.appspot.com"]);
  mkdirSync(join(cwd, "apks"));
  writeFileSync(join(cwd, "apks", "billetera.apk"), testApk());
  const result = await tool.execute({ path: "apks/billetera.apk" }, abort);
  const text = result.text;
  assert.match(text, /^APK com\.ejemplo\.billetera 4\.2\.0 \(code 420\) · minSdk 24 · targetSdk 33/);
  assert.match(text, /Modo: sin decompilar\. jadx y apktool no están en esta máquina y en el host no se instalan/);
  assert.match(text, /debuggable sí ⚠ · allowBackup sí/);
  assert.match(text, /Exportados sin permiso \(2\): activity \.DeepLinkActivity \(implícito\), provider \.ArchivosProvider \[com\.ejemplo\.billetera\.archivos\]/);
  assert.doesNotMatch(text, /PushReceiver|MainActivity|SyncService/, "con permiso, lanzador o no exportado no van en la lista");
  assert.match(text, /a mirar: READ_SMS, CAMERA/);
  assert.match(text, /permisos propios débiles: com\.ejemplo\.billetera\.PERMISO \(normal\)/);
  assert.match(text, /Deep links \(1\): billetera:\/\/pagar \(verificado\)/);
  assert.match(text, /Red: cleartext permitido para dev\.ejemplo\.com · confía en CAs instaladas por el usuario/);
  assert.match(text, /pinning probable: 1 pin\(es\) sha256/);
  assert.match(text, /Hosts del alcance \(\d+\): [^\n]*api\.ejemplo\.com \(\d+ rutas\)/);
  assert.match(text, /staging-api\.ejemplo\.com \(1 rutas, no productivo\)/);
  assert.match(text, /Fuera del alcance \(\d+; no se tocan[^\n]*tracker\.terceros\.io/);
  assert.doesNotMatch(text, /Fuera del alcance[^\n]*schemas\.android\.com/);
  assert.match(text, /\/api\/v2\/admin\/usuarios\/\{id\}/);
  assert.match(text, /users\/\{userId\}\/wallets \(relativa\)/);
  assert.match(text, /POST \/api\/v2\/pagos\/transferir/);
  assert.doesNotMatch(text, /\/system\/bin\/su|dd\/MM|application\/json/);
  assert.match(text, /base de datos https:\/\/ejemplo-prod\.firebaseio\.com \(FUERA del alcance/);
  assert.match(text, /bucket de Storage ejemplo-prod\.appspot\.com \(EN alcance: lectura pública con http_request GET https:\/\/firebasestorage\.googleapis\.com\/v0\/b\/ejemplo-prod\.appspot\.com\/o\?maxResults=1\)/);
  assert.doesNotMatch(text, /Otros esquemas/, "billetera:// ya es un deep link declarado");
  // Secretos: enteros para el modelo (son hallazgos del objetivo).
  assert.match(text, new RegExp(`clave de acceso AWS ${AWS} \\[alta\\] en classes\\.dex`));
  for (const secret of [AWS, GOOGLE, BEARER, BASIC, SLACK, ALGOLIA]) assert.ok(text.includes(secret), `el texto del modelo lleva ${secret.slice(0, 6)}…`);
  for (const tipo of ["clave de API de Google", "token Bearer", "credencial Basic", "webhook de Slack", "clave de Algolia", "DSN de Sentry"]) assert.match(text, new RegExp(tipo));
  // Enteros también en el artefacto del análisis (el que el modelo amplía con artifact_read) y en el de secretos.
  const full = artifacts.read(String(result.details!.secretos)).toString("utf8");
  for (const secret of [AWS, GOOGLE, BEARER, BASIC, SLACK, ALGOLIA]) assert.ok(full.includes(secret), `el artefacto de secretos guarda ${secret.slice(0, 6)}…`);
  const analysis = artifacts.read(String(result.details!.artefacto)).toString("utf8");
  for (const secret of [AWS, GOOGLE, BEARER, BASIC, SLACK, ALGOLIA]) assert.ok(analysis.includes(secret), `el análisis guarda ${secret.slice(0, 6)}…`);
  assert.match(text, new RegExp(`Artefacto: ${String(result.details!.artefacto)}`));
  assert.ok(!text.includes(String(result.details!.secretos)), "el modelo no recibe el hash del artefacto de secretos");
  // Pistas, sin el valor completo, y nada fuera del alcance.
  const leads = findings.list();
  assert.ok(leads.every((item) => item.state === "pista"));
  assert.ok(leads.some((item) => item.kind === "secreto en app móvil: clave de acceso aws" && item.asset === "android:com.ejemplo.billetera"));
  assert.ok(leads.some((item) => item.kind === "superficie de app móvil" && item.asset === "staging-api.ejemplo.com"));
  assert.ok(leads.some((item) => item.kind === "configuración de app móvil" && /debuggable/.test(item.summary)));
  assert.ok(!leads.some((item) => /terceros\.io/.test(item.asset)));
  for (const item of leads) for (const secret of [AWS, GOOGLE, BEARER, BASIC, SLACK]) assert.ok(!item.summary.includes(secret));
  assert.ok(leads.every((item) => item.evidence.includes(String(result.details!.artefacto))));
  // Cobertura: lo del alcance queda visto (no probado); lo de afuera no entra. No salió ninguna petición.
  const surface = http.surface();
  assert.ok(surface.some((row) => row.host === "api.ejemplo.com" && row.path === "/v2/cuentas" && row.state === "visto"));
  assert.ok(surface.some((row) => row.host === "staging-api.ejemplo.com" && row.path === "/internal/debug/config"));
  assert.ok(!surface.some((row) => row.host.includes("terceros")));
  // Con varios hosts del alcance, una ruta suelta no se le asigna a ninguno.
  assert.ok(!surface.some((row) => row.path.startsWith("/api/v2/admin")));
  assert.equal(http.count, 0);
  // Con dos hosts del alcance no se sabe a cuál va el Bearer: no se propone identidad.
  assert.deepEqual(http.proposedIdentities(), []);
  // Repetir no duplica las pistas: avisa que ya estaban.
  const again = await tool.execute({ path: "apks/billetera.apk" }, abort);
  assert.match(again.text, /\(ya estaba\)/);
  assert.equal(findings.list().length, leads.length);
});

test("apk_analyze: un Bearer con un único host del alcance queda propuesto como identidad, sin aprobar", async () => {
  const { cwd, http, tool } = setup(["api.solo.com"]);
  writeFileSync(join(cwd, "app.apk"), zip([
    { name: "classes.dex", data: dex(["https://api.solo.com/v1/perfil", `Bearer ${BEARER}`]) },
    { name: "assets/index.android.bundle", data: 'fetch("/api/v1/pagos",{method:"POST",body:JSON.stringify({monto:1})})' },
  ]));
  const result = await tool.execute({ path: "app.apk" }, abort);
  assert.match(result.text, /Manifest: no hay AndroidManifest\.xml/);
  assert.match(result.text, /las absolutas se asignaron a api\.solo\.com, el único host del alcance/);
  assert.ok(http.surface().some((row) => row.host === "api.solo.com" && row.path === "/api/v1/pagos" && row.seenMethods.includes("POST") && row.state === "visto"));
  assert.match(result.text, /Identidades propuestas \(no se usan hasta que el operador las apruebe con \/identity aprobar <nombre>\): apk \(s1, Authorization para https:\/\/api\.solo\.com\)/);
  assert.deepEqual(http.proposedIdentities(), [{ name: "apk", headers: ["authorization"], origin: "https://api.solo.com" }]);
  assert.deepEqual(http.identityNames(), [], "propuesta no es aprobada como identidad");
  assert.ok(result.text.includes(BEARER), "el Bearer de la app es material del objetivo: el modelo lo ve y lo puede escribir tal cual");
  assert.deepEqual(http.sensitiveValues().filter(({ value }) => value === BEARER).map(({ kind }) => kind), ["objetivo"], "la propuesta sacada del APK es del objetivo");
});

test("apk_analyze con jadx (doble): lee lo decompilado sin bibliotecas, conserva el código y marca resultado parcial", async () => {
  const calls: string[][] = [];
  const { cwd, tool } = setup(["*.ejemplo.com"], {
    decompilers: () => ({ jadx: "/caja/bin/jadx" }),
    run: async ({ argv }) => {
      calls.push(argv);
      const out = argv[argv.indexOf("-d") + 1]!;
      const write = (rel: string, body: string) => { mkdirSync(join(out, rel, ".."), { recursive: true }); writeFileSync(join(out, rel), body); };
      write("sources/com/ejemplo/billetera/api/Servicio.java", `interface Servicio {\n  @POST("v1/transferencias/{id}/aprobar")\n  Call<Void> aprobar(@Path("id") String id);\n  @GET("https://api.ejemplo.com/v1/admin/reportes")\n  Call<Void> reportes();\n}\nclass Red { void armar() { new CertificatePinner.Builder().add("api.ejemplo.com", "${PIN}"); } }\n`);
      write("sources/okhttp3/Interno.java", `class Interno { String k = "${"AKIA" + "LIBRERIA00000000"}"; }`);
      write("resources/res/values/strings.xml", `<resources><string name="internal_api_token">tok_9f8e7d6c5b4a</string><string name="app_name">Billetera</string></resources>`);
      write("resources/AndroidManifest.xml", `<manifest package="com.ejemplo.billetera"/>`);
      return { exitCode: 1, stdout: "", stderr: "ERROR - finished with errors, count: 3" };
    },
  });
  writeFileSync(join(cwd, "billetera.apk"), testApk());
  const result = await tool.execute({ path: "billetera.apk", conservar: true }, abort);
  assert.equal(calls.length, 1);
  assert.equal(calls[0]![0], "/caja/bin/jadx");
  assert.ok(calls[0]!.at(-1)!.endsWith("billetera.apk"), "jadx recibe el APK del proyecto");
  assert.match(result.text, /Modo: con jadx\. jadx: \d+ archivos de texto revisados \(terminó con 1: resultado parcial\)/);
  assert.match(result.text, /POST v1\/transferencias\/\{id\}\/aprobar \(relativa\)/);
  assert.match(result.text, /api\.ejemplo\.com\/v1\/admin\/reportes/);
  assert.match(result.text, /OkHttp CertificatePinner en uso/);
  assert.match(result.text, /recurso «internal_api_token»/);
  assert.doesNotMatch(result.text, /LIBRER/, "las bibliotecas no se revisan");
  assert.match(result.text, /Código decompilado en apk-decompilado\/com\.ejemplo\.billetera-4\.2\.0/);
  assert.ok(existsSync(join(cwd, "apk-decompilado", "com.ejemplo.billetera-4.2.0", "sources", "com", "ejemplo", "billetera", "api", "Servicio.java")));
});

test("apk_analyze: rutas fuera del proyecto, enlaces que salen y .cyber se rechazan", async () => {
  const { cwd, tool } = setup(["*.ejemplo.com"]);
  const outside = tmp();
  writeFileSync(join(outside, "ajeno.apk"), testApk());
  await assert.rejects(Promise.resolve(tool.execute({ path: join(outside, "ajeno.apk") }, abort)), /fuera de la carpeta del proyecto/);
  await assert.rejects(Promise.resolve(tool.execute({ path: "../ajeno.apk" }, abort)), /fuera de la carpeta del proyecto|No existe/);
  symlinkSync(join(outside, "ajeno.apk"), join(cwd, "enlace.apk"));
  await assert.rejects(Promise.resolve(tool.execute({ path: "enlace.apk" }, abort)), /fuera de la carpeta del proyecto/);
  mkdirSync(join(cwd, ".cyber"), { recursive: true });
  writeFileSync(join(cwd, ".cyber", "x.apk"), testApk());
  await assert.rejects(Promise.resolve(tool.execute({ path: ".cyber/x.apk" }, abort)), /\.cyber/);
  writeFileSync(join(cwd, "texto.apk"), "no soy un zip");
  await assert.rejects(Promise.resolve(tool.execute({ path: "texto.apk" }, abort)), /no parece un APK/);
  await assert.rejects(Promise.resolve(tool.execute({}, abort)), /Pasá path .* o url/);
});

test("apk_analyze por URL: baja dentro del alcance; fuera del alcance, tiendas, mirrors y redirecciones afuera no", async () => {
  const apk = zip([{ name: "classes.dex", data: dex(["https://api.ejemplo.com/v1/x"]) }]);
  const server = createServer((request, response) => {
    if (request.url === "/app.apk") { response.writeHead(200, { "content-type": "application/vnd.android.package-archive" }); response.end(apk); return; }
    if (request.url === "/redir") { response.writeHead(302, { location: "http://otro.invalid/app.apk" }); response.end(); return; }
    if (request.url === "/vuelta") { response.writeHead(302, { location: "/app.apk" }); response.end(); return; }
    response.writeHead(404); response.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as any).port}`;
  try {
    const { http, tool } = setup([`${base}/`, "apkpure.com", "*.ejemplo.com"]);
    const result = await tool.execute({ url: `${base}/vuelta` }, abort);
    assert.match(result.text, /bajado en h2/);
    assert.equal(http.count, 2, "la redirección y la descarga cuentan como peticiones");
    await assert.rejects(Promise.resolve(tool.execute({ url: "https://fuera.test/app.apk" }, abort)), /Fuera del alcance de esta sesión/);
    await assert.rejects(Promise.resolve(tool.execute({ url: "https://play.google.com/store/apps/details?id=com.ejemplo" }, abort)), /No bajo apps de una tienda[^]*dej[ea] el APK/);
    await assert.rejects(Promise.resolve(tool.execute({ url: "https://apkpure.com/x.apk" }, abort)), /mirror de APKs de terceros/);
    await assert.rejects(Promise.resolve(tool.execute({ url: `${base}/redir` }, abort)), /Fuera del alcance de esta sesión: http:\/\/otro\.invalid/);
    assert.equal(http.count, 3, "lo rechazado no sale: sólo la primera redirección del último intento");
  } finally {
    server.close();
  }
});

test("formatos: zip con topes, AXML roto, dex falso y lectores lineales", () => {
  const archive = zip([{ name: "a.txt", data: "x".repeat(10_000) }, { name: "b/c.txt", data: "hola", store: true }]);
  const entries = zipEntries(archive);
  assert.deepEqual(entries.map((entry) => entry.name), ["a.txt", "b/c.txt"]);
  assert.equal(zipRead(archive, entries[0]!, 100), undefined, "más grande que el tope: no se lee a medias");
  assert.equal(zipRead(archive, entries[1]!, 100)!.toString(), "hola");
  assert.throws(() => zipEntries(Buffer.from("no es un zip")), /no es un zip/);
  const dir = tmp();
  assert.throws(() => zipExtract(zip([{ name: "../fuera.txt", data: "x" }]), dir), /ruta insegura/);
  assert.equal(zipExtract(archive, dir), 2);
  assert.equal(readFileSync(join(dir, "b", "c.txt"), "utf8"), "hola");
  // AXML truncado o con índices fuera de rango: no tira, devuelve lo que pudo.
  const broken = manifest().subarray(0, 300);
  assert.doesNotThrow(() => decodeAxml(broken));
  assert.equal(decodeAxml(Buffer.from("<manifest/>")), undefined);
  assert.equal(parseTextXml('<a x="1"><b y=\'2\'>texto &amp; más</b><c/></a>')!.children[0]!.text, "texto & más");
  assert.equal(dexStrings(Buffer.from("no es dex")), undefined);
  assert.deepEqual(printableStrings(Buffer.from("\x00\x01hola mundo\x00ab\x00")), ["hola mundo"]);
  // Lineal: un texto enorme sin «://» o con un esquema larguísimo no traba la búsqueda de URLs.
  const started = Date.now();
  assert.equal(findUrls(`${"a".repeat(3_000_000)}://x`).length, 1);
  assert.equal(findUrls(`${"a-".repeat(200_000)} https://api.ejemplo.com/v1).`)[0], "https://api.ejemplo.com/v1");
  assert.ok(Date.now() - started < 3000);
  assert.deepEqual(apiPath("/api/v1/users/{id}"), { path: "/api/v1/users/{id}", relative: false });
  assert.deepEqual(apiPath("users/{id}/orders"), { path: "users/{id}/orders", relative: true });
  for (const value of ["/system/bin/sh", "com/google/Foo", "application/json", "Lcom/x/Y;", "dd/MM/yyyy", "/assets/x.png", "hola mundo"]) assert.equal(apiPath(value), undefined, value);
  assert.equal(redactSecret(AWS), "AKIA…VL (20)");
  assert.equal(redactSecret(SLACK), "https:…Jd3F (77)");
  assert.equal(redactSecret("abcdefghijklmn"), "abcd…mn (14)");
});

test("instalación de jadx y apktool: sólo en la caja, versión fija y sha256 verificado antes de abrir nada", async () => {
  const calls: string[][] = [];
  const runner: Runner = async (argv) => { calls.push(argv); return { exitCode: 0, stdout: argv.includes("--version") ? "1.5.6\n" : "", stderr: "", durationMs: 1 }; };
  const home = tmp();
  // En el host (esta máquina): no se ofrece ni se instala.
  assert.ok(!INSTALLABLE.includes("jadx") && !INSTALLABLE.includes("apktool"));
  await assert.rejects(installTool("jadx", home, runner, { enCaja: false, home }), /sólo dentro de la caja/);
  await assert.rejects(installTool("apktool", home, runner), /sólo dentro de la caja/);
  assert.equal(calls.length, 0);
  assert.deepEqual(readdirSync(home), []);
  assert.ok(movilStatus().every((line) => line.includes("sólo en la caja") && !line.includes("✗")), "en el host no cuentan como faltantes");
  // Versiones y sumas fijas.
  for (const item of [MOVIL.jadx, MOVIL.apktool, MOVIL.jre.x64, MOVIL.jre.arm64]) {
    assert.match(item.sha256, /^[0-9a-f]{64}$/);
    assert.match(item.url, /^https:\/\/github\.com\//);
  }
  assert.match(MOVIL.jadx.url, /v1\.5\.6\/jadx-1\.5\.6\.zip$/);
  // La imagen de la caja trae las mismas versiones con las mismas sumas: desde #42 el Dockerfile las baja con
  // distro/bajar-fijado.sh, que las lee (versión, suma y URL) de distro/fijados.txt.
  const dockerfile = readFileSync(join(import.meta.dirname, "..", "distro", "Dockerfile"), "utf8");
  const fijados = readFileSync(join(import.meta.dirname, "..", "distro", "fijados.txt"), "utf8");
  for (const [nombre, item] of [["jadx", MOVIL.jadx], ["apktool", MOVIL.apktool]] as const) {
    assert.ok(fijados.split("\n").some((linea) => linea.startsWith(`${nombre} `) && linea.endsWith(` ${item.sha256} ${item.url}`)), `${nombre}: ${item.url}`);
    assert.ok(dockerfile.includes(`$($b ${nombre})`), `el Dockerfile baja ${nombre} con bajar-fijado`);
  }
  assert.match(dockerfile, /COPY skills \.\/skills/);
  assert.match(MOVIL.apktool.url, /v3\.0\.3\/apktool_3\.0\.3\.jar$/);
  if (!which("java")) assert.throws(() => planesMovil("jadx", { home, arch: "ia32" }), /arquitectura ia32/);
  // Dentro de la caja, con una descarga que no coincide: no se guarda, no se abre, no se ejecuta.
  const bad = await installTool("jadx", home, runner, { enCaja: true, home, arch: "x64", fetcher: async () => ({ ok: true, status: 200, arrayBuffer: async () => new TextEncoder().encode("otra cosa").buffer as ArrayBuffer }) });
  assert.match(bad, /no coincide con lo fijado[^]*No se guardó ni se abrió nada/);
  assert.equal(calls.length, 0);
  assert.ok(!existsSync(join(home, ".local", "bin", "jadx")));
  // Con lo fijado (dobles con su propio sha256): Java, jadx y el envoltorio.
  const jadxZip = zip([{ name: "lib/jadx-1.5.6-all.jar", data: "jar" }, { name: "bin/jadx", data: "#!/bin/sh" }]);
  const jre = Buffer.from("tar.gz falso");
  const pin = (data: Buffer) => ({ url: "https://github.com/prueba/x", sha256: createHash("sha256").update(data).digest("hex"), bytes: data.length });
  const served = new Map([["jadx", jadxZip], ["jre", jre]]);
  const fetched: string[] = [];
  const good = await installTool("jadx", home, runner, {
    enCaja: true,
    home,
    fijas: { jadx: { ...pin(jadxZip), url: "https://github.com/prueba/jadx" }, jre: { ...pin(jre), url: "https://github.com/prueba/jre" } },
    fetcher: async (url) => { fetched.push(url); const data = served.get(url.split("/").at(-1)!)!; return { ok: true, status: 200, arrayBuffer: async () => data.buffer.slice(data.byteOffset, data.byteOffset + data.length) as ArrayBuffer }; },
  });
  assert.deepEqual(fetched, ["https://github.com/prueba/jre", "https://github.com/prueba/jadx"]);
  assert.match(good, /jadx: instalado en .*\.local\/bin\/jadx/);
  const base = join(home, ".local", "share", "cyber-movil");
  assert.equal(calls[0]![0], "tar");
  assert.deepEqual(calls[0]!.slice(1, 4), ["-xzf", join(base, "jre.tar.gz"), "-C"]);
  assert.ok(existsSync(join(base, "jadx-1.5.6", "lib", "jadx-1.5.6-all.jar")));
  assert.ok(!existsSync(join(base, "jadx-1.5.6.zip")), "el zip ya abierto se borra");
  const wrapper = join(home, ".local", "bin", "jadx");
  const script = readFileSync(wrapper, "utf8");
  assert.match(script, /^#!\/bin\/sh\n/);
  assert.ok(script.includes(`'${join(base, MOVIL.jre.carpeta, "bin", "java")}'`));
  assert.ok(script.includes(`'${join(base, "jadx-1.5.6", "lib", "*")}' 'jadx.cli.JadxCLI' "$@"`));
  assert.equal(statSync(wrapper).mode & 0o111, 0o111);
  assert.deepEqual(calls.at(-1), [wrapper, "--version"]);
  // apktool: el .jar se queda (no es un paquete que se abra) y el envoltorio lo corre con java -jar.
  const plans = planesMovil("apktool", { home, arch: "arm64" });
  const jar = plans.find((plan) => plan.download?.url === MOVIL.apktool.url)!;
  assert.equal(jar.download!.sha256, MOVIL.apktool.sha256);
  const apktoolWrapper = plans.find((plan) => plan.wrapper)!.wrapper!;
  assert.deepEqual(apktoolWrapper.command.slice(-2), ["-jar", jar.download!.file]);
});

test("motor: apk_analyze está en el catálogo (grupo móvil), la habilidad movil lo carga y sus pistas son de la sesión", async () => {
  const { Engine } = await import("../src/engine.ts");
  const { resolveProvider } = await import("../src/providers.ts");
  const cwd = tmp();
  writeFileSync(join(cwd, "app.apk"), testApk());
  const engine = new Engine({ cwd, provider: resolveProvider("faux"), autoVerify: false });
  try {
    assert.ok(engine.catalog.available.has("apk_analyze"));
    assert.ok(!engine.catalog.loaded().includes("apk_analyze"), "por demanda, no en el núcleo");
    assert.match(engine.catalog.summary(), /^móvil: apk_analyze \(Analizar APK\)$/m);
    assert.match(engine.agent.system, /movil — Apps Android del programa/);
    const load = engine.agent.tools.find((tool) => tool.name === "skill_load")!;
    const read = await load.execute({ name: "movil" }, abort);
    assert.match(read.text, /^# Habilidad movil\n\n## Cuándo/);
    assert.ok(engine.catalog.loaded().includes("apk_analyze"));
    engine.scope.edit({ include: ["*.ejemplo.com"] });
    const tool = engine.agent.tools.find((item) => item.name === "apk_analyze")!;
    const result = await tool.execute({ path: "app.apk" }, abort);
    assert.match(result.text, /Hosts del alcance \(\d+\): api\.ejemplo\.com/);
    const mine = engine.findings.list({ sessionId: engine.sessionId });
    assert.ok(mine.length >= 3 && mine.every((item) => item.state === "pista"));
    assert.ok(!mine.some((item) => item.summary.includes(AWS)));
  } finally {
    await engine.close();
  }
});

test("apk_analyze: un asset armado para trabar expresiones regulares no lo traba", async () => {
  const { cwd, tool } = setup(["*.ejemplo.com"]);
  const hostile = ["xoxb-".repeat(300_000), "eyJ-".repeat(300_000), `"token":"${"a".repeat(500_000)}`, `<string name="${"k".repeat(200_000)}">x`, "Basic " + "A".repeat(400_000) + "===", "a://".repeat(100_000)].join("\n");
  writeFileSync(join(cwd, "hostil.apk"), zip([{ name: "assets/datos.txt", data: hostile }, { name: "classes.dex", data: dex(["https://api.ejemplo.com/v1/ok"]) }]));
  const started = Date.now();
  const result = await tool.execute({ path: "hostil.apk" }, abort);
  assert.ok(Date.now() - started < 15_000, `tardó ${Date.now() - started} ms`);
  assert.match(result.text, /api\.ejemplo\.com/);
});

test("apk_analyze sugiere seguir con REA sólo cuando la sesión lo tiene (dentro de la caja)", async () => {
  const conRea = setup(["*.ejemplo.com"], { rea: () => true });
  writeFileSync(join(conRea.cwd, "app.apk"), testApk());
  assert.match((await conRea.tool.execute({ path: "app.apk" }, abort)).text, /Para profundizar en la caja \(firma, recursos con apktool, inventario completo, librerías \.so, Flutter\): habilidad ingenieria-inversa, con REA sobre app\.apk\./);
  const sinRea = setup(["*.ejemplo.com"]);
  writeFileSync(join(sinRea.cwd, "app.apk"), testApk());
  assert.doesNotMatch((await sinRea.tool.execute({ path: "app.apk" }, abort)).text, /con REA|ingenieria-inversa/, "fuera de la caja no se ofrece");
});
