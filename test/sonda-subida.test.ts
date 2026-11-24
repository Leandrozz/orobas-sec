// upload_probe y multipart: laboratorio que guarda y sirve mal (nombre sin sanear, tipo por extensión,
// parser XML que resuelve entidades) contra uno que guarda bien (id propio, attachment, nosniff).
import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, get } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, posix } from "node:path";
import { test, type TestContext } from "node:test";
import type { Tool } from "../src/agent.ts";
import { Artifacts } from "../src/artifacts.ts";
import { ConsentStore } from "../src/consent.ts";
import { Findings } from "../src/findings.ts";
import { encodeMultipart, HttpClient } from "../src/http.ts";
import { Ledger } from "../src/ledger.ts";
import { createPayloadTools, payloadSetFor, xxeExpansion } from "../src/payloads.ts";
import { PROFILE_GRANTS, type ProfileGrants } from "../src/perfil.ts";
import { generateReport } from "../src/report.ts";
import { listResidues } from "../src/residuos.ts";
import { ScopeStore } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { createNetTools } from "../src/toolbox.ts";
import { createUploadProbe, unzipStored, UPLOAD_VARIANTS } from "../src/upload-probe.ts";
import { createWebTools } from "../src/webtools.ts";

const signal = new AbortController().signal;

interface Part { name: string; filename?: string; contentType?: string; data: Buffer }
/** Parser multipart mínimo del laboratorio: trabaja sobre bytes, no sobre texto. */
function parseMultipart(raw: Buffer, type: string): Part[] {
  const boundary = /boundary=([^;]+)/.exec(type)?.[1];
  if (!boundary) return [];
  const parts: Part[] = [];
  const delimiter = Buffer.from(`--${boundary}`);
  let at = raw.indexOf(delimiter);
  while (at >= 0) {
    const start = at + delimiter.length;
    if (raw.subarray(start, start + 2).toString() === "--") break;
    const next = raw.indexOf(delimiter, start);
    if (next < 0) break;
    const chunk = raw.subarray(start + 2, next - 2);
    const split = chunk.indexOf("\r\n\r\n");
    const head = chunk.subarray(0, split).toString("utf8");
    parts.push({
      name: /name="([^"]*)"/.exec(head)?.[1] ?? "",
      filename: /filename="([^"]*)"/.exec(head)?.[1],
      contentType: /content-type:\s*(\S+)/i.exec(head)?.[1],
      data: Buffer.from(chunk.subarray(split + 4)),
    });
    at = next;
  }
  return parts;
}

/** El «parser XML» del laboratorio vulnerable: resuelve &xxe; con un nombre de equipo y visita el oyente si el DTD lo pide. */
async function resolveXml(text: string): Promise<string> {
  if (!text.includes('<!ENTITY xxe SYSTEM "file:///etc/hostname">')) return text;
  const oob = /<!ENTITY % oob SYSTEM "([^"]+)">/.exec(text)?.[1];
  if (oob && new URL(oob).hostname === "127.0.0.1") await new Promise<void>((resolve) => get(oob, (incoming) => { incoming.resume(); incoming.on("end", resolve); }).on("error", () => resolve()));
  return text.replaceAll("&xxe;", "lab-equipo");
}

async function uploadLab(t: TestContext, mode: "vulnerable" | "seguro") {
  const files = new Map<string, { data: Buffer; type: string }>();
  const received: Part[][] = [];
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const raw = Buffer.concat(chunks);
    const url = new URL(req.url!, "http://lab");
    const json = (status: number, value: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(value));
    if (req.method === "POST" && url.pathname === "/upload") {
      const parts = parseMultipart(raw, req.headers["content-type"] ?? "");
      received.push(parts);
      const file = parts.find((part) => part.name === "file" && part.filename !== undefined);
      if (!file) return json(400, { error: "falta file" });
      if (mode === "seguro") {
        const id = randomBytes(8).toString("hex");
        files.set(`/files/${id}`, { data: file.data, type: "application/octet-stream" });
        return json(201, { id, url: `/files/${id}` });
      }
      const path = posix.normalize(`/uploads/${file.filename}`);
      files.set(path, { data: file.data, type: file.contentType ?? "" });
      // Lee el texto de los documentos al subirlos (previsualización): ahí resuelve las entidades.
      let texto = "";
      if (/\.(docx|xlsx)$/.test(path)) for (const [, entry] of unzipStored(file.data)) texto += await resolveXml(entry.toString("utf8"));
      else if (path.endsWith(".svg")) await resolveXml(file.data.toString("utf8"));
      return json(200, { ok: true, url: path, ...(texto ? { texto: texto.replace(/<[^>]+>/g, " ") } : {}) });
    }
    if (req.method === "DELETE") return json(files.delete(decodeURIComponent(url.pathname)) ? 200 : 404, { ok: true });
    const stored = files.get(decodeURIComponent(url.pathname));
    if (!stored) return json(404, { error: "no" });
    if (mode === "seguro") return res.writeHead(200, { "content-type": "application/octet-stream", "content-disposition": "attachment", "x-content-type-options": "nosniff" }).end(stored.data);
    const path = decodeURIComponent(url.pathname);
    let type = stored.type;
    if (path.endsWith(".php")) type = "text/html";
    if (path.endsWith(".svg")) type = "image/svg+xml";
    if (stored.data.subarray(0, 15).toString().toLowerCase() === "<!doctype html>") type = "text/html";
    const body = path.endsWith(".svg") ? Buffer.from(await resolveXml(stored.data.toString("utf8"))) : stored.data;
    res.writeHead(200, { "content-type": type }).end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const cwd = mkdtempSync(join(tmpdir(), "cyber-subida-"));
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const scope = new ScopeStore(db);
  scope.edit({ include: [base] });
  const http = new HttpClient(artifacts, () => scope.current());
  const consents = new ConsentStore(db);
  http.consent = () => consents;
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    db.close();
    rmSync(cwd, { recursive: true, force: true });
  });
  const probe = (grants: ProfileGrants, listener = false) => createUploadProbe({ http, artifacts, db, sessionId: "s1", grants: () => grants, listener: listener ? { host: "127.0.0.1" } : undefined });
  return { base, http, db, artifacts, scope, paths, consents, files, received, probe };
}

test("upload_probe: laboratorio vulnerable — doble extensión, ../, HTML como imagen, SVG con script y XXE in-band y por el oyente", async (t) => {
  const lab = await uploadLab(t, "vulnerable");
  const result = await lab.probe(PROFILE_GRANTS.pentest, true).execute({ url: `${lab.base}/upload`, servedAt: `${lab.base}/uploads/{name}`, delayMs: 0, waitMs: 1500 }, signal);
  const signals = result.details!.senales as Array<{ variante: string; senal: string }>;
  const by = (id: string) => signals.filter((item) => item.variante === id).map((item) => item.senal).join(" | ");
  assert.equal(result.details!.subidas, UPLOAD_VARIANTS.length);
  assert.equal(by("control"), "", "el control no es una señal");
  assert.equal(by("doble-ext-php-jpg"), "", ".php.jpg termina en .jpg");
  assert.match(by("doble-ext-jpg-php"), /extensión \.php/);
  assert.match(by("traversal"), /carpeta de arriba/);
  assert.match(by("mime-html"), /text\/html inline/);
  assert.match(by("svg-script"), /SVG con script servido inline/);
  assert.match(by("svg-xxe"), /XXE in-band: lo servido trae \/etc\/hostname resuelto \(«lab-equipo»\)/);
  assert.match(by("docx-xxe"), /XXE in-band: la respuesta de la subida/);
  assert.match(by("xlsx-xxe"), /XXE in-band: la respuesta de la subida/);
  for (const id of ["svg-xxe", "docx-xxe", "xlsx-xxe"]) assert.match(by(id), /XXE fuera de banda: el servidor pidió el oyente/, `${id} visitó el oyente y se atribuye a su variante`);
  assert.ok((result.details!.peticiones as number) <= 20);
  // Lo subido es texto marcador, nunca código.
  for (const parts of lab.received) for (const part of parts) assert.doesNotMatch(part.data.toString("latin1"), /<\?php|system\(|eval\(|alert\(/);
  const traversal = lab.received.flat().find((part) => part.filename?.startsWith("../"));
  assert.ok(traversal, "el nombre con ../ se mandó tal cual");
  // Residuos: cada archivo aceptado queda para limpiar y se puede borrar como recurso propio.
  const residues = listResidues(lab.db, "s1");
  assert.equal(residues.length, UPLOAD_VARIANTS.length);
  assert.ok(residues.every((item) => item.tool === "upload_probe" && item.kind === "archivo"));
  const control = residues.find((item) => item.detail.includes("(control,"))!;
  assert.match(control.target, /\/uploads\/orobas-[0-9a-f]{8}-c\.txt$/);
  await assert.rejects(() => lab.http.send({ url: `${lab.base}/uploads/ajeno.txt`, method: "DELETE", allowDestructive: true }), /no lleva un id de un recurso creado/);
  const removed = await lab.http.send({ url: control.target, method: "DELETE", allowDestructive: true });
  assert.equal(removed.response?.status, 200, "lo subido por la sonda se borra con allowDestructive");
  // El informe lo lista en «Para limpiar».
  const markdown = (await generateReport({ paths: lab.paths, db: lab.db, artifacts: lab.artifacts, findings: new Findings(lab.db, (hash) => lab.artifacts.find(hash)), scope: lab.scope, ledger: new Ledger(lab.db) })).markdown;
  const section = markdown.split("## Para limpiar")[1]!.split("## ")[0]!;
  assert.match(section, /\| upload\\_probe · archivo \| http:\/\/127\.0\.0\.1:\d+\/uploads\/orobas-[0-9a-f]{8}-c\.txt \|/);
  assert.match(section, /\.\.\/orobas-[0-9a-f]{8}-t\.txt \(traversal/);
});

test("upload_probe: bounty sube sólo lo inerte; /consent subida-activa habilita lo activo; un laboratorio que guarda bien no da señales", async (t) => {
  const lab = await uploadLab(t, "seguro");
  const bounty = lab.probe(PROFILE_GRANTS.bounty);
  await assert.rejects(async () => bounty.execute({ url: `${lab.base}/upload`, variants: ["svg-script", "docx-xxe"], delayMs: 0 }, signal), /subida-activa/);
  assert.equal(lab.http.count, 0, "rechazado antes de mandar nada");
  const inert = await bounty.execute({ url: `${lab.base}/upload`, delayMs: 0, waitMs: 0 }, signal);
  assert.deepEqual(inert.details!.omitidas, ["svg-script", "svg-xxe", "docx-xxe", "xlsx-xxe"]);
  assert.equal(inert.details!.subidas, 5);
  assert.deepEqual(inert.details!.senales, []);
  assert.match(inert.text, /attachment/);
  assert.match(inert.text, /Omitidas por contenido activo/);
  assert.ok(lab.received.every((parts) => !/\.(svg|docx|xlsx)$/.test(parts.find((part) => part.filename)?.filename ?? "")), "nada activo llegó al objetivo");
  lab.consents.grant("subida-activa", "el programa acepta SVG de prueba en la cuenta propia");
  const active = await bounty.execute({ url: `${lab.base}/upload`, variants: ["svg-script", "svg-xxe"], delayMs: 0, waitMs: 0 }, signal);
  assert.equal(active.details!.subidas, 2);
  assert.deepEqual(active.details!.senales, []);
  assert.match(active.text, /Sin oyente declarado/);
  // Tope de la llamada: no pasa de maxRequests.
  const capped = await bounty.execute({ url: `${lab.base}/upload`, maxRequests: 3, delayMs: 0, waitMs: 0 }, signal);
  assert.equal(capped.details!.peticiones, 3);
  assert.match(capped.text, /no se subió \(tope de peticiones/);
});

test("multipart: http_request manda bytes exactos, http_replay los repite y la cabecera Host sólo nombra el alcance o un marcador", async (t) => {
  const lab = await uploadLab(t, "seguro");
  const bytes = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
  const encoded = encodeMultipart([{ name: "nota", value: "hola" }, { name: "file", filename: "a\"b\r\n.bin", contentType: "application/octet-stream", base64: bytes.toString("base64") }]);
  assert.match(encoded.contentType, /^multipart\/form-data; boundary=----orobas[0-9a-f]{24}$/);
  assert.match(encoded.text, /filename="a%22b%0D%0A\.bin"/, "comillas y saltos no rompen la cabecera");
  assert.match(encoded.text, /<binario: 256 bytes; base64 AAECAw/);
  assert.throws(() => encodeMultipart([{ name: "x", value: "a", base64: "YQ==" }]), /value o base64/);
  const tools = Object.fromEntries([...createNetTools({ artifacts: lab.artifacts, http: lab.http, scope: () => lab.scope.current() }), ...createWebTools({ artifacts: lab.artifacts, http: lab.http })].map((tool) => [tool.name, tool])) as Record<string, Tool>;
  const sent = await tools.http_request!.execute({ url: `${lab.base}/upload`, method: "POST", multipart: [{ name: "file", filename: "binario.bin", base64: bytes.toString("base64") }, { name: "nota", value: "hola" }] }, signal);
  assert.equal(sent.details!.status, 201);
  const first = lab.received.at(-1)!;
  assert.ok(first.find((part) => part.name === "file")!.data.equals(bytes), "los 256 bytes llegan intactos");
  assert.equal(first.find((part) => part.name === "nota")!.data.toString(), "hola");
  const logged = lab.http.log.at(-1)!;
  assert.deepEqual(logged.bodyKeys, ["file", "nota"]);
  await tools.http_replay!.execute({ id: sent.details!.id }, signal);
  assert.ok(lab.received.at(-1)!.find((part) => part.name === "file")!.data.equals(bytes), "la repetición manda las mismas partes");
  await assert.rejects(() => lab.http.send({ url: `${lab.base}/upload`, method: "POST", body: "x", multipart: [{ name: "a", value: "b" }] }), /body o multipart/);
  // Host: un marcador reservado llega tal cual; un dominio ajeno no se manda.
  const seen: string[] = [];
  const echo = createServer((req, res) => { seen.push(String(req.headers.host)); res.writeHead(200, { "content-type": "text/plain" }).end("ok"); });
  await new Promise<void>((resolve) => echo.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise<void>((resolve) => echo.close(() => resolve())));
  const echoBase = `http://127.0.0.1:${(echo.address() as AddressInfo).port}`;
  lab.scope.edit({ include: [lab.base, echoBase] });
  const marked = await lab.http.send({ url: `${echoBase}/`, headers: { host: "h-abc.orobas.invalid" } });
  assert.equal(marked.response?.status, 200);
  assert.equal(seen.at(-1), "h-abc.orobas.invalid");
  const count = lab.http.count;
  await assert.rejects(() => lab.http.send({ url: `${echoBase}/`, headers: { host: "interno.empresa.com" } }), /fuera del alcance/);
  assert.equal(lab.http.count, count);
});

test("payloads: clase xxe con lectura in-band de /etc/hostname y entidad hacia el oyente", async (t) => {
  const bounty = payloadSetFor(PROFILE_GRANTS.bounty).filter((payload) => payload.clase === "xxe");
  assert.deepEqual(bounty.map((payload) => payload.id), ["xxe-local-1", "xxe-oob-1"]);
  assert.match(bounty[0]!.plantilla, /<!ENTITY xxe SYSTEM "file:\/\/\/etc\/hostname">/);
  assert.match(bounty[1]!.plantilla, /<!ENTITY % oob SYSTEM "\{oyente\}">/);
  assert.ok(payloadSetFor(PROFILE_GRANTS.pentest).some((payload) => payload.id === "xxe-svg-1"));
  assert.equal(xxeExpansion("<r>orobas-xxe[lab-equipo]</r>", "orobas-xxe"), "lab-equipo");
  assert.equal(xxeExpansion("<r>orobas-xxe[&xxe;]</r>", "orobas-xxe"), undefined);
  assert.equal(xxeExpansion("<r>orobas-xxe[&amp;xxe;]</r>", "orobas-xxe"), undefined);
  const lab = await uploadLab(t, "seguro");
  const tools = Object.fromEntries(createPayloadTools({ artifacts: lab.artifacts, grants: () => PROFILE_GRANTS.bounty }).map((tool) => [tool.name, tool])) as Record<string, Tool>;
  const listed = await tools.payload_list!.execute({ clase: "xxe" }, signal);
  assert.equal(listed.details!.total, 2);
  assert.match((await tools.payload_get!.execute({ id: "xxe-oob-1" }, signal)).text, /upload_probe/);
});
