// reset_probe: un laboratorio de recuperación de contraseña que manda el mail a todas las direcciones
// del pedido, arma el enlace con X-Forwarded-Host o Host y entrega tokens cortos, consecutivos y
// reusables, contra uno que hace todo bien. Los mails llegan a un IMAP de mentira: la casilla del operador.
import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { connect, createServer, type AddressInfo, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test, type TestContext } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { analyzeTokens, createResetProbe } from "../src/reset-probe.ts";
import { createMailTools, type Mailbox } from "../src/correo.ts";
import { HttpClient } from "../src/http.ts";
import { listResidues } from "../src/residuos.ts";
import { ScopeStore } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

const signal = new AbortController().signal;
const message = (to: string, subject: string, html: string) =>
  [`From: Laboratorio <no-reply@lab.test>`, `To: ${to}`, `Subject: ${subject}`, `Date: ${new Date().toUTCString()}`, "MIME-Version: 1.0", "Content-Type: text/html; charset=utf-8", "", html, ""].join("\r\n");

/** IMAP de mentira con una sola bandeja: lo justo para fetchFor. */
async function fakeImap(t: TestContext, inbox: string[]) {
  const server = createServer((socket: Socket) => {
    let pending = "";
    socket.write("* OK listo\r\n");
    socket.on("data", (chunk) => {
      pending += chunk.toString("latin1");
      for (let end = pending.indexOf("\r\n"); end >= 0; end = pending.indexOf("\r\n")) {
        const line = pending.slice(0, end); pending = pending.slice(end + 2);
        const [tag, ...rest] = line.split(" "); const command = rest.join(" ");
        if (/^LOGIN /i.test(command)) { socket.write(`${tag} OK\r\n`); continue; }
        if (/^LIST /i.test(command)) { socket.write(`* LIST (\\HasNoChildren) "/" "INBOX"\r\n${tag} OK\r\n`); continue; }
        if (/^SELECT /i.test(command)) { socket.write(`* ${inbox.length} EXISTS\r\n${tag} OK\r\n`); continue; }
        const search = /^UID SEARCH SINCE \S+ TO "([^"]+)"/i.exec(command);
        if (search) {
          const wanted = search[1]!.replace(/\\(.)/g, "$1").toLowerCase();
          const uids = inbox.flatMap((raw, i) => (/^To: (.*)$/m.exec(raw)?.[1]!.toLowerCase().includes(wanted) ? [i + 1] : []));
          socket.write(`* SEARCH${uids.map((u) => ` ${u}`).join("")}\r\n${tag} OK\r\n`); continue;
        }
        const fetch = /^UID FETCH ([\d,]+) /i.exec(command);
        if (fetch) { for (const uid of fetch[1]!.split(",").map(Number)) { const raw = Buffer.from(inbox[uid - 1]!, "utf8"); socket.write(`* ${uid} FETCH (UID ${uid} BODY[]<0> {${raw.length}}\r\n`); socket.write(raw); socket.write(")\r\n"); } socket.write(`${tag} OK\r\n`); continue; }
        if (/^LOGOUT/i.test(command)) { socket.end(`* BYE\r\n${tag} OK\r\n`); continue; }
        socket.write(`${tag} BAD\r\n`);
      }
    });
    socket.on("error", () => {});
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const port = (server.address() as AddressInfo).port;
  return () => connect(port, "127.0.0.1");
}

/** Laboratorio de recuperación. «vulnerable»: todo mal; «seguro»: todo bien. */
async function resetLab(t: TestContext, mode: "vulnerable" | "seguro", inbox: string[], registered: () => string[]) {
  const tokens = new Map<string, { email: string; used: boolean; at: number }>();
  let next = 482100;
  const requests: Array<{ path: string; headers: Record<string, unknown>; body: string }> = [];
  const server = createHttpServer(async (req, res) => {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const url = new URL(req.url!, "http://lab");
    requests.push({ path: url.pathname, headers: req.headers, body: raw });
    const json = (status: number, value: unknown) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(value));
    const form = /x-www-form-urlencoded/.test(String(req.headers["content-type"]));
    const fields = form ? new URLSearchParams(raw) : undefined;
    const data = form ? Object.fromEntries(fields!) : JSON.parse(raw || "{}");
    if (url.pathname === "/forgot" && req.method === "POST") {
      let emails: string[];
      if (mode === "seguro") {
        if (form ? fields!.getAll("email").length !== 1 : typeof data.email !== "string") return json(400, { error: "un solo correo" });
        const email = String(form ? fields!.get("email") : data.email);
        if (!/^[^\s,@]+@[^\s,@]+$/.test(email)) return json(400, { error: "correo inválido" });
        emails = [email];
      } else {
        const value = form ? fields!.getAll("email") : data.email;
        emails = (Array.isArray(value) ? value : [value]).flatMap((item: string) => String(item).split(/[,\s]+/)).filter(Boolean);
      }
      const owner = emails[0]!;
      if (!registered().includes(owner)) return json(200, { ok: true });
      let token: string;
      if (mode === "seguro") {
        for (const [key, item] of tokens) if (item.email === owner) tokens.delete(key);
        token = randomBytes(24).toString("hex");
      } else token = String(next++);
      tokens.set(token, { email: owner, used: false, at: Date.now() });
      // El seguro arma el enlace con su dirección configurada, no con lo que diga el pedido.
      const host = mode === "seguro" ? `127.0.0.1:${(server.address() as AddressInfo).port}` : String(req.headers["x-forwarded-host"] ?? req.headers.host);
      const link = `http://${host}/reset?token=${token}`;
      inbox.push(message(emails.join(", "), "Restablece tu clave", `<p>Hola. Para restablecer tu contraseña entrá a <a href="${link}">este enlace</a>. Vence en 30 minutos.</p>`));
      return json(200, { ok: true });
    }
    if (url.pathname === "/reset" && req.method === "GET") {
      const item = tokens.get(url.searchParams.get("token") ?? "");
      return item && !item.used ? res.writeHead(200, { "content-type": "text/html" }).end("<form><input name=password><button>Guardar</button></form>") : res.writeHead(400, { "content-type": "text/html" }).end("<p>Enlace inválido o vencido</p>");
    }
    if (url.pathname === "/reset-password" && req.method === "POST") {
      const item = tokens.get(String(data.token));
      if (!item || item.used) return json(400, { error: "token inválido" });
      if (mode === "seguro") { item.used = true; for (const [key, other] of tokens) if (other.email === item.email) tokens.delete(key); }
      return json(200, { ok: true, cambiada: true });
    }
    json(404, { error: "no" });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); });
  return { base: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, requests };
}

async function setup(t: TestContext, mode: "vulnerable" | "seguro") {
  const inbox: string[] = [];
  const connector = await fakeImap(t, inbox);
  const registered: string[] = [];
  const lab = await resetLab(t, mode, inbox, () => registered);
  const cwd = mkdtempSync(join(tmpdir(), "cyber-reset-"));
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const scope = new ScopeStore(db);
  scope.edit({ include: [lab.base] });
  const http = new HttpClient(artifacts, () => scope.current());
  t.after(() => { db.close(); rmSync(cwd, { recursive: true, force: true }); });
  const box: Mailbox = { direccion: "ana@gmail.com", clave: "x", host: "imap.lab.test", puerto: 993 };
  const mail = { connector, boxes: () => [box], sleep: async () => {} };
  const [address] = createMailTools({ db, sessionId: "s1", ...mail });
  const made = await address!.execute({ etiquetas: ["victima", "atacante"] }, signal);
  const [victim, attacker] = [...made.text.matchAll(/: (\S+@gmail\.com)/g)].map((match) => match[1]!);
  registered.push(victim!);
  const probe = createResetProbe({ http, artifacts, db, sessionId: "s1", ...mail });
  return { ...lab, http, db, inbox, victim: victim!, attacker: attacker!, probe, mail };
}

const base = (lab: { base: string }) => ({ url: `${lab.base}/forgot`, delayMs: 0, waitSec: 0 });

test("reset_probe: laboratorio vulnerable — el atacante recibe el mail, el enlace usa el host inyectado y el token es débil", async (t) => {
  const lab = await setup(t, "vulnerable");
  const result = await lab.probe.execute({ ...base(lab), victim: lab.victim, attacker: lab.attacker, complete: { url: `${lab.base}/reset-password`, tokenField: "token", passwordField: "password", password: "Nueva-Prueba-1!" } }, signal);
  const signals = result.details!.senales as Array<{ prueba: string; variante: string; senal: string }>;
  const of = (prueba: string) => signals.filter((item) => item.prueba === prueba);
  // Duplicado: todas las formas mandan el mail también al alias del atacante.
  assert.deepEqual(of("duplicado").map((item) => item.variante).sort(), ["form-duplicado", "json-lista", "separador-coma", "separador-espacio", "separador-salto"]);
  assert.ok(of("duplicado").every((item) => /dirigido a las dos/.test(item.senal)));
  // Envenenamiento: este laboratorio usa X-Forwarded-Host y, si no, Host.
  assert.deepEqual(of("envenenamiento").map((item) => item.variante).sort(), ["Host", "X-Forwarded-Host"]);
  assert.match(of("envenenamiento").find((item) => item.variante === "X-Forwarded-Host")!.senal, /http:\/\/xfh-[0-9a-f]{6}\.orobas\.invalid\/reset\?token=/);
  const hostRequest = lab.requests.find((request) => String(request.headers.host).startsWith("h-"));
  assert.ok(hostRequest, "la cabecera Host inyectada llegó tal cual al laboratorio");
  // Token: el anterior sigue valiendo, se reusa, sirve después de usar el nuevo y es corto y consecutivo.
  const token = of("token").map((item) => item.variante);
  for (const kind of ["vigencia", "reuso", "anterior", "predecible"]) assert.ok(token.includes(kind), `falta la señal de token «${kind}»`);
  assert.match(of("token").filter((item) => item.variante === "predecible").map((item) => item.senal).join(" | "), /código numérico corto|casi consecutivos/);
  assert.match(result.text, /el mail dice: «Vence en 30 minutos»/);
  assert.match(result.text, /la contraseña de .* ahora es Nueva-Prueba-1!/);
  assert.ok((result.details!.peticiones as number) <= 20);
  // A quién se mandó: sólo direcciones de la casilla del operador creadas en esta sesión.
  const own = new Set((lab.db.prepare("select lower(address) a from mail_addresses where session_id='s1'").all() as Array<{ a: string }>).map((row) => row.a));
  for (const request of lab.requests.filter((item) => item.path === "/forgot")) {
    const values = request.body.startsWith("{") ? Object.values(JSON.parse(request.body)).flat().map(String) : [...new URLSearchParams(request.body).values()];
    const found = values.flatMap((value) => value.split(/[\s,]+/)).filter((item) => item.includes("@"));
    assert.ok(found.length);
    for (const address of found) assert.ok(own.has(address.toLowerCase()), `${address} no es una dirección propia`);
  }
  assert.ok([...own].filter((address) => address !== lab.victim.toLowerCase() && address !== lab.attacker.toLowerCase()).every((address) => address.startsWith(lab.attacker.split("@")[0]!.toLowerCase())), "los alias por variante derivan del atacante");
  // La contraseña cambiada de la cuenta de prueba queda para el informe, sin la contraseña.
  const residues = listResidues(lab.db, "s1");
  assert.equal(residues.length, 1);
  assert.equal(residues[0]!.target, lab.victim);
  assert.doesNotMatch(residues[0]!.detail, /Nueva-Prueba/);
});

test("reset_probe: laboratorio seguro sin señales", async (t) => {
  const lab = await setup(t, "seguro");
  const result = await lab.probe.execute({ ...base(lab), victim: lab.victim, attacker: lab.attacker, complete: { url: `${lab.base}/reset-password`, tokenField: "token", passwordField: "password" } }, signal);
  assert.deepEqual(result.details!.senales, [], result.text);
  assert.match(result.text, /el anterior parece invalidado/);
  assert.match(result.text, /B otra vez → 400: rechazado \(bien\)/);
  assert.match(result.text, /la contraseña de .* ahora es Orobas-[0-9a-f]{12}!9/, "sin password, se genera una y se muestra");
});

test("reset_probe: sólo direcciones propias de la sesión; nada sale si la víctima o el atacante no lo son", async (t) => {
  const lab = await setup(t, "vulnerable");
  const run = (params: Record<string, unknown>) => lab.probe.execute({ ...base(lab), ...params }, signal);
  await assert.rejects(() => Promise.resolve(run({ victim: "alguien@empresa.com", attacker: lab.attacker })), /victim tiene que ser una dirección creada con mail_address/);
  await assert.rejects(() => Promise.resolve(run({ victim: lab.victim, attacker: "atacante@otro.com" })), /attacker tiene que ser otra dirección/);
  await assert.rejects(() => Promise.resolve(run({ victim: lab.victim, attacker: lab.victim })), /dos direcciones distintas/);
  await assert.rejects(() => Promise.resolve(run({ victim: lab.victim })), /necesita attacker/);
  await assert.rejects(() => Promise.resolve(run({ victim: lab.victim, attacker: lab.attacker, extraFields: { cc: "tercero@empresa.com" } })), /tercero@empresa\.com, que no es una dirección de prueba/);
  await assert.rejects(() => Promise.resolve(run({ victim: lab.victim, attacker: lab.attacker, headers: { "x-notify": "tercero%40empresa.com" } })), /tercero@empresa\.com/);
  // Una dirección creada en otra sesión del proyecto tampoco vale.
  const [otherAddress] = createMailTools({ db: lab.db, sessionId: "s2", ...lab.mail });
  const other = [...(await otherAddress!.execute({ etiquetas: ["otra"] }, signal)).text.matchAll(/: (\S+@gmail\.com)/g)][0]![1]!;
  await assert.rejects(() => Promise.resolve(run({ victim: other, tests: ["token"] })), /en esta sesión/);
  assert.equal(lab.http.count, 0, "ninguna petición salió");
  assert.equal(lab.inbox.length, 0);
  // Una víctima sin cuenta en el objetivo: el control no trae mail y la sonda corta sin seguir pidiendo.
  const [extra] = createMailTools({ db: lab.db, sessionId: "s1", ...lab.mail });
  const fresh = [...(await extra!.execute({ etiquetas: ["sin-cuenta"] }, signal)).text.matchAll(/: (\S+@gmail\.com)/g)][0]![1]!;
  const none = await run({ victim: fresh, tests: ["token"] });
  assert.match(none.text, /No llegó el mail de control/);
  assert.equal(none.details!.peticiones, 1);
});

test("reset_probe: análisis de tokens sólo mira lo recibido", () => {
  const strong = analyzeTokens([randomBytes(32).toString("hex"), randomBytes(32).toString("hex")], "ana@gmail.com");
  assert.deepEqual(strong.weak, []);
  const weak = analyzeTokens(["482100", "482101"], "ana@gmail.com");
  assert.ok(weak.weak.some((item) => /código numérico corto/.test(item)));
  assert.ok(weak.weak.some((item) => /consecutivos/.test(item)));
  const md5 = analyzeTokens(["8b2d6bfd0d0a0fdda2a3e8e1e3a4b9f8"], "x@y.z");
  assert.deepEqual(md5.weak, []);
  assert.ok(analyzeTokens([createHash("md5").update("ana@gmail.com").digest("hex")], "ana@gmail.com").weak.some((item) => /md5 del correo/.test(item)));
  assert.ok(analyzeTokens(["abc", "abc"], "ana@gmail.com").weak.some((item) => /no se renueva/.test(item)));
});
