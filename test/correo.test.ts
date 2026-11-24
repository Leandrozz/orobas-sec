import "./datos-tmp.ts";
// Correo de prueba: varias direcciones sobre una casilla, y de cada mail sólo el código y el enlace.
import assert from "node:assert/strict";
import { createServer, connect, type Socket } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { aliasFor, detectHost, digest, fetchFor, guessHost, hostFromMx, type Mailbox, parseMail, testMailbox } from "../src/correo.ts";
import { Engine } from "../src/engine.ts";
import { usdToPico } from "../src/money.ts";
import { resolveProvider } from "../src/providers.ts";

const b64 = (text: string) => Buffer.from(text, "utf8").toString("base64");
const message = (to: string, subject: string, html: string, date = new Date()) =>
  [`From: =?utf-8?B?${b64("Tienda Ñandú")}?= <no-reply@tienda.test>`, `To: ${to}`, `Subject: =?utf-8?B?${b64(subject)}?=`, `Date: ${date.toUTCString()}`, "MIME-Version: 1.0",
    'Content-Type: multipart/alternative; boundary="b1"', "", "--b1", "Content-Type: text/html; charset=utf-8", "Content-Transfer-Encoding: base64", "", b64(html), "--b1--", ""].join("\r\n");

/** Servidor IMAP de mentira: una bandeja, una carpeta de spam, y lo justo del protocolo. */
async function fakeImap(password: string, store: { INBOX: string[]; Spam: string[] }) {
  const log: string[] = [];
  const server = createServer((socket: Socket) => {
    let selected: keyof typeof store = "INBOX";
    let pending = "";
    socket.write("* OK listo\r\n");
    socket.on("data", (chunk) => {
      pending += chunk.toString("latin1");
      for (let end = pending.indexOf("\r\n"); end >= 0; end = pending.indexOf("\r\n")) {
        const line = pending.slice(0, end); pending = pending.slice(end + 2);
        const [tag, ...rest] = line.split(" "); const command = rest.join(" ");
        log.push(command.replace(/LOGIN .*/, "LOGIN …"));
        if (/^LOGIN /i.test(command)) { socket.write(command.includes(`"${password}"`) ? `${tag} OK entró\r\n` : `${tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n`); continue; }
        if (/^LIST /i.test(command)) { socket.write(`* LIST (\\HasNoChildren) "/" "INBOX"\r\n* LIST (\\HasNoChildren \\Junk) "/" "Spam"\r\n${tag} OK\r\n`); continue; }
        const select = /^SELECT "?([^"]+)"?/i.exec(command);
        if (select) { selected = select[1] === "Spam" ? "Spam" : "INBOX"; socket.write(`* ${store[selected].length} EXISTS\r\n${tag} OK [READ-WRITE]\r\n`); continue; }
        const search = /^UID SEARCH SINCE \S+ TO "([^"]+)"/i.exec(command);
        if (search) { const uids = store[selected].flatMap((raw, i) => (raw.toLowerCase().includes(search[1]!.toLowerCase()) ? [i + 1] : [])); socket.write(`* SEARCH${uids.map((u) => ` ${u}`).join("")}\r\n${tag} OK\r\n`); continue; }
        const fetch = /^UID FETCH ([\d,]+) /i.exec(command);
        if (fetch) { for (const uid of fetch[1]!.split(",").map(Number)) { const raw = Buffer.from(store[selected][uid - 1]!, "latin1"); socket.write(`* ${uid} FETCH (UID ${uid} BODY[]<0> {${raw.length}}\r\n`); socket.write(raw); socket.write(")\r\n"); } socket.write(`${tag} OK\r\n`); continue; }
        if (/^LOGOUT/i.test(command)) { socket.end(`* BYE\r\n${tag} OK\r\n`); continue; }
        socket.write(`${tag} BAD\r\n`);
      }
    });
    socket.on("error", () => {});
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as { port: number }).port;
  return { log, connector: () => connect(port, "127.0.0.1"), close: () => server.close() };
}

test("lectura de un mail de verificación: asunto codificado, código y enlace; nada de lo demás", () => {
  const mail = parseMail(Buffer.from(message("ana+comprador-a1b2c@gmail.com", "Tu código de verificación", '<p>Hola,</p><p>Tu código es <b>482913</b>. Vence en 10 minutos.</p><p><a href="https://tienda.test/verify?token=abc&amp;u=7">Confirmar cuenta</a> · <a href="https://tienda.test/unsubscribe">baja</a></p><p>© 2026 Tienda</p>'), "latin1"));
  assert.equal(mail.subject, "Tu código de verificación");
  assert.match(mail.from, /Tienda Ñandú/);
  const info = digest(mail);
  assert.deepEqual(info.codes, ["482913"]);
  assert.deepEqual(info.links, ["https://tienda.test/verify?token=abc&u=7"]);
  assert.equal(guessHost("ana@gmail.com"), "imap.gmail.com");
  assert.match(aliasFor("ana@gmail.com", "Comprador A"), /^ana\+comprador-a-[0-9a-f]{5}@gmail\.com$/);
  assert.match(aliasFor("usuario+x@example.org", "admin"), /^usuario\+x-admin-[0-9a-f]{5}@example\.org$/);
});

test("IMAP: contraseña mala se explica; se lee la bandeja y el spam, sólo lo dirigido a la dirección", async () => {
  const store = { INBOX: [message("ana+uno@gmail.com", "Código 111222", "<p>Tu código: 111222</p>"), message("ana@gmail.com", "Factura personal", "<p>privado</p>")], Spam: [message("ana+dos@gmail.com", "Confirmá tu cuenta", '<a href="https://tienda.test/confirm/zz">Confirmar</a>')] };
  const imap = await fakeImap("clave app", store);
  const box: Mailbox = { direccion: "ana@gmail.com", clave: "clave app", host: "imap.ejemplo.test", puerto: 993 };
  try {
    await assert.rejects(() => testMailbox({ ...box, clave: "otra" }, imap.connector), /rechazó el usuario o la contraseña\. Tiene que ser una contraseña de aplicación/);
    assert.equal(await testMailbox(box, imap.connector), 2);
    const one = await fetchFor(box, "ana+uno@gmail.com", Date.now() - 60_000, imap.connector);
    assert.equal(one.length, 1);
    assert.equal(one[0]!.subject, "Código 111222");
    const two = await fetchFor(box, "ana+dos@gmail.com", Date.now() - 60_000, imap.connector);
    assert.equal(two[0]!.folder, "Spam");
    assert.ok(!imap.log.some((line) => /FETCH/.test(line) && /BODY\[\]/.test(line) && !/PEEK/.test(line)), "no marca los mensajes como leídos");
  } finally { imap.close(); }
});

test("el agente crea varias direcciones y recibe de cada una sólo su código; una dirección ajena no se lee", async () => {
  const store = { INBOX: [] as string[], Spam: [] as string[] };
  const imap = await fakeImap("clave", store);
  const cwd = mkdtempSync(join(tmpdir(), "cyber-correo-"));
  const box: Mailbox = { direccion: "ana@gmail.com", clave: "clave", host: "imap.ejemplo.test", puerto: 993, alias: "ana@wearehackerone.com" };
  const engine = new Engine({ cwd, provider: resolveProvider("faux"), budgetPico: usdToPico("1"), mail: { connector: imap.connector, boxes: () => [box], sleep: async () => {} } });
  const tool = (name: string) => engine.catalog.available.get(name)!;
  const signal = new AbortController().signal;
  try {
    const made = await tool("mail_address").execute({ etiquetas: ["comprador-a", "comprador-b", "admin"] }, signal);
    const addresses = [...made.text.matchAll(/: (\S+@wearehackerone\.com)/g)].map((m) => m[1]!);
    assert.equal(addresses.length, 3, "tres cuentas, tres direcciones, sobre el alias de registro");
    assert.equal(new Set(addresses).size, 3);
    store.INBOX.push(message(addresses[0]!, "Código de verificación", "<p>Tu código de verificación es 700111</p>"), message(addresses[1]!, "Código de verificación", "<p>Tu código de verificación es 700222</p>"), message("ana@gmail.com", "Resumen bancario", "<p>saldo y movimientos</p>"));
    const a = await tool("mail_wait").execute({ direccion: addresses[0], esperaSeg: 0 }, signal);
    assert.match(a.text, /Códigos: 700111/);
    assert.doesNotMatch(a.text, /700222|bancario/);
    const b = await tool("mail_wait").execute({ direccion: addresses[1], esperaSeg: 0 }, signal);
    assert.match(b.text, /Códigos: 700222/);
    assert.match((await tool("mail_wait").execute({ direccion: addresses[2], esperaSeg: 0 }, signal)).text, /Todavía no llegó ningún mail/);
    // La casilla personal no se puede pedir: sólo direcciones que generó la herramienta.
    await assert.rejects(async () => tool("mail_wait").execute({ direccion: "ana@gmail.com", esperaSeg: 0 }, signal), /no la creó mail_address/);
    assert.match((await tool("mail_address").execute({}, signal)).text, /comprador-a: .*\n.*comprador-b|admin/s);
  } finally {
    engine.close();
    imap.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("/correo: agregar prueba la casilla antes de guardarla, admite varias, y quitar la borra", async () => {
  const { Daemon } = await import("../src/daemon.ts");
  const { connectDaemon } = await import("../src/client.ts");
  const { mailMenu } = await import("../src/menu.ts");
  const { mailboxes, saveMailboxes } = await import("../src/correo.ts");
  process.env.CYBER_SECRETS_KEY = Buffer.alloc(32, 7).toString("base64");
  saveMailboxes([]);
  const imap = await fakeImap("abcdefgh", { INBOX: [message("x@y.test", "hola", "<p>x</p>")], Spam: [] });
  const cwd = mkdtempSync(join(tmpdir(), "cyber-correo-menu-"));
  const daemon = new Daemon({ cwd, resolve: () => resolveProvider("faux"), mailConnector: imap.connector });
  await daemon.listen();
  const client = await connectDaemon(cwd, { spawn: false });
  const run = (picks: Array<number | undefined>, answers: Array<string | undefined>) =>
    mailMenu({ ask: (op, payload) => client.ask(op, payload), pick: async () => picks.shift(), askHidden: async () => answers.shift() });
  try {
    await assert.rejects(() => run([0], ["ana@gmail.com", "clave mala", ""]), /rechazó el usuario o la contraseña/);
    assert.equal(mailboxes().length, 0, "una casilla que no abre no se guarda");
    assert.match((await run([0], ["ana@gmail.com", "abcd efgh", "ana@wearehackerone.com"]))[0]!, /la casilla ana@gmail\.com abre \(1 mensajes en la bandeja\) y quedó guardada/);
    await run([0], ["otra@icloud.com", "abcdefgh", ""]);
    assert.deepEqual(mailboxes().map((box) => [box.direccion, box.host, box.alias]), [["ana@gmail.com", "imap.gmail.com", "ana@wearehackerone.com"], ["otra@icloud.com", "imap.mail.me.com", undefined]]);
    assert.match((await client.ask("mail_account", { action: "status" })).join("\n"), /ana@gmail\.com \(se registra como ana@wearehackerone\.com\)/);
    assert.ok(!(await client.ask("mail_account", { action: "status" })).join("\n").includes("abcdefgh"));
    await run([1], []);
    assert.deepEqual(mailboxes().map((box) => box.direccion), ["otra@icloud.com"]);
  } finally {
    client.leave();
    await daemon.close();
    imap.close();
    saveMailboxes([]);
    delete process.env.CYBER_SECRETS_KEY;
    rmSync(cwd, { recursive: true, force: true });
  }
});

test("servidor IMAP: por nombre de dominio, por el MX de un dominio propio (Hostinger, Workspace) o Google si no se sabe", async () => {
  const mx = (map: Record<string, string[]>) => async (domain: string) => {
    if (!map[domain]) throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
    return map[domain]!.map((exchange, i) => ({ exchange, priority: (i + 1) * 5 }));
  };
  const dns = mx({ "propio.test": ["mx1.hostinger.com", "mx2.hostinger.com"], "empresa.test": ["smtp.google.com"], "m365.test": ["empresa-test.mail.protection.outlook.com"], "raro.test": ["mx.raro.test"] });
  assert.equal(await detectHost("yo@propio.test", dns), "imap.hostinger.com");
  assert.equal(await detectHost("yo@empresa.test", dns), "imap.gmail.com");
  assert.equal(await detectHost("yo@m365.test", dns), "outlook.office365.com");
  assert.equal(await detectHost("yo@raro.test", dns), "imap.gmail.com");
  assert.equal(await detectHost("yo@sindns.test", dns), "imap.gmail.com");
  assert.equal(await detectHost("yo@icloud.com", async () => { throw new Error("no debería consultar DNS"); }), "imap.mail.me.com");
  assert.equal(hostFromMx(["ALT1.ASPMX.L.GOOGLE.COM."]), "imap.gmail.com");
  assert.equal(hostFromMx(["mx.notgoogle.com"]), undefined);
});
