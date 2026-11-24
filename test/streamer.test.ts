import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import type { Client, ClientEvent } from "../src/client.ts";
import type { Snapshot } from "../src/daemon.ts";
import type { AssistantMessage } from "../src/llm.ts";
import { parseRule, ScopeStore } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { KeyParser } from "../src/tui/keys.ts";
import { PESTANA_CHAT } from "../src/tui/pestanas.ts";
import { startFoco } from "../src/tui/foco.ts";
import { FuenteOBS } from "../src/tui/obs.ts";
import { Privacidad } from "../src/tui/streamer.ts";
import { pantallaVisible } from "./pantalla-visible.ts";

const cwd = mkdtempSync(join(tmpdir(), "emision-"));
const paths = projectPaths(cwd);
const db = openStore(paths);
const alcance = new ScopeStore(db);
db.exec("create table findings(id text primary key, json text not null)");
alcance.save({ source: "hackerone:demo", notes: "", include: ["*.publico.test", "192.0.2.0/24", "2001:db8::/64", "plaza"].map(v => parseRule(v)), exclude: [] });
alcance.save({ source: "manual", notes: "", include: ["secreto.publico.test", "192.0.2.17", "2001:db8::37", "xn--caf-dma.publico.test", "interno"].map(v => parseRule(v)), exclude: [] });
after(() => db.close());

function privacidad() {
  const p = new Privacidad(paths.db, { USER: "operadora", CYBER_STREAMER_PUBLICOS: "hackerone:demo" });
  p.actualizar();
  assert.ok(p.lista);
  return p;
}

const opaco = "muestra-" + "irrepetible";
const ejemplos = [
  ["clave de API", `API key: ${opaco}`, opaco],
  ["clave sin etiqueta", "clave " + "sk-proj-" + "S".repeat(28), "SSSSSS"],
  ["token", JSON.stringify({ access_token: opaco }), opaco],
  ["cookie", `Recibí Cookie: sesion=${opaco}; otra=valor-de-prueba`, opaco],
  ["autorización", `Authorization: Basic ${opaco}`, opaco],
  ["contraseña", `contraseña: "${opaco} con espacios"`, opaco],
  ["contraseña en prosa", `La contraseña es ${opaco}`, opaco],
  ["contraseña en JSON", JSON.stringify({ contraseña: opaco }), opaco],
  ["token de proveedor", "Lo devolvió " + "glpat-" + "Z".repeat(20), "ZZZZZZ"],
  ["saldo en varias líneas", "Saldo disponible\n41,62", "41,62"],
  ["credenciales en URL", `https://operadora:${opaco}@ejemplo.test/ok`, opaco],
  ["clave privada", `-----BEGIN PRIVATE KEY-----\n${opaco}\n-----END PRIVATE KEY-----`, opaco],
  ["correo", "Escribí a persona+demo@ejemplo.test", "persona"],
  ["usuario del sistema", "Lo leyó operadora ayer", "operadora"],
  ["argumento de credencial", `orden --password "${opaco}"`, opaco],
  ["ruta personal completa", "dato en /home/invitada/carpeta-privada/planes.md", "carpeta-privada"],
  ["ruta personal con espacios", 'archivo "/Users/María Ana/carpeta reservada/informe"', "carpeta reservada"],
  ["ruta Linux", "en /home/invitada/archivo", "invitada"],
  ["ruta de Windows", "en C:\\Users\\invitada\\archivo", "invitada"],
  ["IPv4", "Dirección 192.0.2.17.", "192.0.2.17"],
  ["IPv6", "Usá [2001:db8::37]:443 o 2001:db8::40.", "2001:db8"],
  ["host local sin alcance", "Abrí (http://nombrereservado) o //nombrereservado:8080/inicio", "nombrereservado"],
  ["host del alcance", "Encontré secreto.publico.test e interno", "interno"],
  ["saldo", "Saldo disponible 39,81", "39,81"],
  ["costo", "Pagamos USD 0.9876", "0.9876"],
  ["consumo", "Hay 123456 tokens consumidos", "123456"],
  ["controles y enlace oculto", `\x1b]8;;https://${opaco}.test\x07correo\x1b]8;;\x07 password=${opaco.slice(0, 5)}\x1b[31m${opaco.slice(5)}`, opaco],
];

for (const [nombre, origen, secreto] of ejemplos) test(`streamer tapa ${nombre}`, () => {
  const p = privacidad();
  try { assert.ok(!p.texto(origen!).includes(secreto!)); } finally { p.cerrar(); }
});

test("privados distingue programas, comodines, CIDR y destinos que también figuran en un alcance privado", () => {
  const p = privacidad();
  try {
    const hosts = "plaza uno.publico.test secreto.publico.test 192.0.2.28 192.0.2.17 sin-clasificar.test interno";
    assert.equal(p.texto(hosts), Array(7).fill("[host reservado]").join(" "));
    p.soloPrivados = true;
    assert.equal(p.texto(hosts), "plaza uno.publico.test [host reservado] 192.0.2.28 [host reservado] [host reservado] [host reservado]");
    assert.equal(p.texto("2001:0db8:0:0:0:0:0:0037 café.publico.test 2001:db8::38"), "[host reservado] [host reservado] 2001:db8::38");
    p.mostrarUso = true;
    assert.equal(p.texto("USD 8,65 · 900 tokens"), "USD 8,65 · 900 tokens");
  } finally { p.cerrar(); }
});

test("una edición conserva el origen pero sus destinos nuevos quedan tapados", () => {
  const a = new ScopeStore(db, "privacidad-programa");
  a.save({ source: "hackerone:demo", notes: "", include: [parseRule("*.publico.test")], exclude: [] });
  a.edit({ include: ["edicion.publico.test"], exclude: ["agregado-a-mano"] });
  const p = privacidad();
  try {
    p.soloPrivados = true;
    assert.equal(p.texto("plaza publico.test edicion.publico.test agregado-a-mano"), "plaza [host reservado] [host reservado] [host reservado]");
    assert.equal(p.texto("http://plaza/ http://desconocido/"), "http://plaza/ http://[host reservado]/");
  } finally { p.cerrar(); }
});

test("tapa también una contraseña de símbolos y un token numérico que el modelo repite", () => {
  const p = privacidad();
  try {
    p.aprender(JSON.stringify({ password: "!!??##!!", token: 186542 }));
    assert.equal(p.texto("Devolvió !!??##!! y 186542"), "Devolvió [credencial omitida] y [credencial omitida]");
  } finally { p.cerrar(); }
});

test("F8 responde con los bloqueos del teclado y descarta repeticiones y combinaciones", () => {
  const teclado = new KeyParser();
  for (const [codigo, fin] of [["19","~"], ["57371","u"]]) {
    for (const mod of [1,65,129,193]) {
      teclado.parse("\x1b[200~pendiente");
      assert.deepEqual(teclado.parse(`\x1b[${codigo};${mod}:1${fin}`), [{ name: "f8" }]);
    }
    for (const mod of ["2","130","1:2","129:3"]) assert.deepEqual(teclado.parse(`\x1b[${codigo};${mod}${fin}`), []);
  }
});

test("aprende la cookie y el portador de cabeceras JSON aunque reaparezcan sin etiqueta", () => {
  const p = privacidad();
  try {
    p.aprender(JSON.stringify({ headers: { authorization: "Bearer " + opaco, cookie: "sid=otra-muestra" } }));
    assert.ok(!p.texto(opaco).includes(opaco));
    assert.ok(!p.texto("Valor otra-muestra.").includes("otra-muestra"));
    assert.equal(p.modelo("demo\ndetalle"), "[modelo reservado]");
  } finally { p.cerrar(); }
});

test("un alcance ilegible reserva el contenido", () => {
  const p = new Privacidad(join(cwd, "inexistente"));
  p.actualizar();
  assert.equal(p.texto(opaco), "[contenido reservado]");
  p.cerrar();
});

test("OBS protege archivos existentes, enlaces y transmisiones concurrentes", () => {
  const destino = join(cwd, "archivo.txt");
  const archivo = join(cwd, "fuente.txt");
  writeFileSync(destino, "conservar");
  symlinkSync(destino, join(cwd, "enlace.txt"));
  assert.throws(() => new FuenteOBS(destino));
  assert.throws(() => new FuenteOBS(join(cwd, "enlace.txt")));
  const o = new FuenteOBS(archivo);
  try {
    assert.throws(() => new FuenteOBS(archivo));
    o.mostrar("Preparando respuesta", "modelo-demo", 72, 3);
    assert.equal(readFileSync(archivo, "utf8"), "Tarea: Preparando respuesta\nModelo: modelo-demo\nTiempo: 1 min 12 s\nHallazgos: 3\n");
    o.tapar();
    assert.equal(readFileSync(archivo, "utf8"), "");
  } finally { o.cerrar(); }
  assert.ok(!existsSync(archivo));
  assert.equal(readFileSync(destino, "utf8"), "conservar");
});

const respuesta = (content: string): AssistantMessage => ({ role: "assistant", content, toolCalls: [], stopReason: "stop", provider: "faux", model: "demo", requestId: "r", at: 1 });
test("la TUI protege cada cuadro, conserva el envío al agente y vuelve del pánico sólo con F8", async () => {
  const estado = { running: false, interrupted: false, needsKey: false, notes: 0, model: "faux/demo", session: "demo", usage: "123456 tokens", cost: "USD 19.222" };
  const snap: Snapshot = { sessionId: "demo", project: cwd, model: "faux/demo", resumed: true, projectRequests: 0, partial: "", tools: {}, status: estado,
    messages: [respuesta("Respuesta anterior " + opaco), { role: "user", content: `password=${opaco}`, at: 2 },
      { ...respuesta("Revisé la herramienta"), toolCalls: [{ id: "a", name: "lectura", arguments: "{}" }] },
      { role: "tool", content: `Salida de muestra · Cookie: id=${opaco}`, toolCallId: "a", name: "lectura", at: 3, isError: false }] };
  const antes = JSON.stringify(snap);
  const enviados: string[] = [];
  let emitir = (_e: ClientEvent) => {};
  const tituloPrivado = "Muestra confidencial de abril";
  const fecha = "2026-01-01T12:00:00Z";
  const cliente = { status: estado, on(cb: typeof emitir) { emitir = cb; },
    ask: async (op: string, payload: { action?: string; todos?: boolean }) => {
      if (op !== "sesiones" || payload?.action !== "list") return [];
      const fila = payload.todos ? ["otro", cwd, "Prueba", "sesion-1", fecha, "lista", tituloPrivado]
        : ["sesion-1", "lista", fecha, fecha, "1", "0", "0", "0", "demo", "0", tituloPrivado];
      return [fila.join("\t")];
    }, view: async () => [], send(text: string) { enviados.push(text); } } as unknown as Client;
  let teclas = (_s: string) => {}, ajustar = () => {};
  let salida = "";
  const out = { rows: 32, columns: 60, write(s: string) { salida += s; } };
  const archivo = join(cwd, "obs-tui.txt");
  process.env.CYBER_CONFIG = join(cwd, "ajustes.json");
  writeFileSync(process.env.CYBER_CONFIG, JSON.stringify({ pestanas: [{ ...PESTANA_CHAT, detalle: "completo" }] }));
  const tui = startFoco(cliente, snap, { cwd, streamer: true, obs: "./obs-tui.txt", io: { output: out, listen(k, r) { teclas = k; ajustar = r; return () => {}; } } });
  const ver = () => pantallaVisible(salida, out.columns, out.rows).join("\n");
  try {
    assert.match(ver(), /EN VIVO · modo streamer/);
    assert.match(ver(), /Respuesta anterior/);
    assert.match(ver(), /Salida de muestra/);
    for (const comando of ["/sesiones", "/sesiones todos"]) {
      tui.submit(comando);
      await new Promise<void>(r => setImmediate(r));
      teclas("abril");
      assert.match(ver(), /1\/1/);
      assert.doesNotMatch(ver(), /abril|confidencial/i);
      teclas("\x1b");
      await new Promise<void>(r => setImmediate(r));
    }
    teclas("Texto privado " + opaco);
    teclas("\r");
    assert.deepEqual(enviados, ["Texto privado " + opaco]);
    const completo = `El modelo devuelve ${opaco} en el texto.`;
    emitir({ type: "text", delta: completo.slice(0, 25) });
    ajustar();
    assert.match(ver(), /Escribiendo/);
    assert.ok(!salida.includes(opaco.slice(0, 9)));
    emitir({ type: "text", delta: completo.slice(25) });
    emitir({ type: "message", message: respuesta(completo) });
    ajustar();
    assert.match(ver(), /El modelo devuelve/);
    assert.ok(!salida.includes(opaco));
    assert.ok(!salida.includes("123456") && !salida.includes("19.222"));
    tui.submit("/streamer uso mostrar");
    await Promise.resolve();
    ajustar();
    assert.ok(ver().includes("19.222") && ver().includes("123456"));
    tui.submit("/streamer uso tapar");
    await Promise.resolve();
    assert.ok(!ver().includes("19.222") && !ver().includes("123456"));
    const cortado = "Respuesta cortada glpa";
    emitir({ type: "text", delta: cortado });
    emitir({ type: "message", message: { ...respuesta(cortado), stopReason: "aborted" } });
    ajustar();
    assert.ok(!ver().includes("glpa"));
    db.prepare("insert into findings values(?,?)").run("demo", JSON.stringify({ sessionId: "demo", title: opaco }));
    await new Promise(r => setTimeout(r, 1100));
    const fuente = readFileSync(archivo, "utf8");
    assert.match(fuente, /Hallazgos: 1/);
    assert.ok(!fuente.includes(opaco) && !fuente.includes("19.222"));
    const espera = tui.pick("Menú", ["opción"]);
    teclas("\x1b[19~");
    teclas("oculto\r");
    out.columns = 80;
    emitir({ type: "notice", text: "Aviso secreto" });
    ajustar();
    assert.equal(ver().trim(), "");
    assert.equal(readFileSync(archivo, "utf8"), "");
    teclas("\x1b[19~");
    assert.match(ver(), /Menú/);
    assert.match(readFileSync(archivo, "utf8"), /Modelo: faux\/demo/);
    teclas("\x1b");
    await espera;
    tui.submit("/streamer");
    await Promise.resolve();
    ajustar();
    assert.ok(ver().includes(opaco));
    assert.ok(!ver().includes("EN VIVO"));
    assert.equal(JSON.stringify(snap), antes);
    tui.submit("/streamer");
    await Promise.resolve();
    assert.ok(!ver().includes(opaco));
  } finally { tui.exit(); }
});
