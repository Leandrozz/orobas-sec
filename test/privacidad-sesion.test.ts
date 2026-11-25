import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { citaTapada, sendConsent } from "../src/consent.ts";
import { Engine } from "../src/engine.ts";
import { resolveProvider } from "../src/providers.ts";
import { SecretosSesion } from "../src/secretos-sesion.ts";
import { motor, MundoInv } from "./investigar-falso.ts";

for (const herramienta of ["investigation_output", "verdict"]) {
  test(`${herramienta} neutraliza hasta los marcadores desconocidos de claves y listas`, () => {
    const registro = new SecretosSesion({ sal: "prueba" });
    const marca = registro.registrar("DatoFicticio7382", "entorno")!;
    const campos = { nota: [{ [marca]: `dato ${marca} y ‹SECRETO_999›` }] };
    assert.deepEqual(registro.reponer(herramienta, campos).args, { nota: [{ "‹secreto›": "dato ‹secreto› y ‹secreto›" }] });
  });
}

// La cita es parte de las trazas (decisión del 22/11): sale tapada en «compartir»; en «local» y «no» (el modo por defecto
// desde el 25/11), queda en la máquina.
for (const [variable, sale] of [[undefined, false], ["compartir", true], ["local", false], ["no", false]] as const) {
  test(`la cita libre de consentimiento ${sale ? "sale tapada" : "queda en la máquina"} con trazas en ${variable ?? "el modo por defecto"}`, async () => {
    const prev = process.env.CYBER_TRAZAS;
    if (variable === undefined) delete process.env.CYBER_TRAZAS; else process.env.CYBER_TRAZAS = variable;
    try {
      const cita = "Permito la operación en mi cuenta de ejemplo. Frase privada. token=DatoFicticio7382";
      let envio: any, cabecera: string | null = null;
      const recibir: typeof fetch = async (_url, opciones) => {
        envio = JSON.parse(String(opciones?.body));
        cabecera = new Headers(opciones?.headers).get("x-cyber-trazas");
        return new Response(null, { status: 204 });
      };
      await sendConsent("trayectorias", cita, "huella", "fecha", "oro_prueba", recibir, { tapar: (texto) => texto.replace("ejemplo", "‹secreto›") });
      assert.equal(envio.hash, "huella");
      assert.equal(cabecera, variable ?? "no");
      assert.equal(JSON.stringify(envio).includes("Frase privada"), sale);
      assert.ok(!JSON.stringify(envio).includes("DatoFicticio7382"), "un secreto con forma conocida nunca sale");
      if (sale) assert.match(envio.pedido, /mi cuenta de ‹secreto›/, "pasa por el tapado de la sesión");
      else assert.equal(envio.pedido, "Cita conservada por el operador.");
    } finally {
      if (prev === undefined) delete process.env.CYBER_TRAZAS; else process.env.CYBER_TRAZAS = prev;
    }
  });
}

test("el primer pedido ya tapa una credencial declarada en el sistema y repetida sin etiqueta", () => {
  const registro = new SecretosSesion({ sal: "prueba" });
  const valor = "DatoFicticio7382";
  const salida = registro.pedido({
    model: { provider: "faux", baseUrl: "", id: "prueba" },
    system: `Configuración local: password=${valor}`, tools: [],
    messages: [{ role: "user", at: 0, content: `Recibí ${valor}.` }],
  });
  assert.ok(!JSON.stringify(salida).includes(valor));
});

test("la ventana de un artefacto del operador no entrega un pedazo interior del secreto; la de uno del objetivo lo muestra", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "ventana-"));
  const engine = new Engine({ cwd, provider: resolveProvider("faux"), cveFeed: false });
  try {
    const leer = engine.agent.tools.find((tool) => tool.name === "artifact_read")!;
    const valor = "DatoFicticio7382Largo";
    const contenido = JSON.stringify({ token: valor });
    const { hash } = engine.artifacts.put(contenido, "application/json", "shell");
    const resultado = await leer.execute({ hash, at: contenido.indexOf(valor) + 2, chars: 4 }, new AbortController().signal);
    assert.ok(!resultado.text.includes(valor.slice(2, 6)), "salida de la shell local: del operador");
    // Un intercambio HTTP guardado es material del objetivo: el modelo lo lee tal cual.
    const delObjetivo = JSON.stringify({ token: "OtroDatoDelObjetivo4471" });
    const http = engine.artifacts.put(delObjetivo, "application/json", "http");
    const visto = await leer.execute({ hash: http.hash, search: "token" }, new AbortController().signal);
    assert.match(visto.text, /OtroDatoDelObjetivo4471/);
    assert.equal(engine.secretos.vistaTrazas(visto.text, "local").includes("OtroDatoDelObjetivo4471"), false, "en trazas, tapado");
  } finally { await engine.close(); }
});

test("una respuesta larga se aprende antes de perder el campo que declara el secreto", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "respuesta-"));
  const engine = new Engine({ cwd, provider: resolveProvider("faux"), cveFeed: false });
  try {
    const valor = "DatoFicticio7382";
    const texto = `eco ${valor}\n${" ".repeat(9000)}\npassword=${valor}`;
    const tool = engine.bounded({ name: "lectura", label: "Lectura", description: "", parameters: {}, execute: () => ({ text: texto }) });
    const vista = await tool.execute({}, new AbortController().signal);
    assert.ok(!vista.text.includes(valor));
  } finally { await engine.close(); }
});

test("una contraseña declarada en castellano queda tapada desde el primer mensaje, para el modelo y en trazas", () => {
  const s = new SecretosSesion({ sal: "prueba" });
  const valor = "lince71";
  assert.ok(!s.vistaModelo(`Mi contraseña es ${valor}. La repito: ${valor}.`, "operador").includes(valor));
  assert.ok(!s.vistaTrazas(`La repito: ${valor}.`, "modelo").includes(valor));
});

// Regla del 22/11 (decisiones de Lean y auditoría del #39): un secreto del operador no tiene permiso por origen
// exacto. Su marcador se repone en toda herramienta que actúa contra el alcance, hacia cualquier destino del
// alcance; fuera del alcance, la herramienta no lo recibe (la shell y los escáneres por los destinos que nombran;
// el cliente HTTP, salto por salto). Estas cuatro pruebas reemplazan a las que fijaban la regla de cd28e98 y
// 1c3d9f9 (permiso por el origen del primer registro e ids opacos tapados sin etiqueta).
const ALCANCE = new Set(["uno.example", "dos.example"]);
const enAlcance = (destino: string) => {
  try { return ALCANCE.has(/^[a-z]+:\/\//i.test(destino) ? new URL(destino).hostname : destino); } catch { return false; }
};

test("un marcador del operador vale en cualquier destino del alcance y en toda herramienta que actúa contra él; fuera del alcance, no", () => {
  const s = new SecretosSesion({ sal: "prueba", enAlcance });
  const origen = "https://uno.example";
  const otro = "https://dos.example";
  const valor = "DatoFicticio7382";
  const marca = s.registrar(valor, "identidad", origen)!;
  s.registrar(valor, "objetivo", otro);
  assert.equal(s.claseDelValor(valor), "operador", "un eco del objetivo no lo destapa");
  // El cliente HTTP: cualquier host, puerto o esquema del alcance, con redirecciones, cabecera Host o identidad
  // (cada salto y la cabecera los controla el cliente contra el alcance, no el registro).
  for (const url of [otro, origen + ":444", origen.replace("https:", "http:")]) {
    assert.equal(s.reponer("http_request", { url, headers: { authorization: marca } }).args.headers.authorization, valor, url);
  }
  for (const extra of [{ followRedirects: true }, { headers: { Host: "dos.example", cookie: marca } }, { identity: "otra" }]) {
    assert.equal(s.reponer("http_request", { url: origen, body: marca, ...extra }).args.body, valor, JSON.stringify(extra));
  }
  // La shell y los escáneres externos: con todos los destinos de la llamada en el alcance, sí; con uno afuera, no.
  assert.match(s.reponer("shell", { command: `curl -H 'Cookie: s=${marca}' ${otro}/x` }).args.command, new RegExp(valor));
  assert.deepEqual(s.reponer("nuclei_scan", { targets: [origen, otro], headers: [`Cookie: s=${marca}`] }).args.headers, [`Cookie: s=${valor}`]);
  assert.throws(() => s.reponer("shell", { command: `curl -H 'Cookie: s=${marca}' https://tres.example/x` }), /Fuera del alcance: https:\/\/tres\.example/);
  assert.throws(() => s.reponer("katana_crawl", { url: "https://tres.example/", headers: [`Cookie: s=${marca}`] }), /Fuera del alcance/);
  // Lo que no actúa contra el alcance no recibe el valor.
  assert.throws(() => s.reponer("otra_herramienta", { url: origen, texto: marca }), /no ejecuta contra el alcance/);
});

test("una clave del entorno no va a ningún objetivo aunque el objetivo la refleje; un número de antes de las clases se repone hacia el alcance", () => {
  const valor = "DatoFicticio7382";
  const origen = "https://uno.example";
  const anteriores = new Map<string, number>();
  const primero = new SecretosSesion({ sal: "prueba", enAlcance, guardar: (n, huella) => anteriores.set(huella, n) });
  const marca = primero.registrar(valor, "entorno")!;
  primero.registrar(valor, "objetivo", origen);
  assert.throws(() => primero.reponer("http_request", { url: origen, body: marca }), /clave del servicio o de un proveedor/);
  const viejo = primero.registrar("TokenDeAntes-5521qq", "local")!;
  // Retomada como una sesión de antes de las clases (sin la clase guardada): el entorno se vuelve a consultar y
  // sigue sin salir; lo demás que ya estaba tapado sigue tapado y vale en el alcance.
  const retomado = new SecretosSesion({ sal: "prueba", enAlcance, previas: anteriores, fuentes: [() => [{ valor, origen: "entorno" as const }]] });
  retomado.sincronizar();
  retomado.registrar(valor, "objetivo", origen);
  retomado.registrar("TokenDeAntes-5521qq", "objetivo", origen);
  assert.equal(retomado.ocultar("TokenDeAntes-5521qq", "modelo"), viejo, "lo que ya salió tapado no se destapa al retomar");
  assert.throws(() => retomado.reponer("http_request", { url: origen, body: marca }), /clave del servicio o de un proveedor/);
  assert.equal(retomado.reponer("http_request", { url: "https://dos.example/x", body: viejo }).args.body, "TokenDeAntes-5521qq");
  assert.throws(() => retomado.reponer("shell", { command: `curl -d t=${viejo} https://tres.example/` }), /Fuera del alcance/);
});

test("una identidad propuesta (HAR, Chrome) espera la aprobación; aprobada, vale en cualquier destino del alcance como las demás", async () => {
  const engine = new Engine({ cwd: mkdtempSync(join(tmpdir(), "permiso-")), provider: resolveProvider("faux"), cveFeed: false });
  try {
    engine.scope.edit({ include: ["uno.example", "dos.example"] });
    const valor = "DatoDePermiso7139";
    const nombre = engine.http.proposeIdentity({ name: "ejemplo", headers: { authorization: `Bearer ${valor}` } }, "https://dos.example");
    engine.secretos.sincronizar();
    const marca = engine.secretos.ocultar(valor, "modelo");
    assert.match(marca, /^‹SECRETO_\d+›$/, "tapada para el modelo desde que se propuso");
    const args = { url: "https://dos.example/v1/me", headers: { authorization: `Bearer ${marca}` } };
    assert.throws(() => engine.secretos.reponer("http_request", args), /todavía no aprobó/);
    assert.throws(() => engine.secretos.reponer("shell", { command: `curl -H 'Authorization: Bearer ${marca}' https://dos.example/` }), /todavía no aprobó/);
    engine.http.approveIdentity(nombre);
    engine.secretos.sincronizar();
    assert.equal(engine.secretos.reponer("http_request", args).args.headers.authorization, `Bearer ${valor}`);
    assert.equal(engine.secretos.reponer("http_request", { ...args, url: "https://uno.example/otra" }).args.headers.authorization, `Bearer ${valor}`, "otro host del alcance");
    assert.match(engine.secretos.reponer("shell", { command: `curl -H 'Authorization: Bearer ${marca}' https://uno.example/` }).args.command, new RegExp(valor));
    assert.throws(() => engine.secretos.reponer("shell", { command: `curl -H 'Authorization: Bearer ${marca}' https://tres.example/` }), /Fuera del alcance/);
    // Otra credencial que el operador carga directamente: lo mismo, sin aprobación.
    const otra = engine.secretos.registrar("SegundaPrueba7139", "identidad", "https://uno.example")!;
    assert.equal(engine.secretos.reponer("http_request", { url: "https://dos.example/", body: otra }).args.body, "SegundaPrueba7139");
  } finally { await engine.close(); }
});

test("un id opaco sin etiqueta no se tapa (el IDOR se puede probar); si después una fuente lo nombra credencial, se tapa desde ahí según su clase", () => {
  const s = new SecretosSesion({ sal: "prueba" });
  const dato = "rW8sY9H4kLm3PqV5tJx2";
  const primero = s.vistaModelo(`La shell imprimió «${dato}».`, "local");
  assert.ok(primero.includes(dato), "sin etiqueta no es una credencial");
  assert.ok(s.vistaTrazas(`La shell imprimió «${dato}».`, "local").includes(dato), "tampoco en trazas");
  // La shell local lo nombra como contraseña: es del operador, tapado en las dos vistas desde ahora.
  s.vistaModelo(`password=${dato}`, "local");
  assert.equal(s.vistaModelo(`La shell imprimió «${dato}».`, "local"), "La shell imprimió «‹SECRETO_1›».");
  // El mismo tipo de valor en una respuesta del objetivo, con etiqueta: el modelo lo ve; la traza, no.
  const delObjetivo = "Qz7vN2xK9mP4tR8wY3bL";
  assert.ok(s.vistaModelo(`{"session":"${delObjetivo}"} y de nuevo ${delObjetivo}`, "objetivo").includes(delObjetivo));
  assert.ok(!s.vistaTrazas(`El servicio respondió «${delObjetivo}».`, "objetivo").includes(delObjetivo));
  // Y sin etiqueta, del objetivo: a la vista en las dos (un id de pedido no es un secreto).
  const id = "V1StGXR8_Z5jdHi6B-myT";
  assert.ok(s.vistaModelo(`{"orders":[{"id":"${id}"}]}`, "objetivo").includes(id));
  assert.ok(s.vistaTrazas(`{"orders":[{"id":"${id}"}]}`, "objetivo").includes(id));
});

test("la cita de un consentimiento sale con la vista de trazas: tapa lo del operador y también lo que la sesión vio del objetivo", () => {
  const s = new SecretosSesion({ sal: "prueba" });
  s.registrar("ClaveDelOperador-6611", "identidad");
  s.aprender('{"access_token":"TokenDelObjetivo-2290ab"}', "objetivo");
  const cita = citaTapada("Autorizo borrar el recurso creado con TokenDelObjetivo-2290ab y la cuenta ClaveDelOperador-6611.", (texto) => s.vistaTrazas(texto, "operador"));
  assert.ok(!cita.includes("TokenDelObjetivo-2290ab") && !cita.includes("ClaveDelOperador-6611"), cita);
  assert.match(cita, /‹SECRETO_2› y la cuenta ‹SECRETO_1›/);
});

test("el veredicto persistido y su transcripción neutralizan el número del marcador", async () => {
  const mundo = new MundoInv();
  mundo.verificador = (paso) => paso === 0
    ? { toolCalls: [{ name: "verdict", arguments: { state: "candidato", reason: "Dato omitido ‹SECRETO_77›." } }] }
    : { text: "Listo." };
  const { engine } = motor(mundo, { caja: false });
  try {
    const evidencia = engine.artifacts.put("Nota de prueba", "text/plain", "prueba");
    const hallazgo = engine.findings.record({ title: "Observación de prueba", kind: "observación", asset: "https://uno.example", summary: "Sin confirmar.", evidence: [evidencia.hash] }, engine.sessionId);
    const resultado = await engine.verifier.verify(hallazgo.id);
    // Desde #41 el motivo lleva además las comprobaciones del verificador.
    assert.match(resultado.reason, /^Dato omitido ‹secreto›\.\nComprobaciones: /);
    assert.doesNotMatch(resultado.reason, /‹SECRETO_77›/);
    assert.doesNotMatch(engine.artifacts.read(resultado.transcript).toString(), /‹SECRETO_77›/);
  } finally { await engine.close(); }
});

test("el mapa guardado por investigation_output y su transcripción pierden el marcador", async () => {
  const mundo = new MundoInv();
  mundo.tramo = ({ estado, paso }) => {
    if (paso) return { text: "Listo." };
    const args = estado === "analista" ? { mapa: "Dato omitido ‹SECRETO_77›.", puntos_entrada: ["nota"], resumen: "Mapa." }
      : estado === "hipotesis" ? { hipotesis: [], resumen: "Sin hipótesis." }
      : { titulo: "Cierre", informe: "Fin.", resumen: "Fin." };
    return { toolCalls: [{ name: "investigation_output", arguments: args }] };
  };
  const { engine } = motor(mundo, { caja: false });
  try {
    await engine.investigar!.comando("Revisar la nota 5");
    await engine.investigar!.esperar();
    const { p, diario } = engine.investigar!.todas()[0]!;
    assert.match(engine.artifacts.read(p.mapa!).toString(), /Dato omitido ‹secreto›/);
    const transcripcion = diario.leer().find((fila) => fila.tipo === "artefacto" && fila.estado === "analista" && fila.clase === "transcripcion");
    assert.ok(transcripcion?.tipo === "artefacto");
    assert.doesNotMatch(engine.artifacts.read(transcripcion.hash).toString(), /‹SECRETO_77›/);
  } finally { await engine.close(); }
});
