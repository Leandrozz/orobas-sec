import "./datos-tmp.ts";
// Secretos de la sesión en dos clases (decisión de Lean del 22/11): los del operador no le llegan a nadie; el
// material del objetivo lo ve el modelo tal cual, y en las trazas (turnos, trayectorias, llamadas locales) va
// tapado igual que los del operador.
//
// Prueba del canario, de punta a punta y con los dos transportes reales (Chat Completions y Anthropic
// Messages) contra un proveedor de mentira que guarda cada cuerpo tal como le llega. Canarios del operador: en
// una identidad suya, en el chat, en el almacén cifrado y en el entorno (el objetivo los refleja, y aun así no
// salen). Canarios del objetivo: el token que entrega y la cookie que fija. Los del objetivo tienen que llegar al
// modelo (los usa tal cual) y no aparecer en ninguna traza; los del operador, en ningún lado.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { anthropicMessages, openAICompletions, type Transport } from "../src/llm.ts";
import { usdToPico } from "../src/money.ts";
import { deleteSecret, forgetKey, writeSecret } from "../src/secretos.ts";
import { projectPaths } from "../src/store.ts";
import { bloques, type Cerebro, escuchar, type Formato, esperar, noModelo, proveedor, resultados, sinCanarios as sinLos, trazasLocales } from "./secretos-falsos.ts";

// Inventados: reconocibles, con letras y dígitos, y cada uno en un lugar distinto.
/** Del operador: no salen nunca, ni al modelo ni en trazas. */
const DEL_OPERADOR = {
  identidad: "CanarioIdentidad7Q2xZ9pL4mW8",
  operador: "CanarioOperador8F3gH6jK2lZ7x",
  // Con comilla y barra: en la salida de la herramienta llega escapado, y en el cuerpo, escapado dos veces (PR #33).
  almacen: 'Canario"Almacen\\4X9cV2bN7mQ1w',
  entorno: "CanarioEntorno6A1sD8fG3hJ5k",
  otraIdentidad: "CanarioOtraIdentidad9Z8Y7X6W",
};
/**
 * Del objetivo: el modelo los ve; las trazas, no. `opaco` no tiene forma de credencial que reconozca el tachado
 * por formato de las trazas (redactSecrets): llega en un campo «sid» y el modelo lo cita en prosa en su texto
 * final. Sólo lo tapa el registro de la sesión, por procedencia; si el turno o la trayectoria usaran la vista del
 * modelo, saldría (el token en «access_token» no alcanza para detectarlo: ese campo lo tapa el formato).
 */
const DEL_OBJETIVO = {
  salida: "CanarioSalida3K8vB1nR6tY0aH5",
  cookie: "CanarioCookie5J2wE7uI9oP1sD4",
  opaco: "CanarioOpacoSid4Rt7Yu1Io9Pw",
};
const CANARIO = { ...DEL_OPERADOR, ...DEL_OBJETIVO };
const sinCanarios = (cuerpos: Array<{ url: string; body: string }>, canarios: Record<string, string> = CANARIO) => sinLos(cuerpos, canarios);

/** El objetivo: /perfil pide la cookie de la identidad y entrega un token; /admin sólo abre con ese token. */
function objetivo() {
  const admin: string[] = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      if (req.url === "/perfil") {
        if (!String(req.headers.cookie ?? "").includes(`sid=${CANARIO.identidad}`)) return res.writeHead(401).end("sin sesión");
        res.writeHead(200, { "content-type": "application/json", "set-cookie": `refresh=${CANARIO.cookie}; Path=/; HttpOnly` });
        // El objetivo refleja además valores que no le corresponden (el del almacén y el del entorno): igual no salen.
        return res.end(JSON.stringify({ usuario: "ana", access_token: CANARIO.salida, sid: CANARIO.opaco, nota: `eco ${CANARIO.almacen} y ${CANARIO.entorno}` }));
      }
      if (req.url === "/admin") {
        admin.push(String(req.headers.authorization ?? ""));
        if (req.headers.authorization !== `Bearer ${CANARIO.salida}`) return res.writeHead(403).end("prohibido");
        return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ panel: "admin", bienvenida: "acceso concedido" }));
      }
      res.writeHead(404).end();
    });
  });
  return { server, admin };
}

const tokenEn = (texto: string) => /"access_token"\s*:\s*"((?:\\.|[^"\\])*)"/.exec(texto)?.[1] ?? "no-lo-vi";
const sidEn = (texto: string) => /"sid"\s*:\s*"((?:\\.|[^"\\])*)"/.exec(texto)?.[1] ?? "no-lo-vi";

/**
 * El «modelo» del canario: copia lo que ve, como haría uno de verdad. Con el token a la vista lo usaría tal
 * cual; con un marcador, usa el marcador. Al cerrar cita en prosa el token y la sesión que vio.
 */
const canario: Cerebro = (body, formato, base) => {
  const vistos = resultados(body, formato);
  if (vistos.length === 0) return { llamada: { name: "http_request", args: { url: `${base}/perfil`, identity: "panel" } } };
  if (vistos.length === 1) return { llamada: { name: "http_request", args: { url: `${base}/admin`, headers: { authorization: `Bearer ${tokenEn(vistos[0]!)}` } } } };
  return { texto: `Entré al panel de administración con el token ${tokenEn(vistos[0]!)} de /perfil; la sesión era ${sidEn(vistos[0]!)}.` };
};

async function sesion(formato: Formato, cerebro: Cerebro = canario) {
  const target = objetivo();
  const base = await escuchar(target.server);
  const svc = proveedor(formato, () => base, cerebro);
  const svcBase = `${await escuchar(svc.server)}/v1`;
  const dir = mkdtempSync(join(tmpdir(), "cyber-canario-"));
  const prev = { config: process.env.CYBER_CONFIG, key: process.env.OROBAS_API_KEY, llave: process.env.CYBER_SECRETS_KEY, trazas: process.env.CYBER_TRAZAS };
  // Cualquier modelo «orobas/…» que el motor resuelva (fuerte, alternativa) va al servicio de mentira, nunca afuera.
  writeFileSync(join(dir, "config.json"), JSON.stringify({ providers: { orobas: { baseUrl: svcBase, apiKeyEnv: "OROBAS_API_KEY" } } }));
  process.env.CYBER_CONFIG = join(dir, "config.json");
  process.env.OROBAS_API_KEY = "oro_prueba_canario_1";
  process.env.CYBER_CANARIO_API_TOKEN = CANARIO.entorno;
  // Llave del almacén de prueba: el test no toca el llavero real.
  process.env.CYBER_SECRETS_KEY = Buffer.alloc(32, 9).toString("base64");
  delete process.env.CYBER_TRAZAS;
  forgetKey();
  writeSecret("bugcrowd", CANARIO.almacen);
  const transport: Transport = formato === "openai" ? openAICompletions : anthropicMessages;
  const provider = { model: { provider: "orobas", id: "canario", baseUrl: svcBase, apiKeyEnv: "OROBAS_API_KEY" }, transport, account: "OROBAS_API_KEY" };
  const abiertos: Engine[] = [];
  /** Abre el motor (o retoma la sesión) con la identidad del operador cargada: el modelo la usa por su nombre y nunca ve el valor. */
  const abrir = (resume?: string) => {
    const engine = new Engine({ cwd: join(dir, "proyecto"), provider, budgetPico: usdToPico("5"), coverageObjections: 0, closingGate: false, autoVerify: false, router: "fijo", cveFeed: false, retryBaseMs: 1, ...(resume && { resume }) });
    if (!resume) engine.scope.edit({ include: ["127.0.0.1"] });
    engine.http.setIdentity({ name: "panel", headers: { cookie: `sid=${CANARIO.identidad}; lang=es` } });
    abiertos.push(engine);
    return engine;
  };
  const cerrar = async () => {
    for (const engine of abiertos) await engine.close();
    target.server.close();
    svc.server.closeAllConnections();
    svc.server.close();
    deleteSecret("bugcrowd");
    delete process.env.CYBER_CANARIO_API_TOKEN;
    for (const [name, value] of [["CYBER_CONFIG", prev.config], ["OROBAS_API_KEY", prev.key], ["CYBER_SECRETS_KEY", prev.llave], ["CYBER_TRAZAS", prev.trazas]] as const) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
    forgetKey();
    rmSync(dir, { recursive: true, force: true });
  };
  return { abrir, target, svc, base, cerrar, trazasDir: projectPaths(join(dir, "proyecto")).trazas };
}

for (const formato of ["openai", "anthropic"] as const) {
  test(`canario (${formato}): el modelo ve lo del objetivo y nunca lo del operador; las trazas no llevan ninguno`, async () => {
    const { abrir, target, svc, cerrar } = await sesion(formato);
    try {
      const engine = abrir();
      await engine.send(`Probá el panel. Si te pide la contraseña, es password=${CANARIO.operador}`);
      await esperar(() => svc.cuerpos.some((item) => item.url.endsWith("/traces")));
      await engine.close();
      await esperar(() => svc.cuerpos.some((item) => item.url.endsWith("/trayectorias")));

      const modelo = svc.modelo();
      assert.equal(modelo.length, 3, "tres pedidos al modelo: /perfil, /admin y el cierre");
      // Lo del operador no le llega a nadie: ni al modelo ni al servicio.
      sinCanarios(svc.cuerpos, DEL_OPERADOR);
      // Lo del objetivo llega al modelo tal cual, desde que apareció: el token en el cuerpo y la cookie que fijó.
      assert.ok(!modelo[0]!.body.includes(CANARIO.salida), "antes de /perfil el modelo no lo conocía");
      for (const pedido of modelo.slice(1)) {
        assert.ok(pedido.body.includes(CANARIO.salida), "el token que entregó el objetivo, a la vista");
        assert.ok(pedido.body.includes(CANARIO.cookie), "la cookie que fijó el objetivo, a la vista");
        assert.ok(pedido.body.includes(CANARIO.opaco), "la sesión sin forma de credencial, a la vista");
      }
      // Las trazas no llevan ninguno: ni el turno (/traces) ni la trayectoria (/trayectorias).
      const trazas = noModelo(svc.cuerpos);
      assert.ok(trazas.some((item) => item.url.endsWith("/traces")), "el registro del turno llegó al servicio propio");
      assert.ok(trazas.some((item) => item.url.endsWith("/trayectorias")), "y la trayectoria de la sesión");
      sinCanarios(trazas);
      assert.match(trazas.find((item) => item.url.endsWith("/trayectorias"))!.body, /‹SECRETO_\d+›/, "en la trayectoria el token del objetivo va como marcador");
      // El texto final del modelo cita en prosa el token y la sesión. En el turno y en la trayectoria la sesión va con
      // marcador: ni el tachado por formato ni el de la trayectoria la reconocen (no tiene forma de credencial); sólo
      // el registro, por procedencia. Si el turno o la trayectoria usaran la vista del modelo, esto falla (y también
      // sinCanarios, con el canario opaco). El token, además, lo tapa la trayectoria por su cuenta.
      for (const destino of ["/traces", "/trayectorias"]) {
        assert.match(trazas.find((item) => item.url.endsWith(destino))!.body, /con el token (?:‹SECRETO_\d+›|\[credencial omitida\]) de \/perfil; la sesión era ‹SECRETO_\d+›/, destino);
      }
      // El gateway guarda en «compartir» el pedido entero: el que trae material del objetivo a la vista pide que no.
      assert.deepEqual(modelo.map((pedido) => pedido.trazas), ["compartir", "no", "no"]);
      assert.ok(trazas.every((item) => item.trazas === "compartir"), JSON.stringify(trazas.map((item) => [item.url, item.trazas])));

      // La herramienta se ejecutó con el valor real: el modelo lo copió tal cual lo vio, sin reposición.
      assert.deepEqual(target.admin, [`Bearer ${CANARIO.salida}`], "/admin recibió el token real");
      const ultima = engine.agent.messages.filter((m) => m.role === "tool").at(-1);
      assert.ok(ultima && ultima.role === "tool" && /HTTP 200/.test(ultima.content) && /acceso concedido/.test(ultima.content), `la llamada a /admin funcionó: ${ultima?.role === "tool" ? ultima.content.slice(0, 200) : "sin resultado"}`);

      // Lo del operador viaja como marcador (la contraseña del chat y los reflejos del almacén y del entorno), y
      // lo que no es secreto sigue a la vista.
      const segundo = modelo[1]!.body;
      assert.match(segundo, /‹SECRETO_\d+›/, "el modelo recibe marcadores en lugar de los secretos del operador");
      assert.match(segundo, /127\.0\.0\.1/, "el objetivo no se tacha");
      assert.match(segundo, /"usuario\\?"\s*:\s*\\?"ana/, "los datos que no son secretos siguen a la vista");
    } finally {
      await cerrar();
    }
  });

  test(`canario en modo local (${formato}): el pedido lleva lo del objetivo; llamadas, turnos y trayectoria en disco, no`, async () => {
    const { abrir, target, svc, cerrar, trazasDir } = await sesion(formato);
    try {
      process.env.CYBER_TRAZAS = "local";
      const engine = abrir();
      await engine.send(`Probá el panel. Si te pide la contraseña, es password=${CANARIO.operador}`);
      await engine.close();
      assert.deepEqual(target.admin, [`Bearer ${CANARIO.salida}`]);
      const modelo = svc.modelo();
      sinCanarios(modelo, DEL_OPERADOR);
      assert.ok(modelo.slice(1).every((pedido) => pedido.body.includes(CANARIO.salida)), "el modelo vio el token del objetivo");
      assert.ok(modelo.every((pedido) => pedido.trazas === "local"));
      assert.deepEqual(noModelo(svc.cuerpos).filter((item) => /\/(traces|trayectorias|consent)$/.test(item.url)), [], "en local no sale contenido");
      const disco = trazasLocales(trazasDir);
      for (const archivo of ["llamadas.jsonl", "turnos.jsonl"]) assert.ok(disco.some((item) => item.url === archivo), archivo);
      assert.ok(disco.some((item) => item.url.startsWith("trayectorias")), "la trayectoria de la sesión");
      sinCanarios(disco);
      const llamadas = disco.find((item) => item.url === "llamadas.jsonl")!.body;
      assert.match(llamadas, /‹SECRETO_\d+›/, "el pedido anotado lleva marcadores en lugar del token");
    } finally {
      await cerrar();
    }
  });

  test(`caché de prefijo (${formato}): lo que ya salió sale idéntico en cada pedido siguiente, también al retomar la sesión`, async () => {
    // Tres turnos: /perfil, /admin con el token que vio y, ya retomada la sesión, /admin otra vez con el mismo token.
    const cerebro: Cerebro = (body, f, base) => {
      const todo = bloques(body, f);
      const ultimo = todo.at(-1)!;
      if (ultimo.type === "tool_result") return { texto: `Listo (${todo.filter((b) => b.type === "tool_result").length}).` };
      const operador = todo.filter((b) => b.role === "user" && b.type === "text").length;
      if (operador === 1) return { llamada: { name: "http_request", args: { url: `${base}/perfil`, identity: "panel" } } };
      if (operador === 2) return { llamada: { name: "http_request", args: { url: `${base}/admin`, headers: { authorization: `Bearer ${tokenEn(resultados(body, f)[0]!)}` } } } };
      // Retomada: copia la llamada anterior tal cual la ve en la historia.
      const anterior = todo.filter((b) => b.type === "tool_use").at(-1)!.text;
      const token = /Bearer ([^"\\]+)/.exec(anterior)?.[1] ?? "sin-token";
      return { llamada: { name: "http_request", args: { url: `${base}/admin`, headers: { authorization: `Bearer ${token}` } } } };
    };
    const { abrir, target, svc, cerrar } = await sesion(formato, cerebro);
    try {
      const engine = abrir();
      await engine.send("Probá el panel.");
      await engine.send("Ahora entrá a admin con lo que viste.");
      await engine.close();
      const retomado = abrir(engine.sessionId);
      // Al retomar llega primero un secreto nuevo del operador: sin las huellas guardadas se quedaría con el número del token.
      retomado.http.setIdentity({ name: "otra", headers: { authorization: `Bearer ${CANARIO.otraIdentidad}` } });
      await retomado.send("Entrá a admin otra vez.");
      await retomado.close();

      const modelo = svc.modelo().map((item) => JSON.parse(item.body));
      assert.equal(modelo.length, 6, "dos pedidos por turno");
      sinCanarios(svc.cuerpos, DEL_OPERADOR);
      sinCanarios(noModelo(svc.cuerpos));
      assert.deepEqual(target.admin, [`Bearer ${CANARIO.salida}`, `Bearer ${CANARIO.salida}`], "/admin recibió el token real antes y después de retomar");
      // Los puntos de caché de Anthropic (src/prefijo.ts) van en el último bloque de cada pedido, así que se corren:
      // la marca no es parte del prefijo cacheado y se compara sin ella. Sí se exige que estén donde corresponde.
      const sinMarca = (valor: unknown) => JSON.stringify(valor, (clave, v) => (clave === "cache_control" ? undefined : v));
      for (let i = 1; i < modelo.length; i++) {
        const antes = bloques(modelo[i - 1], formato).map((b) => sinMarca(JSON.parse(b.raw)));
        const ahora = bloques(modelo[i], formato).map((b) => sinMarca(JSON.parse(b.raw)));
        assert.deepEqual(ahora.slice(0, antes.length), antes, `el pedido ${i + 1} repite byte por byte lo que mandó el ${i}${i === 4 ? " (el primero después de retomar)" : ""}`);
        assert.equal(JSON.stringify(modelo[i].tools), JSON.stringify(modelo[i - 1].tools));
        if (formato === "anthropic") assert.equal(sinMarca(modelo[i].system), sinMarca(modelo[i - 1].system));
      }
      if (formato === "anthropic") {
        for (const pedido of modelo) {
          assert.deepEqual(pedido.system.at(-1).cache_control, { type: "ephemeral" }, "punto de caché al final del sistema");
          assert.deepEqual(pedido.messages.at(-1).content.at(-1).cache_control, { type: "ephemeral" }, "punto de caché en el último bloque");
          assert.equal(JSON.stringify(pedido).split('"cache_control"').length - 1, 2, "dos puntos de caché por pedido");
        }
      }
      // El token del objetivo va a la vista en la respuesta, en la llamada del turno 2 y en la del turno retomado.
      const cuerpos = svc.modelo().map((item) => item.body);
      assert.ok(cuerpos.slice(1).every((cuerpo) => cuerpo.includes(CANARIO.salida)), "a la vista desde que apareció, también al retomar");
      assert.ok(!cuerpos.some((cuerpo) => /Bearer ‹SECRETO_/.test(cuerpo)), "nunca como marcador");
    } finally {
      await cerrar();
    }
  });
}

test("un marcador que no es de la sesión no llega al objetivo: la herramienta no se ejecuta y el modelo sabe por qué", async () => {
  const cerebro: Cerebro = (body, f, base) => (resultados(body, f).length ? { texto: "Entendido." } : { llamada: { name: "http_request", args: { url: `${base}/admin`, headers: { authorization: "Bearer ‹SECRETO_999›" } } } });
  const { abrir, target, cerrar } = await sesion("openai", cerebro);
  try {
    const engine = abrir();
    await engine.send("Probá admin.");
    assert.deepEqual(target.admin, [], "no salió ninguna petición con un marcador inventado");
    const resultado = engine.agent.messages.find((m) => m.role === "tool");
    assert.ok(resultado?.role === "tool" && resultado.isError && /‹SECRETO_999› no es un marcador/.test(resultado.content), resultado?.role === "tool" ? resultado.content : "sin resultado");
  } finally {
    await cerrar();
  }
});

test("memoria: lo del objetivo queda como el modelo lo vio; un marcador del operador queda «‹secreto›», ni el valor ni el número", async () => {
  const cerebro: Cerebro = (body, f, base) => {
    const vistos = resultados(body, f);
    if (vistos.length === 0) return { llamada: { name: "http_request", args: { url: `${base}/perfil`, identity: "panel" } } };
    if (vistos.length === 1) {
      const marca = /‹SECRETO_\d+›/.exec(bloques(body, f).filter((b) => b.role === "user" && b.type === "text").map((b) => b.text).join("\n"))?.[0] ?? "sin-marcador";
      return { llamada: { name: "memory_write", args: { type: "observacion", title: "Token de perfil", summary: `El perfil entrega el token ${tokenEn(vistos[0]!)} con la contraseña ${marca}.` } } };
    }
    return { texto: "Anotado." };
  };
  const { abrir, cerrar } = await sesion("anthropic", cerebro);
  try {
    const engine = abrir();
    await engine.send(`Mirá el perfil y anotá qué entrega. La contraseña es password=${CANARIO.operador}`);
    const filas = engine.db.prepare("select summary from memory").all() as Array<{ summary: string }>;
    assert.equal(filas.length, 1);
    assert.equal(filas[0]!.summary, `El perfil entrega el token ${CANARIO.salida} con la contraseña ‹secreto›.`);
  } finally {
    await cerrar();
  }
});

// «cantidades» es el nombre de antes: vale como «no». La cabecera lleva el modo que rige.
for (const formato of ["openai", "anthropic"] as const) for (const [variable, modo] of [["no", "no"], ["local", "local"], ["cantidades", "no"]] as const) {
  test(`trazas en ${variable} (${formato}): todos los pedidos al servicio llevan «${modo}» y no salen turno ni trayectoria`, async () => {
    const { abrir, svc, cerrar } = await sesion(formato, () => ({ texto: "Recibido." }));
    try {
      process.env.CYBER_TRAZAS = variable;
      const engine = abrir();
      await engine.send("Buen día.");
      await engine.send("Gracias.");
      await engine.close();
      assert.equal(svc.modelo().length, 2);
      assert.ok(svc.cuerpos.every((envio) => envio.trazas === modo), JSON.stringify(svc.cuerpos.map((envio) => envio.trazas)));
      assert.ok(!svc.cuerpos.some((envio) => /\/(traces|trayectorias)$/.test(envio.url)));
    } finally {
      await cerrar();
    }
  });
}
