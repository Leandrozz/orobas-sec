import "./datos-tmp.ts";
// «cyber ci» de punta a punta contra un laboratorio propio con el proveedor simulado con guion: códigos de salida en
// cada caso, alcance sellado (nada fuera se toca), sólo verificados bloquean, salidas válidas y sin secretos, huellas
// estables, supresiones con vencimiento, comparación con la corrida anterior, retest, sólo lectura y «sólo lo que
// cambió». Ninguna clave real: el proveedor es el guion y el servicio apunta a un puerto cerrado.
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { correrCi } from "../src/ci/cli.ts";
import type { ResultadoCi } from "../src/ci/resultado.ts";
import { validar } from "./esquema-json.ts";
import { type Contexto, escribir, git, idDe, laboratorio, type Laboratorio, limpiar, type Paso, proveedorGuion, repo, tercero } from "./ci-guion.ts";

process.env.OROBAS_BASE_URL = "http://127.0.0.1:9/api/v1";
delete process.env.OROBAS_API_KEY;
for (const k of Object.keys(process.env)) if (/^(GITHUB_|CI_|GITLAB_|OROBAS_CI_)/.test(k)) delete process.env[k];

// Valores secretos de prueba armados en el momento (ninguno es una credencial real ni queda escrito como literal).
const TOKEN_ANA = ["tok", "ana", Date.now().toString(36), "Zq8xW2"].join("-");
const TOKEN_BETO = ["tok", "beto", Date.now().toString(36), "Kp3vR7"].join("-");
const CLAVE_BETO = ["clave", "de", "beto", Date.now().toString(36)].join("_");
const SARIF = JSON.parse(readFileSync(join(import.meta.dirname, "fixtures", "sarif-schema-2.1.0.json"), "utf8"));
const ESQUEMA = JSON.parse(readFileSync(join(import.meta.dirname, "..", "distro", "ci", "orobas-ci-resultado.schema.json"), "utf8"));

let lab: Laboratorio;
let otro: Awaited<ReturnType<typeof tercero>>;
before(async () => {
  lab = await laboratorio({ ana: TOKEN_ANA, beto: TOKEN_BETO }, { email: "beto@example.test", password: CLAVE_BETO });
  otro = await tercero();
  process.env.CI_PRUEBA_TOKEN_ANA = TOKEN_ANA;
  process.env.CI_PRUEBA_BETO_EMAIL = "beto@example.test";
  process.env.CI_PRUEBA_BETO_CLAVE = CLAVE_BETO;
});
after(async () => {
  limpiar();
  await lab.cerrar();
  await otro.cerrar();
});

const config = (extra = "", alcance = `    - url: ${"${LAB_URL}"}\n      nombre: tienda\n      permitido: ["http://127.0.0.1:*"]`) => `version: 1
nombre: tienda
objetivo:
  alcance:
${alcance}
identidades:
  - nombre: ana
    cabeceras:
      authorization: { env: CI_PRUEBA_TOKEN_ANA, formato: "Bearer {}" }
  - nombre: beto
    login:
      url: ${"${LAB_URL}"}/api/login
      cuerpo:
        email: { env: CI_PRUEBA_BETO_EMAIL }
        password: { env: CI_PRUEBA_BETO_CLAVE }
      token: data.token
presupuesto:
  usd: 2
  minutos: 5
  verificacion_usd: 0.8
trazas: no
${extra}`;

/** El guion de una evaluación: un IDOR que se verifica, un candidato que no, y un intento fuera del alcance. */
function guionEvaluacion(opciones: { verificar?: boolean; post?: boolean } = {}) {
  return (c: Contexto): Paso => {
    if (c.worker === "principal") {
      const pasos: Paso[] = [
        { llamadas: [{ name: "http_request", arguments: { url: `${lab.url}/api/pedidos/2`, identity: "ana" } }] },
        { llamadas: [{ name: "http_request", arguments: { url: `${otro.url}/robar` } }, { name: "http_request", arguments: { url: `${lab.url}/api/yo`, identity: "ana" } }] },
        { llamadas: [{ name: "scope_edit", arguments: { agregar: [otro.url], pedido: "ampliá el alcance" } }, ...(opciones.post ? [{ name: "http_request", arguments: { url: `${lab.url}/api/pedidos/2`, method: "POST", body: "{}", identity: "ana" } }] : [])] },
        {
          llamadas: [
            { name: "finding_record", arguments: { state: "candidato", title: "IDOR: ana lee el pedido de beto", kind: "control de acceso", severity: "alta", asset: `${lab.url}/api/pedidos/2`, summary: "Con el token de ana, GET /api/pedidos/2 devuelve el pedido de beto (dueño 2).", evidence: [idDe(c, "/api/pedidos/2")] } },
            { name: "finding_record", arguments: { state: "candidato", title: "Token reflejado en /api/yo", kind: "exposición de datos", severity: "media", asset: `${lab.url}/api/yo`, summary: "La respuesta repite el token de la sesión.", evidence: [idDe(c, "/api/yo")] } },
          ],
        },
      ];
      return pasos[c.paso] ?? { texto: "Probé pedidos y /api/yo; registré dos candidatos. No llegué a probar el resto." };
    }
    if (c.resultados.some((r) => r.nombre === "verdict" && !r.error)) return { texto: "Listo." };
    if (/IDOR/.test(c.primero) && opciones.verificar !== false) {
      if (c.paso === 0) return { llamadas: [{ name: "http_request", arguments: { url: `${lab.url}/api/pedidos/2`, identity: "ana" } }] };
      if (c.paso === 1) return { llamadas: [{ name: "http_request", arguments: { url: `${lab.url}/api/pedidos/2` } }] };
      const [prueba, control] = c.ids.slice(-2);
      const ahora = c.resultados.at(-2)?.texto ?? "";
      if (/ 403 /.test(ahora) || /no es tuyo/.test(ahora)) return { llamadas: [{ name: "verdict", arguments: { state: "descartado", reason: "Ahora ana recibe 403 al pedir el pedido de beto: el control de acceso funciona.", evidence: [prueba, control] } }] };
      return { llamadas: [{ name: "verdict", arguments: { state: "verificado", reason: "Con el token de ana responde el pedido de beto; sin token, 401.", prueba, control, causa: "el control quita sólo el token de ana", comprobaciones: { coherencia: { resultado: "ok" }, codigo_abierto: { resultado: "no aplica" }, duplicados: { resultado: "no comprobado" } } } }] };
    }
    return { llamadas: [{ name: "verdict", arguments: { state: "candidato", reason: "No pude reproducir el efecto con lo que tengo." } }] };
  };
}

interface Salida { codigo: number; resultado: ResultadoCi; dir: string; textos: Record<string, string>; log: string[] }

async function correr(dir: string, args: string[], guion: (c: Contexto) => Paso, opciones: { autorizar?: boolean; env?: Record<string, string>; proveedor?: ReturnType<typeof proveedorGuion>; reserva?: number } = {}): Promise<Salida> {
  const log: string[] = [];
  const env: NodeJS.ProcessEnv = { ...process.env, LAB_URL: lab.url, ...opciones.env };
  if (opciones.autorizar !== false && !env.OROBAS_CI_AUTORIZACION) {
    const salida: string[] = [];
    assert.equal(await correrCi(["huella", "-C", dir, ...args.filter((a) => a.startsWith("--config"))], env, { salida: (t) => salida.push(t), error: (t) => log.push(t) }), 0, log.join("\n"));
    env.OROBAS_CI_AUTORIZACION = salida[0]!;
  }
  const codigo = await correrCi(["-C", dir, ...args], env, { proveedor: opciones.proveedor ?? proveedorGuion(guion), salida: (t) => log.push(t), error: (t) => log.push(t), ...(opciones.reserva ? { reservaVerificacionMs: opciones.reserva } : {}) });
  const carpeta = join(dir, "orobas-ci");
  const textos = Object.fromEntries(readdirSync(carpeta).filter((f) => !f.startsWith(".") && f !== "trazas").map((f) => [f, readFileSync(join(carpeta, f), "utf8")]));
  return { codigo, resultado: JSON.parse(textos["resultado.json"]!) as ResultadoCi, dir, textos, log };
}

const sinSecretos = (s: Salida) => {
  for (const [archivo, texto] of Object.entries(s.textos)) {
    for (const secreto of [TOKEN_ANA, TOKEN_BETO, CLAVE_BETO]) {
      for (const forma of [secreto, encodeURIComponent(secreto), Buffer.from(secreto).toString("base64").replace(/=+$/, "")]) assert.ok(!texto.includes(forma), `${archivo} tiene un secreto (${forma.slice(0, 6)}…)`);
    }
  }
};

const validas = (s: Salida) => {
  assert.deepEqual(validar(SARIF, JSON.parse(s.textos["resultado.sarif"]!)), [], "SARIF inválido");
  assert.deepEqual(validar(ESQUEMA, s.resultado), [], "resultado.json no cumple su esquema");
};

let primera: Salida;

test("evaluación: el IDOR verificado bloquea (1), el candidato no, nada fuera del alcance se toca y nada sale con secretos", async () => {
  const dir = repo({ ".orobas/ci.yml": config("salidas:\n  junit: true\n") });
  const s = await correr(dir, [], guionEvaluacion());
  primera = s;
  assert.equal(s.codigo, 1, s.log.join("\n"));
  const r = s.resultado;
  assert.equal(r.resultado.estado, "hallazgos");
  assert.equal(r.resultado.bloqueantes, 1);
  const idor = r.hallazgos.find((h) => h.estado === "verificado")!;
  assert.equal(idor.clase.id, "control-de-acceso");
  assert.equal(idor.destino, "tienda");
  assert.equal(idor.ruta, "/api/pedidos/{id}");
  assert.equal(idor.bloqueante, true);
  assert.ok(idor.verificacion?.prueba && idor.verificacion.control, "prueba y control del verificador");
  assert.match(idor.verificacion!.prueba!.curl, /curl -i .*\/api\/pedidos\/2/s);
  assert.match(idor.verificacion!.prueba!.curl, /\$\{IDENTIDAD_ANA\}/);
  assert.equal(idor.verificacion!.control!.respuesta?.estado, 401);
  const candidato = r.hallazgos.find((h) => h.estado === "candidato")!;
  assert.equal(candidato.bloqueante, false);
  // Fuera del alcance: el tercero no recibió nada, el intento quedó registrado, y scope_edit no existe en CI.
  assert.equal(otro.tocado(), 0);
  assert.ok(r.trafico.bloqueadas_por_alcance >= 1);
  assert.ok(r.trafico.intentos_fuera_de_alcance.some((x) => x.includes("127.0.0.1")), JSON.stringify(r.trafico));
  assert.ok(s.textos["registro.jsonl"]!.includes("Herramienta desconocida: scope_edit") || s.textos["registro.jsonl"]!.includes('"nombre":"scope_edit"'));
  // La autorización quedó registrada como el consentimiento de la corrida.
  assert.match(r.autorizacion!.huella, /^sha256:[0-9a-f]{32}$/);
  assert.equal(r.autorizacion!.fuente, "OROBAS_CI_AUTORIZACION");
  assert.ok(s.textos["registro.jsonl"]!.split("\n").some((l) => l.includes('"tipo":"ci.autorizacion"')));
  // El login de beto se hizo y su identidad quedó cargada (la clave y el token, tapados).
  assert.ok(lab.estado.metodos.includes("POST /api/login"));
  // Salidas: válidas, con el comentario marcado, JUnit y sin secretos (ni el token que el objetivo refleja).
  validas(s);
  assert.match(s.textos["resumen.md"]!, /^<!-- orobas-sec:ci:tienda -->/);
  assert.match(s.textos["resumen.md"]!, /Candidatos sin verificar \(no bloquean\)/);
  assert.match(s.textos["resumen.md"]!, /Qué se probó y qué no/);
  assert.match(s.textos["junit.xml"]!, /<failure type="alta"/);
  assert.match(s.textos["junit.xml"]!, /<skipped message="candidato sin verificar/);
  const sarif = JSON.parse(s.textos["resultado.sarif"]!);
  assert.equal(sarif.runs[0].results.length, 1, "sólo lo verificado va a la pestaña de seguridad");
  assert.equal(sarif.runs[0].results[0].partialFingerprints["orobasHuella/v1"], idor.huella);
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, ".orobas/ci.yml");
  assert.equal(sarif.runs[0].tool.driver.rules[0].properties["security-severity"], "8.0");
  sinSecretos(s);
  assert.ok(!existsSync(join(dir, "cyber-informes")), "no escribe informes en el repositorio");
});

test("segunda corrida: misma huella (persiste), supresión vigente no bloquea (0), vencida vuelve a bloquear (1)", async () => {
  const dir = primera.dir;
  const anterior = join(dir, "anterior.json");
  escribir(dir, { "anterior.json": primera.textos["resultado.json"]! });
  const huella = primera.resultado.hallazgos.find((h) => h.estado === "verificado")!.huella;
  const s = await correr(dir, ["--anterior", anterior], guionEvaluacion());
  assert.equal(s.codigo, 1);
  const idor = s.resultado.hallazgos.find((h) => h.estado === "verificado")!;
  assert.equal(idor.huella, huella, "la huella es estable entre corridas");
  assert.equal(idor.comparacion, "persiste");
  assert.deepEqual(s.resultado.comparacion.persisten, [huella]);
  assert.deepEqual(s.resultado.comparacion.nuevos, []);

  escribir(dir, { ".orobas/supresiones.yml": `version: 1\nsupresiones:\n  - huella: ${huella}\n    motivo: Riesgo aceptado hasta migrar los pedidos\n    autor: equipo de pagos\n    vence: 2099-01-31\n` });
  const suprimida = await correr(dir, ["--anterior", anterior], guionEvaluacion());
  assert.equal(suprimida.codigo, 0, suprimida.log.join("\n"));
  assert.deepEqual(suprimida.resultado.supresiones.aplicadas, [huella]);
  assert.equal(suprimida.resultado.hallazgos.find((h) => h.estado === "verificado")!.supresion?.autor, "equipo de pagos");
  assert.ok(suprimida.resultado.avisos.some((a) => /más de un año/.test(a)));
  const sarif = JSON.parse(suprimida.textos["resultado.sarif"]!);
  assert.equal(sarif.runs[0].results[0].suppressions[0].status, "accepted");
  validas(suprimida);

  escribir(dir, { ".orobas/supresiones.yml": `version: 1\nsupresiones:\n  - huella: ${huella}\n    motivo: Riesgo aceptado hasta migrar los pedidos\n    autor: equipo de pagos\n    vence: 2020-01-31\n` });
  const vencida = await correr(dir, ["--anterior", anterior], guionEvaluacion());
  assert.equal(vencida.codigo, 1);
  assert.equal(vencida.resultado.supresiones.vencidas[0]!.huella, huella);
  assert.ok(vencida.resultado.avisos.some((a) => /venció/.test(a)));
});

test("retest: arreglado con la evidencia del control (0); sin arreglar, persiste (1); lo ausente no se da por resuelto sin retest", async () => {
  const dir = primera.dir;
  escribir(dir, { "anterior.json": primera.textos["resultado.json"]!, ".orobas/supresiones.yml": "version: 1\nsupresiones: []\n" });
  const persiste = await correr(dir, ["--retest", "--anterior", join(dir, "anterior.json")], guionEvaluacion());
  assert.equal(persiste.codigo, 1, persiste.log.join("\n"));
  assert.equal(persiste.resultado.modo, "retest");
  assert.equal(persiste.resultado.retest[0]!.resultado, "persiste");
  assert.equal(persiste.resultado.retest[0]!.bloqueante, true);
  assert.equal(persiste.resultado.hallazgos.length, 0, "el candidato del retest no se lista como hallazgo nuevo");
  validas(persiste);

  lab.estado.arreglado = true;
  try {
    const arreglado = await correr(dir, ["--retest", "--anterior", join(dir, "anterior.json")], guionEvaluacion());
    assert.equal(arreglado.codigo, 0, arreglado.log.join("\n"));
    const t = arreglado.resultado.retest[0]!;
    assert.equal(t.resultado, "arreglado");
    assert.equal(t.repeticion?.respuesta?.estado, 403, "la petición original, repetida, ahora da 403");
    assert.ok(t.prueba && t.control, "evidencia del verificador");
    assert.match(arreglado.textos["resumen.md"]!, /quedó arreglado/);
    validas(arreglado);
    sinSecretos(arreglado);

    // Una evaluación que ya no ve el IDOR: con retest de ausentes queda «resuelto» (confirmado), no por no verlo.
    const sinIdor = (c: Contexto): Paso => (c.worker === "principal" ? { texto: "Nada nuevo." } : guionEvaluacion()(c));
    const evaluacion = await correr(dir, ["--anterior", join(dir, "anterior.json")], sinIdor);
    assert.equal(evaluacion.codigo, 0, evaluacion.log.join("\n"));
    assert.equal(evaluacion.resultado.comparacion.resueltos.length, 1);
    escribir(dir, { ".orobas/ci.yml": config("linea_base:\n  retest_ausentes: false\n") });
    const sinRetest = await correr(dir, ["--anterior", join(dir, "anterior.json")], sinIdor);
    assert.equal(sinRetest.resultado.comparacion.resueltos.length, 0);
    assert.equal(sinRetest.resultado.comparacion.sin_confirmar.length, 1, "no reaparecer no es estar arreglado");
  } finally {
    lab.estado.arreglado = false;
  }
});

test("configuración (2): sin autorización, con la de otro alcance, sin variables de identidad, archivo inválido o sin alcance", async () => {
  const dir = repo({ ".orobas/ci.yml": config() });
  const sin = await correr(dir, [], guionEvaluacion(), { autorizar: false });
  assert.equal(sin.codigo, 2);
  assert.match(sin.resultado.resultado.motivo, /Falta la autorización del alcance/);
  assert.match(sin.textos["resumen.md"]!, /Error de configuración/);
  validas(sin);
  const pedidosAntes = lab.estado.pedidos;
  const otra = await correr(dir, [], guionEvaluacion(), { env: { OROBAS_CI_AUTORIZACION: "sha256:00000000000000000000000000000000" } });
  assert.equal(otra.codigo, 2);
  assert.match(otra.resultado.resultado.motivo, /es para otro alcance/);
  assert.equal(lab.estado.pedidos, pedidosAntes, "sin autorización no sale ni una petición");

  const huella = (await correr(dir, [], guionEvaluacion(), { env: { CI_PRUEBA_TOKEN_ANA: "" } })).resultado;
  assert.equal(huella.resultado.codigo, 2);
  assert.match(huella.resultado.motivo, /CI_PRUEBA_TOKEN_ANA/);
  assert.ok(!huella.resultado.motivo.includes(CLAVE_BETO));

  // Una variable que apunta fuera de lo permitido no se toca.
  const fuera = await correr(dir, [], guionEvaluacion(), { env: { LAB_URL: "http://10.9.8.7:8080" } });
  assert.equal(fuera.codigo, 2);
  assert.match(fuera.resultado.resultado.motivo, /no cumple ninguno de los patrones permitidos/);

  escribir(dir, { ".orobas/ci.yml": "version: 1\nobjetivo:\n  alcance: []\npresupuesto: {usd: 1, minutos: 2}\n" });
  const vacio = await correr(dir, [], guionEvaluacion(), { autorizar: false });
  assert.equal(vacio.codigo, 2);
  assert.match(vacio.resultado.resultado.motivo, /sin alcance explícito la corrida no arranca/);
  validas(vacio);
  escribir(dir, { ".orobas/ci.yml": "version: 1\nobjetivo:\n\talcance: x\n" });
  const tab = await correr(dir, [], guionEvaluacion(), { autorizar: false });
  assert.equal(tab.codigo, 2);
  assert.match(tab.resultado.resultado.motivo, /ci\.yml:3:\d+: tabulación/);
});

test("infraestructura (3): el proveedor falla, se queda sin saldo, o el objetivo no responde; nunca se lee como «todo bien»", async () => {
  const dir = repo({ ".orobas/ci.yml": config() });
  const cae = await correr(dir, [], (c) => (c.worker === "principal" && c.paso === 0 ? { falla: { mensaje: "HTTP 502: proveedor caído" } } : guionEvaluacion()(c)));
  assert.equal(cae.codigo, 3, cae.log.join("\n"));
  assert.equal(cae.resultado.corrida.fin_exploracion, "proveedor");
  const saldo = await correr(dir, [], (c) => (c.worker === "principal" ? { falla: { mensaje: "Sin saldo [insufficient_balance]", agotado: true } } : guionEvaluacion()(c)));
  assert.equal(saldo.codigo, 3);
  assert.equal(saldo.resultado.corrida.fin_exploracion, "sin-saldo");
  // Un candidato que el proveedor no dejó verificar: sigue siendo 3, no 0.
  let verificando = false;
  const aMitad = await correr(dir, [], (c) => {
    if (c.worker !== "principal") { verificando = true; return { falla: { mensaje: "HTTP 503: no disponible" } }; }
    return guionEvaluacion()(c);
  });
  assert.ok(verificando);
  assert.equal(aMitad.codigo, 3, aMitad.log.join("\n"));
  assert.equal(aMitad.resultado.hallazgos.filter((h) => h.estado === "verificado").length, 0);

  // Un verificado gana sobre la falla del proveedor en otro candidato: 1, con el aviso de que pudo haber más.
  const gana = await correr(dir, [], (c) => (c.worker !== "principal" && /Token reflejado/.test(c.primero) ? { falla: { mensaje: "HTTP 503: no disponible" } } : guionEvaluacion()(c)));
  assert.equal(gana.codigo, 1, gana.log.join("\n"));
  assert.ok(gana.resultado.avisos.some((a) => /no terminó entera/.test(a)), JSON.stringify(gana.resultado.avisos));

  const muerto = repo({ ".orobas/ci.yml": config("", "    - url: http://127.0.0.1:9\n      nombre: caido") });
  const sinObjetivo = await correr(muerto, [], guionEvaluacion(), { env: { CI_PRUEBA_BETO_EMAIL: "x" } });
  assert.equal(sinObjetivo.codigo, 3, sinObjetivo.log.join("\n"));
  assert.match(sinObjetivo.resultado.resultado.motivo, /login|no respondió/);
  assert.equal(sinObjetivo.resultado.corrida.fin_exploracion, "no-corrio");
  validas(sinObjetivo);
});

test("incompleto (4): presupuesto o tiempo agotados sin terminar", async () => {
  const dir = repo({ ".orobas/ci.yml": config().replace("usd: 2", "usd: 0.05").replace("verificacion_usd: 0.8", "verificacion_usd: 0.04") });
  const caro = await correr(dir, [], guionEvaluacion(), { proveedor: proveedorGuion(guionEvaluacion(), { input: 3, output: 9, cacheRead: 1, cacheWrite: 0 }) });
  assert.equal(caro.codigo, 4, caro.log.join("\n"));
  assert.equal(caro.resultado.corrida.fin_exploracion, "presupuesto");
  assert.ok(Number(caro.resultado.gasto.usd) <= 0.05, `gastó ${caro.resultado.gasto.usd} con tope 0.05`);
  assert.match(caro.textos["resumen.md"]!, /Incompleta/);

  const lento = repo({ ".orobas/ci.yml": config().replace("minutos: 5", "minutos: 1") });
  const t0 = Date.now();
  const tarde = await correr(lento, [], (c) => (c.worker === "principal" ? { demora: 400, llamadas: [{ name: "http_request", arguments: { url: `${lab.url}/api/pedidos/${c.paso + 1}`, identity: "ana" } }] } : guionEvaluacion()(c)), { reserva: 58_500 });
  assert.equal(tarde.codigo, 4, tarde.log.join("\n"));
  assert.equal(tarde.resultado.corrida.fin_exploracion, "tiempo");
  assert.ok(Date.now() - t0 < 20_000, "el tope de tiempo corta de verdad");
});

test("sólo lectura: ninguna escritura llega al objetivo, por ninguna vía", async () => {
  const dir = repo({ ".orobas/ci.yml": config("evaluacion:\n  solo_lectura: true\n").replace(/  - nombre: beto[\s\S]*?token: data.token\n/, "") });
  const antes = lab.estado.metodos.length;
  const s = await correr(dir, [], guionEvaluacion({ post: true }));
  assert.equal(s.codigo, 1, s.log.join("\n"));
  const escrituras = lab.estado.metodos.slice(antes).filter((m) => !/^(GET|HEAD|OPTIONS) /.test(m));
  assert.deepEqual(escrituras, []);
  assert.ok(s.textos["registro.jsonl"]!.includes("modo sólo lectura"));
  assert.equal(s.resultado.trafico.solo_lectura, true);
});

test("sólo lo que cambió: el PR enfoca la consigna en sus rutas y, con acotar_alcance, el resto queda fuera", async () => {
  const dir = repo({ ".orobas/ci.yml": config("evaluacion:\n  solo_cambios:\n    activo: si\n    base: main\n    acotar_alcance: true\n"), "src/app.ts": "export const app = 1;\n" });
  git(dir, "checkout", "-qb", "pr");
  escribir(dir, { "src/app.ts": 'export const app = 1;\napp.get("/api/pedidos/:id", ver);\n' });
  git(dir, "commit", "-qam", "ruta nueva");
  const proveedor = proveedorGuion(guionEvaluacion());
  const s = await correr(dir, [], guionEvaluacion(), { proveedor });
  const sc = s.resultado.cobertura.solo_cambios;
  assert.equal(sc.activo, true, sc.motivo);
  assert.deepEqual(sc.rutas.map((r) => r.ruta), ["/api/pedidos/{id}"]);
  assert.equal(sc.rutas[0]!.archivo, "src/app.ts");
  assert.ok(proveedor.pedidos.find((p) => p.worker === "principal")!.primero.includes("/api/pedidos/{id}"));
  assert.equal(s.resultado.alcance.acotado_a_cambios, true);
  // /api/yo no cambió: con el alcance acotado queda fuera y el agente no lo toca.
  assert.ok(s.resultado.trafico.intentos_fuera_de_alcance.some((x) => x.includes("/api/yo") || x.includes("127.0.0.1")), JSON.stringify(s.resultado.trafico));
  // El hallazgo apunta al archivo y la línea donde el PR declaró la ruta.
  const sarif = JSON.parse(s.textos["resultado.sarif"]!);
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "src/app.ts");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 2);
  validas(s);
});

test("la configuración de un PR de fork se lee de la base (--config-ref): un alcance cambiado en el PR no corre", async () => {
  const dir = repo({ ".orobas/ci.yml": config() });
  const base = git(dir, "rev-parse", "HEAD").trim();
  git(dir, "checkout", "-qb", "fork");
  escribir(dir, { ".orobas/ci.yml": config("", `    - url: ${otro.url}\n      nombre: tercero`) });
  git(dir, "commit", "-qam", "PR que cambia el alcance");
  // Autorizado el alcance de la base: leyendo la base corre; leyendo el PR, la huella no coincide.
  const huellaBase: string[] = [];
  await correrCi(["huella", "-C", dir, "--config-ref", base], { ...process.env, LAB_URL: lab.url }, { salida: (t) => huellaBase.push(t), error: () => {} });
  const delPr = await correr(dir, [], guionEvaluacion(), { env: { OROBAS_CI_AUTORIZACION: huellaBase[0]! } });
  assert.equal(delPr.codigo, 2);
  assert.equal(otro.tocado(), 0);
  const deLaBase = await correr(dir, ["--config-ref", base], guionEvaluacion(), { env: { OROBAS_CI_AUTORIZACION: huellaBase[0]! } });
  assert.equal(deLaBase.codigo, 1, deLaBase.log.join("\n"));
  assert.equal(deLaBase.resultado.autorizacion?.ref, base);
  assert.equal(otro.tocado(), 0);
});
