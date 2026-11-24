import "./datos-tmp.ts";
// Configuración de CI: el lector de YAML (subconjunto, con línea y columna), el esquema de .orobas/ci.yml con sus
// errores juntos, entorno y banderas, la huella del alcance (qué la cambia y qué no), la expansión con patrones
// permitidos y las identidades desde el entorno (sin valores en los errores).
import assert from "node:assert/strict";
import { test } from "node:test";
import { cargarConfig, cumplePatron, EJEMPLO, ErrorConfig, expandirAlcance, huellaAlcance, problemaDePatron, problemaDeRegla, resolverIdentidades } from "../src/ci/config.ts";
import { ErrorYaml, leerYaml } from "../src/ci/yaml.ts";
import { escribir, git, limpiar, repo } from "./ci-guion.ts";
import { after } from "node:test";

after(limpiar);

test("yaml: mapas, listas, en línea, bloques de texto, comillas y comentarios", () => {
  const { valor, posiciones } = leerYaml(`---
# comentario
a: 1
b: texto#pegado no es comentario # éste sí
c: "dos # tres"   # comentario
d: 'it''s'
e: [1, "x", {env: Y, formato: "Bearer {}"}]
f:
- uno
- clave: valor
  otra: 2
g: |
  línea 1
    sangrada

  última
h: >-
  plegado
  en una
i: ~
j: true
k: 0.5
l: 1.0.0
m: 2026-12-31
n: "\\u00e1\\n"
o: https://x.example.com:8443/a#frag
`);
  assert.deepEqual(valor, {
    a: 1, b: "texto#pegado no es comentario", c: "dos # tres", d: "it's", e: [1, "x", { env: "Y", formato: "Bearer {}" }],
    f: ["uno", { clave: "valor", otra: 2 }], g: "línea 1\n  sangrada\n\núltima\n", h: "plegado en una", i: null, j: true, k: 0.5, l: "1.0.0", m: "2026-12-31", n: "á\n", o: "https://x.example.com:8443/a#frag",
  });
  assert.deepEqual(posiciones.get("f[1].otra"), { linea: 11, columna: 3 });
  assert.deepEqual(posiciones.get("e[2].env"), { linea: 7, columna: 19 });
});

test("yaml: lo que no está en el subconjunto se rechaza con línea y columna", () => {
  const casos: Array<[string, RegExp, number]> = [
    ["a:\n\tb: 1\n", /tabulación/, 2],
    ["a: 1\na: 2\n", /clave repetida «a»/, 2],
    ["a: &ancla 1\n", /anclas/, 1],
    ["a: *alias\n", /alias/, 1],
    ["a: !!str 1\n", /etiquetas/, 1],
    ["a: \"sin cerrar\n", /comillas sin cerrar/, 1],
    ["a: 1\n   b: 2\n", /sangría inesperada/, 2],
    ["a: x: y\n", /poné el valor entre comillas/, 1],
    ["a: 1\n---\nb: 2\n", /un solo documento/, 2],
    ["a: [1, 2\n", /se esperaba «,» o «]»/, 1],
    ["? a\n: b\n", /claves complejas/, 1],
  ];
  for (const [fuente, mensaje, linea] of casos) {
    assert.throws(() => leerYaml(fuente), (e: unknown) => e instanceof ErrorYaml && mensaje.test(e.message) && e.linea === linea, fuente);
  }
});

const env = { STAGING_TOKEN_ALICIA: "x", STAGING_BRUNO_EMAIL: "y", STAGING_BRUNO_CLAVE: "z" };

test("config: el ejemplo es válido y trae los valores por defecto", () => {
  const dir = repo({ ".orobas/ci.yml": EJEMPLO });
  const c = cargarConfig({ cwd: dir, archivo: ".orobas/ci.yml", env: {} });
  assert.equal(c.nombre, "staging");
  assert.equal(c.alcance.length, 2);
  assert.deepEqual(c.alcance[1]!.puertos, [443]);
  assert.equal(c.evaluacion.perfil, "api");
  assert.equal(c.evaluacion.capacidades, "bounty");
  assert.equal(c.evaluacion.soloLectura, false);
  assert.equal(c.presupuesto.verificacionUsd, 1);
  assert.equal(c.presupuesto.porCandidatoUsd, 0.5);
  assert.equal(c.politica.fallarDesde, "alta");
  assert.equal(c.trazas, "no");
  assert.equal(c.salidas.carpeta, "orobas-ci");
  assert.equal(resolverIdentidades(c, env).length, 2);
});

function errores(texto: string, extra: Partial<Parameters<typeof cargarConfig>[0]> = {}): string {
  const dir = repo({ ".orobas/ci.yml": texto });
  try {
    cargarConfig({ cwd: dir, archivo: ".orobas/ci.yml", env: {}, ...extra });
  } catch (e) {
    assert.ok(e instanceof ErrorConfig, String(e));
    return e.message;
  }
  assert.fail("tenía que fallar");
}

test("config: todos los errores juntos, con archivo, línea, columna y sugerencia", () => {
  const m = errores(`version: 1
objetivo:
  alcanse:
    - url: https://x.example.com
presupuesto:
  usd: tres
  minutos: 9999
politica:
  fallar_desde: grave
`);
  assert.match(m, /\.orobas\/ci\.yml:3:3: «objetivo\.alcanse» no es una clave conocida \(¿quisiste decir «alcance»\?\)/);
  assert.match(m, /«objetivo\.alcance» falta o está vacío: sin alcance explícito la corrida no arranca/);
  assert.match(m, /:6:3: «presupuesto\.usd» tiene que ser un número y es «tres»/);
  assert.match(m, /:7:3: «presupuesto\.minutos» tiene que estar entre 1 y 360/);
  assert.match(m, /«politica\.fallar_desde» tiene que ser .*«critica».* y es «grave»/);
  assert.match(errores(""), /El archivo está vacío/);
  assert.match(errores("version: 1\nobjetivo:\n  alcance:\n    - url: https://x.example.com\n"), /«presupuesto» falta: los topes de gasto y de tiempo son obligatorios/);
  const dir = repo({});
  assert.throws(() => cargarConfig({ cwd: dir, archivo: ".orobas/ci.yml", env: {} }), /No existe \.orobas\/ci\.yml\. Sin un alcance explícito y versionado, la corrida no arranca/);
});

test("config: credenciales nunca en el archivo, y reglas explícitas", () => {
  const base = (cosa: string) => `version: 1\nobjetivo:\n  alcance:\n${cosa}\npresupuesto: {usd: 1, minutos: 5}\n`;
  assert.match(errores(base("    - url: https://x.example.com") + "identidades:\n  - nombre: ana\n    cabeceras:\n      authorization: Bearer abc123\n"), /no puede ir escrito en el archivo: las credenciales van por referencia/);
  assert.match(errores(base("    - url: https://x.example.com") + "identidades:\n  - nombre: ana\n    login:\n      url: https://x.example.com/login\n      cuerpo:\n        password: secreta\n      token: t\n"), /parece un secreto y no puede ir escrito en el archivo/);
  // La URL con usuario y contraseña se arma acá: escrita entera, el verificador del árbol público la tomaría por una credencial.
  assert.match(errores(base(`    - url: https://${["usuario", "clave"].join(":")}@x.example.com`)), /lleva usuario o contraseña/);
  assert.match(errores(base("    - host: '*.example.com'")), /sin comodines/);
  assert.match(errores(base("    - url: https://x.example.com\n      puertos: [443]")), /no va con «url»/);
  assert.match(errores(base("    - cidr: 10.0.0.0/8")), /demasiado amplia para CI \(mínimo \/16\)/);
  assert.match(errores(base("    - cidr: 10.0.0.0/20\n      puertos: [80, 443]")), /8192 destinos/);
  assert.match(errores(base("    - url: ${PREVIEW}")), /una regla con variables necesita la lista de valores permitidos/);
  assert.match(errores(base("    - url: ${PREVIEW}\n      permitido: ['https://*.app']")), /demasiado amplio/);
  assert.match(errores(base("    - url: ${PREVIEW}\n      permitido: ['https://*.vercel.app']")), /alojamiento compartido/);
  assert.match(errores(base("    - url: https://x.example.com\n      permitido: ['https://x.example.com']")), /sólo va en reglas con variables/);
  assert.match(errores(base("    - url: https://x.example.com\n    - url: https://y.example.com") + "presupuesto2: 1\n"), /«presupuesto2» no es una clave conocida \(¿quisiste decir «presupuesto»\?\)/);
});

test("config: el entorno y las banderas pisan el archivo (las banderas ganan), nunca el alcance", () => {
  const dir = repo({ ".orobas/ci.yml": EJEMPLO });
  const c = cargarConfig({ cwd: dir, archivo: ".orobas/ci.yml", env: { OROBAS_CI_PRESUPUESTO_USD: "5", OROBAS_CI_MINUTOS: "45", OROBAS_CI_MODELO: "anthropic/x", OROBAS_CI_FALLAR_DESDE: "crítica", OROBAS_CI_SOLO_LECTURA: "si", OROBAS_CI_TRAZAS: "local" }, banderas: { minutos: "10", fallarDesde: "media" } });
  assert.equal(c.presupuesto.usd, 5);
  assert.equal(c.presupuesto.minutos, 10);
  assert.equal(c.modelo.nombre, "anthropic/x");
  assert.equal(c.politica.fallarDesde, "media");
  assert.equal(c.evaluacion.soloLectura, true);
  assert.equal(c.trazas, "local");
  assert.throws(() => cargarConfig({ cwd: dir, archivo: ".orobas/ci.yml", env: { OROBAS_CI_MINUTOS: "mil" } }), /OROBAS_CI_MINUTOS tiene que ser un número/);
  assert.throws(() => cargarConfig({ cwd: dir, archivo: ".orobas/ci.yml", env: {}, banderas: { fallarDesde: "grave" } }), /--fallar-desde tiene que ser/);
  assert.equal(huellaAlcance(c), huellaAlcance(cargarConfig({ cwd: dir, archivo: ".orobas/ci.yml", env: {} })));
});

test("config: la huella cambia con a quién se le pega, no con nombres, orden, presupuesto ni consigna", () => {
  const con = (alcance: string, resto = "presupuesto: {usd: 1, minutos: 5}") => {
    const dir = repo({ ".orobas/ci.yml": `version: 1\nobjetivo:\n  alcance:\n${alcance}\n${resto}\n` });
    return huellaAlcance(cargarConfig({ cwd: dir, archivo: ".orobas/ci.yml", env: {} }));
  };
  const a = con("    - url: https://a.example.com\n      nombre: web\n    - host: b.example.com\n      puertos: [443, 8443]");
  assert.match(a, /^sha256:[0-9a-f]{32}$/);
  assert.equal(a, con("    - host: b.example.com\n      puertos: [8443, 443]\n    - url: https://A.example.com/\n      nombre: otro"));
  assert.equal(a, con("    - url: https://a.example.com\n    - host: b.example.com\n      puertos: [443, 8443]", "presupuesto: {usd: 9, minutos: 50}\nevaluacion:\n  consigna: otra cosa"));
  assert.notEqual(a, con("    - url: https://a.example.com\n    - host: b.example.com\n      puertos: [443]"));
  assert.notEqual(a, con("    - url: https://c.example.com\n    - host: b.example.com\n      puertos: [443, 8443]"));
  assert.notEqual(a, con("    - url: https://a.example.com\n    - host: b.example.com\n      puertos: [443, 8443]\n  excluir:\n    - url: https://a.example.com/admin"));
  const v = con("    - url: ${PREVIEW}\n      permitido: ['https://pr-*.preview.example.com']");
  assert.notEqual(v, con("    - url: ${PREVIEW}\n      permitido: ['https://*.preview.example.com']"));
});

test("config: expansión con patrones permitidos, CIDR con puertos e identidades desde el entorno", () => {
  const dir = repo({ ".orobas/ci.yml": `version: 1
objetivo:
  alcance:
    - url: \${PREVIEW}
      permitido: ['https://pr-*.preview.example.com', 'http://127.0.0.1:*']
    - cidr: 10.20.0.0/30
      puertos: [8080]
  excluir:
    - url: \${PREVIEW}/admin
      permitido: ['https://pr-*.preview.example.com', 'http://127.0.0.1:*']
identidades:
  - nombre: ana
    cabeceras:
      cookie: { env: COOKIE_ANA }
presupuesto: {usd: 1, minutos: 5}
` });
  const c = cargarConfig({ cwd: dir, archivo: ".orobas/ci.yml", env: {} });
  const { incluidas, excluidas } = expandirAlcance(c, { PREVIEW: "https://pr-12.preview.example.com" });
  assert.equal(incluidas[0]!.reglas[0]!.value, "https://pr-12.preview.example.com");
  assert.deepEqual(incluidas[1]!.reglas.map((r) => r.value), ["10.20.0.0:8080", "10.20.0.1:8080", "10.20.0.2:8080", "10.20.0.3:8080"]);
  assert.equal(excluidas[0]!.reglas[0]!.value, "https://pr-12.preview.example.com/admin");
  assert.throws(() => expandirAlcance(c, { PREVIEW: "https://evil.example.org" }), /no cumple ninguno de los patrones permitidos/);
  assert.throws(() => expandirAlcance(c, { PREVIEW: "https://pr-1.preview.example.com.evil.example.org" }), /no cumple/);
  assert.throws(() => expandirAlcance(c, {}), /usa \$\{PREVIEW\} y la variable no está definida/);
  const secreto = ["cookie", "de", "ana", "9f8e7d"].join("-");
  assert.deepEqual(resolverIdentidades(c, { COOKIE_ANA: secreto }), [{ nombre: "ana", cabeceras: { cookie: secreto }, secretos: [secreto] }]);
  assert.throws(() => resolverIdentidades(c, {}), (e: unknown) => e instanceof ErrorConfig && /COOKIE_ANA/.test(e.message) && !e.message.includes(secreto));
  assert.ok(cumplePatron("https://pr-12.preview.example.com", "https://pr-*.preview.example.com"));
  assert.ok(!cumplePatron("https://pr-12.x.preview.example.com", "https://pr-*.preview.example.com"), "el comodín no cruza puntos");
  assert.equal(problemaDePatron("https://miapp-*-equipo.vercel.app"), undefined);
  assert.equal(problemaDeRegla("url", "https://x.example.com/?a=1"), "la URL de alcance no lleva consulta (?…) ni fragmento (#…)");
});

test("config: de un commit con --config-ref (la base de un PR), no del árbol de trabajo", () => {
  const dir = repo({ ".orobas/ci.yml": EJEMPLO });
  const base = git(dir, "rev-parse", "HEAD").trim();
  escribir(dir, { ".orobas/ci.yml": EJEMPLO.replace("https://staging.ejemplo.com\n      nombre: web", "https://otro.example.com\n      nombre: web") });
  const delArbol = cargarConfig({ cwd: dir, archivo: ".orobas/ci.yml", env: {} });
  const deLaBase = cargarConfig({ cwd: dir, archivo: ".orobas/ci.yml", ref: base, env: {} });
  assert.notEqual(huellaAlcance(delArbol), huellaAlcance(deLaBase));
  assert.equal(deLaBase.alcance[0]!.literal, "https://staging.ejemplo.com");
  assert.equal(deLaBase.ref, base);
  assert.throws(() => cargarConfig({ cwd: dir, archivo: ".orobas/otro.yml", ref: base, env: {} }), /No existe \.orobas\/otro\.yml en/);
});

test("config: sin modo de trazas explícito, una corrida de CI no comparte (no); el entorno de CI lo puede cambiar", () => {
  const dir = repo({ ".orobas/ci.yml": EJEMPLO.replace(/^trazas: .*\n/m, "") });
  assert.doesNotMatch(EJEMPLO.replace(/^trazas: .*\n/m, ""), /^trazas:/m);
  assert.equal(cargarConfig({ cwd: dir, archivo: ".orobas/ci.yml", env: { CYBER_TRAZAS: "compartir" }, banderas: {} }).trazas, "no");
  assert.equal(cargarConfig({ cwd: dir, archivo: ".orobas/ci.yml", env: { OROBAS_CI_TRAZAS: "compartir" }, banderas: {} }).trazas, "compartir");
});
