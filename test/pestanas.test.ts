import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { test } from "node:test";
import type { Entrada } from "../src/tui/entradas.ts";
import { dibujar, dibujarPanel, PESTANA_CHAT, separador, type Pestana } from "../src/tui/pestanas.ts";
import { renderMarkdown } from "../src/tui/markdown.ts";
import { ADORNO_ABRE, ADORNO_CIERRA, CORTE_ESPACIO, adornoTUI, accent, bold, dim, stripAnsi, visibleWidth, wrapText } from "../src/tui/text.ts";
import { usarTema } from "../src/tui/temas.ts";

type Conv = Pestana & { tipo: "conversacion" };
const pestana = (contenido: Conv["contenido"], detalle: Conv["detalle"]): Conv => ({ nombre: "Perú", tipo: "conversacion", contenido, detalle });
const sinAnsi = (l: string[]) => l.map(stripAnsi);
const opciones = (extra: Partial<Parameters<typeof dibujar>[2]> = {}) => ({ ancho: 80, expandidas: new Set<number>(), resultados: (e: { texto?: string }) => e.texto, ...extra });
const accion = (id: number, extra: Partial<Extract<Entrada, { tipo: "acciones" }>> = {}): Entrada =>
  ({ id, tipo: "acciones", llamada: `c${id}`, nombre: "http_request", etiqueta: "HTTP", estado: "ok", resumen: "status 200", ...extra });
const resultado = (id: number, texto: string): Entrada => ({ id, tipo: "resultados", llamada: "c1", texto });
const todas: Entrada[] = [
  { id: 1, tipo: "mensajes", texto: "hola" },
  { id: 2, tipo: "texto", markdown: "respuesta", completo: true },
  accion(3),
  resultado(4, "cuerpo"),
  { id: 5, tipo: "comandos", panel: { title: "PANELITO", lines: ["x"] } },
  { id: 6, tipo: "avisos", texto: "aviso", tono: "dim" },
];

test("dibujo: una pestaña sólo muestra sus tipos y los resultados sólo en completo", () => {
  const solo = sinAnsi(dibujar(pestana(["comandos"], "normal"), todas, opciones()).lineas).join("\n");
  assert.match(solo, /PANELITO/);
  assert.doesNotMatch(solo, /Vos|Orobas|HTTP|aviso/);
  const normal = sinAnsi(dibujar(pestana(["acciones", "resultados"], "normal"), todas, opciones()).lineas);
  assert.ok(!normal.some((l) => l.includes("│")));
  const completo = sinAnsi(dibujar(pestana(["acciones", "resultados"], "completo"), todas, opciones()).lineas);
  assert.ok(completo.some((l) => l.includes("│ cuerpo")));
});

test("dibujo: completo recorta resultados largos y expandidos se ven enteros", () => {
  const largo = Array.from({ length: 30 }, (_, i) => `l${i}`).join("\n");
  const p = pestana(["resultados"], "completo");
  const corto = sinAnsi(dibujar(p, [resultado(4, largo)], opciones()).lineas);
  assert.equal(corto.filter((l) => l.includes("│")).length, 12);
  assert.ok(corto.some((l) => l.includes("… 18 líneas más · Enter expande")));
  const entero = sinAnsi(dibujar(p, [resultado(4, largo)], opciones({ expandidas: new Set([4]) })).lineas);
  assert.equal(entero.filter((l) => l.includes("│")).length, 30);
});

test("dibujo: los resultados conservan la sangría, también al cortarse una línea larga", () => {
  const texto = `{\n  "id": 1042,\n    ${"palabra ".repeat(20).trim()}\n}`;
  const filas = sinAnsi(dibujar(pestana(["resultados"], "completo"), [resultado(4, texto)], opciones()).lineas).filter((l) => l.includes("│")).map((l) => l.replace(/^ *│ /, ""));
  assert.ok(filas.includes('  "id": 1042,'));
  const larga = filas.filter((l) => l.startsWith("    palabra") || (l.startsWith("    ") && l.includes("palabra")));
  assert.ok(larga.length >= 2 && larga.every((l) => /^ {4}\S/.test(l)));
});

test("dibujo: argumentos completos de shell y http en detalle completo", () => {
  const p = pestana(["acciones"], "completo");
  const e = [
    accion(1, { nombre: "shell", etiqueta: "Shell", argumentos: { command: "ls -la" } }),
    accion(2, { argumentos: { url: "http://x/y", method: "POST", body: "a=1" } }),
    accion(3, { nombre: "scope_check", argumentos: { host: "x" } }),
  ];
  const l = sinAnsi(dibujar(p, e, opciones()).lineas);
  assert.ok(l.includes("    $ ls -la"));
  assert.ok(l.includes("    POST http://x/y"));
  assert.ok(l.includes("    a=1"));
  assert.ok(l.includes('    {"host":"x"}'));
  assert.ok(!sinAnsi(dibujar(pestana(["acciones"], "normal"), e, opciones()).lineas).some((x) => x.includes("$ ls")));
});

test("dibujo: la pestaña Chat por defecto se ve como la TUI de hoy", () => {
  const e: Entrada[] = [
    { id: 1, tipo: "mensajes", texto: "hola mundo" },
    { id: 2, tipo: "texto", markdown: "**hola** che", completo: true },
    accion(3),
    accion(4, { estado: "error", resumen: "falló" }),
  ];
  const { lineas, desde } = dibujar(PESTANA_CHAT as Conv, e, opciones({ seleccion: 3 }));
  const esperado = ["", separador("Vos", undefined, 80, dim, dim), ...wrapText("hola mundo", 78, "  "), "", separador("Orobas", undefined, 80, accent, bold), ...renderMarkdown("**hola** che", 78), "", "  ◆ 2 acciones · 1 con error", "  ├─ ✓ HTTP · status 200", "  └─ ✗ HTTP · falló"];
  const visto = sinAnsi(lineas);
  assert.deepEqual(visto.map((l) => l.replace("▌", " ")), sinAnsi(esperado));
  assert.ok(visto.slice(desde.get(3)!, desde.get(3)! + 2).some((l) => l.startsWith("▌")));
});

test("caché: 300 entradas dibujadas 50 veces con caché dan lo mismo y bajan de 16 ms por cuadro", () => {
  const e: Entrada[] = [];
  for (let i = 0; i < 100; i++) {
    const id = i * 3 + 1;
    e.push({ id, tipo: "mensajes", texto: `pregunta número ${i} sobre el objetivo con bastante texto para que haya que envolverlo en más de una línea de la terminal` });
    e.push({ id: id + 1, tipo: "texto", markdown: `## Paso ${i}\n\nResultado con **negrita**, \`código\` y una lista:\n\n- uno ${i}\n- dos\n- tres con un texto largo que se tiene que cortar en varias líneas al envolverlo`, completo: true });
    e.push(accion(id + 2, { resumen: `status ${i}` }));
  }
  const p = pestana(["mensajes", "texto", "acciones"], "normal");
  const sin = () => dibujar(p, e, opciones());
  const cache = new Map();
  const con = () => dibujar(p, e, opciones({ cache }));
  const medir = (f: () => unknown) => { const t0 = performance.now(); for (let i = 0; i < 50; i++) f(); return (performance.now() - t0) / 50; };
  con();
  const antes = medir(sin);
  const despues = medir(con);
  console.log(`medición I1: sin caché ${antes.toFixed(2)} ms/cuadro · con caché ${despues.toFixed(2)} ms/cuadro`);
  assert.deepEqual(con(), sin());
  assert.ok(despues < 16, `${despues} ms por cuadro`);
  assert.ok(despues < antes / 3, `${despues} ms con caché contra ${antes} sin caché`);
  // Un cambio en una entrada se ve; el resto sale del caché.
  (e[1] as { markdown: string }).markdown += "\n\nmás texto";
  assert.deepEqual(con(), sin());
});

test("I2: una acción en curso con herramienta viva no se dibuja en mínimo ni normal; sin herramienta o en completo lleva una marca neutra, nunca ✓", () => {
  const e: Entrada[] = [accion(1, { estado: "en curso", resumen: "" })];
  const vivas = new Set(["c1"]);
  for (const d of ["minimo", "normal"] as const) assert.deepEqual(dibujar(pestana(["acciones"], d), e, opciones({ vivas })).lineas, []);
  const sinHerramienta = sinAnsi(dibujar(pestana(["acciones"], "normal"), e, opciones({ vivas: new Set() })).lineas).join("\n");
  assert.match(sinHerramienta, /· HTTP/);
  assert.doesNotMatch(sinHerramienta, /✓/);
  const completo = sinAnsi(dibujar(pestana(["acciones"], "completo"), e, opciones({ vivas })).lineas).join("\n");
  assert.match(completo, /· HTTP/);
  assert.doesNotMatch(completo, /✓/);
  // Al terminar, la misma entrada se dibuja con ✓ aunque el caché la tenga como oculta.
  const cache = new Map();
  assert.deepEqual(dibujar(pestana(["acciones"], "normal"), e, opciones({ vivas, cache })).lineas, []);
  (e[0] as { estado: string }).estado = "ok";
  assert.match(sinAnsi(dibujar(pestana(["acciones"], "normal"), e, opciones({ vivas, cache })).lineas).join("\n"), /✓ HTTP/);
});

test("temas: el panel usa los bordes del tema", () => {
  try {
    usarTema("hacker");
    const h = dibujarPanel({ title: "T", lines: ["x"] }, 40).map(stripAnsi);
    assert.ok(h[1]!.startsWith("  +- T -"));
    assert.ok(h.at(-1)!.startsWith("  +-"));
    usarTema("filete");
    assert.ok(stripAnsi(dibujarPanel({ title: "T", lines: ["x"] }, 40)[1]!).includes("╔═ ❦ T ❦ ═"));
  } finally { usarTema("orobas"); }
});

test("temas: un aviso warn lleva el símbolo del tema al principio", () => {
  const aviso = (texto: string) => sinAnsi(dibujar(pestana(["avisos"], "normal"), [{ id: 1, tipo: "avisos", texto, tono: "warn" }], opciones()).lineas ?? []).filter(Boolean);
  try {
    usarTema("ambar");
    assert.deepEqual(aviso("vence"), ["  [!] vence"]);
    usarTema("orobas");
    assert.deepEqual(aviso("vence"), ["  ⚠ vence"]);
    assert.deepEqual(aviso("⚠ vence"), ["  ⚠ vence"]);
  } finally { usarTema("orobas"); }
});

test("temas: las marcas de acción son las del tema", () => {
  try {
    usarTema("hacker");
    const ver = (estado: "ok" | "error") => sinAnsi(dibujar(pestana(["acciones"], "normal"), [accion(1, { estado })], opciones()).lineas ?? []).join("\n");
    assert.match(ver("ok"), /\[\+\]/);
    assert.match(ver("error"), /\[!\]/);
  } finally { usarTema("orobas"); }
});

test("tema: cambiarlo invalida el caché de entradas", () => {
  const cache = new Map();
  try {
    usarTema("orobas");
    dibujar(pestana(["acciones"], "normal"), [accion(1)], opciones({ cache }));
    usarTema("hacker");
    assert.match(sinAnsi(dibujar(pestana(["acciones"], "normal"), [accion(1)], opciones({ cache })).lineas).join("\n"), /\[\+\]/);
  } finally { usarTema("orobas"); }
});

test("mensajes: separador con nombre y hora", () => {
  const en = new Date(2026, 10, 16, 23, 41).getTime();
  const e: Entrada[] = [{ id: 1, tipo: "mensajes", texto: "hola", en }, { id: 2, tipo: "texto", markdown: "ok", completo: true, en }];
  const l = sinAnsi(dibujar(PESTANA_CHAT as Conv, e, opciones({ ancho: 60 })).lineas);
  const vos = l.find((x) => x.startsWith("  ── Vos "))!;
  assert.equal(vos, "  ── Vos " + "─".repeat(60 - "  ── Vos ".length - " 23:41 ──".length) + " 23:41 ──");
  assert.equal(vos.length, 60);
  const oro = l.find((x) => x.startsWith("  ── Orobas ─"))!;
  assert.equal(oro.length, 60);
  assert.match(oro, / 23:41 ──$/);
  const sin = sinAnsi(dibujar(PESTANA_CHAT as Conv, [{ id: 1, tipo: "mensajes", texto: "hola" }], opciones({ ancho: 60 })).lineas);
  assert.match(sin[1]!, /^  ── Vos ─+──$/);
  assert.equal(sin[1]!.length, 60);
  const previo = process.env.LC_ALL;
  process.env.LC_ALL = "en_US.UTF-8";
  try {
    assert.match(sinAnsi(dibujar(PESTANA_CHAT as Conv, [{ id: 1, tipo: "mensajes", texto: "hola" }], opciones({ ancho: 60 })).lineas)[1]!, /^  ── You /);
  } finally { if (previo === undefined) delete process.env.LC_ALL; else process.env.LC_ALL = previo; }
});

test("mensajes: el separador nunca pasa del ancho en terminales angostas", () => {
  const en = new Date(2026, 10, 16, 23, 41).getTime();
  for (const [nombre, minimo] of [["Vos", 19], ["Orobas", 22]] as const) {
    for (let ancho = 6; ancho <= 30; ancho++) {
      const l = stripAnsi(separador(nombre, en, ancho, dim, dim));
      assert.ok(l.length <= ancho, `${nombre} a ${ancho}: «${l}»`);
      if (ancho >= minimo) assert.equal(l.length, ancho);
      if (ancho >= minimo) assert.match(l, / 23:41 ──$/);
    }
    assert.doesNotMatch(stripAnsi(separador(nombre, en, minimo - 1, dim, dim)), /23:41/);
  }
});

test("árbol: acciones seguidas se agrupan con título y ramas", () => {
  const e = [accion(1, { inicio: 0, fin: 10_000 }), accion(2, { inicio: 10_000, fin: 20_000 }), accion(3, { estado: "error", resumen: "falló", inicio: 20_000, fin: 32_000 })];
  assert.deepEqual(sinAnsi(dibujar(pestana(["acciones"], "normal"), e, opciones()).lineas), ["", "  ◆ 3 acciones · 32 s · 1 con error", "  ├─ ✓ HTTP · status 200", "  ├─ ✓ HTTP · status 200", "  └─ ✗ HTTP · falló"]);
});

test("árbol: sin errores no dice «con error» y sin tiempos no dice segundos", () => {
  const l = sinAnsi(dibujar(pestana(["acciones"], "normal"), [accion(1), accion(2)], opciones()).lineas);
  assert.equal(l[1], "  ◆ 2 acciones");
});

test("árbol: una sola acción no lleva título ni rama", () => {
  assert.deepEqual(sinAnsi(dibujar(pestana(["acciones"], "normal"), [accion(1)], opciones()).lineas), ["", "  ✓ HTTP · status 200"]);
});

test("árbol: los resultados cuelgan alineados", () => {
  const e = [accion(1), resultado(2, "uno"), accion(3), { ...resultado(4, "dos"), llamada: "c3" }];
  const l = sinAnsi(dibujar(pestana(["acciones", "resultados"], "completo"), e, opciones()).lineas);
  assert.ok(l.includes("  │    │ uno"));
  assert.ok(l.includes("       │ dos"));
});

test("árbol: un texto en el medio corta el grupo", () => {
  const e: Entrada[] = [accion(1), { id: 2, tipo: "texto", markdown: "hola", completo: true }, accion(3)];
  const l = sinAnsi(dibujar(pestana(["acciones", "texto"], "normal"), e, opciones()).lineas);
  assert.ok(!l.some((x) => x.includes("◆") || x.includes("├─") || x.includes("└─")));
});

test("árbol: sumar una acción con el caché compartido reescribe las ramas", () => {
  const cache = new Map();
  dibujar(pestana(["acciones"], "normal"), [accion(1)], opciones({ cache }));
  const l = sinAnsi(dibujar(pestana(["acciones"], "normal"), [accion(1), accion(2)], opciones({ cache })).lineas);
  assert.deepEqual(l, ["", "  ◆ 2 acciones", "  ├─ ✓ HTTP · status 200", "  └─ ✓ HTTP · status 200"]);
});

test("árbol: en inglés el título dice actions y failed; 0 s no se muestra", () => {
  const antes = process.env.LC_ALL;
  process.env.LC_ALL = "en_US.UTF-8";
  try {
    const e = [accion(1, { inicio: 0, fin: 1 }), accion(2, { inicio: 1, fin: 32_000 }), accion(3, { estado: "error", inicio: 2, fin: 3 })];
    assert.equal(sinAnsi(dibujar(pestana(["acciones"], "normal"), e, opciones()).lineas)[1], "  ◆ 3 actions · 32 s · 1 failed");
    assert.equal(sinAnsi(dibujar(pestana(["acciones"], "normal"), [accion(1, { inicio: 0, fin: 100 }), accion(2, { inicio: 0, fin: 200 })], opciones()).lineas)[1], "  ◆ 2 actions");
  } finally {
    if (antes === undefined) delete process.env.LC_ALL; else process.env.LC_ALL = antes;
  }
});

test("descifrado: no cambia líneas ni anchos del Markdown", () => {
  usarTema("hacker");
  try {
  const md = "Hola **negrita** y *cursiva* con `código` é ñ 😀\n\n- uno 12\n- dos\n\n```\nlet x = 1;\n```\n\n| a | b |\n|---|---|\n| 1 | dos |";
  const e: Entrada[] = [{ id: 1, tipo: "texto", markdown: md, completo: false, llegadas: [[0, 1000]] }];
  const p = pestana(["texto"], "normal");
  const con = dibujar(p, e, opciones({ ahora: 1100 }));
  const sin = dibujar(p, e, opciones());
  assert.equal(con.animando, true);
  assert.equal(con.lineas.length, sin.lineas.length);
  con.lineas.forEach((l, i) => assert.equal(visibleWidth(l), visibleWidth(sin.lineas[i]!), l));
  assert.notDeepEqual(sinAnsi(con.lineas), sinAnsi(sin.lineas));
  // pasado el plazo, con el mismo caché sale el texto resuelto
  const cache = new Map();
  dibujar(p, e, opciones({ ahora: 1100, cache }));
  const fin = dibujar(p, e, opciones({ ahora: 5000, cache }));
  assert.equal(fin.animando, false);
  assert.deepEqual(fin.lineas, sin.lineas);
  } finally { usarTema("orobas"); }
});

test("descifrado: sólo en lo que llega en vivo", () => {
  usarTema("hacker");
  try {
  const e: Entrada[] = [{ id: 1, tipo: "texto", markdown: "Hola mundo", completo: true }];
  const p = pestana(["texto"], "normal");
  const con = dibujar(p, e, opciones({ ahora: 1100 }));
  assert.deepEqual(con.lineas, dibujar(p, e, opciones()).lineas);
  assert.equal(con.animando, false);
  } finally { usarTema("orobas"); }
});

test("descifrado: la acción en curso muestra el cuadro del spinner y las terminadas siguen en caché", () => {
  const p = pestana(["acciones"], "completo");
  const cache = new Map();
  const e = [accion(1, { estado: "en curso" }), accion(2)];
  assert.match(sinAnsi(dibujar(p, e, opciones({ cache, marco: "⠋" })).lineas).join("\n"), /⠋ /);
  const hecha = cache.get(2).lineas;
  assert.match(sinAnsi(dibujar(p, e, opciones({ cache, marco: "⠙" })).lineas).join("\n"), /⠙ /);
  assert.equal(cache.get(2).lineas, hecha);
});

test("dibujo: con herramientas en paralelo cada resultado queda bajo su propia acción", () => {
  const e: Entrada[] = [
    accion(1, { llamada: "A", etiqueta: "AAA" }),
    accion(2, { llamada: "B", etiqueta: "BBB" }),
    { id: 3, tipo: "resultados", llamada: "B", texto: "res-de-B" },
    { id: 4, tipo: "resultados", llamada: "A", texto: "res-de-A" },
  ];
  const l = sinAnsi(dibujar(pestana(["acciones", "resultados"], "completo"), e, opciones()).lineas);
  // A no es la última: sus resultados llevan la columna del árbol (│); B es la última y va con espacios.
  assert.ok(l.find((x) => x.includes("res-de-A"))!.startsWith("  │"), l.join("\n"));
  assert.ok(!l.find((x) => x.includes("res-de-B"))!.startsWith("  │"), l.join("\n"));
});

test("separador y panel: los glifos de la TUI van entre marcas de adorno, el nombre no", () => {
  const en = new Date(2026, 10, 16, 23, 41).getTime();
  const sep = separador("Vos", en, 40, dim, dim);
  assert.ok(sep.startsWith(`  ${ADORNO_ABRE}`) && sep.includes(`${ADORNO_ABRE}${dim("── ")}`));
  assert.ok(sep.includes(`${ADORNO_ABRE}${dim(" 23:41 ")}${ADORNO_CIERRA}`));
  const fuera = sep.replace(new RegExp(`${ADORNO_ABRE.replace("[", "\\[")}.*?${ADORNO_CIERRA.replace("[", "\\[")}`, "g"), "");
  assert.match(stripAnsi(fuera), /Vos/);
  assert.doesNotMatch(stripAnsi(fuera), /[─\d]/);
  const p = dibujarPanel({ title: "T", lines: ["x"] }, 40);
  const cuerpo = p[2]!;
  assert.match(cuerpo, new RegExp(`^  ${ADORNO_ABRE.replace("[", "\\[")}[^]*?│[^]*?${ADORNO_CIERRA.replace("[", "\\[")}`));
  assert.ok(cuerpo.endsWith(ADORNO_CIERRA) && cuerpo.includes("│"));
  for (const borde of [p[1]!, p.at(-1)!]) assert.ok(borde.startsWith(`  ${ADORNO_ABRE}`) && borde.endsWith(ADORNO_CIERRA));
});

test("lista en panel: el marcador no es punto de corte y la continuación sangra bajo el texto con su marca", () => {
  const l = dibujarPanel({ title: "T", lines: [`${adornoTUI(" ")} ${"palabra ".repeat(8)}`, `${adornoTUI(accent("▌"))} ${"palabra ".repeat(8)}`] }, 30);
  const filas = l.slice(2, -1).map(stripAnsi);
  assert.ok(filas.length >= 4);
  assert.match(filas[0]!, /^ {2}│ {3}palabra/);
  assert.match(filas[1]!, /^ {2}│ {3}palabra/); // sangría de ancho marcador+espacio
  assert.ok(l[3]!.includes(CORTE_ESPACIO));
  const sel = l.findIndex((x) => x.includes("▌"));
  assert.match(stripAnsi(l[sel + 1]!), /^ {2}│ {3}palabra/);
  assert.ok(l[sel + 1]!.includes(CORTE_ESPACIO));
});

test("resultados: el │ del árbol de acciones va dentro de un adorno", () => {
  const e: Entrada[] = [accion(1), accion(2), resultado(3, "cuerpo")];
  const fila = dibujar(pestana(["acciones", "resultados"], "completo"), e, opciones()).lineas.find((x) => stripAnsi(x).includes("cuerpo"))!;
  const m = new RegExp(`${ADORNO_ABRE.replace("[", "\\[")}[^]*?${ADORNO_CIERRA.replace("[", "\\[")}`, "g");
  const dentro = [...fila.matchAll(m)].map((x) => stripAnsi(x[0])).join("");
  assert.equal((dentro.match(/│/g) ?? []).length, 2); // el del árbol y el del resultado
});
