import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { abrirProyecto, arregloGuardado, guardarArreglo } from "../src/tui/ajustes.ts";
import { PESTANA_CHAT } from "../src/tui/pestanas.ts";
import { cantidad, repartir, validarArreglo, type Rect } from "../src/tui/ventanas.ts";

const area = (ancho: number, alto: number): Rect => ({ x: 0, y: 0, ancho, alto });
const visibles = (r: ReturnType<typeof repartir>) => r.ventanas.filter((v): v is Rect => !!v);
const sinSuperponer = (rs: Rect[]) => rs.every((a, i) => rs.every((b, j) => i >= j || a.x + a.ancho <= b.x || b.x + b.ancho <= a.x || a.y + a.alto <= b.y || b.y + b.alto <= a.y));

test("repartir: «una» ocupa toda el área", () => {
  const r = repartir("una", area(120, 30), {}, false, 0);
  assert.deepEqual(r.ventanas, [{ x: 0, y: 0, ancho: 120, alto: 30 }]);
  assert.equal(r.ocultas, 0);
});

test("repartir: «lado» parte al medio y «lateral» deja la ancha a la izquierda", () => {
  const lado = repartir("lado", area(120, 30), {}, false, 0).ventanas as Rect[];
  assert.deepEqual(lado.map((v) => v.ancho), [60, 60]);
  assert.deepEqual(lado.map((v) => v.x), [0, 60]);
  const lat = repartir("lateral", area(120, 30), {}, false, 0).ventanas as [Rect, Rect];
  assert.ok(lat[0].ancho > lat[1].ancho && lat[1].ancho >= 40);
  assert.equal(lat[0].ancho + lat[1].ancho, 120);
});

test("repartir: «tres» y «cuatro» apilan a la derecha / en cuadrícula", () => {
  const [a, b, c] = repartir("tres", area(120, 30), {}, false, 0).ventanas as [Rect, Rect, Rect];
  assert.equal(a.alto, 30);
  assert.equal(b.x, c.x);
  assert.deepEqual([b.alto, c.alto], [15, 15]);
  const cuatro = repartir("cuatro", area(120, 30), {}, false, 0).ventanas as Rect[];
  assert.ok(cuatro.every((v) => v.ancho === 60 && v.alto === 15));
  assert.ok(sinSuperponer(cuatro));
});

test("repartir: con la lista, ocupa 24 columnas a la izquierda y las ventanas empiezan en x=24", () => {
  const r = repartir("lado", area(130, 30), {}, true, 0);
  assert.deepEqual(r.lista, { x: 0, y: 0, ancho: 24, alto: 30 });
  assert.deepEqual((r.ventanas as Rect[]).map((v) => v.x), [24, 77]);
  assert.equal(r.forma, "lado");
});

test("repartir: terminal chica esconde la lista primero y después degrada", () => {
  const a = repartir("lado", area(100, 30), {}, true, 0);
  assert.equal(a.lista, undefined);
  assert.equal(visibles(a).length, 2);
  const u60 = repartir("una", area(60, 30), {}, true, 0);
  assert.equal(u60.lista, undefined);
  assert.equal(u60.ventanas[0]?.ancho, 60);
  const u70 = repartir("una", area(70, 30), {}, true, 0);
  assert.ok(u70.lista);
  assert.equal(u70.ventanas[0]?.ancho, 46);
  assert.equal(repartir("cuatro", area(100, 12), {}, true, 0).lista, undefined);
  const b = repartir("cuatro", area(100, 12), {}, false, 3);
  assert.equal(b.forma, "lado");
  assert.equal(b.ocultas, 2);
  assert.ok(b.ventanas[3]);
  const c = repartir("lado", area(70, 30), {}, false, 1);
  assert.equal(c.forma, "una");
  assert.equal(c.ocultas, 1);
  assert.ok(c.ventanas[1] && !c.ventanas[0]);
});

test("validarArreglo: sin valor usa las pestañas previas como única ventana; forma inválida es «una»; ajusta la cantidad de listas a la forma", () => {
  const previas = [{ ...PESTANA_CHAT, nombre: "X" }];
  assert.deepEqual(validarArreglo(undefined, previas), { forma: "una", pestanas: [previas], divisores: {}, lista: false });
  assert.equal(validarArreglo({ forma: "rara" }, previas).forma, "una");
  const tres = validarArreglo({ forma: "tres", pestanas: [[PESTANA_CHAT]], divisores: { x: 0.95, y: 0.4 }, lista: true }, previas);
  assert.equal(tres.pestanas.length, cantidad("tres"));
  assert.deepEqual(tres.pestanas[2], [PESTANA_CHAT]);
  assert.deepEqual(tres.divisores, { y: 0.4 });
  assert.equal(tres.lista, true);
  assert.equal(validarArreglo({ forma: "una", pestanas: [[PESTANA_CHAT], [PESTANA_CHAT]] }, previas).pestanas.length, 1);
});

test("ajustes: guardarArreglo escribe «ventanas» y también «pestanas» con la ventana 0", () => {
  const prev = process.env.CYBER_CONFIG;
  process.env.CYBER_CONFIG = join(mkdtempSync(join(tmpdir(), "cyber-vent-")), "config.json");
  try {
    abrirProyecto("/p");
    const otra = [{ ...PESTANA_CHAT, nombre: "Otra" }];
    const arreglo = { forma: "lado" as const, pestanas: [otra, [PESTANA_CHAT]], divisores: { x: 0.4 }, lista: true };
    guardarArreglo(arreglo);
    const p = JSON.parse(readFileSync(process.env.CYBER_CONFIG, "utf8"));
    assert.deepEqual(p.ventanas, arreglo, "general, no dentro del proyecto");
    assert.deepEqual(p.pestanas, otra);
    assert.deepEqual(arregloGuardado(), arreglo);
  } finally {
    abrirProyecto("");
    if (prev === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev;
  }
});
