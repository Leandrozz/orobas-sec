import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { test } from "node:test";
import { Harnesses, parsearVer } from "../src/tui/harnesses.ts";

import { Orquesta, type Run } from "../src/orquesta.ts";

const run = (r: Partial<Run>): Run => ({ id: "a3f", harness: "claude", task: "arreglá el login", state: "corriendo", cwd: "/c", command: "x", log: "/l", startedAt: Date.parse("2026-11-17T21:40:00Z"), ...r } as Run);
const ver = (r: Run) => Orquesta.prototype.summary.call(null as never, r).split("\n");
// view() real de Orquesta, con corridas en memoria y las anteriores inyectadas.
const vista = (vivas: Run[], viejas: Run[]) => (Object.assign(Object.create(Orquesta.prototype), { runs: new Map(vivas.map((r) => [r.id, r])), saved: () => viejas }) as Orquesta).view();
const LISTA = vista([run({ branch: "orobas/login-1" })], [run({ id: "b4", state: "terminado", task: "vieja" })]);
const T0 = Date.parse("2026-11-17T21:40:00Z");
const VER = ver(run({ endedAt: T0 + 42_000, worktree: "/w", branch: "orobas/login-1", tail: "linea 1\nlinea 2" }));
const VER_FIN = ver(run({ state: "terminado", exitCode: 0, endedAt: Date.parse("2026-11-17T21:40:50Z"), tail: "" }));

function falso(ver: () => string[]) {
  const llamadas: object[] = [];
  const ask = async (_op: string, p: object) => { llamadas.push(p); if ("action" in p) return ver(); return LISTA; };
  return { ask, llamadas };
}

test("harnesses: la lista se lee con leerCorridas y marca anteriores", async () => {
  const h = new Harnesses(falso(() => VER).ask);
  const r = await h.refrescar();
  assert.deepEqual(r.map((x) => [x.id, x.anterior, x.enCurso, x.cola]), [["a3f", false, true, ""], ["b4", true, false, ""]]);
  assert.equal(h.de("a3f")?.rama, "orobas/login-1");
});

test("harnesses: ver trae estado, segundos, salida y la cola después de «salida (final):»", async () => {
  assert.deepEqual(parsearVer(VER), { estado: "corriendo", segundos: 42, salida: undefined, cola: "linea 1\nlinea 2" });
  assert.deepEqual(parsearVer(["#a3f · Claude Code · terminado · 5 s · salida 2", "salida (final):", "x"]), { estado: "terminado", segundos: 5, salida: 2, cola: "x" });
  const h = new Harnesses(falso(() => VER).ask);
  await h.refrescar();
  const r = await h.seguir("a3f");
  assert.equal(r?.cola, "linea 1\nlinea 2");
  assert.equal(r?.segundos, 42);
});

test("harnesses: «(sin salida todavía)» deja la cola vacía", async () => {
  assert.deepEqual(parsearVer(VER_FIN), { estado: "terminado", segundos: 50, salida: 0, cola: "" });
});

test("harnesses: una corrida anterior no pide ver", async () => {
  const f = falso(() => VER);
  const h = new Harnesses(f.ask);
  await h.refrescar();
  const n = f.llamadas.length;
  assert.equal((await h.seguir("b4"))?.anterior, true);
  assert.equal(await h.seguir("zzz"), undefined);
  assert.equal(f.llamadas.length, n);
});

test("harnesses: si ver falla queda error y no tira; refrescar conserva la cola", async () => {
  let falla = false;
  const f = falso(() => { if (falla) throw new Error("boom"); return VER; });
  const h = new Harnesses(f.ask);
  await h.refrescar();
  await h.seguir("a3f");
  falla = true;
  const r = await h.seguir("a3f");
  assert.equal(r?.error, "boom");
  assert.equal(r?.cola, "linea 1\nlinea 2");
  await h.refrescar();
  assert.equal(h.de("a3f")?.cola, "linea 1\nlinea 2");
  assert.equal(h.de("a3f")?.segundos, 42);
  assert.equal(h.de("a3f")?.error, "boom");
  falla = false;
  assert.equal((await h.seguir("a3f"))?.error, undefined);
});

const diferido = () => { let ok!: (l: string[]) => void; const p = new Promise<string[]>((r) => { ok = r; }); return { p, ok }; };
const verCon = (cola: string) => ver(run({ endedAt: T0 + 1000, tail: cola }));

test("harnesses: refrescar borra una corrida que desaparece de la lista", async () => {
  let lista = LISTA;
  const h = new Harnesses(async () => lista);
  await h.refrescar();
  lista = LISTA.filter((l) => !l.startsWith("#b4"));
  await h.refrescar();
  assert.equal(h.de("b4"), undefined);
  assert.ok(h.de("a3f"));
});

test("harnesses: ver ilegible no pisa nada y marca error", async () => {
  let r = VER;
  const h = new Harnesses(async (_o, p) => ("action" in p ? r : LISTA));
  await h.refrescar();
  await h.seguir("a3f");
  r = ["basura"];
  const x = await h.seguir("a3f");
  assert.ok(x?.error);
  assert.equal(x?.cola, "linea 1\nlinea 2");
});

test("harnesses: seguir en vuelo, refrescar completo, seguir resuelve: la cola nueva queda en la fila vigente", async () => {
  const d = diferido();
  const h = new Harnesses((_o, p) => ("action" in p ? d.p : Promise.resolve(LISTA)));
  await h.refrescar();
  const s = h.seguir("a3f");
  await h.refrescar();
  d.ok(verCon("nueva"));
  const r = await s;
  assert.equal(h.de("a3f")?.cola, "nueva");
  assert.equal(r, h.de("a3f"));
});

test("harnesses: dos seguir, el primero resuelve último: queda la cola del segundo", async () => {
  const ds = [diferido(), diferido()];
  let i = 0;
  const h = new Harnesses((_o, p) => ("action" in p ? ds[i++]!.p : Promise.resolve(LISTA)));
  await h.refrescar();
  const a = h.seguir("a3f");
  const b = h.seguir("a3f");
  ds[1]!.ok(verCon("segunda"));
  await b;
  ds[0]!.ok(verCon("primera"));
  await a;
  assert.equal(h.de("a3f")?.cola, "segunda");
});

test("harnesses: dos refrescar fuera de orden: queda la lista del último lanzado", async () => {
  const ds = [diferido(), diferido()];
  let i = 0;
  const h = new Harnesses(() => ds[i++]!.p);
  const a = h.refrescar();
  const b = h.refrescar();
  ds[1]!.ok(LISTA.slice(0, 2));
  await b;
  ds[0]!.ok(LISTA);
  await a;
  assert.equal(h.de("b4"), undefined);
  assert.ok(h.de("a3f"));
});

test("harnesses: refrescar no propaga el error de ask: guarda errorLista y devuelve lo vigente", async () => {
  let falla = false;
  const h = new Harnesses(async () => { if (falla) throw new Error("sin daemon"); return LISTA; });
  await h.refrescar();
  falla = true;
  const r = await h.refrescar();
  assert.deepEqual(r.map((x) => x.id), ["a3f", "b4"]);
  assert.equal(h.errorLista, "sin daemon");
  falla = false;
  await h.refrescar();
  assert.equal(h.errorLista, undefined);
});

test("harnesses: la cola se limpia de escapes, de OSC 52, de lo que un \\r sobreescribe y de controles", () => {
  const sucia = ["#a3f · Claude Code · corriendo · 5 s", "salida (final):", "\x1b[31mrojo\x1b[0m \x1b]52;c;QUJD\x07fin", "50%\r100%\r", "a\x07b\x00c\x7fd", "x\r"];
  assert.equal(parsearVer(sucia).cola, "rojo fin\n100%\nabcd\nx");
});
