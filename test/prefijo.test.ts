import "./datos-tmp.ts";
// Prefijo estable (src/prefijo.ts y el orden del catálogo): lo que va antes de los mensajes no cambia entre
// pasos ni al retomar, y Anthropic recibe los puntos de caché que necesita para cachear algo.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import type { Tool } from "../src/agent.ts";
import { Catalog } from "../src/catalog.ts";
import { puntosDeCacheAnthropic } from "../src/prefijo.ts";

test("Anthropic: punto de caché al final del sistema y en el último bloque del último mensaje", () => {
  type Bloque = { type: string; text?: string; cache_control?: { type: "ephemeral" } };
  const mensajes: Array<{ role: "user" | "assistant"; content: Bloque[] }> = [
    { role: "user", content: [{ type: "text", text: "hola" }] },
    { role: "assistant", content: [{ type: "tool_use" }] },
    { role: "user", content: [{ type: "tool_result" }, { type: "text", text: "nota" }] },
  ];
  const { system, messages } = puntosDeCacheAnthropic("sistema", mensajes);
  assert.deepEqual(system, [{ type: "text", text: "sistema", cache_control: { type: "ephemeral" } }]);
  assert.deepEqual(messages.map((m) => m.content.map((b) => b.cache_control?.type ?? "-")), [["-"], ["-"], ["-", "ephemeral"]]);
  assert.equal(mensajes[2]!.content[1]!.cache_control, undefined, "no modifica lo que recibe");
  assert.equal("system" in puntosDeCacheAnthropic("", mensajes), false, "un sistema vacío no se manda (Anthropic rechaza bloques vacíos)");
});

const herramienta = (name: string): Tool => ({ name, label: name, description: name, parameters: { type: "object" }, execute: () => ({ text: "" }) });

test("al retomar, las herramientas cargadas vuelven en el orden en que se cargaron", () => {
  const db = new DatabaseSync(join(mkdtempSync(join(tmpdir(), "cyber-prefijo-")), "c.db"));
  const catalogo = [herramienta("zeta_probe"), herramienta("alfa_scan"), herramienta("mail_wait")];
  const activas: Tool[] = [];
  const antes = new Catalog(db, "s1", activas, (t) => t);
  antes.register(catalogo);
  for (const nombre of ["zeta_probe", "mail_wait", "alfa_scan"]) antes.load(nombre);
  const retomadas: Tool[] = [];
  const despues = new Catalog(db, "s1", retomadas, (t) => t);
  despues.register(catalogo);
  despues.restore();
  assert.deepEqual(retomadas.map((t) => t.name), activas.map((t) => t.name));
  assert.deepEqual(retomadas.map((t) => t.name), ["zeta_probe", "mail_wait", "alfa_scan"]);
});
