import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { cliHelp, formatManual, manualEntries, ROOT, searchManual } from "../src/manual.ts";

test("manual: el agente encuentra comandos del operador, herramientas, MCP y guías", () => {
  const entries = manualEntries({ tools: [{ name: "http_request", label: "HTTP", description: "Envía una petición; responde un desafío Digest", loaded: true }], mcp: ["vulndb"] });
  const kinds = new Set(entries.map((entry) => entry.kind));
  for (const kind of ["cli", "tui", "herramienta", "mcp", "guia"]) assert.ok(kinds.has(kind as never), `falta ${kind}`);
  // La pregunta de la sesión real: «¿tenés HackerOne?» tiene que devolver el comando del operador, no un «no».
  const h1 = searchManual(entries, "hackerone programa");
  assert.ok(h1.some((entry) => entry.kind === "tui" && entry.name === "/h1"), formatManual(h1));
  assert.ok(h1.some((entry) => entry.kind === "cli" && /cyber h1/.test(entry.name)));
  assert.ok(searchManual(entries, "digest").some((entry) => entry.kind === "herramienta" && entry.name.startsWith("http_request")));
  assert.ok(searchManual(entries, "vulndb").some((entry) => entry.kind === "mcp"));
  assert.ok(searchManual(entries, "tope proyecto").some((entry) => entry.kind === "cli" && /tope/.test(entry.name)));
  assert.ok(searchManual(entries, "docker").some((entry) => entry.kind === "guia"));
  assert.match(formatManual(searchManual(entries, "zzz-nada")), /Nada en el manual/);
});

test("manual: /help lista /orobas y /hackerone y la ayuda describe el lanzador", () => {
  const entries = manualEntries();
  for (const name of ["/orobas", "/hackerone", "/github"]) assert.ok(entries.some((entry) => entry.kind === "tui" && entry.name === name), name);
  const help = cliHelp();
  for (const flag of ["--instalar", "--actualizar", "--resumen", "cyber orobas"]) assert.ok(help.includes(flag), flag);
  assert.ok(!help.includes(".cyber/"));
  for (const file of ["README.md"]) assert.ok(!readFileSync(join(ROOT, file), "utf8").includes(".cyber/"), file);
});
