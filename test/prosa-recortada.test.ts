import "./datos-tmp.ts";
// De las trazas reales: ~40 llamadas rechazadas enteras por «argumentos.note: máximo 600 caracteres»,
// «summary: máximo 1200», «limits: máximo 300». Un texto para personas que se pasa se recorta con «…»
// y se avisa; un campo con semántica (cuerpo, comando, URL) sigue fallando.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fitProse, PROSE_FIELDS, validate } from "../src/agent.ts";
import { Engine } from "../src/engine.ts";
import { usdToPico } from "../src/money.ts";
import { resolveProvider } from "../src/providers.ts";

const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });

test("prosa: recorta al máximo con «…», dice qué recortó y no toca lo que tiene semántica", () => {
  const schema = {
    type: "object",
    properties: {
      note: { type: "string", maxLength: 10 },
      body: { type: "string", maxLength: 10 },
      etiqueta: { type: "string", maxLength: 5, truncate: true },
      title: { type: "string", maxLength: 5, truncate: false },
      items: { type: "array", items: { type: "object", properties: { reason: { type: "string", maxLength: 4 } } } },
    },
  };
  const args = { note: "una nota bastante larga", body: "0123456789AB", etiqueta: "abcdefgh", title: "titulo largo", items: [{ reason: "corto" }, { reason: "ok" }] };
  const { value, trimmed } = fitProse(schema, args) as { value: Record<string, any>; trimmed: Array<{ path: string; from: number; to: number }> };
  assert.equal(value.note, "una nota…");
  assert.equal(value.note.length, 9, "nunca más largo que el máximo");
  assert.equal(value.etiqueta, "abcd…", "truncate: true habilita un campo que no está en la lista");
  assert.equal(value.title, "titulo largo", "truncate: false lo excluye aunque el nombre esté en la lista");
  assert.equal(value.body, "0123456789AB", "un cuerpo no se recorta");
  assert.equal(value.items[0].reason, "cor…");
  assert.equal(value.items[1], args.items[1], "lo que no cambió no se copia");
  assert.deepEqual(trimmed.map((item) => item.path), ["argumentos.note", "argumentos.etiqueta", "argumentos.items[0].reason"]);
  assert.equal(args.note, "una nota bastante larga", "los argumentos originales no se tocan");
  // Después del recorte, lo único que falla es lo que tiene semántica.
  assert.match(validate(schema, value)!, /argumentos\.body: máximo 10 caracteres/);
  for (const name of ["note", "summary", "limits", "reason", "title", "description", "motivo", "causa", "titulo"]) assert.ok(PROSE_FIELDS.has(name), name);
  for (const name of ["command", "body", "url", "query", "data", "payload", "value", "task"]) assert.ok(!PROSE_FIELDS.has(name), name);
});

test("prosa: coverage_mark y finding_record con textos largos pasan recortados y el agente se entera", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-prosa-"));
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd, provider, budgetPico: usdToPico("1"), autoVerify: false });
  try {
    engine.scope.edit({ include: ["app.ejemplo.test"] });
    const long = (n: number) => "x".repeat(n);
    provider.faux!.queue = [
      call("coverage_mark", { category: "reconocimiento", state: "limitada", note: `${long(900)} fin` }),
      call("finding_record", { state: "pista", title: long(200), kind: "control de acceso", asset: "https://app.ejemplo.test/api/x", summary: long(2000), limits: long(500) }),
      call("http_request", { url: "https://app.ejemplo.test/", body: long(30000), method: "POST" }),
      { text: "listo" },
    ];
    await engine.send("mirá app.ejemplo.test");
    const tools = engine.agent.messages.filter((m) => m.role === "tool") as Array<{ content: string; isError?: boolean }>;
    assert.ok(!tools[0]!.isError, tools[0]!.content);
    assert.match(tools[0]!.content, /reconocimiento: limitada/);
    assert.match(tools[0]!.content, /\[aviso\] Recorté argumentos\.note a 600 caracteres \(tenía 904\)/);
    const mark = engine.coverage.marks(engine.sessionId).get("reconocimiento")!;
    assert.equal(mark.note.length, 600);
    assert.ok(mark.note.endsWith("…"));
    assert.ok(!tools[1]!.isError, tools[1]!.content);
    assert.match(tools[1]!.content, /Recorté argumentos\.title a 120 .*argumentos\.summary a 1200 .*argumentos\.limits a 300/);
    const finding = engine.findings.list()[0]!;
    assert.equal(finding.summary.length, 1200);
    assert.equal(finding.title.length, 120);
    // El cuerpo de una petición tiene semántica: sigue fallando entero.
    assert.ok(tools[2]!.isError);
    assert.match(tools[2]!.content, /argumentos\.body: máximo 20000 caracteres/);
    assert.equal(engine.http.count, 0);
  } finally {
    engine.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});
