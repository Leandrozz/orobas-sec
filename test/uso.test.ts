import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Ledger } from "../src/ledger.ts";
import { usageHeaders } from "../src/llm.ts";
import { usdToPico } from "../src/money.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { usageExport } from "../src/views.ts";

test("uso: las etiquetas viajan sólo al servicio propio, y la exportación junta sesiones, solicitudes y hallazgos", () => {
  const own = { provider: "orobas", id: "m", baseUrl: "https://cyber.elevateai.ar/api/v1" } as any;
  const other = { provider: "ejemplo", id: "m", baseUrl: "https://api.example.org/v1" } as any;
  assert.deepEqual(usageHeaders(other, { session: "s1", worker: "principal" }), {});
  const headers = usageHeaders(own, { session: "s1", worker: "verificador:1", project: "mi proyecto ñ" });
  assert.equal(headers["x-cyber-session"], "s1");
  assert.equal(headers["x-cyber-worker"], "verificador:1");
  assert.equal(headers["x-cyber-project"], "mi proyecto ");
  assert.ok(headers["x-cyber-version"]);

  const cwd = mkdtempSync(join(tmpdir(), "cyber-uso-"));
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const ledger = new Ledger(db, usdToPico("5.00"));
  try {
    db.prepare("insert into sessions(id,started_at,model) values('s1','2026-11-13T01:00:00.000Z','orobas/m')").run();
    db.prepare(
      "insert into requests(provider,account,request_id,session_id,worker,model,at,stop_reason,input,cache_read,cache_write,output,cost_input,cost_cache_read,cost_cache_write,cost_output) values('orobas','OROBAS_API_KEY','r1','s1','principal','m','2026-11-13T01:00:05.000Z','stop',100,0,0,20,?,'0','0','0')",
    ).run(String(usdToPico("0.01")));
    db.exec("create table if not exists findings(id text primary key, json text not null)");
    db.prepare("insert into findings(id,json) values('f1',?)").run(JSON.stringify({ id: "f1", state: "candidato", title: "Prueba", kind: "x", severity: "media", asset: "a", decidedBy: "agente", createdAt: "2026-11-13T01:00:10.000Z" }));
    const lines = usageExport(ledger, "proyecto", cwd);
    assert.match(lines[0]!, /USD 0\.010000 · 1 solicitudes · 1 sesiones/);
    const file = lines.at(-1)!.match(/Exportado a (\S+)/)![1]!;
    assert.ok(existsSync(file));
    const data = JSON.parse(readFileSync(file, "utf8"));
    assert.equal(data.sesiones[0].solicitudes, 1);
    assert.equal(data.solicitudes[0].worker, "principal");
    assert.equal(data.hallazgos[0].titulo, "Prueba");
    assert.ok(!JSON.stringify(data).includes("oro_"));
  } finally {
    db.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});
