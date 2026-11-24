import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

test("filtro: 2 MiB, entradas adversas y profundidad sin retroceso explosivo", (t) => {
  // El subproceso impone un corte real si una regexp bloqueara el hilo principal.
  const output = execFileSync(process.execPath, ["--disable-warning=ExperimentalWarning", fileURLToPath(new URL("./fixtures/filtro-agentes/rendimiento.ts", import.meta.url))], { encoding: "utf8", timeout: 20_000 });
  const rows = JSON.parse(output) as Array<{ name: string; bytes: number; cpuMs: number; wallMs: number }>;
  assert.equal(rows.length, 14);
  for (const row of rows) {
    t.diagnostic(`${row.name}: ${row.bytes} bytes; CPU ${row.cpuMs.toFixed(1)} ms; reloj ${row.wallMs.toFixed(1)} ms`);
    // npm test corre otros procesos a la vez: el presupuesto de CPU no cuenta el tiempo sin turno.
    assert.ok(row.cpuMs < 100, `${row.name}: ${row.cpuMs.toFixed(1)} ms de CPU`);
  }
});
