import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Ledger } from "../src/ledger.ts";
import { usdToPico } from "../src/money.ts";
import { openStore, projectPaths } from "../src/store.ts";

test("ledger: el tope del proyecto suma todas las sesiones y lo fija el operador", () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-tope-"));
  const db = openStore(projectPaths(cwd));
  const ledger = new Ledger(db, usdToPico("5.00"));
  const insert = db.prepare(
    "insert into requests(provider,account,request_id,session_id,worker,model,at,stop_reason,input,cache_read,cache_write,output,cost_input,cost_cache_read,cost_cache_write,cost_output) values('faux','test',?,?,'principal','faux','2026-11-12T00:00:00.000Z','stop',10,0,0,10,?,'0','0','0')",
  );
  try {
    insert.run("r1", "s1", String(usdToPico("1.50")));
    insert.run("r2", "s2", String(usdToPico("1.50")));
    // Sin tope de proyecto, cada sesión mira sólo lo suyo y entra en los USD 5.
    assert.equal(ledger.overBudget("s2"), undefined);
    assert.equal(ledger.projectBudget(), undefined);
    // Con tope de proyecto, una sesión nueva tampoco esquiva lo gastado por las anteriores.
    ledger.setProjectBudget(usdToPico("3.00"));
    assert.equal(ledger.knownPicoAll(), usdToPico("3.00"));
    assert.match(ledger.overBudget("s3")!, /Tope del proyecto \(USD 3\.00\) alcanzado/);
    ledger.setProjectBudget(usdToPico("10.00"));
    assert.equal(ledger.overBudget("s3"), undefined);
    ledger.setProjectBudget(undefined);
    assert.equal(ledger.projectBudget(), undefined);
  } finally {
    db.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});
