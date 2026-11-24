import "./datos-tmp.ts";
// Conducta ante un programa de bug bounty: ritmo, tope, identificación y escáneres. La aplica el código, no el modelo.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { HttpClient, PROGRAM_LIMIT, PROGRAM_RATE } from "../src/http.ts";
import { parseRule, type Scope } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { createNetTools } from "../src/toolbox.ts";

async function setup(source: string) {
  const agents: string[] = [];
  const server = createServer((req, res) => { agents.push(String(req.headers["user-agent"])); res.end("ok"); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as any).port}`;
  const paths = projectPaths(mkdtempSync(join(tmpdir(), "cyber-conducta-")));
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const scope: Scope = { rev: 1, source, notes: "", at: "", include: [parseRule(base)], exclude: [] };
  const http = new HttpClient(artifacts, () => scope);
  return { base, http, artifacts, scope, agents, close: () => { server.close(); db.close(); } };
}

test("alcance manual: sin ritmo ni tope por defecto, escáneres habilitados", async () => {
  const lab = await setup("manual");
  try {
    assert.deepEqual(lab.http.conduct(), { rate: undefined, limit: undefined, userAgent: "ElevateAICyber/0.1", program: undefined, scanners: true });
    const started = Date.now();
    await Promise.all(Array.from({ length: 30 }, () => lab.http.send({ url: `${lab.base}/` })));
    assert.ok(Date.now() - started < 10_000, "sin ritmo, 30 peticiones no deberían esperar");
    assert.equal(lab.http.remaining(), undefined);
  } finally { lab.close(); }
});

test("alcance de HackerOne: ritmo y tope por defecto, se identifica con el usuario y apaga los escáneres", async () => {
  const lab = await setup("hackerone:acme");
  let lookups = 0;
  lab.http.operator = () => { lookups++; return "lean1ng"; };
  try {
    const conduct = lab.http.conduct();
    assert.equal(conduct.rate, PROGRAM_RATE);
    assert.equal(conduct.limit, PROGRAM_LIMIT);
    assert.equal(conduct.program, "acme");
    assert.equal(conduct.scanners, false);
    assert.equal(conduct.userAgent, "ElevateAICyber/0.1 (HackerOne: lean1ng)");

    // 12 peticiones a 5 por segundo: 5 salen en ráfaga y las otras 7 esperan su turno (1,4 s).
    const started = Date.now();
    await Promise.all(Array.from({ length: 12 }, () => lab.http.send({ url: `${lab.base}/` })));
    const elapsed = Date.now() - started;
    assert.ok(elapsed >= 1300, `el ritmo no se aplicó: ${elapsed} ms`);
    assert.ok(elapsed < 10_000, `esperó de más: ${elapsed} ms`);
    assert.equal(lab.http.count, 12);
    assert.equal(lab.http.remaining(), PROGRAM_LIMIT - 12);
    assert.ok(lab.agents.every((agent) => agent === "ElevateAICyber/0.1 (HackerOne: lean1ng)"));
    assert.equal(lookups, 1, "el usuario se consulta una sola vez");
  } finally { lab.close(); }
});

test("el operador manda: fija, quita o cambia cada regla, y el tope corta", async () => {
  const lab = await setup("hackerone:acme");
  try {
    lab.http.rate = Infinity;
    lab.http.limit = 3;
    lab.http.userAgent = "acme-research lean1ng";
    lab.http.scanners = true;
    assert.deepEqual(lab.http.conduct(), { rate: undefined, limit: 3, userAgent: "acme-research lean1ng", program: "acme", scanners: true });
    for (let i = 0; i < 3; i++) assert.equal((await lab.http.send({ url: `${lab.base}/` })).response?.status, 200);
    const fourth = await lab.http.send({ url: `${lab.base}/` });
    assert.match(String(fourth.error), /Tope de peticiones alcanzado \(3\)/);
    assert.equal(lab.agents.length, 3, "la cuarta no salió");
    assert.equal(lab.agents[0], "acme-research lean1ng");
    lab.http.limit = Infinity;
    assert.equal(lab.http.remaining(), undefined);
  } finally { lab.close(); }
});

test("un escáner externo no corre contra un programa hasta que el operador lo habilita", async () => {
  const lab = await setup("hackerone:acme");
  try {
    const tools = createNetTools({ artifacts: lab.artifacts, scope: () => lab.scope, http: lab.http });
    const nuclei = tools.find((tool) => tool.name.includes("nuclei"))!;
    await assert.rejects(() => nuclei.execute({ targets: [lab.base] }, new AbortController().signal) as Promise<unknown>, /apagado: el alcance viene del programa acme/);
    assert.equal(lab.agents.length, 0);
  } finally { lab.close(); }
});
