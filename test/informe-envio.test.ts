// El informe como lo pide una plataforma (HackerOne): verificados aparte de los candidatos, severidad con su
// rango CVSS, versión observada, pasos copiables (curl), impacto y remediación; y el informe en inglés ya no
// tapa «USD» ni la lista de activos (el redactor tomaba «session:» de los textos fijos como una clave).
import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { Findings } from "../src/findings.ts";
import { HttpClient } from "../src/http.ts";
import { Ledger } from "../src/ledger.ts";
import { generateReport } from "../src/report.ts";
import { parseRule, ScopeStore } from "../src/scope.ts";
import { openStore, projectPaths } from "../src/store.ts";

test("informe para enviar: verificados primero y aparte, CVSS, versión, curl, impacto y remediación; en inglés no tapa USD ni los activos", async (t) => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-informe-envio-"));
  const paths = projectPaths(cwd);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const findings = new Findings(db, (hash) => artifacts.find(hash));
  const scope = new ScopeStore(db, "s1");
  const server = createServer((request, response) => {
    request.resume();
    request.on("end", () => {
      if (request.url === "/api/orders/1002") return void response.writeHead(200, { "content-type": "application/json", server: "nginx/1.25.3", "x-powered-by": "Express" }).end(JSON.stringify({ id: 1002, owner: "bob@lab.test" }));
      response.writeHead(200, { "content-type": "text/html" }).end("<p><script>alert(1)</script></p>");
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => { server.close(); db.close(); rmSync(cwd, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  scope.save({ source: "hackerone:tienda", include: [parseRule(base)], exclude: [], notes: "" });
  const http = new HttpClient(artifacts, () => scope.current());
  http.setIdentity({ name: "ana", headers: { authorization: "Bearer TOKEN-DE-ANA-SECRETO" } });
  const idor = await http.send({ url: `${base}/api/orders/1002`, method: "POST", headers: { "content-type": "application/json" }, body: "{\"it's\":1}" }, "ana");
  const xss = await http.send({ url: `${base}/search?q=x` });
  // El candidato se registra primero: antes salía primero, mezclado con los verificados.
  findings.record({ title: "XSS reflejado en /search", kind: "xss", asset: `${base}/search`, summary: "q se refleja.", evidence: [xss.artifact], severity: "critica" }, "s1");
  const verified = findings.record({ title: "IDOR en pedidos", kind: "control de acceso", asset: `${base}/api/orders/1002`, summary: "ana lee el pedido de bob.", evidence: [idor.artifact], severity: "alta", limits: "Dos cuentas propias." }, "s1");
  findings.decide(verified.id, "verificado", "reproducido");
  const now = new Date("2026-11-22T12:00:00.000Z");
  const es = (await generateReport({ paths, db, artifacts, findings, scope, ledger: new Ledger(db), sessionId: "s1", now })).markdown;
  const [head, rest] = es.split("## Hallazgos verificados");
  assert.ok(rest, "hay sección de verificados");
  assert.match(head!, /Verificados: 1\.\n- [0-9a-f]{8} — IDOR en pedidos \(alta\)\nCandidatos sin verificar: 1/);
  const [verifiedPart, candidatesPart] = rest!.split("## Candidatos sin verificar");
  assert.match(verifiedPart!, /IDOR en pedidos/);
  assert.doesNotMatch(verifiedPart!, /XSS reflejado/, "un candidato no va con los verificados aunque sea más grave");
  assert.match(candidatesPart!, /no se envían como hallazgo sin verificarlos[\s\S]*XSS reflejado[\s\S]*CVSS 3\.1: 9\.0–10\.0 para severidad crítica/);
  assert.match(verifiedPart!, /CVSS 3\.1: 7\.0–8\.9 para severidad alta\. El vector no se calculó/);
  assert.match(verifiedPart!, /Versiones observadas en la evidencia: nginx\/1\.25\.3, Express\./);
  const curl = /```sh\n(curl [\s\S]*?)\n```/.exec(verifiedPart!)?.[1] ?? "";
  assert.match(curl, /^curl -i -X POST 'http:\/\/127\.0\.0\.1:\d+\/api\/orders\/1002' \\\n/);
  assert.match(curl, /\n  -H "authorization: \$\{IDENTIDAD_ANA\}" \\\n/, "la identidad va como variable, no su valor");
  assert.match(curl, /\n  -H 'content-type: application\/json' \\\n/);
  assert.match(curl, /\n  --data-binary '\{\n  "it'\\''s": 1\n\}'$/, "la comilla simple del cuerpo queda escapada para el shell");
  assert.match(verifiedPart!, /#### Impacto\n\nNo declarado por separado/);
  assert.match(verifiedPart!, /#### Remediación sugerida\n\nComprobar en el servidor, en cada operación, que el recurso pertenece al usuario/);
  assert.doesNotMatch(es, /connection: |transfer-encoding: |keep-alive: /, "sin cabeceras de transporte");
  assert.doesNotMatch(es, /TOKEN-DE-ANA-SECRETO/);
  const en = (await generateReport({ paths, db, artifacts, findings, scope, ledger: new Ledger(db), sessionId: "s1", now, lang: "en" })).markdown;
  assert.match(en, /Known API cost \(this session\): USD 0\.000000/, "antes: «session: [credential redacted] 0.000000»");
  assert.match(en, new RegExp(`Assets with HTTP responses saved \\(this session\\): ${base.replace(/\./g, "\\.")}\\.`), "antes la lista de activos salía tapada");
  assert.match(en, /## Verified findings[\s\S]*## Unverified candidates/);
  assert.match(en, /-H "authorization: \$\{IDENTITY_ANA\}"/);
  assert.match(en, /#### Suggested remediation\n\nCheck on the server/);
  assert.doesNotMatch(en, /TOKEN-DE-ANA-SECRETO/);
});
