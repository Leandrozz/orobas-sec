import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { decode } from "@toon-format/toon";
import { openStore, projectPaths } from "../src/store.ts";
import { Vault } from "../src/vault.ts";

function vault() {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-vault-"));
  const paths = projectPaths(cwd);
  for (const dir of [paths.root, paths.records, paths.notes]) mkdirSync(dir, { recursive: true });
  const db = openStore(paths);
  return { vault: new Vault(db, paths.records, paths.notes), paths, db };
}

test("la nota entera es un solo registro TOON: el detalle va adentro y no hay Markdown al lado", () => {
  const v = vault();
  const record = v.vault.write({ type: "observacion", title: "Panel de administración", summary: "Hay un panel en /admin que responde 200 sin sesión.", body: "Pasos: GET /admin sin cookies.\nEvidencia: h12.", tags: ["admin", "acceso"] });
  assert.ok(existsSync(join(v.paths.records, `${record.id}.toon`)));
  assert.equal(existsSync(join(v.paths.notes, `${record.id}.md`)), false, "ya no se escribe .md");
  const stored = decode(readFileSync(join(v.paths.records, `${record.id}.toon`), "utf8")) as unknown as { body: string; tags: string[] };
  assert.equal(stored.body, "Pasos: GET /admin sin cookies.\nEvidencia: h12.");
  assert.deepEqual(stored.tags, ["admin", "acceso"]);
  assert.equal(v.vault.read(record.id)!.record.body, stored.body);
  // Actualizar sin cuerpo conserva el detalle anterior.
  const again = v.vault.write({ id: record.id, type: "observacion", title: "Panel de administración", summary: "Confirmado dos veces." });
  assert.equal(again.rev, 2);
  assert.equal(v.vault.read(record.id)!.record.body, stored.body);
});

test("una nota Markdown vieja se pliega en su registro al reindexar y el .md desaparece", () => {
  const v = vault();
  const record = v.vault.write({ type: "decision", title: "Sin escáneres", summary: "No usar escáneres en este programa." });
  const legacy = join(v.paths.notes, `${record.id}.md`);
  writeFileSync(legacy, "# Detalle viejo\nEl programa lo prohíbe en su política.");
  const result = v.vault.reindex();
  assert.equal(result.migrated, 1);
  assert.equal(existsSync(legacy), false);
  assert.match(v.vault.read(record.id)!.record.body, /lo prohíbe/);
  assert.equal(v.vault.search("política prohíbe", 3)[0]?.id, record.id, "el detalle migrado se busca");
});

test("búsqueda en dos pasadas: primero lo que tiene todas las palabras; los vigentes antes que los sustituidos", () => {
  const v = vault();
  const both = v.vault.write({ type: "observacion", title: "Token en la URL de reset", summary: "El reset de clave manda el token por la URL." });
  v.vault.write({ type: "observacion", title: "Token de sesión largo", summary: "La cookie de sesión dura 30 días." });
  v.vault.write({ type: "observacion", title: "URL de la API", summary: "La API vive en /api/v2." });
  const hits = v.vault.search("token url", 3);
  assert.equal(hits[0]!.id, both.id, "el que tiene las dos palabras va primero");
  assert.equal(hits.length, 3, "después completa con los que tienen alguna");
  const newer = v.vault.write({ type: "observacion", title: "Token en la URL de reset, corregido", summary: "Ahora el token viaja en el cuerpo.", supersedes: both.id });
  const after = v.vault.search("token url reset", 2);
  assert.equal(after[0]!.id, newer.id);
  assert.equal(after[1]!.id, both.id);
  assert.equal(after[1]!.state, "sustituido");
  assert.deepEqual(v.vault.search("token", 5, { types: ["decision"] }), []);
});

test("recuerdo por enlaces: lo relacionado con un resultado entra marcado con «via»; decisiones y pendientes vigentes", () => {
  const v = vault();
  const base = v.vault.write({ type: "observacion", title: "Endpoint de exportación", summary: "POST /export genera un archivo con todos los pedidos." });
  const linked = v.vault.write({ type: "hipotesis", title: "Exportación sin control de dueño", summary: "Quizá /export acepta ids ajenos.", links: [{ to: base.id, rel: "deriva-de" }] });
  const todo = v.vault.write({ type: "pendiente", title: "Probar /export con otro id", summary: "Falta probarlo con la segunda cuenta." });
  const related = v.vault.related([base.id], 3);
  assert.deepEqual(related.map((hit) => hit.id), [linked.id]);
  assert.equal(related[0]!.via, `deriva-de ${base.id}`);
  assert.deepEqual(v.vault.related([linked.id], 3).map((hit) => hit.id), [base.id], "también en sentido inverso");
  assert.deepEqual(v.vault.pending().map((hit) => hit.id), [todo.id]);
  assert.match(Vault.pack(related), /,via\}:\n.*deriva-de endpoint/);
  assert.doesNotMatch(Vault.pack(v.vault.pending()), /via/);
});
