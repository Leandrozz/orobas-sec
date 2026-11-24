import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { GROUPS } from "../src/catalog.ts";

/** Todos los `name: "..."` que declara una herramienta en el código. */
function declaredNames(dir: string, found = new Set<string>()): Set<string> {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) declaredNames(path, found);
    else if (entry.endsWith(".ts")) {
      const text = readFileSync(path, "utf8");
      for (const match of text.matchAll(/\bname:\s*"([a-z][a-z0-9_]{2,})"/g)) found.add(match[1]!);
      // Algunas se declaran con un ayudante: tool("nombre", …)
      for (const match of text.matchAll(/\btool\(\s*"([a-z][a-z0-9_]{2,})"/g)) found.add(match[1]!);
    }
  }
  return found;
}

/**
 * Una familia de GROUPS que nombra una herramienta inexistente la deja fuera del resumen sin avisar:
 * summary() filtra por `available.has(name)`. Pasó con «dnsx_resolve», que se llama «dns_resolve», y
 * por eso no aparecía bajo «escáneres» sino suelta en «otras».
 */
test("catálogo: cada herramienta nombrada en una familia existe en el código", () => {
  const declared = declaredNames("src");
  const faltan: string[] = [];
  for (const [familia, names] of Object.entries(GROUPS)) {
    for (const name of names) {
      if (name.includes(".")) continue; // herramientas de un MCP: se descubren en ejecución
      if (!declared.has(name)) faltan.push(`${familia} → ${name}`);
    }
  }
  assert.deepEqual(faltan, [], `familias que nombran herramientas inexistentes:\n${faltan.join("\n")}`);
});
