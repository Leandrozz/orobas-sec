// Arma un dataset de entrenamiento (JSONL, un ejemplo por turno, formato chat con herramientas) a
// partir de trayectorias exportadas con `cyber trayectorias`.
//
//   node --disable-warning=ExperimentalWarning scripts/dataset.ts cyber-informes/trayectorias-*.jsonl --salida dataset.jsonl
//   … --solo-verificados      sólo sesiones con algún hallazgo verificado
//   … --con-errores           no descartar turnos con errores
//   … --contexto 4            turnos previos que viajan como contexto (por defecto 2)
import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { buildDataset } from "../src/dataset.ts";

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    salida: { type: "string", default: "dataset.jsonl" },
    "solo-verificados": { type: "boolean", default: false },
    "con-errores": { type: "boolean", default: false },
    "con-corregidos": { type: "boolean", default: false },
    "con-cortados": { type: "boolean", default: false },
    contexto: { type: "string", default: "2" },
  },
});
if (!positionals.length) throw new Error("Falta al menos un archivo de trayectorias (.jsonl).");
const lines = positionals.flatMap((path) => readFileSync(path, "utf8").split("\n"));
const { examples, dropped } = buildDataset(lines, {
  onlyVerified: values["solo-verificados"],
  dropErrors: !values["con-errores"],
  dropCorrected: !values["con-corregidos"],
  dropCut: !values["con-cortados"],
  context: Number(values.contexto) || 2,
});
writeFileSync(values.salida, examples.map((example) => JSON.stringify(example)).join("\n") + (examples.length ? "\n" : ""));
const tools = new Map<string, number>();
for (const example of examples) for (const tool of example.meta.tools) tools.set(tool, (tools.get(tool) ?? 0) + 1);
console.log(`${examples.length} ejemplos → ${values.salida}`);
console.log(`Descartados: ${Object.entries(dropped).filter(([reason, n]) => reason !== "ok" && n).map(([reason, n]) => `${reason} ${n}`).join(" · ") || "ninguno"}`);
console.log(`Herramientas: ${[...tools].sort((a, b) => b[1] - a[1]).map(([name, n]) => `${name} ${n}`).join(" · ") || "ninguna"}`);
