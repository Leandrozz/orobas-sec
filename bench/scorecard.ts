// Tarjeta de puntaje del bench: junta archivos de bench/results/ y resume por etiqueta (y por caso,
// en el objetivo cve) lo que importa para comparar versiones del harness: cuánto resolvió, cuántos
// hallazgos verificó y cuántos falsos registró, cuánto costó y cuánto tardó. Con --base y --nuevo
// muestra los deltas entre dos etiquetas.
//
//   node --disable-warning=ExperimentalWarning bench/scorecard.ts bench/results/*.json
//   node --disable-warning=ExperimentalWarning bench/scorecard.ts bench/results/*.json --base harness-fenix-v7 --nuevo harness-fenix-v8
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";

const { values, positionals } = parseArgs({ allowPositionals: true, options: { base: { type: "string" }, nuevo: { type: "string" }, json: { type: "boolean", default: false } } });
if (!positionals.length) throw new Error("Falta al menos un archivo de resultados.");

type Run = {
  label: string; run: number; target: string; caso?: string; version?: string; durationSec: number; solved: unknown[]; total?: number; oracleExit?: number;
  findings?: { candidatos?: number; verificados?: number; descartados?: number; pistas?: number }; precision?: { verdaderos?: number; falsos?: number; sinClasificar?: number };
  requests?: number; httpRequests?: number; tokens?: number; costUsd?: string; stalls?: number; errors?: unknown[]; invalid?: string;
};
const runs: Run[] = positionals.flatMap((path) => (JSON.parse(readFileSync(path, "utf8")) as { results: Run[] }).results ?? []);

const mean = (items: number[]) => (items.length ? items.reduce((a, b) => a + b, 0) / items.length : 0);
const fmt = (n: number, digits = 1) => (Number.isFinite(n) ? n.toFixed(digits) : "–");

interface Card { label: string; target: string; runs: number; valid: number; solved: number; verified: number; candidates: number; truePos: number; falsePos: number; requests: number; usd: number; seconds: number; stalls: number; errors: number; oracle: number }
function card(label: string, items: Run[]): Card {
  const valid = items.filter((run) => !run.invalid);
  return {
    label, target: items[0]?.target ?? "?", runs: items.length, valid: valid.length,
    solved: mean(valid.map((run) => run.solved?.length ?? 0)),
    verified: mean(valid.map((run) => run.findings?.verificados ?? 0)),
    candidates: mean(valid.map((run) => run.findings?.candidatos ?? 0)),
    truePos: mean(valid.filter((run) => run.precision).map((run) => run.precision!.verdaderos ?? 0)),
    falsePos: mean(valid.filter((run) => run.precision).map((run) => run.precision!.falsos ?? 0)),
    requests: mean(valid.map((run) => run.httpRequests ?? run.requests ?? 0)),
    usd: mean(valid.map((run) => Number(run.costUsd ?? 0))),
    seconds: mean(valid.map((run) => run.durationSec ?? 0)),
    stalls: mean(valid.map((run) => run.stalls ?? 0)),
    errors: mean(valid.map((run) => run.errors?.length ?? 0)),
    oracle: valid.filter((run) => run.oracleExit === 0).length,
  };
}

const groups = new Map<string, Run[]>();
for (const run of runs) {
  const key = run.target === "cve" ? `${run.label} · ${run.caso} · ${run.version ?? ""}` : run.label;
  groups.set(key, [...(groups.get(key) ?? []), run]);
}
const cards = [...groups].map(([label, items]) => card(label, items));

if (values.json) {
  console.log(JSON.stringify(cards, null, 1));
} else {
  console.log("| Etiqueta | Corridas (válidas) | Resueltos | Oráculo ✓ | Verificados | Candidatos | Verdaderos / falsos | HTTP | USD | Segundos | Sin avance | Errores |");
  console.log("|---|---|---|---|---|---|---|---|---|---|---|---|");
  for (const c of cards) {
    console.log(`| ${c.label} | ${c.runs} (${c.valid}) | ${fmt(c.solved)} | ${c.target === "cve" ? `${c.oracle}/${c.valid}` : "–"} | ${fmt(c.verified)} | ${fmt(c.candidates)} | ${c.truePos || c.falsePos ? `${fmt(c.truePos)} / ${fmt(c.falsePos)}` : "–"} | ${fmt(c.requests, 0)} | ${fmt(c.usd, 3)} | ${fmt(c.seconds, 0)} | ${fmt(c.stalls)} | ${fmt(c.errors)} |`);
  }
}

if (values.base && values.nuevo) {
  const pick = (label: string) => card(label, runs.filter((run) => run.label === label));
  const a = pick(values.base), b = pick(values.nuevo);
  if (!a.runs || !b.runs) throw new Error(`No hay corridas para ${!a.runs ? values.base : values.nuevo}.`);
  const delta = (x: number, y: number, digits = 1, better: "más" | "menos" = "más") => {
    const d = y - x;
    const sign = d > 0 ? "+" : "";
    const good = better === "más" ? d > 0 : d < 0;
    return `${sign}${fmt(d, digits)}${d === 0 ? "" : good ? " mejor" : " peor"}`;
  };
  console.log(`\nDe «${values.base}» (${a.valid} corridas) a «${values.nuevo}» (${b.valid} corridas):`);
  console.log(`  resueltos ${fmt(a.solved)} → ${fmt(b.solved)} (${delta(a.solved, b.solved)})`);
  console.log(`  verificados ${fmt(a.verified)} → ${fmt(b.verified)} (${delta(a.verified, b.verified)})`);
  console.log(`  falsos ${fmt(a.falsePos)} → ${fmt(b.falsePos)} (${delta(a.falsePos, b.falsePos, 1, "menos")})`);
  console.log(`  HTTP ${fmt(a.requests, 0)} → ${fmt(b.requests, 0)} (${delta(a.requests, b.requests, 0, "menos")})`);
  console.log(`  USD ${fmt(a.usd, 3)} → ${fmt(b.usd, 3)} (${delta(a.usd, b.usd, 3, "menos")})`);
  console.log(`  segundos ${fmt(a.seconds, 0)} → ${fmt(b.seconds, 0)} (${delta(a.seconds, b.seconds, 0, "menos")})`);
  console.log(`  sin avance ${fmt(a.stalls)} → ${fmt(b.stalls)} (${delta(a.stalls, b.stalls, 1, "menos")})`);
}
