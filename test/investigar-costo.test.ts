import "./datos-tmp.ts";
// Costo de una investigación simulada con tamaños realistas (lecturas de código de ~6k tokens, salidas de
// harness y fuzzer de 2k a 3k) y las tarifas reales del catálogo: el analista con el medio (hy4), hipótesis y
// reporte con un estándar blue (kimi), los harnesses con el fuerte red (ultra) y el orquestador con el modelo
// del bucle (glm). Se compara con la misma investigación toda con el fuerte. Imprime el desglose por estado.
import assert from "node:assert/strict";
import { test } from "node:test";
import type { Tool } from "../src/agent.ts";
import type { Engine } from "../src/engine.ts";
import { usd } from "../src/money.ts";
import type { Scripted } from "../src/llm.ts";
import { type InfoTramo, motor, MundoInv } from "./investigar-falso.ts";

process.env.LC_ALL = "es_AR.UTF-8";

const out = (args: object): Scripted => ({ toolCalls: [{ name: "investigation_output", arguments: args }] });
const llama = (name: string, args: object, text = "Sigo."): Scripted => ({ text, toolCalls: [{ name, arguments: args }] });
const NIVEL_MAX: Record<string, number> = { h1: 3, h2: 1, h3: 0, h4: 0, h5: 0 };

/** Un guion con el largo de una investigación real: lee mucho, prueba varias hipótesis, profundiza dos. */
function guion(info: InfoTramo): Scripted {
  const { estado, hipotesis = "", paso } = info;
  if (estado === "analista") return paso < 12 ? llama("code_read", { path: `src/m${paso}.c` }, "Leo el siguiente módulo y anoto el flujo.") : paso === 12 ? out({ mapa: "m".repeat(14_000), puntos_entrada: Array.from({ length: 9 }, (_, i) => `src/m${i}.c:${10 + i} entrada ${i}`), resumen: "mapa" }) : { text: "Listo." };
  if (estado === "hipotesis") return paso < 3 ? llama("code_read", { path: `src/m${paso}.c` }) : paso === 3 ? out({ hipotesis: Object.keys(NIVEL_MAX).map((id, i) => ({ titulo: `Hipótesis ${id}: falla en m${i}`, clase: `clase ${i}`, activo: `src/m${i}.c:f${i}`, porque: "p".repeat(300), evidencia: `src/m${i}.c:${20 + i}`, prioridad: i < 2 ? "alta" : "media" })), resumen: "cinco" }) : { text: "Listo." };
  if (estado.startsWith("harness-")) {
    const nivel = Number(estado.slice(-1));
    const pasos = [llama("code_read", { path: "src/m0.c" }), llama("harness_build", { nivel }), llama("fuzz_run", { nivel }), llama("code_read", { path: "src/m1.c" }), llama("harness_build", { nivel, v: 2 }), llama("fuzz_run", { nivel, v: 2 })];
    if (paso < pasos.length) return pasos[paso]!;
    if (paso === pasos.length) return nivel <= NIVEL_MAX[hipotesis]! ? out({ dispara: true, comando: `./${hipotesis}-n${nivel} crash`, senal: "AddressSanitizer", resumen: "dispara" }) : out({ dispara: false, resumen: "no disparó" });
    return { text: "Listo." };
  }
  if (estado === "reporte") return paso < 2 ? llama("artifact_read", { hash: "x" }) : paso === 2 ? out({ titulo: "Informe", informe: "i".repeat(8000), resumen: "ok" }) : { text: "Listo." };
  return { text: "?" };
}

/** Profundiza lo que ya disparó; si no, la primera hipótesis sin probar en su nivel; si no, el reporte. */
function orquestador(prompt: string): string {
  const lista = [...prompt.matchAll(/^(\d+)\. (.+)$/gm)].map((m) => ({ n: m[1]!, texto: m[2]!, nivel: Number(/nivel (\d)/.exec(m[2]!)?.[1] ?? -1), clave: /^(harness-\d) \(.*\) sobre (h\d+)/.exec(m[2]!) }));
  const nuevas = lista.filter((o) => o.clave && !prompt.includes(`${o.clave[1]}:${o.clave[2]}`)).sort((a, b) => b.nivel - a.nivel);
  const reporte = lista.find((o) => /^reporte/.test(o.texto));
  return `MOVIDA: ${(nuevas[0] ?? reporte ?? lista[0])!.n}\nMOTIVO: regla de la simulación.`;
}

function dobles(engine: Engine): void {
  const doble = (name: string, size: number): Tool => ({ name, label: name, description: `doble de ${name}`, parameters: { type: "object", properties: {}, additionalProperties: true }, execute: () => ({ text: `${name}: ${"c".repeat(size)}` }) });
  engine.catalog.register([doble("code_read", 24_000), doble("harness_build", 8_000), doble("fuzz_run", 12_000), doble("artifact_read", 7_900)]);
}

async function investigar(todoFuerte: boolean): Promise<{ engine: Engine; mundo: MundoInv; filas: string[]; total: bigint; tokens: number }> {
  const mundo = new MundoInv();
  mundo.tramo = guion;
  mundo.orquestador = orquestador;
  const { engine } = motor(mundo, todoFuerte ? { routerModels: {} } : {});
  dobles(engine);
  if (!todoFuerte) await engine.setMediumModel("faux/hy4");
  await engine.investigar!.comando("libparse 40");
  await engine.investigar!.esperar();
  const { p } = engine.investigar!.todas()[0]!;
  assert.equal(p.fase, "cerrada", "terminó con el reporte, sin tocar el tope");
  assert.deepEqual(Object.fromEntries(p.hipotesis.map((h) => [h.id, h.nivel])), NIVEL_MAX);
  const costos = engine.investigar!.costos(p.id);
  const filas = [...costos.porEstado.entries()].map(([estado, c]) => `${estado.padEnd(12)} ${String(c.tramos).padStart(2)} tramos ${String(c.pasos).padStart(3)} pasos ${(c.tokens / 1000).toFixed(0).padStart(6)}k tokens  USD ${usd(c.pico, 3)}`);
  return { engine, mundo, filas, total: costos.total.pico, tokens: costos.total.tokens };
}

test("costo de una investigación simulada: desglose por estado y comparación con todo el trabajo en el fuerte", async (t) => {
  const ruteada = await investigar(false);
  const fuerte = await investigar(true);
  try {
    const modelos = new Set(ruteada.mundo.de(/^inv:/).map((pedido) => `${pedido.worker.split(":")[2]}=${pedido.modelo}`));
    assert.ok(modelos.has("analista=hy4") && modelos.has("hipotesis=kimi") && modelos.has("harness-1=ultra") && modelos.has("orquestador=glm"), [...modelos].join(" "));
    t.diagnostic(`Investigación ruteada por rol: USD ${usd(ruteada.total, 2)}, ${(ruteada.tokens / 1e6).toFixed(2)}M tokens`);
    for (const fila of ruteada.filas) t.diagnostic(`  ${fila}`);
    t.diagnostic(`Toda con el fuerte (ultra): USD ${usd(fuerte.total, 2)}, ${(fuerte.tokens / 1e6).toFixed(2)}M tokens`);
    for (const fila of fuerte.filas) t.diagnostic(`  ${fila}`);
    assert.ok(ruteada.total < fuerte.total, "rutear por rol cuesta menos que todo con el fuerte");
    assert.ok(ruteada.total < 40_000_000_000_000n);
  } finally {
    await ruteada.engine.close();
    await fuerte.engine.close();
  }
});
