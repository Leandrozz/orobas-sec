import "./datos-tmp.ts";
// Corrida simulada con la distribución de las trazas reales (4.380 pasos del agente principal: sondeo y
// lectura 51 %, mecánico 26 %, decisión y análisis 10 %, el resto texto y otras herramientas; ~15 pasos
// por turno). El mismo guion corre tres veces con el motor de verdad y un proveedor falso que cobra con
// caché de prompts por modelo: todo el bucle con el fuerte (cyber-ultra), todo con el ejecutor sin router
// (glm-5.3-flash) y con el router. Además se repite, con la misma caché, la alternativa de rutear pasando
// el historial entero al fuerte, para medir lo que ahorra el traspaso.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import type { Scripted } from "../src/llm.ts";
import { ratePico, usd } from "../src/money.ts";
import type { Provider } from "../src/providers.ts";
import { con, type Llamada, MundoFalso, simular, TARIFAS } from "./router-falso.ts";

process.env.LC_ALL = "es_AR.UTF-8";

/** Pseudoaleatorio determinista (mulberry32): la corrida es la misma siempre. */
function azar(seed: number): () => number {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface Turno { mensaje: string; pasos: Scripted[] }

/**
 * Sesión con la mezcla de las trazas: categoría por paso con rachas (la misma categoría sigue con
 * probabilidad 0,55, como las rachas de sondeo de las trazas) y resultados de 0,5k a 3,5k tokens. Las
 * señales, con las tasas que dio repetir las trazas reales por el router (4.405 pasos): ~0,9 % de pasos
 * con un candidato, ~0,5 % con un hallazgo registrado, 57 objeciones de cierre y 67 avisos de sin avance.
 */
function sesion(seed: number, turnos: number): Turno[] {
  const r = azar(seed);
  const pensado = (n: number) => `Veo ${n} rutas; sigo con la siguiente. `.repeat(1 + Math.floor(r() * 4));
  const cuerpo = (min: number, max: number) => "x".repeat(min + Math.floor(r() * (max - min)));
  const out: Turno[] = [];
  let n = 0;
  for (let k = 0; k < turnos; k++) {
    const pasos: Scripted[] = [];
    const largo = 8 + Math.floor(r() * 15);
    let cat = "S";
    for (let i = 0; i < largo; i++) {
      if (r() > 0.55) { const x = r(); cat = x < 0.51 ? "S" : x < 0.77 ? "M" : x < 0.87 ? "D" : "O"; }
      n++;
      if (cat === "S") {
        const x = r();
        const resultado = x < 0.006 ? `HTTP 200: GET /api/recurso/${n} devolvió el recurso de otro usuario con mi sesión ${cuerpo(1000, 6000)}` : x < 0.026 ? `HTTP 500 Internal Server Error\nTraceback (most recent call last): ${cuerpo(1000, 4000)}` : `HTTP 200 OK ${cuerpo(2000, 14000)}`;
        pasos.push(con("http_request", { url: `https://app.test/api/r${n}` }, resultado, pensado(n)));
      } else if (cat === "M") pasos.push(con("memory_search", { query: `ruta ${n}` }, `memoria: ${cuerpo(400, 2000)}`, pensado(n)));
      else if (cat === "D") {
        if (r() < 0.15) pasos.push(con("finding_record", { state: "pista", title: `Pista ${n}`, kind: "control de acceso", asset: "https://app.test/api", summary: "respuesta distinta por identidad" }, `Registrado ${n.toString(16).padStart(8, "0")} como pista.`));
        else pasos.push(con("access_matrix", { urls: [`https://app.test/api/r${n}`] }, r() < 0.08 ? `acceso cruzado: la identidad B leyó el recurso ${n} de otro usuario ${cuerpo(1000, 6000)}` : `matriz: sin diferencias ${cuerpo(1000, 6000)}`, pensado(n)));
      } else {
        const x = r();
        pasos.push(con("http_probe", { urls: [`https://app.test/api/o${n}`], ...(x < 0.17 ? { senal: "sin-avance" } : x < 0.31 ? { senal: "objecion" } : {}) }, `sondeo: ${cuerpo(1000, 8000)}`, pensado(n)));
      }
    }
    pasos.push({ text: `Cierre del turno ${k}: ${pensado(k)}` });
    out.push({ mensaje: r() < 0.76 ? `Seguí con el pedido ${k}: probá el módulo ${k} de app.test y buscá control de acceso roto` : "seguí", pasos });
  }
  return out;
}

/** Corre la sesión con un ejecutor (y el router en auto o fijo); devuelve lo que cobró el proveedor falso. */
async function correr(ejecutor: "glm" | "ultra", router: "auto" | "fijo", turnos: Turno[]): Promise<{ mundo: MundoFalso; engine: Engine }> {
  process.env.CYBER_CONFIG = join(mkdtempSync(join(tmpdir(), "cyber-sim-config-")), "config.json");
  const mundo = new MundoFalso();
  const providers: Record<string, Provider> = { glm: mundo.proveedor("glm", TARIFAS.glm), ultra: mundo.proveedor("ultra", TARIFAS.ultra), kimi: mundo.proveedor("kimi", TARIFAS.kimi) };
  // Sin dieta: este test mide el router (con tarifas, la dieta decide por economía y resume cada pocos pasos en este
  // mundo de salidas grandes; sus cortes de prefijo no son del encargo). La dieta tiene sus propios tests.
  const engine = new Engine({ cwd: mkdtempSync(join(tmpdir(), "cyber-sim-")), provider: providers[ejecutor]!, strong: providers.ultra!, resolve: (spec) => ({ ...providers[spec.slice(5)]!, model: { ...providers[spec.slice(5)]!.model } }), routerModels: { blue: { fuerte: "faux/kimi" } }, autoVerify: false, router, maskAt: Infinity });
  for (const name of ["http_request", "memory_search", "finding_record", "access_matrix"]) simular(engine, name);
  // Un tramo del fuerte comprueba de verdad: tres peticiones y el informe.
  mundo.tramo = (worker, n) => (n < 3 ? con("http_request", { url: `https://app.test/api/${worker}/${n}` }, `HTTP 200 ${"y".repeat(3000)}`, "Compruebo con la otra identidad.") : { text: "RESULTADO: se sostiene con h12 y h13. LÍMITES: no probé escritura. SIGUIENTE: registrarlo." });
  simular(engine, "http_probe", (args) => {
    if (args.senal === "sin-avance") engine.router.senal("sin-avance", "40 peticiones sin registrar ningún hallazgo");
    if (args.senal === "objecion") engine.router.senal("objecion", "falta probar autorización con la segunda identidad");
    return `sondeo ${String(args.r)}`;
  });
  for (const turno of turnos) {
    mundo.bucle = [...turno.pasos];
    await engine.send(turno.mensaje);
  }
  return { mundo, engine };
}

const total = (calls: Llamada[]) => calls.reduce((sum, call) => sum + call.pico, 0n);
const precio = (tarifa: typeof TARIFAS.ultra, nuevo: number, cacheado: number, salida: number) => BigInt(nuevo) * ratePico(tarifa.input) + BigInt(cacheado) * ratePico(tarifa.cacheRead) + BigInt(salida) * ratePico(tarifa.output);

test("simulación con la mezcla de las trazas: el router con traspaso cuesta una fracción de todo el bucle en el fuerte, y rutear con el historial entero costaría varias veces más por encargo", async (t) => {
  const guion = () => sesion(20261120, 16);
  const caro = await correr("ultra", "fijo", guion());
  const barato = await correr("glm", "fijo", guion());
  const ruteado = await correr("glm", "auto", guion());
  const pasos = ruteado.mundo.llamadas.filter((call) => call.worker === "principal").length;
  assert.equal(caro.mundo.llamadas.filter((call) => call.worker === "principal").length, pasos, "el mismo guion, los mismos pasos");

  // Con el router, el bucle nunca cambia de modelo y su caché queda intacta después de cada encargo.
  const calls = ruteado.mundo.llamadas;
  assert.ok(calls.filter((call) => call.worker === "principal").every((call) => call.modelo === "glm"));
  let previo: Llamada | undefined;
  let compacto = false;
  let encargo = false;
  let tras = 0;
  for (const call of calls) {
    if (call.worker === "compactacion") compacto = true;
    if (/^(router:|sub:)/.test(call.worker)) encargo = true;
    if (call.worker !== "principal") continue;
    if (previo && encargo && !compacto) {
      tras++;
      assert.ok(call.cacheado >= previo.prompt, `después de un encargo el ejecutor relee del caché todo su prompt anterior (${call.cacheado} de ${previo.prompt})`);
    }
    previo = call;
    compacto = encargo = false;
  }
  assert.ok(tras >= 5, `pasos del ejecutor justo después de un encargo: ${tras}`);

  // Encargos: cuántos y de qué costo, con traspaso.
  const decisiones = ruteado.engine.db.prepare("select payload from events where session_id=? and type='router.decision' order by seq").all(ruteado.engine.sessionId).map((row) => JSON.parse((row as { payload: string }).payload));
  const porMil = Math.round((decisiones.length / pasos) * 1000);
  assert.ok(porMil >= 30 && porMil <= 200, `encargos por mil pasos: ${porMil}`);
  const deRouter = calls.filter((call) => /^(traspaso|router:|sub:)/.test(call.worker));
  const conTraspaso = total(deRouter) / BigInt(decisiones.length);

  // La alternativa: el mismo encargo con el historial entero en el fuerte. Se cobra con la misma caché por
  // modelo: el fuerte relee todo el prompt del bucle (frío la primera vez y después de compactar; tibio, lo
  // que ya había leído antes) y escribe lo mismo; un tramo, además, sus pasos sobre ese historial.
  let cacheFuerte = 0;
  let ultimoBucle: Llamada | undefined;
  let historial = 0n;
  const tramos = new Map<string, Llamada[]>();
  for (const call of calls) if (call.worker.startsWith("sub:")) tramos.set(call.worker, [...(tramos.get(call.worker) ?? []), call]);
  for (const call of calls) {
    if (call.worker === "compactacion") cacheFuerte = 0;
    if (call.worker === "principal") ultimoBucle = call;
    if (!ultimoBucle) continue;
    const base = ultimoBucle.prompt + ultimoBucle.salida;
    if (call.worker.startsWith("router:")) {
      const cacheado = Math.min(cacheFuerte, base);
      historial += precio(TARIFAS.ultra, base - cacheado, cacheado, call.salida);
      cacheFuerte = base;
    } else if (call.worker.startsWith("sub:") && tramos.get(call.worker)![0] === call) {
      let leido = Math.min(cacheFuerte, base);
      let contexto = base;
      for (const [i, paso] of tramos.get(call.worker)!.entries()) {
        const propio = i ? paso.prompt - tramos.get(call.worker)![i - 1]!.prompt : 0;
        contexto += Math.max(0, propio);
        historial += precio(TARIFAS.ultra, contexto - leido, leido, paso.salida);
        leido = contexto;
      }
      cacheFuerte = contexto;
    }
  }
  const conHistorial = historial / BigInt(decisiones.length);

  const sumCaro = total(caro.mundo.llamadas);
  const sumBarato = total(barato.mundo.llamadas);
  const sumRouter = total(calls);
  const ahorro = Number(sumCaro - sumRouter) / Number(sumCaro);
  const motivos = decisiones.reduce((acc: Record<string, number>, item) => ({ ...acc, [item.motivo]: (acc[item.motivo] ?? 0) + 1 }), {});
  const filas = [
    `${pasos} pasos del ejecutor en 16 turnos; ${decisiones.length} encargos (${porMil} por mil): ${Object.entries(motivos).map(([k, v]) => `${k} ${v}`).join(", ")}`,
    `todo el bucle con cyber-ultra:       USD ${usd(sumCaro, 3)}`,
    `todo con glm-5.3-flash, sin router:  USD ${usd(sumBarato, 3)}`,
    `con el router (traspasos):           USD ${usd(sumRouter, 3)}  → ${Math.round(ahorro * 100)} % menos que todo con el fuerte; +${Math.round((Number(sumRouter) / Number(sumBarato) - 1) * 100)} % sobre el ejecutor solo`,
    `por encargo: con traspaso USD ${usd(conTraspaso, 4)} · con el historial entero USD ${usd(conHistorial, 4)} (${(Number(conHistorial) / Number(conTraspaso)).toFixed(1)}×)`,
  ];
  for (const fila of filas) t.diagnostic(fila);

  assert.ok(ahorro >= 0.85, `ahorro contra todo el bucle en el fuerte: ${Math.round(ahorro * 100)} %`);
  assert.ok(sumRouter < sumBarato * 3n, "la calidad que agrega el fuerte cuesta menos que triplicar el gasto del ejecutor solo");
  assert.ok(conHistorial > conTraspaso * 3n, "el traspaso cuesta menos de un tercio que pasarle el historial al fuerte");
  // El estado del router dice lo mismo que el proveedor cobró.
  const estado = ruteado.engine.routerEstado();
  assert.equal(estado.gasto.bucle + estado.gasto.router, total(calls.filter((call) => call.worker !== "compactacion")));
  for (const run of [caro, barato, ruteado]) run.engine.close();
});
