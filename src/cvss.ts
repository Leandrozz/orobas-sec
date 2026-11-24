// CVSS 3.1 según FIRST, secciones 6 y 7 y apéndice A.
// https://www.first.org/cvss/v3.1/specification-document
const base = { AV: "NALP", AC: "LH", PR: "NLH", UI: "NR", S: "UC", C: "NLH", I: "NLH", A: "NLH" };
const temporales = { E: "XHFPU", RL: "XUWTO", RC: "XCRU" };
const ambientales = {
  CR: "XHML", IR: "XHML", AR: "XHML",
  ...Object.fromEntries(Object.entries(base).map(([nombre, valores]) => [`M${nombre}`, `X${valores}`])),
};
const valores = new Map(Object.entries({ ...base, ...temporales, ...ambientales }));

function leer(vector: string): Map<string, string> {
  if (typeof vector !== "string") throw new Error("CVSS requiere un vector de texto.");
  const [version, ...pares] = vector.split("/");
  if (version !== "CVSS:3.1") throw new Error("La versión del vector debe ser CVSS:3.1.");
  const metricas = new Map<string, string>();
  for (const par of pares) {
    const [nombre, valor, resto] = par.split(":");
    if (!nombre || valor?.length !== 1 || resto !== undefined || !valores.get(nombre)?.includes(valor)) {
      throw new Error("El vector CVSS contiene una métrica o un valor inválido.");
    }
    if (metricas.has(nombre)) throw new Error(`Métrica CVSS repetida: ${nombre}.`);
    metricas.set(nombre, valor);
  }
  for (const nombre of Object.keys(base)) {
    if (!metricas.has(nombre)) throw new Error(`Falta la métrica base CVSS ${nombre}.`);
  }
  return metricas;
}

type Pesos = Readonly<Record<string, number>>;
const acceso: Pesos = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const complejidad: Pesos = { L: 0.77, H: 0.44 };
const privilegios = { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } } satisfies Record<string, Pesos>;
const usuario: Pesos = { N: 0.85, R: 0.62 };
const efecto: Pesos = { N: 0, L: 0.22, H: 0.56 };
const requisito: Pesos = { X: 1, H: 1.5, M: 1, L: 0.5 };
const madurez: Pesos = { X: 1, H: 1, F: 0.97, P: 0.94, U: 0.91 };
const remedio: Pesos = { X: 1, U: 1, W: 0.97, T: 0.96, O: 0.95 };
const confianza: Pesos = { X: 1, C: 1, R: 0.96, U: 0.92 };

const redondear = (valor: number) => Math.ceil(Math.round(valor * 100_000) / 10_000) / 10;

function nivel(puntaje: number) {
  if (puntaje === 0) return "informativa";
  if (puntaje < 4) return "baja";
  if (puntaje < 7) return "media";
  if (puntaje < 9) return "alta";
  return "critica";
}

/** Puntaje del grupo más específico con valores definidos. X equivale a omitir la métrica. */
export function calcularCvss(vector: string) {
  const metricas = leer(vector);
  const valor = (nombre: string) => metricas.get(nombre) ?? "X";
  const ambiental = Object.keys(ambientales).some((nombre) => valor(nombre) !== "X");
  const temporal = Object.keys(temporales).some((nombre) => valor(nombre) !== "X");
  const grupo = ambiental ? "ambiental" : temporal ? "temporal" : "base";
  const vigente = (nombre: keyof typeof base) => {
    const modificado = valor(`M${nombre}`);
    return modificado === "X" ? valor(nombre) : modificado;
  };
  const cambia = vigente("S") === "C";
  const pr: Pesos = privilegios[cambia ? "C" : "U"];
  const facilidad = 8.22 * acceso[vigente("AV")]! * complejidad[vigente("AC")]! * pr[vigente("PR")]! * usuario[vigente("UI")]!;
  const perdida = (nombre: "C" | "I" | "A") => efecto[vigente(nombre)]! * requisito[valor(`${nombre}R`)]!;
  let iss = 1 - (1 - perdida("C")) * (1 - perdida("I")) * (1 - perdida("A"));
  if (ambiental) iss = Math.min(0.915, iss);
  let impacto = 6.42 * iss;
  if (cambia) {
    const ajuste = ambiental ? (iss * 0.9731 - 0.02) ** 13 : (iss - 0.02) ** 15;
    impacto = 7.52 * (iss - 0.029) - 3.25 * ajuste;
  }
  const inicial = impacto <= 0 ? 0 : redondear(Math.min(10, (cambia ? 1.08 : 1) * (impacto + facilidad)));
  const puntaje = redondear(inicial * madurez[valor("E")]! * remedio[valor("RL")]! * confianza[valor("RC")]!);
  return { puntaje, grupo, severidad: nivel(puntaje) } as const;
}
