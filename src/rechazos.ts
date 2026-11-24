// Tasa de negativas por modelo y por nivel de la tarea, para el router. «blue» es trabajo que un modelo
// estándar (con barandas) hace sin problema: leer y entender código o una app, planificar, redactar,
// analizar una causa. «red» es armar cargas, explotar, evadir controles. Vive en un archivo del usuario,
// junto a la configuración y fuera de los proyectos, para que lo aprendido en uno sirva en los demás.
// La tasa va suavizada (prior por tipo de modelo): un rechazo suelto no saca a un modelo del ruteo.
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { configPath } from "./providers.ts";

export type Nivel = "blue" | "red";
export interface Cuenta { pasos: number; rechazos: number }
interface Archivo { modelos: Record<string, Partial<Record<Nivel, Cuenta>>>; clases: Record<string, Record<string, Cuenta>> }

/** Peso del prior, en pasos: con 5, hacen falta varios rechazos seguidos para pasar el umbral. */
export const PESO_PRIOR = 5;
/** Tasa esperada antes de ver nada: los estándar se niegan a veces a lo ofensivo, casi nunca a lo demás. */
export const PRIOR: Record<"estandar" | "otro", Record<Nivel, number>> = { estandar: { blue: 0.03, red: 0.2 }, otro: { blue: 0.01, red: 0.01 } };
/** Por encima de esta tasa suavizada, el router deja de mandarle ese nivel al modelo. */
export const UMBRAL_RECHAZO = 0.3;

export const rechazosPath = () => join(dirname(configPath()), "router-rechazos.json");

function leer(): Archivo {
  try {
    const path = rechazosPath();
    if (!existsSync(path)) return { modelos: {}, clases: {} };
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Partial<Archivo>;
    return { modelos: parsed.modelos && typeof parsed.modelos === "object" ? parsed.modelos : {}, clases: parsed.clases && typeof parsed.clases === "object" ? parsed.clases : {} };
  } catch {
    return { modelos: {}, clases: {} };
  }
}

/** Cuentas en memoria que se suman al archivo al vaciarse (fin de turno, cierre): no se escribe en cada paso. */
export class Rechazos {
  private pendiente: Archivo = { modelos: {}, clases: {} };

  /** Anota un paso de `modelo` («proveedor/id») en un nivel; `clase` es la tarea (plan, candidato, código…). */
  anotar(modelo: string, nivel: Nivel, clase: string, rechazado: boolean): void {
    const suma = (cuenta: Cuenta | undefined): Cuenta => ({ pasos: (cuenta?.pasos ?? 0) + 1, rechazos: (cuenta?.rechazos ?? 0) + (rechazado ? 1 : 0) });
    const propio = (this.pendiente.modelos[modelo] ??= {});
    propio[nivel] = suma(propio[nivel]);
    const clases = (this.pendiente.clases[modelo] ??= {});
    clases[`${nivel}:${clase}`] = suma(clases[`${nivel}:${clase}`]);
  }

  /** Lo guardado más lo pendiente. */
  cuenta(modelo: string, nivel: Nivel): Cuenta {
    const guardado = leer().modelos[modelo]?.[nivel];
    const propio = this.pendiente.modelos[modelo]?.[nivel];
    return { pasos: (guardado?.pasos ?? 0) + (propio?.pasos ?? 0), rechazos: (guardado?.rechazos ?? 0) + (propio?.rechazos ?? 0) };
  }

  /** Tasa suavizada: (rechazos + peso·prior) / (pasos + peso). */
  tasa(modelo: string, nivel: Nivel, estandar: boolean): number {
    const { pasos, rechazos } = this.cuenta(modelo, nivel);
    return (rechazos + PESO_PRIOR * PRIOR[estandar ? "estandar" : "otro"][nivel]) / (pasos + PESO_PRIOR);
  }

  /** Si conviene seguir mandándole ese nivel al modelo. */
  sirve(modelo: string, nivel: Nivel, estandar: boolean): boolean {
    return this.tasa(modelo, nivel, estandar) <= UMBRAL_RECHAZO;
  }

  /** Suma lo pendiente al archivo (escritura atómica). Nunca tira: sin disco, se pierde la cuenta, no el turno. */
  vaciar(): void {
    if (!Object.keys(this.pendiente.modelos).length) return;
    try {
      const archivo = leer();
      for (const [modelo, niveles] of Object.entries(this.pendiente.modelos)) {
        const destino = (archivo.modelos[modelo] ??= {});
        for (const [nivel, cuenta] of Object.entries(niveles) as Array<[Nivel, Cuenta]>) destino[nivel] = { pasos: (destino[nivel]?.pasos ?? 0) + cuenta.pasos, rechazos: (destino[nivel]?.rechazos ?? 0) + cuenta.rechazos };
      }
      for (const [modelo, clases] of Object.entries(this.pendiente.clases)) {
        const destino = (archivo.clases[modelo] ??= {});
        for (const [clase, cuenta] of Object.entries(clases)) destino[clase] = { pasos: (destino[clase]?.pasos ?? 0) + cuenta.pasos, rechazos: (destino[clase]?.rechazos ?? 0) + cuenta.rechazos };
      }
      const path = rechazosPath();
      mkdirSync(dirname(path), { recursive: true });
      const temporal = `${path}.${process.pid}.tmp`;
      writeFileSync(temporal, `${JSON.stringify(archivo, null, 1)}\n`);
      renameSync(temporal, path);
      this.pendiente = { modelos: {}, clases: {} };
    } catch { /* sin disco: la cuenta sigue en memoria y se intenta en el próximo vaciado */ }
  }
}
