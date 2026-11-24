// Detección purple (perfil «defensa»/«laboratorio»): las mismas sondas ofensivas corren contra
// infra propia para validar que los controles detectan lo que dicen detectar. Un ataque exitoso
// sin señal detectada es un hallazgo de gap de detección, con la misma evidencia que cualquier
// otro. La señal la declara el operador (canal syslog mínimo de laboratorio) o queda NULL
// (ninguna esperada). Aquí sólo la base: marcado de expected_signal, análisis hits/misses,
// hallazgos detection-gap y la categoría de cobertura «detección».
import type { DatabaseSync } from "node:sqlite";
import type { Tool, ToolResult } from "./agent.ts";
import type { Findings } from "./findings.ts";
import type { Coverage } from "./coverage.ts";
import type { ProfileGrants } from "./perfil.ts";

export interface DetectionSignal {
  id: string;
  /** Acción ofensiva que debía disparar la señal (id de intercambio, id de artefacto o etiqueta). */
  accion: string;
  /** Señal esperada: nombre de regla Sigma/Snort o etiqueta del operador. */
  esperada: string;
  /** Si la señal llegó por el canal declarado. */
  detectada: boolean;
  at: string;
}

/** Registra la señal esperada de una acción y, más tarde, si llegó. */
export class DetectionLedger {
  readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
    db.exec("create table if not exists detection(id text primary key, accion text not null, esperada text not null, detectada integer not null, at text not null)");
  }

  expect(accion: string, esperada: string): DetectionSignal {
    const id = `d${Math.random().toString(36).slice(2, 8)}`;
    const at = new Date().toISOString();
    this.db.prepare("insert into detection(id,accion,esperada,detectada,at) values(?,?,?,?,?)").run(id, accion, esperada, 0, at);
    return { id, accion, esperada, detectada: false, at };
  }

  /** Marca que la señal de una acción llegó por el canal declarado. */
  hit(accion: string): boolean {
    const rows = this.db.prepare("select id from detection where accion=? and detectada=0 order by at limit 1").all(accion) as Array<{ id: string }>;
    if (!rows.length) return false;
    this.db.prepare("update detection set detectada=1 where id=?").run(rows[0]!.id);
    return true;
  }

  /** Todas las señales, o las que matcheen una acción. */
  signals(accion?: string): DetectionSignal[] {
    const rows = accion
      ? this.db.prepare("select id,accion,esperada,detectada,at from detection where accion=? order by at").all(accion)
      : this.db.prepare("select id,accion,esperada,detectada,at from detection order by at").all();
    return (rows as any[]).map((row) => ({ id: row.id, accion: row.accion, esperada: row.esperada, detectada: !!row.detectada, at: row.at }));
  }

  /** Resumen purple: totales, misses (gaps de detección) y la lista para el informe. */
  summary(): { esperadas: number; detectadas: number; gaps: DetectionSignal[] } {
    const all = this.signals();
    const detectadas = all.filter((signal) => signal.detectada).length;
    return { esperadas: all.length, detectadas, gaps: all.filter((signal) => !signal.detectada) };
  }
}

const str = (extra: object = {}) => ({ type: "string", ...extra });
const obj = (properties: Record<string, object>, required: string[]) => ({ type: "object", properties, required });
const finish = (text: string, details: Record<string, unknown> = {}): ToolResult => ({ text, details });

export interface DetectionContext {
  ledger: () => DetectionLedger | undefined;
  grants: () => ProfileGrants;
  findings: Findings;
  coverage: Coverage;
  sessionId: string;
}

/**
 * Herramientas del modo purple. Sólo con perfil defensa/laboratorio: el registro de señales
 * esperadas y el análisis de gaps. La señal la declara el operador (regla Sigma/Snort o
 * etiqueta) antes de la acción ofensiva; detection_hit marca que llegó por el canal declarado.
 */
export function createDetectionTools(context: DetectionContext): Tool[] {
  const { ledger, grants, findings, coverage, sessionId } = context;

  const gate = () => {
    if (!grants().detection) throw new Error("El modo detección requiere perfil «laboratorio» o «defensa» (el operador lo cambia con /perfil).");
    return ledger()!;
  };

  const detectionExpect: Tool = {
    name: "detection_expect",
    label: "Registrar señal esperada (purple)",
    description:
      "Antes de una acción ofensiva contra infra propia, registra qué señal debería disparar (regla Sigma/Snort o etiqueta del operador) y sobre qué acción (id de intercambio HTTP o etiqueta). Después de la acción, detection_hit marca si llegó por el canal declarado. " +
      "Una señal esperada que nunca llega es un gap de detección: se registra como hallazgo detection-gap con la misma evidencia que cualquier otro. Sólo perfil defensa/laboratorio.",
    parameters: obj({ accion: str({ description: "Id del intercambio HTTP o etiqueta de la acción ofensiva" }), esperada: str({ description: "Regla o etiqueta de la señal que debería dispararse" }) }, ["accion", "esperada"]),
    execute: (params) => {
      const ledger = gate();
      const signal = ledger.expect(params.accion, params.esperada);
      return finish(`Señal esperada ${signal.id}: «${params.esperada}» por la acción «${params.accion}». Después de la acción, marcá si llegó con detection_hit.`, { id: signal.id });
    },
  };

  const detectionHit: Tool = {
    name: "detection_hit",
    label: "Marcar señal detectada (purple)",
    description: "Marca que la señal esperada de una acción llegó por el canal de detección declarado (syslog de laboratorio, lupa, etc.). Si nunca llega, no se marca: queda como gap y detection_view lo lista para el informe.",
    parameters: obj({ accion: str({ description: "Acción de la señal esperada" }) }, ["accion"]),
    execute: (params) => {
      const ledger = gate();
      if (!ledger.hit(params.accion)) throw new Error(`No hay señal esperada pendiente para la acción «${params.accion}». Se registra primero con detection_expect.`);
      return finish(`Señal de «${params.accion}» detectada.`, { accion: params.accion });
    },
  };

  const detectionView: Tool = {
    name: "detection_view",
    label: "Análisis de detección (purple)",
    description:
      "Al cerrar el ejercicio de detección, consultá los totales y las señales esperadas que siguen pendientes. El operador revisa cada ausencia antes de decidir si corresponde registrar un hallazgo.",
    parameters: obj({}, []),
    execute: (params) => {
      const ledger = gate();
      const summary = ledger.summary();
      if (!summary.esperadas) return finish("Sin señales esperadas todavía (detection_expect antes de cada acción ofensiva). No hay análisis sin expectativas.");
      const rows = ledger.signals().map((signal) => `${signal.id}  «${signal.esperada}» por «${signal.accion}»  ${signal.detectada ? "detectada" : "GAP: nunca llegó"}`);
      const gapsText = summary.gaps.length ? `\nGaps (${summary.gaps.length}): cada uno va como hallazgo detection-gap; el operador decide severidad. Un ataque exitoso que nadie detectó es la falla del lado de la defensa, con la misma evidencia que cualquier hallazgo.` : "\nSin gaps: todas las señales esperadas llegaron por el canal declarado.";
      return finish(`detección · ${summary.detectadas}/${summary.esperadas} señales detectadas\n${rows.join("\n")}${gapsText}`, { esperadas: summary.esperadas, detectadas: summary.detectadas, gaps: summary.gaps.length });
    },
  };

  return [detectionExpect, detectionHit, detectionView];
}