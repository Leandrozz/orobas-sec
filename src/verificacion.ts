// Cuándo corre el verificador independiente solo. Es un ajuste del operador (en /config y en config.json,
// clave «verificacion»), no del agente:
//   «automatica»: al cierre de cada turno verifica los candidatos nuevos o cambiados;
//   «a-pedido»: sólo con /verificar;
//   «tope» (por defecto, USD 1): automática hasta un gasto del verificador por sesión (topeUsd, USD), después espera /verificar.
// Y la huella de un candidato: lo que el verificador ya vio. Con la misma huella no se vuelve a verificar solo.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { Finding } from "./findings.ts";
import { configPath } from "./providers.ts";

export type VerifyMode = "automatica" | "a-pedido" | "tope";
export interface VerifySetting { mode: VerifyMode; topeUsd: number }

export const DEFAULT_VERIFY: VerifySetting = { mode: "tope", topeUsd: 1 };

/** Lee el ajuste de config.json; uno ilegible o ausente es el por defecto (tope de USD 1). */
export function readVerifySetting(): VerifySetting {
  try {
    const path = configPath();
    if (!existsSync(path)) return DEFAULT_VERIFY;
    const raw = (JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, "")) as { verificacion?: unknown }).verificacion;
    if (typeof raw === "string") return parseVerifySetting(raw) ?? DEFAULT_VERIFY;
    if (raw && typeof raw === "object") {
      const { modo, topeUsd } = raw as { modo?: unknown; topeUsd?: unknown };
      const mode = parseVerifySetting(String(modo ?? ""))?.mode ?? DEFAULT_VERIFY.mode;
      const tope = Number(topeUsd);
      return { mode, topeUsd: Number.isFinite(tope) && tope > 0 ? tope : DEFAULT_VERIFY.topeUsd };
    }
  } catch { /* configuración ilegible: la de siempre */ }
  return DEFAULT_VERIFY;
}

/** «automatica», «a pedido», «tope 2», «tope 1,5». undefined si no es ninguno. */
export function parseVerifySetting(text: string): VerifySetting | undefined {
  const value = text.trim().toLowerCase().normalize("NFKD").replace(/\p{M}/gu, "");
  if (/^(automatica|auto|si|on)$/.test(value)) return { mode: "automatica", topeUsd: DEFAULT_VERIFY.topeUsd };
  if (/^(a[- ]?pedido|manual|no|off)$/.test(value)) return { mode: "a-pedido", topeUsd: DEFAULT_VERIFY.topeUsd };
  const tope = /^tope(?:\s+(?:usd\s*)?(\d+(?:[.,]\d+)?))?$/.exec(value);
  if (tope) {
    const amount = tope[1] ? Number(tope[1].replace(",", ".")) : DEFAULT_VERIFY.topeUsd;
    return amount > 0 ? { mode: "tope", topeUsd: amount } : undefined;
  }
  return undefined;
}

/** Guarda el ajuste en config.json sin tocar lo demás. */
export function saveVerifySetting(setting: VerifySetting): void {
  const path = configPath();
  let config: Record<string, unknown> = {};
  if (existsSync(path)) {
    const parsed = JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, "")) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) config = parsed as Record<string, unknown>;
  }
  config.verificacion = setting.mode === "tope" ? { modo: "tope", topeUsd: setting.topeUsd } : setting.mode;
  mkdirSync(dirname(path), { recursive: true });
  const temp = `${path}.${process.pid}.tmp`;
  writeFileSync(temp, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  renameSync(temp, path);
}

export function verifySettingLine(setting: VerifySetting): string {
  const what = setting.mode === "automatica"
    ? "automática: al cierre de cada turno verifica los candidatos nuevos o con evidencia nueva"
    : setting.mode === "a-pedido"
      ? "a pedido: sólo con /verificar"
      : `automática con tope: hasta USD ${setting.topeUsd} del verificador por sesión, después espera /verificar`;
  return `Verificación ${what}. Se guarda en ${configPath()} («verificacion»). Uso: /verificacion automatica | a-pedido | tope <USD>`;
}

/**
 * Huella de lo que el verificador tiene para mirar: el activo y la evidencia (hashes, en orden). El título o
 * el resumen pueden cambiar sin que haya nada nuevo que reproducir; con evidencia nueva, sí.
 */
export function findingPrint(finding: Pick<Finding, "asset" | "evidence">): string {
  return createHash("sha256").update(JSON.stringify([finding.asset.trim().toLowerCase(), [...finding.evidence].sort()])).digest("hex").slice(0, 24);
}
