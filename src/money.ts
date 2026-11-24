// Única unidad monetaria interna: picoUSD en bigint. Se serializa como texto decimal.
export const PICO_PER_USD = 1_000_000_000_000n;

/** Tarifa en USD por millón de tokens → picoUSD por token (exacto hasta 6 decimales). */
export function ratePico(usdPerMillion: number | string): bigint {
  const text = typeof usdPerMillion === "number" ? usdPerMillion.toFixed(6) : usdPerMillion;
  if (!/^\d+(\.\d{1,6})?$/.test(text)) throw new Error(`Tarifa inválida: ${text}`);
  const [integer, fraction = ""] = text.split(".");
  return BigInt(integer!) * 1_000_000n + BigInt(fraction.padEnd(6, "0"));
}

/** Importe decimal en USD (hasta 12 decimales) → picoUSD. */
export function usdToPico(amount: number | string): bigint {
  const text = typeof amount === "number" ? amount.toFixed(12) : amount;
  if (!/^\d+(\.\d{1,12})?$/.test(text)) throw new Error(`Importe inválido: ${text}`);
  const [integer, fraction = ""] = text.split(".");
  return BigInt(integer!) * PICO_PER_USD + BigInt(fraction.padEnd(12, "0"));
}

export function usd(pico: bigint, places = 4): string {
  const factor = 10n ** BigInt(places);
  const rounded = (pico * factor + PICO_PER_USD / 2n) / PICO_PER_USD;
  return `${rounded / factor}.${String(rounded % factor).padStart(places, "0")}`;
}

export function kTokens(n: number): string {
  return n < 1000 ? String(n) : `${(n / 1000).toFixed(1)}k`;
}
