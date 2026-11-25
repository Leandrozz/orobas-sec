import { t } from "../idioma.ts";
export const BRANDS: Record<string, string> = { deepseek: "DeepSeek", glm: "GLM", qwen: "Qwen", gpt: "GPT", oss: "OSS", claude: "Claude", gemini: "Gemini", llama: "Llama", mistral: "Mistral", kimi: "Kimi", grok: "Grok", estandar: "Estándar" };
/** Nombre legible a partir del id del modelo: «deepseek-v4.1-flash» → «DeepSeek V4.1 Flash», «qwen3.8-27b» → «Qwen3.8 27B». */
export function modelName(spec: string): string {
  const words = spec.slice(spec.indexOf("/") + 1).split(/[-_\s]+/).filter(Boolean).map((word) => {
    if (word === "faux") return t("Simulado", "Simulated");
    const brand = /^([a-z]+)(\d.*)?$/i.exec(word);
    if (brand && BRANDS[brand[1]!.toLowerCase()]) return BRANDS[brand[1]!.toLowerCase()] + (brand[2] ?? "");
    if (/^\d[\d.]*b$/i.test(word) || /^v\d/i.test(word)) return word.toUpperCase();
    if (/^\d/.test(word)) return word;
    return word.charAt(0).toUpperCase() + word.slice(1);
  });
  // Versiones partidas en el id («claude-sonnet-5-5») vuelven a llevar punto.
  return words.join(" ").replace(/(\d) (?=\d+(?: |$))/g, "$1.");
}

export function personalModelName(id: string): string {
  const label = modelName(id);
  return label.replace(/^Gemini ([0-9.]+) (Hydrogen|Flash|Neon|Carbon|Argon)(?= |$)/, "Gemini $2 $1");
}
