// Textos nuevos en es/en: español si LC_ALL, LC_MESSAGES o LANG (el primero definido) empieza con "es".
export function t(es: string, en: string): string {
  const lang = process.env.LC_ALL || process.env.LC_MESSAGES || process.env.LANG || "";
  return lang.startsWith("es") ? es : en;
}
