import { t } from "../idioma.ts";

export type TemaId = "orobas" | "elevate" | "hacker" | "filete" | "hornero" | "ambar";
export type Intensidad = "no" | "suave" | "fuerte";

export interface Tema {
  id: TemaId;
  nombre(): string;
  descripcion(): string;
  fondo?: string; // hex "#rrggbb"; sin definir = el de la terminal (sólo Orobas)
  texto?: string;
  acento: string;
  acentoNegrita: boolean;
  aviso: string;
  avisoInverso: boolean;
  apagado: string;
  insignia: [texto: string, fondo: string];
  segmento: [string, string];
  segmentoApagado: [string, string];
  adorno?: { glifo: string; color: string };
  bordes: string; // 6 caracteres: ┌ ┐ └ ┘ ─ │ en ese orden
  cursor: string;
  ok: string;
  error: string;
  avisoSimbolo: string;
  escarapela: boolean;
  descifrado: Intensidad;
  glifos: string;
}

/** Fondo supuesto de Orobas (el de la terminal) para contraste y badgeWarn. */
export const FONDO_REFERENCIA = "#14181e";

export const TEMAS: readonly Tema[] = [
  {
    id: "orobas",
    nombre: () => "Orobas",
    descripcion: () => t("el de hoy", "the default"),
    acento: "#74acdf", acentoNegrita: false, aviso: "#f6b40e", avisoInverso: false, apagado: "#808b98",
    insignia: ["#14181e", "#74acdf"], segmento: ["#dce2e8", "#2a3038"], segmentoApagado: ["#808b98", "#1e2228"],
    bordes: "╭╮╰╯─│", cursor: "›", ok: "✓", error: "✗", avisoSimbolo: "⚠", escarapela: false,
    descifrado: "suave", glifos: "ΔΩλμ",
  },
  {
    id: "elevate",
    nombre: () => "Elevate AI",
    descripcion: () => t("sobrio", "understated"),
    fondo: "#0d1117", texto: "#eeeef2",
    acento: "#eeeef2", acentoNegrita: true, aviso: "#f6b40e", avisoInverso: false, apagado: "#8a96a8",
    insignia: ["#0d1117", "#eeeef2"], segmento: ["#eeeef2", "#1b2c3e"], segmentoApagado: ["#8a96a8", "#102030"],
    bordes: "┌┐└┘─│", cursor: "▸", ok: "✓", error: "✗", avisoSimbolo: "⚠", escarapela: false,
    descifrado: "no", glifos: "",
  },
  {
    id: "hacker",
    nombre: () => "Hacker",
    descripcion: () => t("fósforo verde", "green phosphor"),
    fondo: "#000000", texto: "#39ff6a",
    acento: "#b6ffc8", acentoNegrita: false, aviso: "#ffb000", avisoInverso: true, apagado: "#2f9e4f",
    insignia: ["#000000", "#39ff6a"], segmento: ["#39ff6a", "#0b2a14"], segmentoApagado: ["#2f9e4f", "#06160b"],
    bordes: "++++-|", cursor: ">_", ok: "[+]", error: "[!]", avisoSimbolo: "[!]", escarapela: false,
    descifrado: "fuerte", glifos: "ΞΣΨΔЖЯЮλ",
  },
  {
    id: "filete",
    nombre: () => "Filete porteño",
    descripcion: () => t("oro y marfil", "gold and ivory"),
    fondo: "#0e0e0e", texto: "#f3ead7",
    acento: "#f2c230", acentoNegrita: false, aviso: "#ff6b4a", avisoInverso: true, apagado: "#a59b86",
    insignia: ["#0e0e0e", "#f2c230"], segmento: ["#f3ead7", "#2a2418"], segmentoApagado: ["#a59b86", "#1a1712"],
    adorno: { glifo: "❦", color: "#5fb4e6" },
    bordes: "╔╗╚╝═║", cursor: "❧", ok: "✓", error: "✗", avisoSimbolo: "⚠", escarapela: false,
    descifrado: "suave", glifos: "ǂƒǁ",
  },
  {
    id: "hornero",
    nombre: () => "Hornero",
    descripcion: () => t("barro y paja", "mud and straw"),
    fondo: "#1c1611", texto: "#efe3cf",
    acento: "#d9954f", acentoNegrita: false, aviso: "#f7d774", avisoInverso: false, apagado: "#9a8b7a",
    insignia: ["#1c1611", "#d9954f"], segmento: ["#efe3cf", "#3a2c20"], segmentoApagado: ["#9a8b7a", "#271e16"],
    bordes: "╭╮╰╯─│", cursor: "⌂", ok: "✓", error: "✗", avisoSimbolo: "⚠", escarapela: false,
    descifrado: "suave", glifos: "ʘɷɐǝ",
  },
  {
    id: "ambar",
    nombre: () => t("Hacker argentino (ámbar)", "Argentine hacker (amber)"),
    descripcion: () => t("fósforo ámbar", "amber phosphor"),
    fondo: "#000000", texto: "#ffb000",
    acento: "#ffd98a", acentoNegrita: false, aviso: "#ffffff", avisoInverso: true, apagado: "#b07a10",
    insignia: ["#000000", "#ffb000"], segmento: ["#ffb000", "#2a1c00"], segmentoApagado: ["#b07a10", "#140e00"],
    bordes: "++++-|", cursor: "che@orobas:~$", ok: "[+]", error: "[!]", avisoSimbolo: "[!]", escarapela: true,
    descifrado: "fuerte", glifos: "ñÑçÇßΞЖ",
  },
];

let activo: Tema = TEMAS[0]!;

export function temaActivo(): Tema {
  return activo;
}

/** Sólo en memoria; no persiste. */
export function usarTema(id: TemaId): void {
  activo = TEMAS.find((x) => x.id === id) ?? TEMAS[0]!;
}

const normalizar = (s: string) => s.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase().trim().replace(/\s+/g, " ");

/** Por id o por nombre, sin tildes ni mayúsculas ni espacios de más. */
export function buscarTema(texto: string): Tema | undefined {
  const q = normalizar(texto);
  return TEMAS.find((x) => x.id === q || normalizar(x.nombre()) === q);
}

const CONHOST: Record<string, string> = { "❦": "*", "❧": ">", "⌂": ">", "◎": "o", "▸": ">", "╭": "┌", "╮": "┐", "╰": "└", "╯": "┘" };

export function simbolos(): { bordes: [string, string, string, string, string, string]; cursor: string; ok: string; error: string; avisoSimbolo: string; adorno?: string; escarapela?: string } {
  const conhost = process.env.CYBER_CONSOLE === "conhost";
  const mapa = (s: string) => (conhost ? [...s].map((c) => CONHOST[c] ?? c).join("") : s);
  return {
    bordes: [...mapa(activo.bordes)] as [string, string, string, string, string, string],
    cursor: mapa(activo.cursor),
    ok: activo.ok,
    error: activo.error,
    avisoSimbolo: activo.avisoSimbolo,
    adorno: activo.adorno && mapa(activo.adorno.glifo),
    escarapela: activo.escarapela ? mapa("◎") : undefined,
  };
}

const luminancia = (hex: string) => {
  const [r = 0, g = 0, b = 0] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};

/** Razón de contraste WCAG 2.x entre dos colores "#rrggbb". */
export function contraste(a: string, b: string): number {
  const [x, y] = [luminancia(a), luminancia(b)];
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}
