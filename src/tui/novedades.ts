// Novedades de la TUI: lo nuevo que alguien que ya usaba cyber no se enteraría solo. Sumar una es agregar una
// entrada arriba de NOVEDADES (más nueva primero); al abrir, las no vistas salen juntas en un panel (máx. 3).
import { t } from "../idioma.ts";

export interface Novedad { id: string; titulo: () => string; lineas: () => string[] }

export const NOVEDADES: Novedad[] = [
  {
    id: "2026-11-navegador",
    titulo: () => t("Tu navegador, autorizado una vez por proyecto", "Your browser, allowed once per project"),
    lineas: () => [t("/navegador si (o decirle «usá mi navegador») lo autoriza para todas las sesiones del proyecto; /navegador no lo revoca y /navegador solo muestra si la extensión está conectada, dormida o sin emparejar, y qué hacer.", "/navegador si (or telling it \"use my browser\") allows it for every session of the project; /navegador no revokes it, and /navegador alone shows whether the extension is connected, asleep or not paired, and what to do."), t("Si la extensión está dormida, el agente la espera hasta 35 s en vez de fallar. Recargá la extensión en chrome://extensions para tener la versión 0.4.0.", "If the extension is asleep, the agent waits up to 35 s for it instead of failing. Reload the extension in chrome://extensions to get version 0.4.0.")],
  },
  {
    id: "2026-11-cves-nuevos",
    titulo: () => t("CVEs nuevos que podrían aplicar", "New CVEs that could apply"),
    lineas: () => [t("Los CVE críticos y altos recién publicados (Zero Wire, Cloudflare Radar) se cruzan solos con lo que el agente vio en el alcance: te aviso con el link y se lo paso al agente en su próximo turno, sin cortar lo que hace.", "Freshly published critical and high CVEs (Zero Wire, Cloudflare Radar) are matched on their own against what the agent saw in scope: I warn you with the link and hand it to the agent on its next turn, without stopping what it is doing."), t("/cves muestra el estado, los cruces y los últimos críticos; «cveFeed»: false en la configuración lo apaga.", "/cves shows the status, the matches and the latest critical ones; «cveFeed»: false in the settings turns it off.")],
  },
  {
    id: "2026-11-comandos-agrupados",
    titulo: () => t("Menos comandos a la vista", "Fewer commands in sight"),
    lineas: () => [t("Al tocar / ves 17 comandos; lo demás vive en su grupo: /conexiones (GitHub, HackerOne, nubes…), /limites, /diseño (ventanas y pestañas), /herramientas.", "Typing / shows 17 commands; the rest live in their group: /conexiones (GitHub, HackerOne, clouds…), /limites, /diseño (windows and tabs), /herramientas."), t("Los nombres de siempre siguen andando: escribí /git y aparece, con el grupo donde vive. /ayuda tiene las teclas por sección.", "The usual names still work: type /git and it shows up, with the group it lives in. /ayuda lists the keys by section.")],
  },
  {
    id: "2026-11-ventanas-ia",
    titulo: () => t("Ver a los subagentes y a /ultra trabajando", "Watch subagents and /ultra at work"),
    lineas: () => [t("En F2, debajo de cada sesión, aparecen sus subagentes y los harnesses de /ultra que corren en ella; las corridas anteriores van al final.", "In F2, under each session, its subagents and the /ultra harnesses running in it show up; earlier runs go at the end."), t("Enter abre uno en una ventana; si es de otra sesión, la ventana pasa a esa sesión.", "Enter opens one in a window; if it belongs to another session, the window switches to that session.")],
  },
  {
    id: "2026-11-ventanas",
    titulo: () => t("Varias ventanas a la vez", "Several windows at once"),
    lineas: () => [t("/ventanas divide la pantalla: lado a lado, tres o 2×2.", "/ventanas splits the screen: side by side, three or 2×2."), t("F6 cambia de ventana; F2 muestra la lista de sesiones.", "F6 switches window; F2 shows the session list.")],
  },
  {
    id: "2026-11-mouse",
    titulo: () => t("Copiar con el mouse", "Copy with the mouse"),
    lineas: () => [t("Arrastrá y al soltar se copia; doble clic toma una palabra, triple una línea.", "Drag and it copies on release; double click picks a word, triple a line."), t("Se apaga en /config (Mouse).", "Turn it off in /config (Mouse).")],
  },
  {
    id: "2026-11-temas",
    titulo: () => t("Temas de colores", "Color themes"),
    lineas: () => [t("/tema elige entre seis temas.", "/tema picks one of six themes.")],
  },
  {
    id: "2026-11-ultra",
    titulo: () => t("Modo ultra", "Ultra mode"),
    lineas: () => [t("/ultra <tarea> reparte el trabajo entre harnesses; /ultra solo elige cuáles.", "/ultra <task> splits the work across harnesses; plain /ultra picks which ones."), t("/orquesta los muestra.", "/orquesta shows them.")],
  },
];

/** Las no vistas, más nuevas primero, hasta 3. */
export const pendientes = (vistas: string[]): Novedad[] => NOVEDADES.filter((n) => !vistas.includes(n.id)).slice(0, 3);

/** Líneas de un panel: «◆ título» y el texto con sangría. */
export const lineasDe = (lista: Novedad[]): string[] => lista.flatMap((n) => [`◆ ${n.titulo()}`, ...n.lineas().map((l) => `  ${l}`)]);
