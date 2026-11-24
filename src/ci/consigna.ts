// La consigna de una corrida de CI: lo que el agente recibe como único mensaje. No hay operador: dice qué está
// autorizado (y que no se puede ampliar), con qué identidades, con cuánto, qué buscar y cómo dejar la evidencia
// para que el verificador independiente la reproduzca después.
import type { Cambios } from "./cambios.ts";
import type { ConfigCi, Perfil } from "./config.ts";

const PERFIL: Record<Perfil, string> = {
  general: "Recorré la superficie del alcance (rutas, API, autenticación) y buscá fallas con efecto: control de acceso entre identidades (IDOR/BOLA, funciones de administración), autenticación y sesión, inyección (SQL, comandos, plantillas), XSS, redirecciones abiertas, exposición de datos o de configuración y lógica de negocio.",
  api: "Es una API. Prioridad: control de acceso entre identidades (IDOR/BOLA y funciones de administración: probá cada recurso con cada identidad y sin credenciales), asignación masiva, autenticación y tokens (JWT, sesiones), inyección en parámetros y cuerpos, y exposición de datos en las respuestas.",
  web: "Es una aplicación web. Prioridad: XSS reflejado y almacenado, CSRF, redirecciones abiertas, manejo de sesión y cookies, exposición de archivos y de configuración, y control de acceso de las páginas y de sus llamadas a la API.",
  superficie: "Pasada rápida y barata: mapa de rutas, exposición de configuración, archivos y versiones, autenticación básica y control de acceso evidente. Sin pruebas profundas ni muchas variantes.",
  completo: "Evaluación completa: toda la superficie del alcance, control de acceso con cada identidad, autenticación, inyección, XSS, CSRF, SSRF, subida de archivos, lógica de negocio y condiciones de carrera.",
};

export interface DatosConsigna {
  config: ConfigCi;
  huella: string;
  identidades: string[];
  exploracionUsd: number;
  exploracionMin: number;
  cambios: Cambios;
}

export function armarConsigna({ config, huella, identidades, exploracionUsd, exploracionMin, cambios }: DatosConsigna): string {
  const ev = config.evaluacion;
  const lineas = [
    `[CI] Evaluación de seguridad no interactiva (integración continua) «${config.nombre}». No hay operador: nadie va a contestar preguntas. Decidí vos con lo que tenés y dejalo registrado.`,
    `Alcance: lo autorizó el equipo en ${config.archivo} (huella ${huella}) y está sellado: no se puede ampliar ni cambiar, y lo que esté afuera no se toca (el harness lo rechaza). Está en el bloque <alcance>.`,
    identidades.length ? `Identidades de prueba cargadas: ${identidades.join(", ")}. Usalas con «identity»; sus valores no los ves ni los necesitás. Probá el acceso cruzado entre ellas.` : "No hay identidades de prueba: probá lo que se puede sin credenciales y decí qué no se pudo por eso.",
    `Topes: USD ${exploracionUsd.toFixed(2)} para explorar y ${Math.max(1, Math.round(exploracionMin))} minutos. No gastes en variantes triviales de lo mismo.`,
    ...(ev.soloLectura ? ["Modo sólo lectura: sólo salen GET, HEAD y OPTIONS; cualquier otro método se rechaza. No intentes escrituras."] : []),
    ...(cambios.activo
      ? [`Este PR cambió estas rutas (inferidas del diff); concentrate en ellas y en lo que las habilita, como el inicio de sesión:\n${cambios.rutas.slice(0, 40).map((r) => `- ${r.ruta} (${r.archivo}${r.linea ? `:${r.linea}` : ""})`).join("\n")}${cambios.rutas.length > 40 ? `\n- y ${cambios.rutas.length - 40} más` : ""}`]
      : []),
    `Objetivo: ${PERFIL[ev.perfil]}`,
    "Registrá cada falla con finding_record como candidato, con su evidencia (los ids hN de tus peticiones) y con el activo como URL completa: un verificador independiente la va a reproducir después con una prueba y un control. Sin evidencia queda como pista. No marques nada como verificado. No borres ni modifiques datos ajenos.",
    "Al terminar, cerrá con un resumen corto: qué probaste, qué encontraste y qué no llegaste a probar.",
  ];
  if (ev.consigna) lineas.push(`Indicaciones del equipo:\n${ev.consigna}`);
  return lineas.join("\n\n");
}
