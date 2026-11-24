// Lo que el operador ve de las trazas: el estado para /datos y /config, y el aviso de la primera vez.
// El modo y su lógica están en privacidad-trazas.ts; el formato local, en trazas-locales.ts.
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { dataDir } from "./datos.ts";
import { t } from "./idioma.ts";
import { modoCuenta, modoLocal, modoTrazas, type ModoTrazas } from "./privacidad-trazas.ts";
import { resumenCarpeta } from "./trazas-locales.ts";

const ORIGEN = () => ({ variable: t("por la variable CYBER_TRAZAS", "by the CYBER_TRAZAS variable"), "configuración": t("en la configuración", "in the settings"), defecto: t("por defecto", "by default") });

/** Qué hace cada modo, en una línea. */
export const QUE_HACE = (): Record<ModoTrazas, string> => ({
  compartir: t("el material va a Elevate AI para evaluar y entrenar el agente (sólo de las sesiones con la suscripción)", "the material goes to Elevate AI to evaluate and train the agent (only from subscription sessions)"),
  local: t("nada de contenido va al servicio; el material completo queda en tu máquina", "no content goes to the service; the full material stays on your machine"),
  no: t("nada de contenido va al servicio y no se arma material de entrenamiento", "no content goes to the service and no training material is built"),
});

/** Estado para /datos y para la fila de /config (que lee «elegido: <modo>»). */
export function lineasTrazas(dir: string): string[] {
  const local = modoLocal(), cuenta = modoCuenta(), rige = modoTrazas();
  const carpeta = resumenCarpeta(dir);
  return [
    t(`Modo de trazas elegido: ${local.modo} (${ORIGEN()[local.origen]}). Rige: ${rige}${cuenta ? ` · tu cuenta: ${cuenta}` : ""}.`, `Trace mode chosen: ${local.modo} (${ORIGEN()[local.origen]}). In effect: ${rige}${cuenta ? ` · your account: ${cuenta}` : ""}.`),
    `${rige}: ${QUE_HACE()[rige]}.`,
    ...(cuenta && cuenta !== local.modo && rige === cuenta ? [t(`Tu cuenta en cyber.elevateai.ar/cuenta/trazas está en «${cuenta}», más restrictivo: gana ése.`, `Your account at cyber.elevateai.ar/cuenta/trazas is set to “${cuenta}”, which is stricter: it wins.`)] : []),
    t("Qué son: cada pedido al modelo y su respuesta, el registro de cada turno, la trayectoria de cada sesión y la cita de tus consentimientos. Pueden traer datos de los sistemas que probás. El agente tapa los secretos que reconoce antes de que salgan o se guarden.", "What they are: every request to the model and its answer, each turn's record, each session's trajectory and the quote of your consents. They can include data from the systems you test. The agent masks the secrets it recognizes before they leave or are stored."),
    rige === "local" || carpeta.existe
      ? t(`Trazas locales: ${dir} (${carpeta.archivos} archivo${carpeta.archivos === 1 ? "" : "s"}, ${(carpeta.bytes / 1024).toFixed(1)} kB; formato en LEEME.md).`, `Local traces: ${dir} (${carpeta.archivos} file${carpeta.archivos === 1 ? "" : "s"}, ${(carpeta.bytes / 1024).toFixed(1)} kB; format in LEEME.md).`)
      : t(`Trazas locales (modo local): ${dir}`, `Local traces (local mode): ${dir}`),
    t("En cualquier modo: el servicio anota cantidades (tokens, costo, modelo, tiempos), y cada pedido viaja al proveedor del modelo para que lo responda.", "In any mode: the service records quantities (tokens, cost, model, timings), and every request travels to the model provider to be answered."),
    t("Cambiar: /datos compartir | local | no, CYBER_TRAZAS=…, o cyber.elevateai.ar/cuenta/trazas. Rige el más restrictivo.", "Change: /datos compartir | local | no, CYBER_TRAZAS=…, or cyber.elevateai.ar/cuenta/trazas. The strictest one wins."),
  ];
}

/**
 * Aviso de la primera vez en esta máquina (una sola vez: deja una marca en la carpeta de datos). No pide
 * nada: en una sesión no interactiva sale por stderr como cualquier aviso.
 */
export function avisoTrazasPrimeraVez(dir: string): string | undefined {
  const marca = join(dataDir(), "aviso-trazas.json");
  if (existsSync(marca)) return undefined;
  const rige = modoTrazas();
  try {
    mkdirSync(dataDir(), { recursive: true });
    writeFileSync(marca, `${JSON.stringify({ at: new Date().toISOString(), modo: rige })}\n`);
  } catch { /* sin marca se vuelve a avisar: mejor de más que de menos */ }
  if (rige === "compartir") return t(
    `Compartir trazas viene activado. Con los modelos de la suscripción, el material de tus sesiones (pedidos al modelo y respuestas, turnos, trayectorias y la cita de tus consentimientos) se guarda en Elevate AI para evaluar y entrenar el agente. Puede traer datos de los sistemas que probás. Antes de salir, el agente tapa las credenciales y secretos que reconoce. Cambialo cuando quieras: /datos local (queda sólo en tu PC), /datos no, CYBER_TRAZAS=local|no, o cyber.elevateai.ar/cuenta/trazas.`,
    `Sharing traces is on. With subscription models, your sessions' material (model requests and answers, turns, trajectories and the quote of your consents) is stored at Elevate AI to evaluate and train the agent. It can include data from the systems you test. Before it leaves, the agent masks the credentials and secrets it recognizes. Change it any time: /datos local (kept only on your PC), /datos no, CYBER_TRAZAS=local|no, or cyber.elevateai.ar/cuenta/trazas.`,
  );
  return t(
    `Trazas en modo «${rige}»: ${QUE_HACE()[rige]}.${rige === "local" ? ` Quedan en ${dir}.` : ""} /datos muestra el detalle y lo cambia.`,
    `Traces in “${rige}” mode: ${QUE_HACE()[rige]}.${rige === "local" ? ` They are kept in ${dir}.` : ""} /datos shows the details and changes it.`,
  );
}

/** Línea para cada sesión en modo local: dónde queda el material. */
export function avisoTrazasLocales(dir: string): string | undefined {
  return modoTrazas() === "local" ? t(`Trazas en modo local: el material de esta sesión queda en ${dir} (no sale de tu máquina).`, `Traces in local mode: this session's material is kept in ${dir} (it does not leave your machine).`) : undefined;
}
