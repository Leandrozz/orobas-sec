// Inicio guiado: la primera vez que la TUI arranca en una máquina recorre, sobre el sello, los pasos
// que dejan al agente listo: cuenta, perfil de trabajo, caja de herramientas, extensión del navegador,
// cuentas opcionales y primer alcance. Cada paso usa los mismos menús y entradas que los comandos;
// la lógica de cada cosa sigue en el daemon. Se vuelve a correr con /inicio.
import { t } from "../idioma.ts";
import { PROFILES, PROFILE_NOTES } from "../perfil.ts";
import { INSTALLABLE } from "../instalar-herramientas.ts";
import { PLATFORM_NAMES, type CommandIO, fromLines, menuIO } from "./comandos.ts";
import { accountMenu, deviceLink, mailMenu, platformMenu } from "../menu.ts";

export interface WizardStep { step: number; total: number; title: string; body: string[] }

/**
 * Selección de las herramientas a descargar: cada nombre pasa por un plan escrito en nuestro
 * código, no por un comando del modelo. Las actualizaciones quedan listadas con su resultado.
 */
export async function herramientasFaltantes(w: WizardIO, faltantes: string[]): Promise<"seguir" | WizardOutcome> {
  const { io } = w;
  const disponibles = [...new Set(faltantes)].filter((name) => INSTALLABLE.includes(name));
  if (!disponibles.length) return "seguir";
  const elegidas = new Set(disponibles);
  const step = (title: string, lines: string[]) => w.show({ step: 4, total: 7, title, body: lines });
  for (;;) {
    step(t("Descargar herramientas", "Download tools"), [
      t(`Elegidas ${elegidas.size}/${disponibles.length}. Sólo los repositorios oficiales de cada herramienta. Podés cambiar selección con ↑↓.`, `${elegidas.size}/${disponibles.length} chosen. Only official tool repositories. Change selection with the arrow keys.`),
      ...disponibles.map((name) => `${elegidas.has(name) ? "✓" : "·"} ${name}`),
    ]);
    const opciones = [
      { label: t(`descargar e instalar (${elegidas.size})`, `download and install (${elegidas.size})`) },
      { label: t("seguir sin descargar", "continue without downloading") },
      ...disponibles.map((name) => ({ label: `${elegidas.has(name) ? "✓" : "·"} ${name}`, hint: t("marcar o desmarcar", "toggle selection") })),
    ];
    const choice = await io.pick(t("Descargar herramientas", "Download tools"), opciones);
    if (choice === undefined) return onCancel(w);
    if (choice === 1) return "seguir";
    if (choice > 1) {
      const name = disponibles[choice - 2]!;
      if (elegidas.has(name)) elegidas.delete(name);
      else elegidas.add(name);
      continue;
    }
    w.busy(t("descargando e instalando", "downloading and installing"));
    const resultados: string[] = [];
    for (const name of elegidas) {
      try { resultados.push(...(await io.ask("toolbox_install", { tools: [name] }))); }
      catch (error) { resultados.push(`${name}: falló ${(error as Error).message.slice(0, 300)}`); }
    }
    w.busy(null);
    step(t("Herramientas listas", "Tools ready"), [
      ...resultados.slice(0, 18),
      t("¿No arranca? Probá /toolbox, dice qué falta y cómo instalarlo.", "Does it not start? Try /toolbox; it lists what is missing and how to fix it."),
    ]);
    await io.pick(t("Seguir", "Continue"), [{ label: t("seguir", "continue") }]).catch(() => undefined);
    return "seguir";
  }
}

export interface WizardIO {
  io: CommandIO;
  /** Muestra el encabezado del paso (y anima la barra) sin escribir en el historial. */
  show(step: WizardStep): void;
  /** Saca el encabezado. */
  hide(): void;
  /** ¿El modelo de la sesión es de la suscripción y falta la cuenta de orobas? */
  needsKey(): boolean;
  /** ¿Hay una clave de orobas cargada? Sin esto, se deduce de needsKey (como antes). */
  hasKey?(): boolean;
  /** Pegar una clave (entrada oculta), para la alternativa al sitio. */
  pasteKey(): Promise<boolean>;
  /** Mostrar algo mientras se espera (spinner con texto). */
  busy(label: string | null): void;
}

export type WizardOutcome = "completo" | "saltado" | "despues";

const TOTAL = 7;

/** Qué hacer cuando la persona cancela un paso con Esc. */
async function onCancel(w: WizardIO): Promise<"seguir" | WizardOutcome> {
  const choice = await w.io.pick(t("¿Dejamos el inicio acá?", "Leave the setup here?"), [
    { label: t("seguir", "continue"), hint: t("volver al paso", "back to the step") },
    { label: t("después", "later"), hint: t("lo retomamos la próxima vez que abras Cyber", "we pick it up next time you open Cyber") },
    { label: t("no mostrar más", "don't show again"), hint: t("siempre podés volver con /inicio", "you can always come back with /onboarding") },
  ]);
  return choice === 0 ? "seguir" : choice === 2 ? "saltado" : "despues";
}

export async function runWizard(w: WizardIO): Promise<WizardOutcome> {
  const { io } = w;
  const step = (n: number, title: string, body: string[]) => w.show({ step: n, total: TOTAL, title, body });
  // Cada paso devuelve «seguir» o un resultado final (cancelado).
  type Next = "seguir" | WizardOutcome;
  const cancel = async (): Promise<Next> => onCancel(w);

  const steps: Array<() => Promise<Next>> = [
    // 1. Bienvenida
    async () => {
      step(1, t("Bienvenida", "Welcome"), [
        t("Soy Orobas, el agente de seguridad de Elevate AI. Antes de empezar dejo listas seis cosas: tu cuenta, el perfil de trabajo, las herramientas, el navegador, las cuentas que quieras sumar y el primer alcance.", "I am Orobas, Elevate AI's security agent. Before we start I set up six things: your account, work profile, tools, browser, optional accounts and the first scope."),
        t("Tarda dos minutos. Podés saltearlo y volver con /inicio.", "It takes two minutes. You can skip it and come back with /onboarding."),
      ]);
      const choice = await io.pick(t("¿Empezamos?", "Shall we start?"), [{ label: t("empezar", "start") }, { label: t("saltear por ahora", "skip for now"), hint: t("vuelve la próxima vez", "comes back next time") }, { label: t("no mostrar más", "don't show again") }]);
      if (choice === undefined) return cancel();
      return choice === 0 ? "seguir" : choice === 1 ? "despues" : "saltado";
    },
    // 2. Cuenta
    async () => {
      if (w.hasKey ? w.hasKey() : !w.needsKey()) {
        const status = await io.ask("account", { service: "orobas", action: "status" });
        step(2, t("Cuenta", "Account"), [t(`Tu cuenta de orobas ya está vinculada: ${status[0] ?? ""}.`, `Your orobas account is already linked: ${status[0] ?? ""}.`), t("Con ella se miden el uso y el saldo. La ves en cyber.elevateai.ar/cuenta.", "It measures usage and balance. See it at cyber.elevateai.ar/cuenta.")]);
        const choice = await io.pick(t("Cuenta", "Account"), [{ label: t("seguir", "continue") }, { label: t("cambiar de cuenta", "switch account"), hint: t("entrar por el sitio con otra llave", "sign in on the site with another key") }]);
        if (choice === undefined) return cancel();
        if (choice === 1) { w.busy(t("vinculando con el sitio", "linking with the site")); try { io.notice?.(fromLines("orobas", await deviceLink(menuIO(io)), { tone: "ok" })); } catch (error) { io.notice?.({ title: "orobas", lines: [(error as Error).message], tone: "warn" }); } finally { w.busy(null); } }
        return "seguir";
      }
      // Sólo los modelos de la suscripción piden cuenta (ver cuenta.ts): con otro modelo, el paso es opcional.
      const required = w.needsKey();
      step(2, t("Cuenta", "Account"), [
        required
          ? t("El modelo de esta sesión es de la suscripción de orobas: pide tu cuenta, con la identidad verificada. Con ella se miden el uso y el saldo, y es tuya, no del equipo.", "This session's model is from the orobas subscription: it needs your account, with a verified identity. It measures usage and balance, and it is yours, not the team's.")
          : t("La cuenta es opcional: los modelos locales y tus propias claves funcionan sin ella. Los modelos de la suscripción (orobas/…) sí la piden, con la identidad verificada.", "The account is optional: local models and your own keys work without it. Subscription models (orobas/…) do need it, with a verified identity."),
        t("Lo más fácil es entrar por el sitio: te doy un código, lo aprobás con tu llave y la clave llega sola acá.", "Easiest is signing in on the site: I give you a code, you approve it with your key and the key arrives here on its own."),
      ]);
      // Con un modelo que no la pide, seguir sin cuenta va primero (Enter sigue); si no, no se ofrece.
      const options = [
        ...(required ? [] : [{ id: "sin-cuenta", label: t("seguir sin cuenta", "continue without an account"), hint: t("modelos locales o claves propias", "local models or your own keys") }]),
        { id: "sitio", label: t("entrar por el sitio", "sign in on the site"), hint: t("código + llave, recomendado", "code + key, recommended") },
        { id: "pegar", label: t("pegar una clave", "paste a key"), hint: t("de cyber.elevateai.ar/cuenta", "from cyber.elevateai.ar/cuenta") },
      ];
      for (;;) {
        const index = await io.pick(t("Tu cuenta de orobas", "Your orobas account"), options.map(({ label, hint }) => ({ label, hint })));
        if (index === undefined) { const next = await cancel(); if (next !== "seguir") return next; continue; }
        const choice = options[index]?.id;
        if (choice === "sin-cuenta") return "seguir";
        if (choice === "sitio") {
          w.busy(t("esperando tu aprobación en el sitio", "waiting for your approval on the site"));
          try { io.notice?.(fromLines("orobas", await deviceLink(menuIO(io)), { tone: "ok" })); return "seguir"; }
          catch (error) { io.notice?.({ title: "orobas", lines: [(error as Error).message], tone: "warn" }); }
          finally { w.busy(null); }
        } else if (await w.pasteKey()) return "seguir";
      }
    },
    // 3. Perfil
    async () => {
      step(3, t("Perfil de trabajo", "Work profile"), [
        t("El perfil decide qué arsenal tiene el agente y cuánto se contiene. Se cambia cuando quieras con /perfil.", "The profile decides which arsenal the agent has and how much it holds back. Change it anytime with /perfil."),
      ]);
      const current = (await io.ask("perfil", {})).join("\n");
      const at = Math.max(0, PROFILES.findIndex((profile) => new RegExp(`\\b${profile}\\b`).test(current)));
      const choice = await io.pick(t("Perfil", "Profile"), PROFILES.map((profile) => ({ label: profile, hint: PROFILE_NOTES[profile].split(/[:.]/)[0]!.trim() })), { at });
      if (choice === undefined) return cancel();
      if (choice !== at) await io.ask("perfil", { value: PROFILES[choice] });
      return "seguir";
    },
    // 4. Herramientas
    async () => {
      w.busy(t("revisando la caja de herramientas", "checking the toolbox"));
      let lines: string[];
      try { lines = await io.ask("toolbox"); } finally { w.busy(null); }
      const missing = lines.filter((line) => line.includes("✗"));
      step(4, t("Herramientas", "Tools"), [
        missing.length
          ? t(`Faltan ${missing.length}: el agente trabaja igual con lo demás, y te avisa si necesita una de estas.`, `${missing.length} missing: the agent works with the rest and tells you if it needs one of these.`)
          : t("Está todo instalado: escáneres, navegador y banco de CVE.", "Everything is installed: scanners, browser and CVE bank."),
        ...lines.filter((line) => !/^CAJA DE HERRAMIENTAS/.test(line)).slice(0, 14),
      ]);
      const choice = await io.pick(t("Herramientas", "Tools"), [{ label: t("seguir", "continue") }]);
      if (choice === undefined) return cancel();
      return herramientasFaltantes(w, [...missing.map((line) => line.split(/\s+/)[0] ?? "")]);
    },
    // 5. Navegador
    async () => {
      // La extensión es opcional: si el daemon no puede armar la guía (p. ej. EACCES al guardar el código), se avisa y se sigue.
      const guide = await io.ask("extension").catch((error: Error) => [t(`No pude preparar la extensión: ${error.message}`, `Could not set up the extension: ${error.message}`), t("Podés seguir sin ella y reintentar con «cyber extension».", "You can continue without it and retry with \"cyber extension\".")]);
      step(5, t("Tu navegador", "Your browser"), [
        t("Con la extensión de Orobas el agente usa tu Chrome, con tus sesiones abiertas, sólo en sitios del alcance. Es opcional y se instala una vez.", "With the Orobas extension the agent uses your Chrome, with your open sessions, only on in-scope sites. Optional, installed once."),
        ...guide.filter((line) => line && !/^EXTENSI/.test(line)),
      ]);
      const choice = await io.pick(t("Extensión de Chrome", "Chrome extension"), [{ label: t("listo, seguir", "done, continue") }, { label: t("después", "later"), hint: t("cyber extension muestra esto de nuevo", "cyber extension shows this again") }]);
      return choice === undefined ? cancel() : "seguir";
    },
    // 6. Cuentas opcionales
    async () => {
      for (;;) {
        step(6, t("Otras cuentas", "Other accounts"), [
          t("Opcionales. HackerOne trae el alcance de tus programas; una casilla de correo deja al agente crear cuentas en el objetivo; las plataformas (GitHub, Vercel, AWS…) sirven para revisar lo tuyo.", "Optional. HackerOne brings your programs' scope; a mailbox lets the agent create accounts on the target; platforms (GitHub, Vercel, AWS…) are for reviewing your own stuff."),
        ]);
        const choice = await io.pick(t("Sumar una cuenta", "Add an account"), [
          { label: t("seguir", "continue"), hint: t("sin sumar nada ahora", "add nothing now") },
          { label: "HackerOne", hint: t("usuario y token de la API", "username and API token") },
          { label: t("correo de prueba", "test mail"), hint: t("una casilla con contraseña de aplicación", "a mailbox with an app password") },
          { label: t("plataforma", "platform"), hint: PLATFORM_NAMES.join(", ") },
        ]);
        if (choice === undefined) { const next = await cancel(); if (next !== "seguir") return next; continue; }
        if (choice === 0) return "seguir";
        const show = (title: string, lines: string[]) => { if (lines.length) io.notice?.(fromLines(title, lines, { tone: "ok" })); };
        if (choice === 1) show("HackerOne", await accountMenu("hackerone", menuIO(io)));
        else if (choice === 2) show(t("correo", "mail"), await mailMenu(menuIO(io)));
        else {
          const which = await io.pick(t("Plataforma", "Platform"), PLATFORM_NAMES);
          if (which !== undefined) show(PLATFORM_NAMES[which]!, await platformMenu(PLATFORM_NAMES[which]!, PLATFORM_NAMES[which]!, menuIO(io)));
        }
      }
    },
    // 7. Alcance
    async () => {
      const current = await io.view("scope");
      step(7, t("Primer alcance", "First scope"), [
        t("El agente sólo toca lo que está en el alcance autorizado. Podés cargarlo ahora (un dominio, una URL, una red) o después con /scope o desde HackerOne con /h1.", "The agent only touches what is in the authorized scope. Load it now (a domain, URL or network) or later with /scope or from HackerOne with /h1."),
        ...current.slice(0, 6),
      ]);
      const rules = await io.input(t("Alcance (Enter para dejarlo para después)", "Scope (Enter to leave for later)"));
      if (rules === undefined) return cancel();
      if (rules.trim()) io.notice?.(fromLines(t("alcance", "scope"), await io.view("scope", `add ${rules.trim()}`), { tone: "ok" }));
      return "seguir";
    },
  ];

  for (let i = 0; i < steps.length; i++) {
    const next = await steps[i]!();
    if (next !== "seguir") { w.hide(); return next; }
  }
  w.hide();
  return "completo";
}

/** Cierre del inicio: lo que quedó y por dónde seguir. */
export function wizardSummary(outcome: WizardOutcome): { title: string; lines: string[]; footer: string } {
  if (outcome === "completo") return {
    title: t("Listo", "Done"),
    lines: [t("Quedó todo configurado. Decime qué querés investigar: un dominio, una URL, un repo, o «qué podés hacer».", "All set. Tell me what to look into: a domain, a URL, a repo, or “what can you do”.")],
    footer: t("/ayuda muestra todos los comandos (también /help) · /inicio repite esta guía", "/help lists every command · /onboarding repeats this guide"),
  };
  if (outcome === "despues") return { title: t("Inicio pendiente", "Setup pending"), lines: [t("Lo retomamos la próxima vez. Mientras, podés usar el agente igual.", "We pick it up next time. Meanwhile you can use the agent anyway.")], footer: t("/inicio", "/onboarding") };
  return { title: t("Inicio omitido", "Setup skipped"), lines: [t("No se muestra más. Cada paso se hace con su comando: /orobas, /perfil, /herramientas, cyber extension, /hackerone, /correo, /alcance.", "Won't show again. Each step has its command: /orobas, /profile, /toolbox, cyber extension, /hackerone, /mail, /scope.")], footer: t("/inicio", "/onboarding") };
}
