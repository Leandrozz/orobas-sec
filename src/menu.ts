// Menú y entrada oculta en la terminal común (sin TUI): lo mismo que foco.ts, en líneas.
import { detectHost } from "./correo.ts";
import { t } from "./idioma.ts";
import { KeyParser } from "./tui/keys.ts";
import { accent, bold, dim, link, truncate } from "./tui/text.ts";

/** Lee una línea de la terminal; con `hidden` no muestra lo que se escribe. */
export function prompt(question: string, hidden = false): Promise<string> {
  return new Promise((done) => {
    process.stdout.write(question);
    const stdin = process.stdin;
    let value = "";
    stdin.setRawMode?.(true);
    stdin.resume();
    const onData = (chunk: Buffer) => {
      const data = chunk.toString("utf8");
      // Esc suelto cancela (como Enter vacío); las flechas y otras secuencias se ignoran.
      if (data === "\x1b") {
        stdin.setRawMode?.(false);
        stdin.pause();
        stdin.off("data", onData);
        process.stdout.write("\n");
        return done("");
      }
      if (data.startsWith("\x1b")) return;
      for (const char of data) {
        if (char === "\r" || char === "\n") {
          stdin.setRawMode?.(false);
          stdin.pause();
          stdin.off("data", onData);
          process.stdout.write("\n");
          return done(value.trim());
        }
        if (char === "\x03") process.exit(130);
        if (char === "\x7f") value = value.slice(0, -1);
        else if (char >= " ") {
          value += char;
          if (!hidden) process.stdout.write(char);
        }
      }
    };
    stdin.on("data", onData);
  });
}

/**
 * Menú en la terminal común, con el mismo aspecto que el de la TUI: flechas o número, Enter acepta,
 * Esc, q o Ctrl+C salen sin elegir. Al terminar queda una sola línea con lo elegido. Sin terminal
 * interactiva (scripts, tests) es una lista numerada. Devuelve el índice, o undefined si no se eligió.
 */
export async function pickInTerminal(title: string, options: string[]): Promise<number | undefined> {
  const { stdin, stdout } = process;
  if (!stdin.isTTY || !stdout.isTTY) {
    console.log(title);
    options.forEach((option, index) => console.log(`  ${index + 1}. ${option}`));
    const answer = Number(await prompt(t("Elegí un número (Enter para salir): ", "Pick a number (Enter to quit): ")));
    return Number.isInteger(answer) && answer >= 1 && answer <= options.length ? answer - 1 : undefined;
  }
  const width = Math.max(20, (stdout.columns || 80) - 1);
  const help = dim(t("↑↓ elegir · Enter aceptar · Esc salir", "↑↓ move · Enter accept · Esc quit"));
  let at = 0;
  // Cada línea entra en el ancho: si una se partiera, subir N líneas para redibujar dejaría basura.
  const frame = () => ["", `  ${bold(accent(title))}`, ...options.map((option, index) => (index === at ? `  ${accent("›")} ${accent(option)}` : `    ${option}`)), `  ${help}`].map((line) => truncate(line, width));
  const height = options.length + 3;
  stdout.write(`\x1b[?25l${frame().join("\n")}`);
  return new Promise((done) => {
    const parser = new KeyParser();
    const finish = (choice: number | undefined) => {
      stdin.off("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
      const result = choice === undefined ? dim(t("sin cambios", "no changes")) : `${accent("›")} ${options[choice]}`;
      stdout.write(`\r\x1b[${height - 1}A\x1b[0J${truncate(`  ${accent(title)}  ${result}`, width)}\n\x1b[?25h`);
      done(choice);
    };
    const onData = (chunk: Buffer) => {
      for (const key of parser.parse(chunk.toString("utf8"))) {
        if (key.name === "up" || key.name === "down") at = (at + (key.name === "up" ? options.length - 1 : 1)) % options.length;
        else if (key.name === "enter") return finish(at);
        else if (key.name === "escape" || key.name === "ctrl+c" || (key.name === "text" && key.text === "q")) return finish(undefined);
        else if (key.name === "text" && /^[1-9]$/.test(key.text ?? "") && Number(key.text) <= options.length) return finish(Number(key.text) - 1);
        else continue;
        stdout.write(`\r\x1b[${height - 1}A\x1b[0J${frame().join("\n")}`);
      }
    };
    stdin.setRawMode(true);
    stdin.resume();
    stdin.on("data", onData);
  });
}

const H1 = "https://hackerone.com/settings/api_token/edit";
/** Pide un valor sin mostrarlo; vacío es undefined. */
export async function askHiddenInTerminal(label: string): Promise<string | undefined> {
  return (await prompt(`${label}: `, true)) || undefined;
}

export interface AccountIO {
  ask: (op: string, payload: object) => Promise<string[]>;
  pick: (title: string, options: string[]) => Promise<number | undefined>;
  askHidden: (label: string) => Promise<string | undefined>;
  /** Mostrar líneas antes de terminar el menú (p. ej. el código para vincular mientras se espera). */
  notice?: (lines: string[]) => void;
}

/** Vincular entrando al sitio: muestra el código, espera la aprobación y guarda la clave. */
export async function deviceLink(io: AccountIO): Promise<string[]> {
  const shown = await io.ask("account", { service: "orobas", action: "device_start" });
  io.notice?.(shown);
  return io.ask("account", { service: "orobas", action: "device_wait" });
}

/** Menú de cuenta compartido por la TUI y la terminal. El secreto sólo viaja en `ask("account")`. */
export async function accountMenu(service: "orobas" | "hackerone", io: AccountIO): Promise<string[]> {
  const name = service === "orobas" ? "orobas" : "HackerOne";
  const [state = "", ...warning] = await io.ask("account", { service, action: "status" });
  const linked = !/sin vincular|not linked/.test(state);
  // orobas: entrar por el sitio (código + llave) es el camino normal; pegar una clave queda como alternativa.
  const options = service === "orobas"
    ? linked
      ? [t("Entrar por el sitio y renovar la clave", "Sign in on the site and renew the key"), t("Pegar otra clave", "Paste another key"), t("Revocar (borrar de esta máquina)", "Revoke (delete from this machine)")]
      : [t("Entrar por el sitio (recomendado)", "Sign in on the site (recommended)"), t("Pegar una clave", "Paste a key")]
    : linked
      ? [t("Actualizar", "Update"), t("Revocar (borrar de esta máquina)", "Revoke (delete from this machine)")]
      : [t("Iniciar sesión", "Sign in")];
  const choice = await io.pick(`${name}: ${state}`, options);
  if (choice === undefined) return [];
  // El daemon ya puede traer el aviso de OROBAS_API_KEY al guardar: no repetirlo.
  const withWarning = (lines: string[]) => [...new Set([...lines, ...warning])];
  if (service === "orobas") {
    if (choice === 0) return withWarning(await deviceLink(io));
    if (linked && choice === 2) {
      const sure = await io.pick(t(`¿Revocar ${name}?`, `Revoke ${name}?`), [t("Sí, revocar", "Yes, revoke"), t("Cancelar", "Cancel")]);
      return sure === 0 ? io.ask("account", { service, action: "revoke" }) : [];
    }
  } else if (linked && choice === 1) {
    const sure = await io.pick(t(`¿Revocar ${name}?`, `Revoke ${name}?`), [t("Sí, revocar", "Yes, revoke"), t("Cancelar", "Cancel")]);
    return sure === 0 ? io.ask("account", { service, action: "revoke" }) : [];
  }
  let username: string | undefined;
  if (service === "hackerone") {
    username = await io.askHidden(t("Usuario de HackerOne", "HackerOne username"));
    if (!username) return [];
  }
  const value = await io.askHidden(service === "orobas" ? t(`Pegá tu clave de ${link("https://cyber.elevateai.ar/cuenta")}`, `Paste your key from ${link("https://cyber.elevateai.ar/cuenta")}`) : t(`Token de API (${link(H1)})`, `API token (${link(H1)})`));
  if (!value) return [];
  return withWarning(await io.ask("account", { service, action: "save", value, username }));
}

/**
 * Menú de las casillas de correo de prueba. Se pueden vincular varias; el agente genera sobre
 * ellas todas las direcciones «+etiqueta» que necesite. La contraseña sólo viaja en `ask("mail_account")`.
 */
export async function mailMenu(io: AccountIO): Promise<string[]> {
  const state = await io.ask("mail_account", { action: "status" });
  const linked = !/sin vincular|not linked/.test(state[0] ?? "");
  const boxes = linked ? state : [];
  const title = linked ? t(`Correo de prueba: ${boxes.length} casilla${boxes.length > 1 ? "s" : ""} vinculada${boxes.length > 1 ? "s" : ""}`, `Test mail: ${boxes.length} mailbox(es) linked`) : t("Correo de prueba: sin vincular", "Test mail: not linked");
  const options = [t("Agregar una casilla", "Add a mailbox"), ...boxes.map((box) => t(`Quitar ${box.split(" ")[0]}`, `Remove ${box.split(" ")[0]}`))];
  const choice = await io.pick(title, options);
  if (choice === undefined) return [];
  if (choice > 0) return io.ask("mail_account", { action: "remove", address: boxes[choice - 1]!.split(" ")[0] });
  const address = await io.askHidden(t("Dirección de la casilla (p. ej. vos@gmail.com)", "Mailbox address (e.g. you@gmail.com)"));
  if (!address) return [];
  const host = await detectHost(address);
  const value = await io.askHidden(/gmail|google/.test(host)
    ? t(`Contraseña de aplicación de Google (${link("https://myaccount.google.com/apppasswords")}) · servidor ${host}`, `Google app password (${link("https://myaccount.google.com/apppasswords")}) · server ${host}`)
    : t(`Contraseña de la casilla · servidor ${host}`, `Mailbox password · server ${host}`));
  if (!value) return [];
  const alias = await io.askHidden(t("Alias para registrarse, si usás uno (p. ej. usuario@wearehackerone.com); Enter para saltear", "Sign-up alias, if you use one (e.g. user@wearehackerone.com); Enter to skip"));
  return io.ask("mail_account", { action: "add", address, value, alias, host });
}

/** Menú de una plataforma (gh, vercel, …): estado, iniciar sesión por dispositivo o revocar. */
export async function platformMenu(name: string, label: string, io: Pick<AccountIO, "ask" | "pick">): Promise<string[]> {
  const [state = ""] = await io.ask("platform_account", { name, action: "status" });
  if (/sin instalar|not installed/.test(state)) return [`${label}: ${state}`];
  const linked = !/sin vincular|not linked/.test(state);
  const choice = await io.pick(`${label}: ${state}`, linked ? [t("Revocar (cerrar sesión y borrar de esta máquina)", "Revoke (sign out and delete from this machine)")] : [t("Iniciar sesión", "Sign in")]);
  if (choice === undefined) return [];
  if (!linked) return io.ask("platform_account", { name, action: "link" });
  const sure = await io.pick(t(`¿Revocar ${label}?`, `Revoke ${label}?`), [t("Sí, revocar", "Yes, revoke"), t("Cancelar", "Cancel")]);
  return sure === 0 ? io.ask("platform_account", { name, action: "revoke" }) : [];
}

/** El navegador autoriza; la URL se muestra también para máquinas sin escritorio. */
export interface ChatgptIO extends Pick<AccountIO, "ask" | "pick"> {
  notice?: (lines: string[], waiting?: boolean) => void;
}
async function chatgptNotice(io: ChatgptIO): Promise<boolean> {
  const [state, ...lines] = await io.ask("chatgpt", { action: "notice" });
  if (state !== "pendiente") return true;
  io.notice?.(lines);
  const choice = await io.pick("Términos de OpenAI", ["Continue with ChatGPT", "Cancelar"]);
  if (choice !== 0) return false;
  await io.ask("chatgpt", { action: "accept_notice" });
  return true;
}
async function chatgptSignIn(io: ChatgptIO, add = false): Promise<string[]> {
  if (!(await chatgptNotice(io))) return [];
  io.notice?.(await io.ask("chatgpt", { action: add ? "add" : "start" }), true);
  return io.ask("chatgpt", { action: "wait" });
}
export const chatgptLogin = (io: ChatgptIO) => chatgptSignIn(io);
export async function chatgptMenu(io: ChatgptIO): Promise<string[]> {
  const state = JSON.parse((await io.ask("chatgpt", { action: "state" }))[0] ?? "{}") as { accounts?: Array<{ clientId: string; email?: string; active: boolean }>; linked?: boolean };
  const rows = ["Ver estado y uso", "Continue with ChatGPT", "Agregar otra cuenta", ...(state.accounts ?? []).filter((item) => !item.active).map((item) => "Usar " + (item.email ?? item.clientId)), "Salir de ChatGPT"];
  const choice = await io.pick("ChatGPT", rows);
  if (choice === undefined) return [];
  if (choice === 0) return io.ask("chatgpt", { action: "status" });
  if (choice === 1) return chatgptSignIn(io);
  if (choice === 2) return chatgptSignIn(io, true);
  const other = (state.accounts ?? []).filter((item) => !item.active);
  if (choice < 3 + other.length) return io.ask("chatgpt", { action: "switch", clientId: other[choice - 3]!.clientId });
  return io.ask("chatgpt", { action: "logout" });
}
