// Proyección de la sesión para la pantalla pública. Nunca se guarda en la conversación.
import { reemplazarTokensConPrefijo } from "../credenciales.ts";
import { BlockList, isIP } from "node:net";
import { userInfo } from "node:os";
import { domainToASCII } from "node:url";
import { DatabaseSync } from "node:sqlite";
import type { Entrada } from "./entradas.ts";
import type { Message } from "../llm.ts";
import type { Scope, ScopeRule } from "../scope.ts";
import { redactSecrets } from "../plataformas.ts";
import { ReportRedactor } from "../redact.ts";
import { stripAnsi } from "./text.ts";

const HOST = "[host reservado]";
const RESERVADO = "[contenido reservado]";
const escapar = (texto: string) => texto.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const palabra = (texto: string) => new RegExp(`(?<![\\p{L}\\p{N}_-])(?:${texto})(?![\\p{L}\\p{N}_-])`, "giu");
export const prendido = (valor?: string) => /^(?:1|sí|si|true|on)$/i.test(valor ?? "");

class Destinos {
  exactos = new Set<string>();
  sufijos = new Set<string>();
  redes = new BlockList();

  sumar(regla: ScopeRule): string {
    const host = (regla.kind === "url" ? new URL(regla.value).hostname : regla.value).toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
    if (regla.kind === "cidr") {
      const [ip, bits] = host.split("/");
      this.redes.addSubnet(ip!, Number(bits), isIP(ip!) === 6 ? "ipv6" : "ipv4");
    } else if (isIP(host)) {
      this.redes.addAddress(host, isIP(host) === 6 ? "ipv6" : "ipv4");
    } else if (regla.kind === "wildcard") this.sufijos.add(domainToASCII(host.slice(2)));
    else this.exactos.add(domainToASCII(host) || host);
    return host;
  }

  tiene(host: string, incluirBase = false): boolean {
    const familia = isIP(host);
    if (familia) return this.redes.check(host, familia === 6 ? "ipv6" : "ipv4");
    const dominio = domainToASCII(host) || host;
    if (this.exactos.has(dominio)) return true;
    const partes = dominio.split(".");
    return partes.some((_, i) => (i > 0 || incluirBase) && this.sufijos.has(partes.slice(i).join(".")));
  }
}

export class Privacidad {
  private readonly archivo: string;
  private readonly entorno: NodeJS.ProcessEnv;
  private entornoAprendido = false;
  private readonly cache = new Map<string, string>();
  private versionCache = "";
  private readonly redactor = new ReportRedactor({ pantalla: true });
  private readonly usuarios: RegExp | undefined;
  private readonly publicos: Set<string>;
  private readonly reglasPublicadas = new Map<string, Set<string>>();
  private readonly conocidos = new Map<string, string>();
  private readonly privados = new Destinos();
  private readonly visibles = new Destinos();
  private simples?: RegExp;
  private db?: DatabaseSync;
  private revision = 0;
  lista = false;
  soloPrivados: boolean;
  mostrarUso: boolean;

  constructor(archivo: string, env: NodeJS.ProcessEnv = process.env) {
    this.archivo = archivo;
    this.entorno = env;
    const nombres = new Set([env.USER, env.LOGNAME, env.USERNAME, env.SUDO_USER]);
    try { nombres.add(userInfo().username); } catch { /* sistemas sin cuenta local */ }
    for (const ruta of [env.CYBER_HOME_HOST, env.CYBER_DATOS_HOST]) {
      const login = ruta?.match(/(?:^\/(?:home|Users)\/|^[A-Z]:[\\/]Users[\\/])([^/\\]+)/i)?.[1];
      if (login) nombres.add(login);
    }
    const usuarios = [...nombres].filter((s): s is string => !!s).map(escapar);
    if (usuarios.length) this.usuarios = palabra(usuarios.join("|"));
    this.publicos = new Set((env.CYBER_STREAMER_PUBLICOS ?? "").toLowerCase().split(",").map(s => s.trim()).filter(s => s.includes(":")));
    this.soloPrivados = env.CYBER_STREAMER_HOSTS === "privados";
    this.mostrarUso = prendido(env.CYBER_STREAMER_USO);
  }

  private aprenderEntorno() {
    if (this.entornoAprendido) return;
    this.entornoAprendido = true;
    for (const [nombre, valor] of Object.entries(this.entorno)) {
      if (valor && /(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|COOKIE|CREDENTIAL)/i.test(nombre)) this.recordar(valor);
    }
  }
  recordar(valor: string) {
    if (valor) this.redactor.headers({ authorization: valor });
  }

  /** Lee también las revisiones anteriores: pueden seguir nombradas en el chat retomado. */
  actualizar() {
    this.aprenderEntorno();
    try {
      this.db ??= new DatabaseSync(this.archivo, { readOnly: true });
      const nuevas = this.db.prepare("select rev, json from scope where rev > ? order by rev").all(this.revision);
      for (const fila of nuevas) {
        const s = JSON.parse(String(fila.json)) as Scope;
        const origen = s.source.toLowerCase();
        const reglas = [...s.include, ...s.exclude];
        let publicadas = this.reglasPublicadas.get(origen);
        if (this.publicos.has(origen) && !publicadas) {
          // Una edición manual conserva el origen. Sólo la primera importación acredita las reglas públicas.
          publicadas = new Set(reglas.map(r => r.kind + ":" + r.value));
          this.reglasPublicadas.set(origen, publicadas);
        }
        for (const regla of reglas) {
          const destinos = publicadas?.has(regla.kind + ":" + regla.value) ? this.visibles : this.privados;
          const host = destinos.sumar(regla);
          if (/^[\w-]+$/.test(host)) this.conocidos.set(host, escapar(host));
        }
        this.revision = Number(fila.rev);
      }
      if (nuevas.length && this.conocidos.size) this.simples = palabra([...this.conocidos.values()].join("|"));
      this.lista = true;
    } catch { this.lista = false; }
  }

  cantidad(sesion: string): number | undefined {
    if (!this.lista) return;
    try { return Number(this.db!.prepare("select count(*) n from findings where json_extract(json, '$.sessionId')=?").get(sesion)?.n); }
    catch { return undefined; }
  }

  cerrar() { this.db?.close(); this.db = undefined; this.lista = false; this.cache.clear(); }

  /** Elimina controles antes del reconocimiento: un cambio de color no parte un secreto en dos. */
  private plano(texto: string): string {
    return stripAnsi(texto).replace(/\x1b(?:\]|P|_|\^|X)[\s\S]*?(?:\x07|\x1b\\|$)/g, "")
      .replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, "");
  }

  private normalizar(texto: string): string {
    // Normaliza las etiquetas en prosa para que el redactor de trayectorias también aprenda el valor.
    const normal = this.plano(texto)
      .replace(/(["'])(?:contrase[ñn]a|clave de (?:la )?api|api key)\1\s*:/gi, '"password":')
      .replace(/\b(?:contrase[ñn]a|password|clave|token)\s+(?:es|is)\s+/gi, "password=")
      .replace(/\b(contraseña|contrasena|passphrase|clave de (?:la )?api|api key|c[oó]digo (?:de acceso|de vinculaci[oó]n))\s*[:=]\s*/giu, "password=")
      .replace(/(?:^|\s)(?:--(?:password|passwd|token|api-key|cookie|user)|-u)\s+("[^"]*"|'[^']*'|[^\s]+)/gi, (_m, valor: string) => {
        this.recordar(valor.replace(/^["']|["']$/g, ""));
        return " [credencial omitida]";
      })
      .replace(/\bsk-[\w-]{8,}/g, "[credencial omitida]");
    return reemplazarTokensConPrefijo(normal, () => "[credencial omitida]");
  }

  aprender(texto: string) {
    if (texto.length <= 65536) this.redactor.text(this.normalizar(texto));
  }

  aprenderMensaje(m: Message) {
    if (m.role !== "checkpoint") this.aprender(m.content);
    if (m.role === "assistant") for (const c of m.toolCalls) this.aprender(c.arguments);
  }

  get version() {
    return [this.lista, this.revision, this.redactor.cantidadConocida, this.soloPrivados, this.mostrarUso].join("/");
  }

  texto(texto: string): string {
    if (!this.lista || texto.length > 65536) return RESERVADO;
    if (this.versionCache !== this.version) { this.cache.clear(); this.versionCache = this.version; }
    const previa = this.cache.get(texto);
    if (previa !== undefined) return previa;
    const valor = this.filtrar(texto);
    if (this.cache.size >= 512) this.cache.clear();
    this.cache.set(texto, valor);
    return valor;
  }

  modelo(nombre: string): string {
    return /^[a-z\d][a-z\d._:/@+-]{0,127}$/i.test(nombre) ? this.texto(nombre) : "[modelo reservado]";
  }

  private filtrar(texto: string): string {
    if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(texto)) return "[credencial omitida]";

    let s = redactSecrets(this.redactor.finish(this.normalizar(texto)));
    s = s.replace(/(?<![^\s<>()\[\],;:"'=\/\\@])[^\s<>()\[\],;:"'=\/\\@]+@[\p{L}\p{N}_-]+(?:\.[\p{L}\p{N}_-]+)*/gu, "[correo]")
      .replace(/(["'])(?:\/(?:home|Users)\/|[A-Z]:[\\/]Users[\\/])[^"'\r\n]*\1/gi, "$1[ruta privada]$1")
      .replace(/(?:\/(?:home|Users)\/|[A-Z]:[\\/]Users[\\/])[^\s"'<>]*/gi, "[ruta privada]");
    if (this.usuarios) s = s.replace(this.usuarios, "[usuario]");
    const destino = (valor: string) => {
      const host = valor.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
      return this.soloPrivados && this.visibles.tiene(host) && !this.privados.tiene(host, true) ? valor : HOST;
    };
    // Una autoridad de URL identifica incluso un host local que nunca figuró en el alcance.
    s = s.replace(/\/\/(?:[^\s/?#@]*@)?(\[[\da-f:.]+\]|[\p{L}\p{N}_.%-]+)/giu, (_m, host: string) => "//" + destino(host));
    // Primero IPv6 (también con IPv4 embebida), después IPv4, DNS y los hosts de una sola etiqueta.
    s = s.replace(/(?<![\da-f:.])\[?[\da-f:.]+\]?/gi, v => {
      const ip = v.replace(/^\[|\]$/g, "").replace(/\.$/, "");
      return isIP(ip) === 6 ? destino(ip) : v;
    })
      .replace(/(?<![\w.-])(?:\d{1,3}\.){3}\d{1,3}(?![\w-]|\.\d)/g, destino)
      .replace(/(?<![\p{L}\p{N}_-])(?:[\p{L}\p{N}_-]+\.)+(?:[\p{L}][\p{L}\p{N}-]*)/gu, destino);
    if (this.simples) s = s.replace(this.simples, destino);
    if (!this.mostrarUso) {
      // Una tabla suele poner la unidad sólo en el encabezado. Se reserva el bloque completo.
      if (/(?:\b(?:USD|EUR|ARS|saldo|balance|costo|coste|cost|gasto|gastado|presupuesto|créditos|subtotal|tokens?|tope)\b[\s\S]{0,48}\d|\d[\s\S]{0,48}\b(?:USD|EUR|ARS|tokens?|créditos)\b|[$€]\s*\d|\b(?:subtotal|TOKENS\s+SUBTOTAL)\b)/i.test(s)) return "[consumo reservado]";
    }
    return s;
  }
}

/** Sólo se dibujan campos completos; nunca se trata un recorte del daemon como texto íntegro. */
export function entradaPublica(e: Entrada, p: Privacidad): typeof e {
  switch (e.tipo) {
    case "mensajes": return { ...e, texto: p.texto(e.texto) };
    case "texto": return { ...e, markdown: e.reservado ? "[respuesta interrumpida]" : e.completo ? p.texto(e.markdown) : "Escribiendo…", llegadas: undefined };
    case "acciones": return { ...e, nombre: p.texto(e.nombre), etiqueta: p.texto(e.nombre), resumen: "", argumentos: undefined };
    case "resultados": return e; // El lector de resultados tacha el cuerpo antes de envolverlo.
    case "avisos": return { ...e, texto: "Aviso de la sesión · detalle reservado" };
    case "comandos": {
      const { title, lines, footer } = e.panel;
      // Los paneles de cuenta pueden traer códigos sin etiqueta; varias listas traen prefijos de texto.
      if (!/^(?:streamer|ayuda|teclas|ALCANCE\b|COSTO API\b|EVIDENCIA\b)/i.test(title))
        return { ...e, panel: { title: "Panel de la sesión", lines: ["Detalle reservado durante la transmisión."] } };
      const bloque = p.texto(lines.join("\n"));
      return { ...e, panel: { title: p.texto(title), lines: bloque.split("\n"), footer: footer && p.texto(footer) } };
    }
  }
}
