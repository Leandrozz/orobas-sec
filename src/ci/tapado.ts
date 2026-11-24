// Tapado de secretos de todas las salidas de CI (JSON, SARIF, Markdown, JUnit y el registro). Usa los mecanismos
// del harness, en este orden: las identidades de prueba quedan como «<identidad nombre>» (HttpClient), los secretos
// de la sesión (del operador y del objetivo) como marcadores ‹SECRETO_n› (la vista de trazas), y lo que el redactor
// del informe aprende de cada intercambio (cookies, Authorization, campos sensibles) como «[credencial omitida]».
// Al final, por las dudas, cada valor que la corrida leyó de una variable de entorno (identidades, logins, la clave
// del proveedor) se busca literal, codificado para URL, escapado para JSON y en base64.
import type { Engine } from "../engine.ts";
import type { HttpExchange } from "../http.ts";
import { ReportRedactor } from "../redact.ts";
import type { Origen } from "../secretos-sesion.ts";

export const OMITIDO = "[credencial omitida]";

export class Tapador {
  private readonly redactor = new ReportRedactor();
  private literales: string[] = [];
  private readonly engine?: Engine;

  constructor(engine?: Engine, secretos: string[] = []) {
    this.engine = engine;
    this.sumar(secretos);
  }

  /** Suma valores que no pueden salir nunca (los de las variables de entorno que usa la corrida). */
  sumar(secretos: string[]): void {
    const formas = new Set(this.literales);
    for (const s of secretos) {
      if (!s || s.length < 4) continue;
      formas.add(s);
      formas.add(encodeURIComponent(s));
      formas.add(JSON.stringify(s).slice(1, -1));
      formas.add(Buffer.from(s).toString("base64").replace(/=+$/, ""));
    }
    this.literales = [...formas].filter((f) => f.length >= 4).sort((a, b) => b.length - a.length);
  }

  /** Aprende de un intercambio lo que el redactor del informe reconoce como credencial. */
  aprender(exchange: HttpExchange): void {
    this.redactor.url(exchange.request.url);
    this.redactor.headers(exchange.request.headers);
    this.redactor.text(exchange.request.body ?? "");
    if (exchange.response) {
      this.redactor.headers(exchange.response.headers);
      this.redactor.text(exchange.response.body ?? "");
    }
  }

  private literal(texto: string): string {
    let t = texto;
    for (const s of this.literales) if (t.includes(s)) t = t.split(s).join(OMITIDO);
    return t;
  }

  /** Un texto para una salida. `origen`: de dónde viene (lo que devolvió el objetivo, o un texto propio). */
  texto(texto: string, origen: Origen = "local"): string {
    if (!texto) return texto;
    let t = texto;
    if (this.engine) {
      t = this.engine.http.redactIdentities(t);
      t = this.engine.secretos.vistaTrazas(t, origen);
    }
    t = this.redactor.text(t);
    return this.literal(t);
  }

  /** Una URL: además de lo de texto(), los parámetros y fragmentos sensibles. */
  url(url: string): string {
    return this.texto(this.redactor.url(this.engine ? this.engine.http.redactIdentities(url) : url), "objetivo");
  }

  cabeceras(cabeceras: Record<string, string>): Record<string, string> {
    const sinIdentidades = this.engine ? Object.fromEntries(Object.entries(cabeceras).map(([k, v]) => [k, this.engine!.http.redactIdentities(v)])) : cabeceras;
    return Object.fromEntries(Object.entries(this.redactor.headers(sinIdentidades)).map(([k, v]) => [k, this.texto(v, "objetivo")]));
  }

  /** Cada texto de un objeto (recursivo), sin tocar las claves ni la forma. */
  objeto<T>(valor: T): T {
    if (typeof valor === "string") return this.texto(valor) as T;
    if (Array.isArray(valor)) return valor.map((v) => this.objeto(v)) as T;
    if (valor && typeof valor === "object") return Object.fromEntries(Object.entries(valor).map(([k, v]) => [k, this.objeto(v)])) as T;
    return valor;
  }

  /** Última pasada sobre un archivo entero ya armado: los secretos literales y lo aprendido, sin rearmar el formato. */
  final(texto: string): string {
    return this.literal(texto);
  }

  /** ¿Queda algún secreto literal? (Para las pruebas y como control antes de escribir.) */
  contiene(texto: string): boolean {
    return this.literales.some((s) => texto.includes(s));
  }
}
