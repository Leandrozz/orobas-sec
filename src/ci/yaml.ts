// Lector de YAML para la configuración de CI (.orobas/ci.yml y .orobas/supresiones.yml). No es YAML completo:
// es el subconjunto que alcanza para un archivo de configuración versionado, sin dependencias, y con la línea y
// la columna de cada valor para que un error diga dónde está. Lo que no está en el subconjunto se rechaza con un
// mensaje claro en vez de interpretarse a medias.
//
// Admite: mapas y listas en bloque (con sangría de espacios), escalares sin comillas, con comillas simples o
// dobles, listas y mapas en línea ([a, b], {env: X}), bloques de texto con | y > (con - o + al final), comentarios
// con #, y un «---» inicial. Rechaza: tabulaciones en la sangría, anclas (&), alias (*), etiquetas (!), claves
// complejas (?), claves repetidas y más de un documento.

export class ErrorYaml extends Error {
  readonly linea: number;
  readonly columna: number;
  constructor(mensaje: string, linea: number, columna: number) {
    super(`${linea}:${columna}: ${mensaje}`);
    this.linea = linea;
    this.columna = columna;
  }
}

export interface Posicion {
  linea: number;
  columna: number;
}

export interface Documento {
  valor: unknown;
  /** Dónde empieza cada valor, por ruta: «objetivo.alcance[0].url». La raíz es «». */
  posiciones: Map<string, Posicion>;
}

interface Linea {
  /** Número de línea (desde 1). */
  n: number;
  sangria: number;
  /** El contenido sin la sangría ni el comentario del final (sólo se recorta en las líneas que no son de bloque de texto). */
  texto: string;
  /** La línea original entera, para los bloques de texto. */
  cruda: string;
}

const ruta = (base: string, clave: string | number) => (typeof clave === "number" ? `${base}[${clave}]` : base ? `${base}.${clave}` : clave);

/** ¿Unas comillas en la posición i abren un valor? Al principio, o después de «:», «-», «[», «{» o «,» (y espacios). */
function empiezaValor(texto: string, i: number): boolean {
  let k = i - 1;
  while (k >= 0 && texto[k] === " ") k--;
  return k < 0 || /[:[{,-]/.test(texto[k]!);
}

/** Saca el comentario del final respetando comillas. Un «#» es comentario al principio o después de un espacio. */
function sinComentario(texto: string, n: number, base: number): string {
  let comilla: string | undefined;
  for (let i = 0; i < texto.length; i++) {
    const c = texto[i]!;
    if (comilla) {
      if (comilla === '"' && c === "\\") i++;
      else if (c === comilla) {
        if (comilla === "'" && texto[i + 1] === "'") i++;
        else comilla = undefined;
      }
      continue;
    }
    if ((c === '"' || c === "'") && empiezaValor(texto, i)) comilla = c;
    else if (c === "#" && (i === 0 || /\s/.test(texto[i - 1]!))) return texto.slice(0, i).trimEnd();
  }
  if (comilla) throw new ErrorYaml(`comillas sin cerrar (${comilla === '"' ? "dobles" : "simples"})`, n, base + 1);
  return texto.trimEnd();
}

export function leerYaml(fuente: string): Documento {
  const posiciones = new Map<string, Posicion>();
  const crudas = fuente.replace(/^﻿/, "").split(/\r?\n/);
  const lineas: Linea[] = crudas.map((cruda, i) => {
    const n = i + 1;
    const sangria = /^ */.exec(cruda)![0].length;
    return { n, sangria, texto: cruda.slice(sangria), cruda };
  });
  let i = 0;
  // Documentos: un «---» opcional al principio; otro, o «...», no.
  const significativa = (l: Linea) => l.texto.trim() !== "" && !l.texto.startsWith("#");
  const primera = lineas.findIndex(significativa);
  if (primera >= 0 && lineas[primera]!.texto.trimEnd() === "---" && lineas[primera]!.sangria === 0) i = primera + 1;
  for (let k = i; k < lineas.length; k++) {
    const l = lineas[k]!;
    if (l.sangria === 0 && (/^---(\s|$)/.test(l.texto) || /^\.\.\.(\s|$)/.test(l.texto))) throw new ErrorYaml("un solo documento por archivo: sacá el «---» o «...» de acá", l.n, 1);
  }

  /** Avanza hasta la próxima línea con contenido. */
  const proxima = (): Linea | undefined => {
    while (i < lineas.length) {
      const l = lineas[i]!;
      if (significativa(l)) {
        if (l.texto.startsWith("\t")) throw new ErrorYaml("tabulación en la sangría: usá espacios", l.n, l.sangria + 1);
        return l;
      }
      i++;
    }
    return undefined;
  };

  const esItem = (texto: string) => texto === "-" || texto.startsWith("- ");

  function bloque(donde: string): unknown {
    const l = proxima();
    if (!l) return null;
    if (!posiciones.has(donde)) posiciones.set(donde, { linea: l.n, columna: l.sangria + 1 });
    const texto = sinComentario(l.texto, l.n, l.sangria);
    return esItem(texto) ? lista(l.sangria, donde) : mapa(l.sangria, donde);
  }

  function lista(sangria: number, donde: string): unknown[] {
    const salida: unknown[] = [];
    for (let l = proxima(); l && l.sangria === sangria; l = proxima()) {
      const texto = sinComentario(l.texto, l.n, l.sangria);
      // Una lista con la sangría de su clave («a:\n- x\nb: 1») termina en la próxima clave del mismo nivel.
      if (!esItem(texto)) break;
      const aqui = ruta(donde, salida.length);
      const resto = texto.slice(1).replace(/^ +/, "");
      const columna = l.sangria + texto.length - resto.length;
      posiciones.set(aqui, { linea: l.n, columna: columna + 1 });
      if (!resto) {
        i++;
        const sig = proxima();
        if (sig && sig.sangria > sangria) salida.push(bloque(aqui));
        else salida.push(null);
        continue;
      }
      if (esItem(resto) || claveDe(resto, l.n, columna) !== undefined) {
        // «- clave: valor» o «- - x»: la línea pasa a ser el comienzo de un bloque más adentro.
        lineas[i] = { ...l, sangria: columna, texto: resto };
        salida.push(esItem(resto) ? lista(columna, aqui) : mapa(columna, aqui));
        continue;
      }
      salida.push(escalarDeLinea(resto, l, columna, aqui));
    }
    const l = proxima();
    if (l && l.sangria > sangria) throw new ErrorYaml("sangría inesperada", l.n, l.sangria + 1);
    return salida;
  }

  /** Si el texto empieza con «clave:» devuelve la clave y dónde sigue el valor. */
  function claveDe(texto: string, n: number, base: number): { clave: string; resto: string; columnaResto: number } | undefined {
    if (/^[&*!?|>%@`]/.test(texto)) return undefined;
    let fin: number;
    let clave: string;
    if (texto[0] === '"' || texto[0] === "'") {
      const cerrada = cerrarComillas(texto, 0, n, base);
      clave = cerrada.valor;
      fin = cerrada.fin;
      if (texto[fin] !== ":") return undefined;
    } else {
      const m = /^([^:#{}[\],]*?):(?= |$)/.exec(texto);
      if (!m) return undefined;
      clave = m[1]!.trim();
      fin = m[1]!.length;
      if (!clave) return undefined;
    }
    const despues = texto.slice(fin + 1);
    const resto = despues.replace(/^ +/, "");
    return { clave, resto, columnaResto: base + fin + 1 + (despues.length - resto.length) };
  }

  function mapa(sangria: number, donde: string): Record<string, unknown> {
    const salida: Record<string, unknown> = {};
    for (let l = proxima(); l && l.sangria === sangria; l = proxima()) {
      const texto = sinComentario(l.texto, l.n, l.sangria);
      if (esItem(texto)) throw new ErrorYaml("un elemento de lista donde se esperaba «clave: valor»", l.n, l.sangria + 1);
      if (texto.startsWith("? ")) throw new ErrorYaml("claves complejas («? ») no admitidas", l.n, l.sangria + 1);
      const par = claveDe(texto, l.n, l.sangria);
      if (!par) throw new ErrorYaml(`se esperaba «clave: valor» y vino «${texto.slice(0, 40)}»`, l.n, l.sangria + 1);
      if (Object.hasOwn(salida, par.clave)) throw new ErrorYaml(`clave repetida «${par.clave}»`, l.n, l.sangria + 1);
      const aqui = ruta(donde, par.clave);
      posiciones.set(aqui, { linea: l.n, columna: l.sangria + 1 });
      if (!par.resto) {
        i++;
        const sig = proxima();
        if (sig && sig.sangria > sangria) salida[par.clave] = bloque(aqui);
        else if (sig && sig.sangria === sangria && esItem(sinComentario(sig.texto, sig.n, sig.sangria))) salida[par.clave] = lista(sangria, aqui);
        else salida[par.clave] = null;
        continue;
      }
      salida[par.clave] = escalarDeLinea(par.resto, l, par.columnaResto, aqui);
    }
    const l = proxima();
    if (l && l.sangria > sangria) throw new ErrorYaml("sangría inesperada", l.n, l.sangria + 1);
    return salida;
  }

  /** El valor que queda en la línea: escalar, en línea o un bloque de texto (| o >). Avanza las líneas que consume. */
  function escalarDeLinea(textoCrudo: string, l: Linea, columna: number, aqui: string): unknown {
    const texto = sinComentario(textoCrudo, l.n, columna);
    const indicador = /^([|>])([+-]?)(\d?)$/.exec(texto) ?? /^([|>])(\d?)([+-]?)$/.exec(texto);
    if (indicador) {
      i++;
      return textoEnBloque(indicador[1] === "|", /[+-]/.exec(texto)?.[0], sangriaDeBloque(texto), l);
    }
    if (/^[&*!]/.test(texto)) throw new ErrorYaml(`${texto[0] === "&" ? "anclas" : texto[0] === "*" ? "alias" : "etiquetas"} no admitidas en este archivo`, l.n, columna + 1);
    i++;
    if (texto[0] === "[" || texto[0] === "{") {
      const lector = new EnLinea(texto, l.n, columna, aqui, posiciones);
      const valor = lector.valor();
      lector.fin();
      return valor;
    }
    if (texto[0] === '"' || texto[0] === "'") {
      const cerrada = cerrarComillas(texto, 0, l.n, columna);
      if (texto.slice(cerrada.fin).trim()) throw new ErrorYaml("texto de más después de las comillas", l.n, columna + cerrada.fin + 1);
      return cerrada.valor;
    }
    if (/: /.test(texto) || texto.endsWith(":")) throw new ErrorYaml(`«${texto.slice(0, 40)}» tiene «: » adentro: poné el valor entre comillas`, l.n, columna + 1);
    return plano(texto);
  }

  function sangriaDeBloque(indicador: string): number | undefined {
    const d = /\d/.exec(indicador)?.[0];
    return d ? Number(d) : undefined;
  }

  function textoEnBloque(literal: boolean, recorte: string | undefined, explicita: number | undefined, padre: Linea): string {
    const partes: string[] = [];
    let base: number | undefined = explicita !== undefined ? padre.sangria + explicita : undefined;
    while (i < lineas.length) {
      const l = lineas[i]!;
      if (l.cruda.trim() === "") {
        partes.push("");
        i++;
        continue;
      }
      if (base === undefined) {
        if (l.sangria <= padre.sangria) break;
        base = l.sangria;
      }
      if (l.sangria < base) break;
      partes.push(l.cruda.slice(base));
      i++;
    }
    // Las líneas vacías del final no son del bloque salvo con «+».
    let finales = 0;
    while (partes.length && partes[partes.length - 1] === "") {
      partes.pop();
      finales++;
    }
    let texto: string;
    if (literal) texto = partes.join("\n");
    else {
      texto = "";
      for (let k = 0; k < partes.length; k++) {
        const p = partes[k]!;
        if (k === 0) texto = p;
        else if (p === "" || /^\s/.test(p) || partes[k - 1] === "" || /^\s/.test(partes[k - 1]!)) texto += `\n${p}`;
        else texto += ` ${p}`;
      }
    }
    if (!partes.length) return "";
    if (recorte === "-") return texto;
    if (recorte === "+") return texto + "\n".repeat(finales + 1);
    return `${texto}\n`;
  }

  const valor = bloque("");
  const sobra = proxima();
  if (sobra) throw new ErrorYaml("sangría inesperada (este bloque no pertenece a ninguna clave)", sobra.n, sobra.sangria + 1);
  if (!posiciones.has("")) posiciones.set("", { linea: 1, columna: 1 });
  return { valor, posiciones };
}

/** Lee un texto entre comillas que empieza en `desde`. */
function cerrarComillas(texto: string, desde: number, n: number, base: number): { valor: string; fin: number } {
  const comilla = texto[desde]!;
  let valor = "";
  for (let k = desde + 1; k < texto.length; k++) {
    const c = texto[k]!;
    if (comilla === "'") {
      if (c === "'") {
        if (texto[k + 1] === "'") {
          valor += "'";
          k++;
          continue;
        }
        return { valor, fin: k + 1 };
      }
      valor += c;
      continue;
    }
    if (c === '"') return { valor, fin: k + 1 };
    if (c !== "\\") {
      valor += c;
      continue;
    }
    const e = texto[++k];
    const simples: Record<string, string> = { n: "\n", t: "\t", r: "\r", "0": "\0", '"': '"', "\\": "\\", "/": "/", " ": " ", e: "\x1b" };
    if (e !== undefined && e in simples) valor += simples[e];
    else if (e === "u" || e === "x" || e === "U") {
      const largo = e === "x" ? 2 : e === "u" ? 4 : 8;
      const hex = texto.slice(k + 1, k + 1 + largo);
      if (!new RegExp(`^[0-9a-fA-F]{${largo}}$`).test(hex)) throw new ErrorYaml(`escape \\${e} inválido`, n, base + k + 1);
      valor += String.fromCodePoint(parseInt(hex, 16));
      k += largo;
    } else throw new ErrorYaml(`escape «\\${e ?? ""}» desconocido entre comillas dobles`, n, base + k + 1);
  }
  throw new ErrorYaml(`comillas sin cerrar (${comilla === '"' ? "dobles" : "simples"})`, n, base + desde + 1);
}

/** Escalar sin comillas: booleanos, nulos y números a su tipo; el resto, texto. */
function plano(texto: string): unknown {
  const t = texto.trim();
  if (t === "" || t === "~" || /^(null|Null|NULL)$/.test(t)) return null;
  if (/^(true|True|TRUE)$/.test(t)) return true;
  if (/^(false|False|FALSE)$/.test(t)) return false;
  if (/^[-+]?(0|[1-9][0-9_]*)$/.test(t)) return Number(t.replace(/_/g, ""));
  if (/^[-+]?(\d[\d_]*)?\.\d+([eE][-+]?\d+)?$/.test(t) || /^[-+]?\d[\d_]*(\.\d*)?[eE][-+]?\d+$/.test(t)) return Number(t.replace(/_/g, ""));
  return t;
}

/** Valores en línea: [a, b] y {clave: valor}, anidables, con escalares planos o entre comillas. */
class EnLinea {
  private k = 0;
  private readonly texto: string;
  private readonly n: number;
  private readonly base: number;
  private readonly donde: string;
  private readonly posiciones: Map<string, Posicion>;
  constructor(texto: string, n: number, base: number, donde: string, posiciones: Map<string, Posicion>) {
    this.texto = texto;
    this.n = n;
    this.base = base;
    this.donde = donde;
    this.posiciones = posiciones;
  }

  private error(mensaje: string): never {
    throw new ErrorYaml(mensaje, this.n, this.base + this.k + 1);
  }

  private espacios(): void {
    while (this.texto[this.k] === " ") this.k++;
  }

  fin(): void {
    this.espacios();
    if (this.k < this.texto.length) this.error("texto de más después del valor en línea");
  }

  valor(donde = this.donde): unknown {
    this.espacios();
    if (!this.posiciones.has(donde)) this.posiciones.set(donde, { linea: this.n, columna: this.base + this.k + 1 });
    const c = this.texto[this.k];
    if (c === "[") return this.secuencia(donde);
    if (c === "{") return this.mapa(donde);
    if (c === '"' || c === "'") {
      const cerrada = cerrarComillas(this.texto, this.k, this.n, this.base);
      this.k = cerrada.fin;
      return cerrada.valor;
    }
    if (c === undefined) this.error("falta un valor");
    if (/[&*!]/.test(c)) this.error("anclas, alias y etiquetas no admitidas");
    const desde = this.k;
    while (this.k < this.texto.length && !/[,\]}]/.test(this.texto[this.k]!) && !(this.texto[this.k] === ":" && /[ ,\]}]|$/.test(this.texto[this.k + 1] ?? ""))) this.k++;
    return plano(this.texto.slice(desde, this.k));
  }

  private secuencia(donde: string): unknown[] {
    this.k++;
    const salida: unknown[] = [];
    this.espacios();
    if (this.texto[this.k] === "]") {
      this.k++;
      return salida;
    }
    for (;;) {
      salida.push(this.valor(ruta(donde, salida.length)));
      this.espacios();
      const c = this.texto[this.k];
      if (c === ",") {
        this.k++;
        continue;
      }
      if (c === "]") {
        this.k++;
        return salida;
      }
      this.error("se esperaba «,» o «]»");
    }
  }

  private mapa(donde: string): Record<string, unknown> {
    this.k++;
    const salida: Record<string, unknown> = {};
    this.espacios();
    if (this.texto[this.k] === "}") {
      this.k++;
      return salida;
    }
    for (;;) {
      this.espacios();
      const inicio = this.k;
      const clave = this.valor(`${donde}{clave}`);
      if (typeof clave !== "string" && typeof clave !== "number") this.error("clave inválida en el mapa en línea");
      this.espacios();
      if (this.texto[this.k] !== ":") this.error("se esperaba «:» después de la clave");
      this.k++;
      const nombre = String(clave);
      if (Object.hasOwn(salida, nombre)) {
        this.k = inicio;
        this.error(`clave repetida «${nombre}»`);
      }
      salida[nombre] = this.valor(ruta(donde, nombre));
      this.espacios();
      const c = this.texto[this.k];
      if (c === ",") {
        this.k++;
        continue;
      }
      if (c === "}") {
        this.k++;
        this.posiciones.delete(`${donde}{clave}`);
        return salida;
      }
      this.error("se esperaba «,» o «}»");
    }
  }
}
