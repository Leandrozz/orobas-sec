// Validador de JSON Schema (draft-04 y draft-07, lo que usan el esquema oficial de SARIF 2.1.0 y el de orobas-ci/1),
// para las pruebas, sin dependencias. Cubre: type, enum, const, properties, required, additionalProperties,
// patternProperties, items (esquema o lista), minItems, maxItems, uniqueItems, minimum, maximum, exclusiveMinimum,
// exclusiveMaximum, minLength, maxLength, pattern, format (date-time, uri, uri-reference), $ref locales, allOf, anyOf,
// oneOf y not. Una palabra clave que no conoce hace fallar la validación (no la ignora en silencio).
type Esquema = Record<string, unknown> | boolean;

const CONOCIDAS = new Set(["$schema", "$id", "id", "title", "description", "default", "definitions", "examples", "$comment", "type", "enum", "const", "properties", "required", "additionalProperties", "patternProperties", "items", "minItems", "maxItems", "uniqueItems", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength", "maxLength", "pattern", "format", "$ref", "allOf", "anyOf", "oneOf", "not"]);

const tipoDe = (v: unknown) => (v === null ? "null" : Array.isArray(v) ? "array" : Number.isInteger(v) ? "integer" : typeof v);
const cumpleTipo = (v: unknown, t: string) => (t === "number" ? typeof v === "number" : t === "integer" ? Number.isInteger(v) : tipoDe(v) === t || (t === "number" && tipoDe(v) === "integer"));

function formatoValido(formato: string, v: string): boolean {
  if (formato === "date-time") return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(v) && !Number.isNaN(Date.parse(v));
  if (formato === "uri") return /^[a-z][a-z0-9+.-]*:/i.test(v) && !/\s/.test(v);
  if (formato === "uri-reference") return !/\s/.test(v);
  return true;
}

export function validar(raiz: Esquema, dato: unknown): string[] {
  const errores: string[] = [];
  const resolver = (ref: string): Esquema => {
    if (!ref.startsWith("#/")) throw new Error(`$ref no local: ${ref}`);
    let actual: unknown = raiz;
    for (const parte of ref.slice(2).split("/")) actual = (actual as Record<string, unknown>)[parte.replace(/~1/g, "/").replace(/~0/g, "~")];
    if (actual === undefined) throw new Error(`$ref sin destino: ${ref}`);
    return actual as Esquema;
  };
  const ir = (e: Esquema, v: unknown, ruta: string): void => {
    if (e === true) return;
    if (e === false) return void errores.push(`${ruta}: no se admite ningún valor`);
    for (const clave of Object.keys(e)) if (!CONOCIDAS.has(clave)) throw new Error(`palabra clave no soportada «${clave}» en ${ruta}`);
    if (typeof e.$ref === "string") return ir(resolver(e.$ref), v, ruta);
    if (e.type !== undefined) {
      const tipos = Array.isArray(e.type) ? (e.type as string[]) : [e.type as string];
      if (!tipos.some((t) => cumpleTipo(v, t))) return void errores.push(`${ruta}: se esperaba ${tipos.join("|")} y es ${tipoDe(v)}`);
    }
    if (Array.isArray(e.enum) && !e.enum.some((x) => JSON.stringify(x) === JSON.stringify(v))) errores.push(`${ruta}: ${JSON.stringify(v)} no está en ${JSON.stringify(e.enum)}`);
    if ("const" in e && JSON.stringify(e.const) !== JSON.stringify(v)) errores.push(`${ruta}: tiene que ser ${JSON.stringify(e.const)}`);
    if (typeof v === "string") {
      if (typeof e.minLength === "number" && v.length < e.minLength) errores.push(`${ruta}: más corto que ${e.minLength}`);
      if (typeof e.maxLength === "number" && v.length > e.maxLength) errores.push(`${ruta}: más largo que ${e.maxLength}`);
      if (typeof e.pattern === "string" && !new RegExp(e.pattern, "u").test(v)) errores.push(`${ruta}: «${v.slice(0, 60)}» no cumple ${e.pattern}`);
      if (typeof e.format === "string" && !formatoValido(e.format, v)) errores.push(`${ruta}: «${v.slice(0, 60)}» no es ${e.format}`);
    }
    if (typeof v === "number") {
      if (typeof e.minimum === "number" && (e.exclusiveMinimum === true ? v <= e.minimum : v < e.minimum)) errores.push(`${ruta}: menor que ${e.minimum}`);
      if (typeof e.maximum === "number" && (e.exclusiveMaximum === true ? v >= e.maximum : v > e.maximum)) errores.push(`${ruta}: mayor que ${e.maximum}`);
      if (typeof e.exclusiveMinimum === "number" && v <= e.exclusiveMinimum) errores.push(`${ruta}: no mayor que ${e.exclusiveMinimum}`);
      if (typeof e.exclusiveMaximum === "number" && v >= e.exclusiveMaximum) errores.push(`${ruta}: no menor que ${e.exclusiveMaximum}`);
    }
    if (Array.isArray(v)) {
      if (typeof e.minItems === "number" && v.length < e.minItems) errores.push(`${ruta}: menos de ${e.minItems} elementos`);
      if (typeof e.maxItems === "number" && v.length > e.maxItems) errores.push(`${ruta}: más de ${e.maxItems} elementos`);
      if (e.uniqueItems === true && new Set(v.map((x) => JSON.stringify(x))).size !== v.length) errores.push(`${ruta}: elementos repetidos`);
      if (Array.isArray(e.items)) (e.items as Esquema[]).forEach((s, k) => k < v.length && ir(s, v[k], `${ruta}[${k}]`));
      else if (e.items !== undefined) v.forEach((x, k) => ir(e.items as Esquema, x, `${ruta}[${k}]`));
    }
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const o = v as Record<string, unknown>;
      for (const r of (e.required as string[] | undefined) ?? []) if (!(r in o)) errores.push(`${ruta}: falta «${r}»`);
      const props = (e.properties as Record<string, Esquema> | undefined) ?? {};
      const patrones = Object.entries((e.patternProperties as Record<string, Esquema> | undefined) ?? {}).map(([p, s]) => [new RegExp(p, "u"), s] as const);
      for (const [k, x] of Object.entries(o)) {
        let cubierta = false;
        if (k in props) {
          cubierta = true;
          ir(props[k]!, x, `${ruta}.${k}`);
        }
        for (const [p, s] of patrones) if (p.test(k)) { cubierta = true; ir(s, x, `${ruta}.${k}`); }
        if (!cubierta && e.additionalProperties !== undefined) {
          if (e.additionalProperties === false) errores.push(`${ruta}: propiedad no admitida «${k}»`);
          else ir(e.additionalProperties as Esquema, x, `${ruta}.${k}`);
        }
      }
    }
    const subvalida = (s: Esquema) => {
      const antes = errores.length;
      ir(s, v, ruta);
      const ok = errores.length === antes;
      errores.length = antes;
      return ok;
    };
    if (Array.isArray(e.allOf)) for (const s of e.allOf as Esquema[]) ir(s, v, ruta);
    if (Array.isArray(e.anyOf) && !(e.anyOf as Esquema[]).some(subvalida)) errores.push(`${ruta}: no cumple ninguna opción de anyOf`);
    if (Array.isArray(e.oneOf)) {
      const n = (e.oneOf as Esquema[]).filter(subvalida).length;
      if (n !== 1) errores.push(`${ruta}: cumple ${n} opciones de oneOf (debe ser exactamente una)`);
    }
    if (e.not !== undefined && subvalida(e.not as Esquema)) errores.push(`${ruta}: cumple el esquema de «not»`);
  };
  ir(raiz, dato, "$");
  return errores;
}
