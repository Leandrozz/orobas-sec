// Salir de la caja negra: el código del programa (un repositorio o una carpeta del proyecto) y el de una
// web del alcance (su JavaScript, los chunks que carga después y el fuente original si publica mapas).
// Tres herramientas que funcionan dentro y fuera de la caja y alimentan a las que ya existen:
//   web_source_pull baja la web a una carpeta del proyecto (por el cliente HTTP: alcance, ritmo, tope y
//     señuelos de siempre), así code_search, code_read, code_crypto y REA (en la caja) la leen como fuente;
//   code_crypto mapea las funciones propias que importan para romper algo: derivación de claves, hashes,
//     firmas, cifrado, aleatoriedad, comparaciones, secretos fijos y validaciones que hace el cliente;
//   hash_crack confirma offline una derivación sospechada («este token es sha256(email + hora)») contra un
//     valor observado. No sale a la red ni toca el objetivo.
// Lo que devuelven es observación estática: una pista hasta que una petición propia lo muestre en vivo.
import { createHash, createHmac, getHashes } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { Tool, ToolResult } from "./agent.ts";
import type { Artifacts } from "./artifacts.ts";
import { insideProject, projectFiles } from "./codigo.ts";
import { carpetaDelOperador } from "./datos.ts";
import type { HttpClient, HttpExchange } from "./http.ts";
import { extractApi } from "./jsanalisis.ts";
import { redactSecrets } from "./plataformas.ts";

const obj = (properties: Record<string, object>, required: string[]) => ({ type: "object", properties, required });
const str = (extra: object = {}) => ({ type: "string", ...extra });
const int = (extra: object = {}) => ({ type: "integer", ...extra });

// ───────────────────────────── code_crypto ─────────────────────────────

export type Riesgo = "alto" | "medio" | "bajo" | "info";
export interface CryptoHit {
  /** Relativo al proyecto. */
  file: string;
  line: number;
  kind: "hash" | "derivación" | "hmac" | "mac casero" | "kdf" | "cifrado" | "firma" | "jwt" | "aleatorio" | "comparación" | "secreto fijo" | "validación en el cliente" | "monto en el cliente" | "token en el cliente";
  detail: string;
  risk: Riesgo;
  /** Función propia que lo contiene, si se reconoce. */
  fn?: string;
  /** Extracto (secretos tapados). */
  snippet: string;
  /** Cómo se prueba o se rompe. */
  attack: string;
}

const SOURCE_EXT = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte", ".html", ".htm", ".py", ".php", ".phtml", ".go", ".java", ".kt", ".kts", ".scala", ".rb", ".cs", ".swift", ".dart", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".m", ".lua", ".pl", ".ex", ".exs", ".erl", ".groovy"]);
const MAX_SCAN_FILE = 8 * 1024 * 1024;
const MAX_SCAN_BYTES = 200 * 1024 * 1024;
const MAX_HITS = 2000;

/** Nombres que hacen de un hash algo que importa: una clave, un token, una firma, una contraseña. */
const SENSITIVE = /pass(word|wd)?|pwd|token|secret|api_?key|apikey|\bkey\b|_key\b|key_|signature|\bsig\b|otp|reset|session|nonce|salt|auth|hmac|digest|verif|code\b|invite|coupon|voucher|license|serial/i;
/** Entradas que se pueden adivinar o enumerar. */
const PREDICTABLE = /Date\.now|new Date|getTime\(|time\(\)|time\.time|microtime|uniqid|timestamp|\bts\b|email|mail|user_?name|username|user_?id|userId|uid\b|\bid\b|counter|\bseq\b|Math\.random|rand\(|phone|dni|cuit|cpf/i;
const TOKEN_CONTEXT = /token|secret|password|passwd|\bkey\b|api_?key|nonce|salt|otp|code|reset|session|invite|coupon|voucher|uuid|guid|\bid\b/i;
const FAST_HASH = /^(md5|sha-?1|sha-?224|sha-?256|sha-?384|sha-?512|ripemd160|crc32b?)$/i;

interface Rule {
  kind: CryptoHit["kind"];
  re: RegExp;
  /** Devuelve undefined para descartar la coincidencia. */
  judge: (match: RegExpExecArray, line: string) => { detail: string; risk: Riesgo; attack: string; kind?: CryptoHit["kind"] } | undefined;
}

const norm = (alg: string) => alg.toLowerCase().replace(/_/g, "-").replace(/^sha(\d)/, "sha-$1").replace(/^sha-1$/, "sha1");
const literalSecret = (text: string) => /^\s*(["'`])[^"'`]{4,}\1/.test(text);

/** Hash común: si lo que se hashea es una contraseña o una clave, o sale de algo predecible, deja de ser «info». */
function judgeHash(alg: string, line: string): { detail: string; risk: Riesgo; attack: string; kind?: CryptoHit["kind"] } {
  const name = norm(alg);
  const weak = /^(md5|sha1|crc32b?)$/.test(name.replace(/-/g, ""));
  // MAC casero: hash(secreto + datos). SHA-1/SHA-2 y MD5 admiten extensión de longitud.
  if (/(secret|key|salt)\w*(\s*\+|\s+\.\s|\s*\}?\s*\$\{)|(\+|\s\.\s)\s*\$?\w*(secret|key)\b|\$\{\s*\w*(secret|key)/i.test(line) && /^(md5|sha1|sha-(224|256|384|512))$/.test(name)) {
    return { kind: "mac casero", detail: `${name}(secreto ‖ datos)`, risk: "alto", attack: "Un MAC armado como hash(secreto + datos) con MD5/SHA-1/SHA-2 admite extensión de longitud: con una firma válida y el largo del secreto se firma «datos + relleno + lo que quieras» sin conocerlo (hash_extender / hashpump). Si el secreto está en el código, se forja directo." };
  }
  if (/pass(word|wd)?|pwd/i.test(line) && FAST_HASH.test(name)) {
    return { kind: "derivación", detail: `contraseña con ${name} (hash rápido, sin KDF)`, risk: "alto", attack: "Un hash rápido sin KDF para contraseñas se rompe offline con diccionario (hash_crack con palabras o un diccionario del proyecto; hashcat afuera). Sin sal, la misma contraseña da el mismo hash en toda la base." };
  }
  if (SENSITIVE.test(line) && PREDICTABLE.test(line)) {
    return { kind: "derivación", detail: `${name} de entrada predecible`, risk: "alto", attack: "La clave o el token sale de un hash de datos que se pueden adivinar (hora, email, id): con un valor tuyo observado, confirmá la fórmula con hash_crack (plantilla con {n:inicio-fin} para la hora o el id) y, si cierra, calculá el de otra cuenta tuya para probarlo en vivo." };
  }
  if (SENSITIVE.test(line)) {
    return { kind: "derivación", detail: `${name} sobre ${(/(pass(word|wd)?|pwd|token|secret|api_?key|signature|otp|reset|session|nonce|salt|hmac|invite|coupon|license)/i.exec(line)?.[0] ?? "un valor sensible").toLowerCase()}`, risk: weak ? "medio" : "bajo", attack: "Leé con code_read de dónde salen las entradas: si alguna es predecible o fija, se puede recalcular (hash_crack para confirmarlo con un valor observado). Un hash sin secreto no autentica nada." };
  }
  return { detail: name, risk: weak ? "bajo" : "info", attack: weak ? "MD5/SHA-1 sirven para integridad casual, no para seguridad: mirá si este valor decide un acceso." : "Hash común: importa qué entra y para qué se usa." };
}

const RULES: Rule[] = [
  // Hashes
  { kind: "hash", re: /\bcreateHash\(\s*["'`]([\w-]+)["'`]/g, judge: (m, line) => judgeHash(m[1]!, line) },
  { kind: "hash", re: /\bhashlib\.(md5|sha1|sha224|sha256|sha384|sha512|sha3_\d+|blake2[bs])\b/g, judge: (m, line) => judgeHash(m[1]!, line) },
  { kind: "hash", re: /\bhash\(\s*["'](md5|sha1|sha224|sha256|sha384|sha512|crc32b?|sha3-\d+)["']/g, judge: (m, line) => judgeHash(m[1]!, line) },
  { kind: "hash", re: /\bCryptoJS\.(MD5|SHA1|SHA224|SHA256|SHA384|SHA512|SHA3|RIPEMD160)\b(?!\s*\.)/g, judge: (m, line) => judgeHash(m[1]!, line) },
  { kind: "hash", re: /\bsubtle\.digest\(\s*["'`]?(SHA-\d+)/g, judge: (m, line) => judgeHash(m[1]!, line) },
  { kind: "hash", re: /MessageDigest\.getInstance\(\s*"([^"]+)"/g, judge: (m, line) => judgeHash(m[1]!, line) },
  { kind: "hash", re: /\b(md5|sha1|sha256|sha512)\.(?:Sum(?:\d+)?|New)\(/g, judge: (m, line) => judgeHash(m[1]!, line) },
  { kind: "hash", re: /Digest::(MD5|SHA1|SHA256|SHA384|SHA512)/g, judge: (m, line) => judgeHash(m[1]!, line) },
  { kind: "hash", re: /(?<![\w.$])(md5|sha1|sha256|sha512|sha224)\s*\(/g, judge: (m, line) => (/\b(function|def|func)\s+(md5|sha1|sha256|sha512|sha224)\b/.test(line) ? undefined : judgeHash(m[1]!, line)) },
  // HMAC
  {
    kind: "hmac",
    re: /\b(?:createHmac\(\s*["'`]([\w-]+)["'`]\s*,|hmac\.new\(|hash_hmac\(\s*["'](\w+)["']\s*,[^,]+,|CryptoJS\.Hmac(SHA\d+|MD5)\(|Mac\.getInstance\(\s*"Hmac(\w+)"|hmac\.New\(\s*(?:sha256|sha1|sha512|md5)\.New\s*,)\s*([^)\n]{0,80})/g,
    judge: (m, line) => {
      const alg = norm(m[1] ?? m[2] ?? m[3] ?? m[4] ?? (/(sha256|sha1|sha512|md5)/i.exec(line)?.[1] ?? "?"));
      const key = m[5] ?? "";
      if (literalSecret(key) || /["'`][^"'`]{6,}["'`]\s*\)?\s*$/.test(key.split(",")[0] ?? "")) return { detail: `HMAC-${alg} con clave fija en el código`, risk: "alto", attack: "La clave del HMAC está escrita en el código: quien lo lea firma lo que quiera. Si este código llega al navegador, la firma no protege nada. Confirmalo con hash_crack (algoritmo hmac y codigo apuntando a esa línea) contra una firma observada." };
      return { detail: `HMAC-${alg}`, risk: "info", attack: "Firma con HMAC: mirá de dónde sale la clave y si la comparación de la firma es de tiempo constante." };
    },
  },
  // KDF
  {
    kind: "kdf",
    re: /\b(pbkdf2(?:Sync)?|pbkdf2_hmac|PBKDF2|hash_pbkdf2|Rfc2898DeriveBytes|PBEKeySpec)\s*\(([^)\n]{0,160})/g,
    judge: (m) => {
      const numbers = [...(m[2] ?? "").matchAll(/(?<![\w.])(\d{1,7})(?![\w.])/g)].map((n) => Number(n[1])).filter((n) => n >= 1);
      const iterations = numbers.find((n) => n !== 16 && n !== 32 && n !== 64 && n >= 1 && n !== 8);
      if (iterations !== undefined && iterations < 100_000) return { detail: `PBKDF2 con ${iterations} iteraciones`, risk: iterations < 10_000 ? "alto" : "medio", attack: `Pocas iteraciones: cada intento de diccionario cuesta ${iterations} hashes (OWASP pide 600 000 con SHA-256). Con el hash y la sal, el diccionario offline rinde.` };
      return { detail: "PBKDF2", risk: "info", attack: "KDF: revisá iteraciones, sal por usuario y largo de la clave." };
    },
  },
  {
    kind: "kdf",
    re: /\b(bcrypt\.(?:hash|hashSync|genSalt|genSaltSync|gensalt)|password_hash|scrypt(?:Sync)?|argon2\.\w+|hkdf(?:Sync)?|EVP_BytesToKey|crypt)\s*\(([^)\n]{0,80})/g,
    judge: (m) => {
      const fn = m[1]!;
      const cost = /bcrypt/.test(fn) ? Number(/(?:rounds\s*=\s*|,\s*)(\d{1,2})\s*\)?\s*$/.exec(m[2] ?? "")?.[1] ?? NaN) : NaN;
      if (Number.isFinite(cost) && cost < 10) return { detail: `bcrypt con costo ${cost}`, risk: "medio", attack: "Costo de bcrypt bajo: el diccionario offline rinde más de lo debido." };
      if (/EVP_BytesToKey/.test(fn)) return { detail: "EVP_BytesToKey (MD5, una iteración)", risk: "alto", attack: "Deriva la clave de una contraseña con MD5 y una iteración: diccionario offline barato." };
      if (fn === "crypt") return { detail: "crypt()", risk: "bajo", attack: "Mirá el prefijo de la sal: DES o MD5 ($1$) son débiles." };
      return { detail: fn, risk: "info", attack: "KDF adecuado: lo débil, si hay algo, está en la entrada o en lo que se hace con el resultado." };
    },
  },
  // Cifrado
  {
    kind: "cifrado",
    re: /\b(createCipheriv|createDecipheriv|createCipher|createDecipher)\(\s*(?:["'`]([\w-]+)["'`])?/g,
    judge: (m, line) => {
      const alg = (m[2] ?? "").toLowerCase();
      if (/^create(De)?cipher$/.test(m[1]!)) return { detail: `${m[1]} sin IV (deriva la clave con MD5)`, risk: "alto", attack: "createCipher deriva clave e IV de una contraseña con MD5 y sin sal: el mismo texto da el mismo cifrado y la contraseña se ataca por diccionario." };
      if (/ecb/.test(alg)) return { detail: `${alg}: modo ECB`, risk: "alto", attack: "ECB cifra igual los bloques iguales: se ven patrones y se pueden recortar y pegar bloques (cambiar un campo por otro de otro mensaje)." };
      if (/(^|-)(des|rc4|des3|des-ede3|bf|rc2)(-|$)/.test(alg)) return { detail: `${alg}: algoritmo débil`, risk: "alto", attack: "Algoritmo roto o con bloque corto." };
      if (/iv\s*[,)]/.test(line) && /(Buffer\.alloc\(\s*1[26]\s*\)|["'`][0-9a-f]{16,32}["'`])/i.test(line)) return { detail: `${alg} con IV fijo`, risk: "alto", attack: "IV fijo: dos mensajes con el mismo inicio dan el mismo cifrado (CBC) o se reusa el keystream (CTR/GCM: se recupera el XOR de los textos y en GCM se forjan etiquetas)." };
      if (/cbc/.test(alg)) return { detail: `${alg} (sin autenticar)`, risk: "medio", attack: "CBC sin MAC: si el servidor distingue error de relleno, padding oracle (descifrar y cifrar sin la clave)." };
      return { detail: alg || m[1]!, risk: "info", attack: "Cifrado: mirá de dónde salen la clave y el IV o nonce." };
    },
  },
  { kind: "cifrado", re: /\b(MODE_ECB|mode\.ECB|AES\/ECB|\/ECB\/|aes-\d+-ecb)\b/gi, judge: (_m, line) => (/createCipher|openssl_encrypt|Cipher\.getInstance/.test(line) ? undefined : { detail: "modo ECB", risk: "alto", attack: "ECB: bloques iguales cifran igual; se puede recortar y pegar bloques entre mensajes." }) },
  { kind: "cifrado", re: /Cipher\.getInstance\(\s*"(AES|DES|DESede|RC4|Blowfish)"\s*\)/g, judge: (m) => ({ detail: `Cipher.getInstance("${m[1]}") = ${m[1]}/ECB por defecto`, risk: "alto", attack: "En Java, sin modo explícito es ECB." }) },
  { kind: "cifrado", re: /\bopenssl_encrypt\(\s*[^,]+,\s*["']([\w-]+)["']/g, judge: (m, line) => (/ecb/i.test(m[1]!) ? { detail: `${m[1]}: ECB`, risk: "alto", attack: "ECB: bloques iguales cifran igual." } : /,\s*["'][^"']{8,}["']\s*\)/.test(line) ? { detail: `${m[1]} con IV fijo`, risk: "alto", attack: "IV fijo en el código." } : { detail: m[1]!, risk: "info", attack: "Cifrado: mirá clave e IV." }) },
  { kind: "cifrado", re: /\bCryptoJS\.(AES|DES|TripleDES|RC4|Rabbit)\.(encrypt|decrypt)\(\s*[^,]+,\s*([^,)\n]{1,80})/g, judge: (m) => (/^\s*["'`]/.test(m[3]!) ? { detail: `CryptoJS.${m[1]} con contraseña fija en el código`, risk: "alto", attack: "La «clave» es una contraseña escrita en el código (EVP_BytesToKey con MD5): con este código cualquiera descifra y cifra." } : { detail: `CryptoJS.${m[1]}`, risk: m[1] === "AES" ? "info" : "alto", attack: "Si esto corre en el navegador, la clave también está ahí." }) },
  { kind: "cifrado", re: /\b(iv|nonce)\s*[:=]\s*(?:Buffer\.from\(\s*)?["'`]([^"'`]{8,})["'`]/gi, judge: (m) => ({ detail: `${m[1]} fijo`, risk: "alto", attack: "IV o nonce fijo: con CTR/GCM se reusa el keystream (XOR de textos, etiquetas forjables); con CBC se ven prefijos iguales." }) },
  // Firmas y JWT
  {
    kind: "jwt",
    re: /\bjwt\.(sign|verify|decode)\(([^)\n]{0,200})/g,
    judge: (m, line) => {
      const args = m[2] ?? "";
      if (m[1] === "decode") return { detail: "jwt.decode (no verifica la firma)", risk: "medio", attack: "decode no verifica: si su resultado decide un acceso, un token con la firma rota o alg none pasa. Probá con jwt_inspect y un token alterado." };
      if (/["'`]none["'`]/i.test(line)) return { detail: `jwt.${m[1]} con alg none`, risk: "alto", attack: "Acepta alg none: un token sin firma pasa." };
      if (/,\s*["'`][^"'`]{3,}["'`]/.test(args)) return { detail: `jwt.${m[1]} con secreto fijo`, risk: "alto", attack: "El secreto HS256 está en el código: se forjan tokens de cualquier usuario. Si el código es del cliente, es público." };
      if (m[1] === "verify" && !/algorithms/.test(line)) return { detail: "jwt.verify sin lista de algoritmos", risk: "medio", attack: "Sin algorithms fijo, revisá confusión RS256→HS256 (la clave pública como secreto HMAC)." };
      return { detail: `jwt.${m[1]}`, risk: "info", attack: "Revisá algoritmo fijo, expiración y de dónde sale la clave." };
    },
  },
  { kind: "jwt", re: /verify_signature["']?\s*:\s*False|verify\s*=\s*False|ignoreExpiration\s*:\s*true|algorithms\s*=\s*\[[^\]]*["']none["']/g, judge: (m) => ({ detail: m[0].slice(0, 60), risk: /expiration/i.test(m[0]) ? "medio" : "alto", attack: "La verificación del token está apagada o acepta none: un token alterado pasa." }) },
  { kind: "firma", re: /\b(createSign|createVerify|crypto\.sign|crypto\.verify|subtle\.(?:sign|verify|importKey)|Signature\.getInstance|ed25519|ecdsa|rsa\.(?:sign|verify)|openssl_sign|openssl_verify)\b/gi, judge: (m) => ({ detail: m[1]!, risk: "info", attack: "Firma asimétrica: revisá qué se firma (todo el mensaje o una parte), si la clave privada está a la vista y si un error de verificación se ignora." }) },
  // Aleatoriedad
  {
    kind: "aleatorio",
    re: /\b(Math\.random|random\.(?:random|randint|choice|getrandbits)|mt_rand|(?<![\w.])rand|uniqid|lcg_value|new Random|rand\.(?:Intn|Int63|Int)|srand|mt_srand|random\.seed)\s*\(/g,
    judge: (m, line) => {
      if (/^(srand|mt_srand|random\.seed)$/.test(m[1]!)) return { detail: `${m[1]} (semilla)`, risk: "medio", attack: "Con una semilla conocida o de la hora, toda la secuencia se repite." };
      if (TOKEN_CONTEXT.test(line)) return { detail: `${m[1]} para un token`, risk: "alto", attack: "Generador no criptográfico para un token/clave/código: el estado se recupera con pocas salidas (Math.random de V8 con unas 5; mt_rand con 624 o con la semilla) o el espacio es chico. Pedí varios tokens tuyos seguidos y probá predecir el próximo." };
      return { detail: m[1]!, risk: "bajo", attack: "No criptográfico: sólo importa si el valor protege algo." };
    },
  },
  // Comparaciones que no son de tiempo constante
  { kind: "comparación", re: /\b\w*(signature|hmac|digest|mac|hash|token|otp|apikey|api_key|secret)\w*\s*(===?|!==?)\s*[\w.$[\]"'`]+|[\w.$[\]"'`]+\s*(===?|!==?)\s*\w*(signature|hmac|digest|hash|token|otp|apikey|api_key|secret)\w*\b/gi, judge: (m, line) => (/timingSafeEqual|compare_digest|hash_equals|isEqual|ConstantTimeCompare|secure_compare|===?\s*(null|undefined|["'`]{2}|0|false|true)\b|typeof/.test(line) ? undefined : { detail: "comparación con == de un valor secreto", risk: "medio", attack: "Comparar una firma o token con == corta en el primer byte distinto: en teoría se adivina por tiempo. Más importante: mirá qué pasa si el valor falta o es vacío." }) },
  // Secretos fijos
  {
    kind: "secreto fijo",
    re: /\b(\w*(?:secret|secret_?key|api_?key|private_?key|hmac_?key|jwt_?secret|signing_?key|encryption_?key|aes_?key|salt|pepper|passphrase|password|passwd)\w*)\s*[:=]\s*(["'`])([^"'`\s]{6,})\2/gi,
    judge: (m) => (/^(process\.env|os\.environ|getenv|env\(|config|settings|true|false|null|undefined|password|changeme|example|placeholder|your[_-]|xxx+|\*+|<.*>|\$\{)/i.test(m[3]!) || /^(type|name|label|placeholder|id|for|autocomplete|input|field)$/i.test(m[1]!) || /^[A-ZÁÉÍÓÚÑ][a-záéíóúñü]+$/.test(m[3]!) || /[^\x00-\x7f]/.test(m[3]!) ? undefined : { detail: `${m[1]} fijo (${m[3]!.length} caracteres)`, risk: "alto", attack: "Valor secreto escrito en el código: si el código es público o llega al navegador, el secreto también. Usalo para confirmar (hash_crack con codigo) y registrá la exposición; no lo uses contra cuentas ajenas." }),
  },
  // Validaciones y decisiones en el cliente
  { kind: "validación en el cliente", re: /\b(isAdmin|is_admin|isSuperuser|isStaff|hasRole|hasPermission|canEdit|canDelete|canAccess|isPremium|isPaid|isOwner)\b|\brole\s*===?\s*["'`]\w+["'`]|\broles?\.(?:includes|indexOf)\(|\bpermissions?\.(?:includes|indexOf)\(|\bplan\s*===?\s*["'`]\w+["'`]/g, judge: (m) => ({ detail: `decisión de permiso: ${m[0].slice(0, 50)}`, risk: "medio", attack: "Si este control está en el cliente, el servidor tiene que repetirlo: llamá la operación directo con http_request (o access_matrix con otra identidad) sin pasar por la pantalla." }) },
  { kind: "validación en el cliente", re: /\b(?:function\s+|const\s+|let\s+|var\s+|def\s+)(validate\w*|isValid\w*|check(?:Password|Email|Code|Otp|Captcha|Coupon|Pin|Age|Amount)\w*|verify(?:Code|Otp|Captcha|Pin)\w*)\b/g, judge: (m) => ({ detail: `validación propia: ${m[1]}`, risk: "bajo", attack: "Leé qué valida: si sólo corre en el cliente, mandá el valor que rechaza directo al endpoint." }) },
  { kind: "monto en el cliente", re: /\b(price|total|amount|subtotal|discount|precio|monto|importe|descuento)\w*\s*[:=][^;\n]{0,60}[*+-]\s*[\w(]/gi, judge: () => ({ detail: "monto calculado en el cliente", risk: "medio", attack: "Si el precio o el total viajan desde el cliente, el servidor tiene que recalcularlos: mandá otro valor (con una compra propia y reversible) y mirá qué cobra." }) },
  { kind: "token en el cliente", re: /\b(localStorage|sessionStorage)\.setItem\(\s*["'`]([^"'`]*(?:token|jwt|auth|session|secret|key)[^"'`]*)["'`]/gi, judge: (m) => ({ detail: `${m[1]}: ${m[2]}`, risk: "bajo", attack: "Token en almacenamiento del navegador: una XSS lo lee. Sumalo al impacto si encontrás una." }) },
];

/** Nombre de la función que empieza en esta línea (JS/TS, Python, PHP, Go, Java/C#/Kotlin, Ruby), si hay una. */
function functionName(line: string): string | undefined {
  const patterns = [
    /\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(/,
    /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)/,
    /^\s*def\s+([A-Za-z_]\w*[?!]?)\s*[(:]/,
    /^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(/,
    /^\s*(?:(?:public|private|protected|internal|static|final|async|override|virtual|suspend|fun)\s+)+[\w<>[\],.?\s]*?\b([A-Za-z_]\w*)\s*\([^;]*$/,
    /^\s*(?:async\s+)?(?!if\b|for\b|while\b|switch\b|catch\b|return\b|function\b)([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{\s*$/,
    /^\s*([A-Za-z_$][\w$]*)\s*:\s*(?:async\s*)?function\b/,
  ];
  for (const pattern of patterns) {
    const found = pattern.exec(line)?.[1];
    if (found) return found;
  }
  return undefined;
}

/** Nombres de algoritmos, codificaciones y rutas que se pueden mostrar; cualquier otro texto entre comillas de 6 o más caracteres puede ser una clave. */
const SHOWABLE = /^(sha[\w-]*|md5|ripemd\d*|aes[\w-]*|des[\w-]*|rc4|bf[\w-]*|chacha[\w-]*|hmac[\w-]*|rsa[\w-]*|ecdsa|ed25519|[HREP]S\d{3}|hex|base64(url)?|utf-?8|latin1|binary|ascii|none|admin|user|owner|premium|\/[\w\/{}$.:-]*)$/i;
/**
 * Tapa los textos entre comillas que pueden ser una clave. Con `all` (la línea tiene un secreto escrito), todo
 * lo que no sea un nombre de algoritmo, codificación o ruta; si no, lo que tiene pinta de clave (largo, con
 * letras y números). Recorre los literales de izquierda a derecha para no confundir el cierre de uno con la
 * apertura del siguiente.
 */
function maskLiterals(text: string, all: boolean): string {
  return text.replace(/(["'`])((?:\\.|(?!\1)[^\\])*)\1/g, (whole, quote: string, value: string) => {
    if (SHOWABLE.test(value)) return whole;
    const keyLike = value.length >= 16 && /[a-z]/i.test(value) && /\d/.test(value) && !/\s/.test(value);
    return (all ? value.length >= 4 : keyLike) ? `${quote}[valor omitido, ${value.length}]${quote}` : whole;
  });
}

/** Llaves abiertas menos cerradas, sin contar las que están dentro de textos entre comillas. */
function braceDelta(line: string): number {
  const bare = line.replace(/(["'`])(?:\\.|(?!\1)[^\\])*\1/g, "");
  return (bare.match(/\{/g)?.length ?? 0) - (bare.match(/\}/g)?.length ?? 0);
}

/** Busca en un texto (un archivo) las reglas de RULES; las líneas enormes (minificado) se miran por ventanas. */
export function scanText(text: string, file: string): CryptoHit[] {
  const hits: CryptoHit[] = [];
  const lines = text.split(/\r?\n/);
  // Función que contiene la línea: hasta que se cierra su llave (o, en Python y Ruby, hasta que vuelve la sangría).
  let current: string | undefined;
  let depth = 0;
  let fnDepth = 0;
  let fnIndent = -1;
  for (let index = 0; index < lines.length && hits.length < MAX_HITS; index++) {
    const line = lines[index]!;
    const indent = /^\s*/.exec(line)![0].length;
    const started = line.length < 4000 ? functionName(line) : undefined;
    if (current && fnIndent >= 0 && !started && line.trim() && indent <= fnIndent) current = undefined;
    if (started) {
      current = started;
      fnDepth = depth;
      fnIndent = /^\s*def\s/.test(line) ? indent : -1;
    }
    const seen = new Set<string>();
    for (const rule of RULES) {
      rule.re.lastIndex = 0;
      let match: RegExpExecArray | null;
      let perLine = 0;
      while ((match = rule.re.exec(line)) && perLine < 6) {
        if (match[0].length === 0) { rule.re.lastIndex++; continue; }
        perLine++;
        // En una línea larga (un bundle), el contexto es una ventana alrededor de la coincidencia.
        const context = line.length > 600 ? line.slice(Math.max(0, match.index - 160), match.index + match[0].length + 160) : line;
        const verdict = rule.judge(match, context);
        if (!verdict) continue;
        const kind = verdict.kind ?? rule.kind;
        const key = `${kind}:${verdict.detail}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const secret = kind === "secreto fijo" || /fij[oa]|secreto/.test(verdict.detail);
        const snippet = maskLiterals(redactSecrets((line.length > 600 ? `…${context}…` : line).trim()), secret).slice(0, 240);
        hits.push({ file, line: index + 1, kind, detail: verdict.detail, risk: verdict.risk, ...(current && line.length < 4000 ? { fn: current } : {}), snippet, attack: verdict.attack });
      }
    }
    depth += line.length < 4000 ? braceDelta(line) : 0;
    // Se cerró: una función de una línea, o la llave que cierra la actual (una firma sin llave sigue abierta).
    if (current && fnIndent < 0 && depth <= fnDepth && (!started || /\{/.test(line))) current = undefined;
  }
  return hits;
}

const RISK_ORDER: Record<Riesgo, number> = { alto: 0, medio: 1, bajo: 2, info: 3 };

export async function scanProject(cwd: string, path = ".", signal?: AbortSignal): Promise<{ hits: CryptoHit[]; files: number; bytes: number; cut?: string; big: string[] }> {
  const listed = await projectFiles(cwd, path, { signal });
  const hits: CryptoHit[] = [];
  let files = 0;
  let bytes = 0;
  let cut = listed.cut as string | undefined;
  for (const file of listed.files) {
    signal?.throwIfAborted();
    if (!SOURCE_EXT.has(extname(file).toLowerCase()) && listed.files.length > 1) continue;
    let size = 0;
    try { size = statSync(file).size; } catch { continue; }
    if (size > MAX_SCAN_FILE) continue;
    if (bytes + size > MAX_SCAN_BYTES) { cut = "bytes"; break; }
    const content = readFileSync(file);
    if (content.subarray(0, 4096).includes(0)) continue;
    files++;
    bytes += size;
    hits.push(...scanText(content.toString("utf8"), relative(listed.root, file).split(sep).join("/")));
    if (hits.length >= MAX_HITS) { cut = "resultados"; break; }
  }
  hits.sort((a, b) => RISK_ORDER[a.risk] - RISK_ORDER[b.risk] || a.file.localeCompare(b.file) || a.line - b.line);
  return { hits, files, bytes, ...(cut ? { cut } : {}), big: listed.big };
}

/** Funciones propias con criptografía o decisiones: dónde leer primero (archivo, función, líneas y riesgo mayor). */
function functionsOf(hits: CryptoHit[]): Array<{ file: string; fn: string; lines: number[]; risk: Riesgo; kinds: string[] }> {
  const by = new Map<string, { file: string; fn: string; lines: number[]; risk: Riesgo; kinds: Set<string> }>();
  for (const hit of hits) {
    if (!hit.fn) continue;
    const key = `${hit.file}#${hit.fn}`;
    const entry = by.get(key) ?? { file: hit.file, fn: hit.fn, lines: [], risk: hit.risk, kinds: new Set<string>() };
    entry.lines.push(hit.line);
    entry.kinds.add(hit.kind);
    if (RISK_ORDER[hit.risk] < RISK_ORDER[entry.risk]) entry.risk = hit.risk;
    by.set(key, entry);
  }
  return [...by.values()].map((entry) => ({ ...entry, kinds: [...entry.kinds] })).sort((a, b) => RISK_ORDER[a.risk] - RISK_ORDER[b.risk] || b.lines.length - a.lines.length);
}

export function cryptoSummary(scan: Awaited<ReturnType<typeof scanProject>>, max = 40): string[] {
  const counts = (["alto", "medio", "bajo", "info"] as Riesgo[]).map((risk) => `${scan.hits.filter((hit) => hit.risk === risk).length} ${risk}`).join(" · ");
  const functions = functionsOf(scan.hits).slice(0, 12);
  const shown = scan.hits.filter((hit) => hit.risk !== "info").slice(0, max);
  const attacks = [...new Set(shown.filter((hit) => hit.risk === "alto").map((hit) => `${hit.kind}: ${hit.attack}`))].slice(0, 6);
  return [
    `Criptografía, claves y validaciones: ${scan.hits.length} puntos en ${scan.files} archivos (${counts})${scan.cut ? ` · recorte por ${scan.cut}: acotá con path` : ""}.`,
    ...(functions.length ? ["Funciones propias para leer primero (code_read):", ...functions.map((entry) => `  ${entry.file}:${Math.min(...entry.lines)} ${entry.fn}() · ${entry.kinds.join(", ")} · ${entry.risk}`)] : []),
    ...(shown.length ? ["", ...shown.map((hit) => `[${hit.risk}] ${hit.file}:${hit.line}${hit.fn ? ` ${hit.fn}()` : ""} · ${hit.kind}: ${hit.detail}\n    ${hit.snippet}`)] : ["Sin puntos de riesgo; lo informativo está en el artefacto."]),
    ...(scan.hits.filter((hit) => hit.risk !== "info").length > max ? [`… ${scan.hits.filter((hit) => hit.risk !== "info").length - max} más en el artefacto`] : []),
    ...(attacks.length ? ["", "Cómo se prueba (lo alto):", ...attacks.map((line) => `  · ${line}`)] : []),
    ...(scan.big.length ? [`Sin recorrer (carpetas enormes): ${scan.big.slice(0, 4).join(", ")}`] : []),
  ];
}

// ───────────────────────────── hash_crack ─────────────────────────────

const DIGEST_LEN: Record<string, number> = { md5: 16, sha1: 20, sha224: 28, sha256: 32, sha384: 48, sha512: 64, "sha3-256": 32, "sha3-512": 64 };
export const MAX_CANDIDATES = 50_000_000;

type Part = { literal: string } | { values: () => Iterable<string>; size: number; name: string };

/** Lee «archivo:línea» del proyecto y devuelve el primer literal entre comillas de esa línea (el valor no se muestra nunca). */
export function codeLiteral(cwd: string, reference: string): { value: string; where: string } {
  const match = /^(.+):(\d+)$/.exec(reference.trim());
  if (!match) throw new Error(`codigo: «${reference}» tiene que ser archivo:línea (por ejemplo src/auth.js:12).`);
  const file = insideProject(cwd, match[1]!);
  const lines = readFileSync(file, "utf8").split(/\r?\n/);
  const line = lines[Number(match[2]) - 1];
  if (line === undefined) throw new Error(`codigo: ${match[1]} no tiene la línea ${match[2]}.`);
  const literal = /(["'`])((?:\\.|(?!\1).)*)\1/.exec(line);
  if (!literal?.[2]) throw new Error(`codigo: la línea ${match[2]} de ${match[1]} no tiene un texto entre comillas (no vacío).`);
  return { value: literal[2]!.replace(/\\(["'`\\])/g, "$1"), where: `${match[1]}:${match[2]}` };
}

/** Parte la plantilla en literales y comodines: {w} (palabras), {n:0-9999} (rango, con ceros si el inicio los tiene), {nombre} (valores), {codigo}. */
export function parseTemplate(template: string, sources: { words: string[]; values: Record<string, string[]>; code?: string }): Part[] {
  const parts: Part[] = [];
  let last = 0;
  for (const match of template.matchAll(/\{([a-zA-Z_][\w]*)(?::(\d+)-(\d+))?\}/g)) {
    if (match.index > last) parts.push({ literal: template.slice(last, match.index) });
    last = match.index + match[0].length;
    const name = match[1]!;
    if (match[2] !== undefined) {
      const [from, to] = [Number(match[2]), Number(match[3])];
      if (to < from) throw new Error(`Rango invertido en ${match[0]}.`);
      const width = match[2].length > 1 && match[2].startsWith("0") ? match[2].length : 0;
      parts.push({ name, size: to - from + 1, values: function* () { for (let n = from; n <= to; n++) yield width ? String(n).padStart(width, "0") : String(n); } });
    } else if (name === "w") {
      if (!sources.words.length) throw new Error("La plantilla usa {w}: pasá palabras o diccionario.");
      parts.push({ name, size: sources.words.length, values: () => sources.words });
    } else if (name === "codigo") {
      if (sources.code === undefined) throw new Error("La plantilla usa {codigo}: pasá codigo con archivo:línea.");
      const code = sources.code;
      parts.push({ name, size: 1, values: () => [code] });
    } else {
      const list = sources.values[name];
      if (!list?.length) throw new Error(`La plantilla usa {${name}}: pasalo en valores (${name}: [..]).`);
      parts.push({ name, size: list.length, values: () => list });
    }
  }
  if (last < template.length) parts.push({ literal: template.slice(last) });
  return parts;
}

/** Qué valor tomó cada comodín en el candidato actual. */
function choiceOf(parts: Part[], current: string[]): Record<string, string> {
  const choice: Record<string, string> = {};
  parts.forEach((part, index) => { if (!("literal" in part)) choice[part.name] = current[index]!; });
  return choice;
}

/** Recorre el producto de las partes (odómetro) sin armar la lista entera; entrega siempre el mismo arreglo, actualizado. */
function* candidates(parts: Part[]): Generator<string[]> {
  const slots = parts.map((part) => ("literal" in part ? undefined : part));
  const iterators: Array<Iterator<string> | undefined> = slots.map((slot) => slot?.values()[Symbol.iterator]());
  const current: string[] = parts.map((part, index) => ("literal" in part ? part.literal : (iterators[index]!.next().value as string)));
  const active = slots.map((slot, index) => (slot ? index : -1)).filter((index) => index >= 0);
  for (;;) {
    yield current;
    let position = active.length - 1;
    for (; position >= 0; position--) {
      const index = active[position]!;
      const next = iterators[index]!.next();
      if (!next.done) { current[index] = next.value; break; }
      iterators[index] = slots[index]!.values()[Symbol.iterator]();
      current[index] = iterators[index]!.next().value as string;
    }
    if (position < 0) return;
  }
}

/** Valor objetivo normalizado: bytes del hex o del base64 y si es un prefijo (token truncado). */
function targetBytes(value: string, full: number): { bytes: Buffer; encoding: "hex" | "base64"; prefix: boolean } {
  const clean = value.trim();
  const hex = /^[0-9a-fA-F]+$/.test(clean) && clean.length % 2 === 0;
  const bytes = hex ? Buffer.from(clean, "hex") : Buffer.from(clean.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  if (!bytes.length) throw new Error(`«${clean.slice(0, 20)}…» no es hex ni base64.`);
  if (bytes.length > full) throw new Error(`El valor tiene ${bytes.length} bytes y ese algoritmo da ${full}: no es ese algoritmo.`);
  return { bytes, encoding: hex ? "hex" : "base64", prefix: bytes.length < full };
}

// ───────────────────────────── web_source_pull ─────────────────────────────

const MAX_PULL_BYTES = 60 * 1024 * 1024;
const MAX_SOURCES = 5000;

/** Carpetas que code_search, code_list y code_crypto no recorren (las de SKIP en src/codigo.ts) y las ocultas. */
const UNWALKED = new Set([".git", ".cyber", ".cache", "node_modules", ".next", "dist", "build", ".venv", "venv", "__pycache__", ".terraform", "target", ".gradle", ".idea", "coverage"]);

/** Un segmento de ruta seguro para el disco; uno que el recorrido saltearía («dist», «build», «.next») va con «_» adelante. */
const safeSegment = (segment: string) => {
  let value = segment;
  try { value = decodeURIComponent(segment); } catch { /* queda como vino */ }
  value = value.replace(/[^\w.\-@+=,~]/g, "_").slice(0, 120);
  if (value === "." || value === ".." || !value) return "_";
  return UNWALKED.has(value) || value.startsWith(".") ? `_${value}` : value;
};

/** Ruta relativa segura (sin «..», sin raíz, sin esquema) para una URL o un «source» de un mapa. */
export function safeRelative(path: string): string {
  const cleaned = path.replace(/^\/+/, "").replace(/^[a-z][a-z0-9+.-]*:\/*/i, "").replace(/^\/+/, "");
  const segments = cleaned.split(/[\\/]+/).filter((segment) => segment && segment !== "." && segment !== "..").map(safeSegment);
  return segments.join("/") || "index";
}

function fileForUrl(url: URL, html: boolean): string {
  let path = url.pathname.endsWith("/") ? `${url.pathname}index.html` : url.pathname;
  if (html && !/\.html?$/i.test(path)) path = `${path}/index.html`;
  let rel = safeRelative(path);
  if (url.search) {
    const tag = createHash("sha1").update(url.search).digest("hex").slice(0, 8);
    const ext = extname(rel);
    rel = ext ? `${rel.slice(0, -ext.length)}__${tag}${ext}` : `${rel}__${tag}`;
  }
  return rel;
}

/** Referencias a otros .js dentro de un script: imports dinámicos, listas de Vite, rutas de Next, chunks de webpack. */
export function chunkRefs(source: string): string[] {
  const found = new Set<string>();
  for (const match of source.matchAll(/["'`]((?:\.{1,2}\/|\/)?(?:[\w\-~@%+]+\/)*[\w\-~@%+.]+?\.m?js)(?:\?[\w=&.-]{0,40})?["'`]/g)) {
    const value = match[1]!;
    // Un nombre de paquete o un archivo suelto sin carpeta («lodash.js», «x.js»): sólo si viene con ./ o carpeta.
    if (!/[/]/.test(value) && !/^[\w-]+[.-][0-9a-f]{6,}\.m?js$/i.test(value)) continue;
    if (/^(?:node_modules|https?:)/.test(value) || value.length > 200) continue;
    found.add(value);
  }
  // webpack: "static/js/" + e + "." + {0:"a1b2",1:"c3"}[e] + ".chunk.js"  (con o sin un mapa de nombres en el medio)
  for (const match of source.matchAll(/["']([\w./-]*)["']\s*\+\s*(?:\(\s*\{([^{}]{1,20000})\}\s*\[\s*\w+\s*\]\s*\|\|\s*\w+\s*\)|\w+)\s*\+\s*["']([.\w-]*)["']\s*\+\s*\{([^{}]{1,40000})\}\s*\[\s*\w+\s*\]\s*\+\s*["']([\w.-]*\.m?js)["']/g)) {
    const [prefix, names, middle, hashes, suffix] = [match[1]!, match[2], match[3]!, match[4]!, match[5]!];
    const nameOf = new Map([...(names ?? "").matchAll(/["']?([\w-]+)["']?\s*:\s*["']([\w.-]+)["']/g)].map((pair) => [pair[1]!, pair[2]!]));
    for (const pair of hashes.matchAll(/["']?([\w-]+)["']?\s*:\s*["']([\w-]+)["']/g)) {
      found.add(`${prefix}${nameOf.get(pair[1]!) ?? pair[1]}${middle}${pair[2]}${suffix}`);
      if (found.size > 2000) break;
    }
  }
  return [...found];
}

/** Lo que el cliente arma: rutas de la interfaz, dónde guarda el token, cómo arma la autorización, chequeos de rol, bases de API, operaciones GraphQL. */
export function clientFlows(source: string): { pantallas: string[]; almacenamiento: string[]; autorizacion: string[]; bases: string[]; graphql: string[]; banderas: string[] } {
  const take = (re: RegExp, group = 1, limit = 60) => [...new Set([...source.matchAll(re)].map((match) => match[group]!.slice(0, 120)))].slice(0, limit);
  return {
    pantallas: take(/(?:\bpath\s*:\s*|<Route\b[^>]*\bpath=\{?\s*|\.(?:push|navigate|replace)\(\s*)["'`](\/[\w\-/:.*[\]]*)["'`]/g),
    almacenamiento: take(/\b((?:local|session)Storage\.setItem\(\s*["'`][^"'`]{1,60}["'`]|document\.cookie\s*=\s*["'`]?[\w-]{1,40}=)/g),
    autorizacion: take(/["'`]?(Authorization|X-[\w-]*(?:Token|Auth|Key|Signature|Sign|Csrf|Xsrf)[\w-]*)["'`]?\s*[:,]\s*(?:["'`]\s*)?(`?(?:Bearer|Basic|Token|JWT)?[^,;\n]{0,40})/gi, 0, 30),
    bases: take(/\b(?:apiUrl|apiURL|baseURL|baseUrl|API_URL|API_BASE|apiBase|apiEndpoint|graphqlEndpoint|GRAPHQL_URL|backendUrl|BACKEND_URL)\s*[:=]\s*["'`](https?:\/\/[^"'`\s]+)["'`]/g),
    graphql: take(/\b(query|mutation|subscription)\s+([A-Z]\w{2,60})\s*[({]/g, 0, 80),
    banderas: take(/\b(?:isEnabled|isFeatureEnabled|featureFlag|useFlag|getFeatureValue|useFeature)\(\s*["'`]([\w.:-]{2,60})["'`]/g),
  };
}

interface Pulled { url: string; file: string; bytes: number; sha256: string; exchange: string; kind: "html" | "js" | "map" | "inline" }

export interface SourceContext {
  cwd: string;
  http: HttpClient;
  artifacts: Artifacts;
}

export function createSourceTools(context: SourceContext): Tool[] {
  const { http, artifacts } = context;
  const root = () => realpathSync(resolve(context.cwd));

  /** Carpeta de salida dentro del proyecto (nueva o existente), nunca en .cyber, sin enlaces simbólicos. */
  const outputDir = (wanted: string): string => {
    const base = root();
    const target = resolve(base, wanted);
    const rel = relative(base, target);
    if (!rel || rel.startsWith("..") || rel.split(sep).includes(".cyber") || isAbsolute(rel)) throw new Error(`carpeta: «${wanted}» tiene que ser una carpeta nueva o propia dentro del proyecto (y no .cyber).`);
    // El primer ancestro que existe tiene que estar adentro (un enlace a otro lado no pasa).
    let probe = target;
    while (probe !== base) {
      try { lstatSync(probe); break; } catch { probe = dirname(probe); }
    }
    insideProject(base, relative(base, probe) || ".");
    mkdirSync(target, { recursive: true });
    if (lstatSync(target).isSymbolicLink()) throw new Error(`carpeta: «${wanted}» es un enlace simbólico.`);
    return insideProject(base, rel);
  };

  /** Escribe un archivo bajo `dir` y devuelve su ruta relativa al proyecto; nunca fuera de `dir`. */
  const write = (dir: string, rel: string, content: string | Buffer): string => {
    const target = resolve(dir, rel);
    if (!target.startsWith(dir + sep)) throw new Error(`Ruta fuera de la carpeta: ${rel}`);
    mkdirSync(dirname(target), { recursive: true });
    const parent = realpathSync(dirname(target));
    if (parent !== dir && !parent.startsWith(dir + sep)) throw new Error(`Ruta fuera de la carpeta: ${rel}`);
    try { if (lstatSync(target).isSymbolicLink()) throw new Error(`No piso un enlace simbólico: ${rel}`); } catch (error) { if (/enlace/.test((error as Error).message)) throw error; }
    writeFileSync(target, content);
    return relative(root(), target).split(sep).join("/");
  };

  const webSourcePull: Tool = {
    name: "web_source_pull",
    label: "Bajar el código de una web",
    description:
      "Sale de la caja negra de una web del alcance: baja la página, todos sus scripts (también los chunks que cargan después: imports dinámicos, listas de Vite, rutas de Next, mapas de chunks de webpack) y los mapas de fuente que publique, reconstruye el código original de esos mapas, y lo deja en una carpeta del proyecto (por defecto fuente-web/<host>) con un manifiesto. " +
      "Devuelve el contrato de la API, los flujos que arma el cliente (pantallas, dónde guarda el token, cómo arma la autorización, bases de API, operaciones GraphQL, banderas) y la criptografía y validaciones del cliente (code_crypto). Después: code_search y code_read sobre esa carpeta y, en la caja, rea.analyze_javascript_application con input_path en ella. " +
      "Todo sale por el cliente HTTP (alcance, ritmo, tope de peticiones y señuelos): lo de otros hosts no se baja y se dice.",
    parameters: obj({
      url: str({ description: "Página (o un .js) del alcance" }),
      identity: str({ description: "Identidad con la que pedir la página (zona autenticada)" }),
      carpeta: str({ description: "Carpeta del proyecto donde dejarlo; por defecto fuente-web/<host>" }),
      maxScripts: int({ minimum: 1, maximum: 300, description: "Scripts a bajar como máximo, chunks incluidos; por defecto 80" }),
      mapas: { type: "boolean", description: "Pedir los mapas de fuente declarados (por defecto sí)" },
      dependencias: { type: "boolean", description: "Reconstruir también node_modules de los mapas (por defecto no: sólo el código propio)" },
    }, ["url"]),
    execute: async (params, signal): Promise<ToolResult> => {
      const start = new URL(String(params.url));
      if (!/^https?:$/.test(start.protocol)) throw new Error("web_source_pull baja una página http(s) del alcance.");
      const dir = outputDir(params.carpeta ? String(params.carpeta) : join("fuente-web", safeSegment(start.host.replace(/:/g, "_"))));
      const maxScripts = Math.min(300, Math.max(1, Number(params.maxScripts) || 80));
      const pulled: Pulled[] = [];
      const outside = new Map<string, number>();
      const failed: string[] = [];
      let bytes = 0;
      const sha = (content: string | Buffer) => createHash("sha256").update(content).digest("hex");
      const keep = (exchange: HttpExchange, kind: Pulled["kind"], html = false): string | undefined => {
        const response = exchange.response;
        if (!response || response.status >= 400) { failed.push(`${exchange.request.url} → ${response ? `HTTP ${response.status}` : (exchange.error ?? "sin respuesta")}`); return undefined; }
        const body = response.bodyEncoding === "base64" ? Buffer.from(response.body, "base64").toString("utf8") : response.body;
        if (bytes + body.length > MAX_PULL_BYTES) { failed.push(`${exchange.request.url} → tope de ${MAX_PULL_BYTES / 1024 / 1024} MB`); return undefined; }
        bytes += body.length;
        const file = write(dir, join("web", fileForUrl(new URL(exchange.request.url), html)), body);
        pulled.push({ url: exchange.request.url, file, bytes: body.length, sha256: sha(body), exchange: exchange.id, kind });
        return body;
      };
      const note = (url: string) => { try { const host = new URL(url).host; outside.set(host, (outside.get(host) ?? 0) + 1); } catch { /* URL rara */ } };

      const first = await http.send({ url: start.href, maxBodyBytes: 8 * 1024 * 1024 }, params.identity);
      if (!first.response) throw new Error(first.error ?? "Sin respuesta");
      const isHtml = /html/i.test(first.response.headers["content-type"] ?? "") || /^\s*</.test(first.response.body);
      const page = keep(first, isHtml ? "html" : "js", isHtml);
      if (page === undefined) throw new Error(`La página respondió ${first.response.status}: no hay nada que bajar.`);
      const queue: Array<{ url: string; depth: number; alt?: string }> = [];
      const queued = new Set<string>();
      const enqueue = (url: string, depth: number, alt?: string) => {
        if (queued.has(url)) return;
        queued.add(url);
        if (!http.inScope(url)) { note(url); return; }
        queue.push({ url, depth, ...(alt ? { alt } : {}) });
      };
      const sources: Array<{ url: string; text: string }> = [];
      if (isHtml) {
        for (const match of page.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi)) try { enqueue(new URL(match[1]!, start).href, 0); } catch { /* src inválido */ }
        for (const match of page.matchAll(/<link\b[^>]*\brel=["'](?:modulepreload|preload|prefetch)["'][^>]*\bhref=["']([^"']+\.m?js[^"']*)["']/gi)) try { enqueue(new URL(match[1]!, start).href, 0); } catch { /* href inválido */ }
        // Scripts en línea: también son código del cliente (configuración, estado inicial, claves públicas).
        let inline = 0;
        for (const match of page.matchAll(/<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)) {
          const code = match[1]!.trim();
          if (code.length < 40 || inline >= 50) continue;
          inline++;
          const file = write(dir, join("web", "_en-linea", `script-${inline}.js`), code);
          pulled.push({ url: `${start.href}#script-${inline}`, file, bytes: code.length, sha256: sha(code), exchange: first.id, kind: "inline" });
          sources.push({ url: `${start.href}#script-${inline}`, text: code });
        }
      } else sources.push({ url: start.href, text: page });

      // Scripts y sus chunks, en anchura, con profundidad 3.
      const scripts: Array<{ url: string; text: string; headers: Record<string, string> }> = isHtml ? [] : [{ url: start.href, text: page, headers: first.response.headers }];
      if (!isHtml) for (const ref of chunkRefs(page)) addRef(ref, start.href, 1);
      function addRef(ref: string, from: string, depth: number) {
        try {
          if (/^\.{1,2}\//.test(ref) || /^\//.test(ref)) enqueue(new URL(ref, from).href, depth);
          // «static/js/x.js» o «assets/x.js»: relativo a la raíz del sitio (publicPath «/») y, si no está, al script.
          else enqueue(new URL(`/${ref}`, from).href, depth, new URL(ref, from).href);
        } catch { /* referencia inválida */ }
      }
      while (queue.length && scripts.length < maxScripts) {
        signal?.throwIfAborted();
        if (http.remaining() === 0) { failed.push("tope de peticiones de la sesión: se cortó la bajada"); break; }
        const batch = queue.splice(0, 4);
        const exchanges = await Promise.all(batch.map((item) => http.send({ url: item.url, maxBodyBytes: 8 * 1024 * 1024 })));
        for (const [index, exchange] of exchanges.entries()) {
          const item = batch[index]!;
          if (exchange.response?.status === 404 && item.alt && !queued.has(item.alt)) {
            queued.add(item.alt);
            if (http.inScope(item.alt)) queue.push({ url: item.alt, depth: item.depth });
            continue;
          }
          const text = keep(exchange, "js");
          if (text === undefined) continue;
          scripts.push({ url: item.url, text, headers: exchange.response!.headers });
          sources.push({ url: item.url, text });
          if (item.depth < 3) for (const ref of chunkRefs(text)) addRef(ref, item.url, item.depth + 1);
        }
      }
      const pendingScripts = queue.length;

      // Mapas de fuente: comentario sourceMappingURL o cabecera SourceMap; los data: se decodifican sin pedir nada.
      const maps: Array<{ map: string; from: string; sources: number; written: number; skipped: number }> = [];
      const recovered: string[] = [];
      if (params.mapas !== false) {
        for (const script of scripts) {
          signal?.throwIfAborted();
          const declared = /\/\/[#@]\s*sourceMappingURL=(\S+)\s*$/m.exec(script.text.slice(-4000))?.[1] ?? Object.entries(script.headers).find(([key]) => /^(x-)?source-?map$/i.test(key))?.[1];
          if (!declared) continue;
          let raw: string | undefined;
          let mapUrl: string;
          if (/^data:/i.test(declared)) {
            const data = /^data:[^,]*?(;base64)?,(.*)$/is.exec(declared);
            if (!data) continue;
            raw = data[1] ? Buffer.from(data[2]!, "base64").toString("utf8") : decodeURIComponent(data[2]!);
            mapUrl = `${script.url} (en línea)`;
          } else {
            mapUrl = new URL(declared, script.url).href;
            if (!http.inScope(mapUrl)) { note(mapUrl); continue; }
            if (http.remaining() === 0) { failed.push("tope de peticiones: mapas sin pedir"); break; }
            const exchange = await http.send({ url: mapUrl, maxBodyBytes: 16 * 1024 * 1024 });
            raw = keep(exchange, "map");
          }
          if (raw === undefined) continue;
          let parsed: { sources?: unknown[]; sourcesContent?: unknown[]; sourceRoot?: string };
          try { parsed = JSON.parse(raw); } catch { failed.push(`${mapUrl} → no es JSON`); continue; }
          const list = Array.isArray(parsed.sources) ? parsed.sources : [];
          const contents = Array.isArray(parsed.sourcesContent) ? parsed.sourcesContent : [];
          let written = 0;
          let skipped = 0;
          for (const [index, name] of list.entries()) {
            const content = contents[index];
            if (typeof name !== "string" || typeof content !== "string") continue;
            if (!params.dependencias && /(^|\/)node_modules\//.test(name)) { skipped++; continue; }
            if (recovered.length >= MAX_SOURCES || bytes + content.length > MAX_PULL_BYTES) { skipped++; continue; }
            bytes += content.length;
            const file = write(dir, join("fuentes", safeRelative(parsed.sourceRoot ? `${parsed.sourceRoot}/${name}` : name)), content);
            recovered.push(file);
            sources.push({ url: `${mapUrl}#${name}`, text: content });
            written++;
          }
          maps.push({ map: mapUrl, from: script.url, sources: list.length, written, skipped });
        }
      }

      // Análisis: contrato de la API, flujos del cliente y criptografía/validaciones (sobre la carpeta escrita).
      const operations = new Map<string, { methods: Set<string>; keys: Set<string>; object: boolean }>();
      const headers = new Set<string>();
      const hosts = new Set<string>();
      const flows = { pantallas: new Set<string>(), almacenamiento: new Set<string>(), autorizacion: new Set<string>(), bases: new Set<string>(), graphql: new Set<string>(), banderas: new Set<string>() };
      for (const source of sources) {
        const contract = extractApi(source.text);
        contract.headers.forEach((header) => headers.add(header));
        contract.hosts.forEach((host) => hosts.add(host));
        for (const op of contract.operations) {
          const entry = operations.get(op.path) ?? { methods: new Set<string>(), keys: new Set<string>(), object: op.object };
          op.methods.forEach((method) => entry.methods.add(method));
          op.keys.forEach((key) => entry.keys.add(key));
          operations.set(op.path, entry);
        }
        const found = clientFlows(source.text);
        for (const key of Object.keys(flows) as Array<keyof typeof flows>) for (const value of found[key]) if (flows[key].size < 80) flows[key].add(value);
      }
      for (const [path, entry] of operations) for (const method of entry.methods.size ? entry.methods : ["GET"]) {
        try { http.observe({ url: start.origin + path.replace(/\{[^}]*\}/g, "1"), method, bodyKeys: method === "GET" ? [] : [...entry.keys] }); } catch { /* ruta que no arma URL */ }
      }
      const scan = await scanProject(context.cwd, relative(root(), dir) || ".", signal);
      const apiOut = [...flows.bases].map((base) => { try { return new URL(base).href; } catch { return base; } }).filter((base) => !http.inScope(base));
      const manifest = {
        pagina: start.href,
        fecha: new Date().toISOString(),
        carpeta: relative(root(), dir).split(sep).join("/"),
        archivos: pulled,
        mapas: maps,
        fuentesRecuperadas: recovered.length,
        fueraDelAlcance: Object.fromEntries(outside),
        fallas: failed,
        pendientes: pendingScripts,
      };
      write(dir, "manifiesto.json", JSON.stringify(manifest, null, 1));
      const ops = [...operations].map(([path, entry]) => ({ path, methods: [...entry.methods].sort(), keys: [...entry.keys].slice(0, 12), object: entry.object }));
      ops.sort((a, b) => Number(b.object) - Number(a.object) || Number(b.methods.some((m) => m !== "GET")) - Number(a.methods.some((m) => m !== "GET")) || a.path.localeCompare(b.path));
      const analysis = { ...manifest, api: ops, cabeceras: [...headers], hosts: [...hosts], flujos: Object.fromEntries(Object.entries(flows).map(([key, set]) => [key, [...set]])), cripto: scan.hits };
      const artifact = artifacts.put(JSON.stringify(analysis, null, 1), "application/json", "web_source_pull");
      const folder = relative(root(), dir).split(sep).join("/");
      const flowLines = ([
        ["Pantallas del cliente", flows.pantallas],
        ["Dónde guarda la sesión", flows.almacenamiento],
        ["Cómo arma la autorización", flows.autorizacion],
        ["Bases de API", flows.bases],
        ["Operaciones GraphQL", flows.graphql],
        ["Banderas", flows.banderas],
      ] as Array<[string, Set<string>]>).filter(([, set]) => set.size).map(([label, set]) => `${label}: ${[...set].slice(0, 12).join(", ")}${set.size > 12 ? ` (+${set.size - 12})` : ""}`);
      const lines = [
        `${start.href} → ${folder}/ · ${pulled.filter((item) => item.kind === "js").length} scripts${pulled.some((item) => item.kind === "inline") ? ` + ${pulled.filter((item) => item.kind === "inline").length} en línea` : ""}, ${maps.length} mapas, ${recovered.length} fuentes originales recuperadas (${Math.round(bytes / 1024)} KB) · manifiesto ${folder}/manifiesto.json · artefacto ${artifact.hash}`,
        ...(outside.size ? [`Fuera del alcance, no bajado: ${[...outside].map(([host, n]) => `${host} (${n})`).slice(0, 10).join(", ")}. Si alguno es del programa, que el operador lo agregue.`] : []),
        ...(pendingScripts ? [`Quedaron ${pendingScripts} scripts sin bajar por el tope (maxScripts ${maxScripts}).`] : []),
        ...(failed.length ? [`No se pudo: ${failed.slice(0, 6).join(" · ")}${failed.length > 6 ? ` (+${failed.length - 6})` : ""}`] : []),
        "",
        `API que usa el cliente: ${ops.length} rutas, ${ops.filter((op) => op.object).length} con identificador de objeto${headers.size ? ` · cabeceras propias: ${[...headers].slice(0, 8).join(", ")}` : ""}`,
        ...ops.slice(0, 25).map((op) => `  ${(op.methods.join(",") || "?").padEnd(12)} ${op.path}${op.keys.length ? `  campos: ${op.keys.join(", ")}` : ""}`),
        ...(ops.length > 25 ? [`  … ${ops.length - 25} más en el artefacto`] : []),
        ...(apiOut.length ? [`Bases de API fuera del alcance: ${apiOut.slice(0, 5).join(", ")} (el operador decide si entran).`] : []),
        ...(flowLines.length ? ["", ...flowLines] : []),
        "",
        ...cryptoSummary(scan, 15),
        "",
        `Seguí con code_search o code_read sobre ${folder}/${recovered.length ? "fuentes" : "web"}, code_crypto para el detalle, y en la caja rea.analyze_javascript_application con input_path ${folder}/${recovered.length ? "fuentes" : "web"}. Lo que diga el código es una pista hasta probarlo en vivo dentro del alcance.`,
        `peticiones HTTP: ${http.count}${http.remaining() !== undefined ? ` · quedan ${http.remaining()}` : ""}`,
      ];
      return { text: lines.join("\n"), details: { scripts: pulled.filter((item) => item.kind === "js").length, mapas: maps.length, fuentes: recovered.length, rutas: ops.length, carpeta: folder, artefacto: artifact.hash } };
    },
  };

  const codeCrypto: Tool = {
    name: "code_crypto",
    label: "Cripto y validaciones en el código",
    description:
      "Mapea en el código del proyecto (un repositorio del programa, una carpeta, un archivo, o lo que bajó web_source_pull) las funciones propias que importan para romper algo: derivación de claves y tokens (un hash de datos predecibles), hashes de contraseñas sin KDF, MAC casero hash(secreto‖datos) con extensión de longitud, HMAC o JWT con secreto fijo, cifrado en ECB o con IV fijo, KDF con pocas iteraciones, aleatoriedad no criptográfica para tokens, comparaciones de firmas con ==, secretos escritos y validaciones o permisos que decide el cliente. " +
      "Devuelve archivo:línea, la función que lo contiene y cómo se prueba cada uno; los valores secretos no se muestran. Para confirmar una derivación con un valor observado, hash_crack.",
    parameters: obj({ path: str({ description: "Carpeta o archivo relativo al proyecto; por defecto la raíz" }), max: int({ minimum: 5, maximum: 200, description: "Puntos a mostrar (por defecto 40; todos en el artefacto)" }) }, []),
    parallel: true,
    replay: "safe",
    execute: async (params, signal): Promise<ToolResult> => {
      const scan = await scanProject(context.cwd, params.path ? String(params.path) : ".", signal);
      const artifact = artifacts.put(JSON.stringify({ path: params.path ?? ".", archivos: scan.files, puntos: scan.hits }, null, 1), "application/json", "code_crypto");
      const lines = cryptoSummary(scan, Number(params.max) || 40);
      lines.push(`Completo en el artefacto ${artifact.hash}. Es observación estática: pista hasta mostrarlo en vivo.`);
      // Como code_read: en la carpeta del operador (su home, la raíz) lo que se lee es suyo (src/secretos-sesion.ts).
      const procedencia = carpetaDelOperador(context.cwd) ? "local" : "objetivo";
      return { text: lines.join("\n"), details: { puntos: scan.hits.length, altos: scan.hits.filter((hit) => hit.risk === "alto").length, archivos: scan.files, artefacto: artifact.hash }, procedencia };
    },
  };

  const hashCrack: Tool = {
    name: "hash_crack",
    label: "Confirmar una derivación (offline)",
    description:
      "Confirma offline cómo se arma un hash, token o firma observados: prueba candidatos de una plantilla contra el valor (hex o base64, completo o truncado) sin salir a la red. Comodines: {w} (palabras o diccionario), {n:0-99999} (rango; con ceros a la izquierda si el inicio los tiene), {nombre} (valores propios) y {codigo} (el texto entre comillas de archivo:línea del proyecto, sin mostrarlo). " +
      "Algoritmos md5, sha1, sha224, sha256, sha384, sha512, sha3-256, sha3-512 y hmac-<uno de ésos> (clave en «clave» o en «codigo»). Ejemplo: un token tuyo que parece sha256(email:hora) → plantilla «{email}:{n:1732200000-1732290000}» con valores {email:[tu correo]}. Con la fórmula confirmada, calculá el de otra cuenta tuya y probalo en vivo dentro del alcance.",
    parameters: obj({
      objetivo: { type: "array", items: { type: "string" }, description: "Valores observados (hex o base64), hasta 20" },
      algoritmo: str(),
      plantilla: str({ description: "Texto con comodines, p. ej. {w}, {email}:{n:0-999999}, {codigo}{w}" }),
      palabras: { type: "array", items: { type: "string" }, description: "Para {w} (hasta 100 000)" },
      diccionario: str({ description: "Archivo del proyecto, una palabra por línea, para {w}" }),
      valores: { type: "object", additionalProperties: { type: "array", items: { type: "string" } }, description: "Listas para comodines con nombre: {email: [..], id: [..]}" },
      clave: str({ description: "Clave del HMAC, si la sabés" }),
      codigo: str({ description: "archivo:línea con un texto entre comillas: clave del HMAC o comodín {codigo} (no se muestra)" }),
      segundos: int({ minimum: 1, maximum: 300, description: "Tiempo máximo (por defecto 60)" }),
    }, ["objetivo", "algoritmo", "plantilla"]),
    execute: async (params, signal): Promise<ToolResult> => {
      const algorithm = String(params.algoritmo).toLowerCase().replace(/_/g, "-");
      const hmac = /^hmac-/.test(algorithm);
      const base = algorithm.replace(/^hmac-/, "").replace(/^sha-(\d)/, "sha$1");
      if (!(base in DIGEST_LEN) || !getHashes().includes(base)) throw new Error(`Algoritmo «${params.algoritmo}»: md5, sha1, sha224, sha256, sha384, sha512, sha3-256, sha3-512 o hmac-<uno de ésos>.`);
      const observed: string[] = (Array.isArray(params.objetivo) ? (params.objetivo as unknown[]) : [params.objetivo]).map(String).filter(Boolean).slice(0, 20);
      const targets = observed.map((value: string) => ({ value, ...targetBytes(value, DIGEST_LEN[base]!) }));
      if (!targets.length) throw new Error("Falta objetivo: el valor observado (hex o base64).");
      const code = params.codigo ? codeLiteral(context.cwd, String(params.codigo)) : undefined;
      const key = hmac ? (params.clave !== undefined ? String(params.clave) : code?.value) : undefined;
      if (hmac && key === undefined) throw new Error("Un HMAC necesita la clave: «clave» o «codigo» (archivo:línea donde está escrita).");
      let words: string[] = (Array.isArray(params.palabras) ? params.palabras : []).map(String).slice(0, 100_000);
      if (params.diccionario) {
        const file = insideProject(context.cwd, String(params.diccionario));
        if (statSync(file).size > 200 * 1024 * 1024) throw new Error("Diccionario de más de 200 MB: partilo.");
        words = [...words, ...readFileSync(file, "utf8").split(/\r?\n/).filter(Boolean)].slice(0, 20_000_000);
      }
      const values: Record<string, string[]> = {};
      for (const [name, list] of Object.entries((params.valores ?? {}) as Record<string, unknown>)) if (Array.isArray(list)) values[name] = (list as unknown[]).map(String).slice(0, 100_000);
      const template = String(params.plantilla);
      const parts = parseTemplate(template, { words, values, code: hmac ? undefined : code?.value });
      const total = parts.reduce((product, part) => product * ("literal" in part ? 1 : part.size), 1);
      if (total > MAX_CANDIDATES) throw new Error(`La plantilla arma ${total.toLocaleString("es-AR")} candidatos: el tope es ${MAX_CANDIDATES.toLocaleString("es-AR")}. Acotá los rangos (la hora a la ventana en que se pidió el token, los ids a los cercanos al tuyo).`);
      const deadline = Date.now() + Math.min(300, Math.max(1, Number(params.segundos) || 60)) * 1000;
      const found: Array<{ objetivo: string; texto: string; comodines: Record<string, string> }> = [];
      const pending = new Set(targets.map((target) => target.value));
      let tried = 0;
      let stopped: string | undefined;
      const digest = (text: string) => (hmac ? createHmac(base, key!).update(text).digest() : createHash(base).update(text).digest());
      for (const current of candidates(parts)) {
        tried++;
        const text = current.join("");
        const value = digest(text);
        for (const target of targets) {
          if (!pending.has(target.value)) continue;
          if (target.prefix ? value.subarray(0, target.bytes.length).equals(target.bytes) : value.equals(target.bytes)) {
            pending.delete(target.value);
            found.push({ objetivo: target.value, texto: code && !hmac ? text.split(code.value).join(`«${code.where}»`) : text, comodines: Object.fromEntries(Object.entries(choiceOf(parts, current)).map(([name, value]) => [name, name === "codigo" ? `«${code!.where}»` : value])) });
          }
        }
        if (!pending.size) break;
        if ((tried & 0xfff) === 0) {
          if (signal?.aborted) { stopped = "cancelado"; break; }
          if (Date.now() > deadline) { stopped = "tiempo"; break; }
          await new Promise((done) => setImmediate(done));
        }
      }
      const artifact = artifacts.put(JSON.stringify({ algoritmo: algorithm, plantilla: template, candidatos: total, probados: tried, encontrados: found, clave: hmac ? (params.clave !== undefined ? "dada por el agente (no se guarda)" : `de ${code!.where}`) : undefined }, null, 1), "application/json", "hash_crack");
      const how = `${hmac ? `HMAC-${base} con clave ${params.clave !== undefined ? "dada" : `de ${code!.where} (${key!.length} caracteres, no se muestra)`}` : base}${targets.some((target) => target.prefix) ? " (valor truncado: se compara el prefijo)" : ""}`;
      if (!found.length) {
        return { text: `Sin coincidencia: ${tried.toLocaleString("es-AR")} de ${total.toLocaleString("es-AR")} candidatos con ${how}${stopped ? ` (cortado por ${stopped}: subí segundos o acotá)` : ""}. La fórmula no es ésa o las entradas no están en los rangos: revisá la función con code_read. Artefacto ${artifact.hash}.`, details: { probados: tried, encontrados: 0, artefacto: artifact.hash } };
      }
      return {
        text: [`Confirmado ${found.length} de ${targets.length} con ${how}, ${tried.toLocaleString("es-AR")} candidatos probados:`, ...found.map((item) => `  ${item.objetivo.slice(0, 16)}… = ${hmac ? "HMAC" : base}(«${item.texto}»)${Object.keys(item.comodines).length ? `  · ${Object.entries(item.comodines).map(([name, text]) => `${name}=${text}`).join(", ")}` : ""}`), ...(pending.size ? [`Sin confirmar: ${[...pending].map((value) => `${value.slice(0, 16)}…`).join(", ")}`] : []), "La derivación es predecible: calculá el valor para otra cuenta tuya y probalo en vivo dentro del alcance antes de registrar candidato (con esta salida y la petición como evidencia).", `Artefacto ${artifact.hash}.`].join("\n"),
        details: { probados: tried, encontrados: found.length, artefacto: artifact.hash },
      };
    },
  };

  return [webSourcePull, codeCrypto, hashCrack];
}

/** Para pruebas: el nombre del archivo que web_source_pull usa para una URL. */
export const archivoDeUrl = (url: string, html = false) => fileForUrl(new URL(url), html);
