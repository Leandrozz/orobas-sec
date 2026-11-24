// Importarlo primero: los tests nunca tocan la carpeta de datos real del usuario.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.CYBER_DATA_DIR ||= mkdtempSync(join(tmpdir(), "cyber-datos-"));
process.env.CYBER_CREDENTIALS_DIR ||= mkdtempSync(join(tmpdir(), "cyber-cred-"));
process.env.CYBER_CONFIG ||= join(mkdtempSync(join(tmpdir(), "cyber-config-")), "config.json");
// Los tests no salen a internet: el feed de CVEs nuevos queda apagado salvo en las pruebas que lo prenden con un fetch propio.
process.env.CYBER_CVE_FEED ||= "no";
// El aviso de trazas de la primera vez ya se vio: las pruebas de pantalla no lo esperan. Las de trazas borran la marca.
import { existsSync as existe, writeFileSync as escribir } from "node:fs";
if (!existe(join(process.env.CYBER_DATA_DIR, "aviso-trazas.json"))) escribir(join(process.env.CYBER_DATA_DIR, "aviso-trazas.json"), '{"prueba":true}\n');
