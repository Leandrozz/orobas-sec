// Servidor de releases falso para las pruebas del instalador y de los lanzadores. Corre en un proceso aparte
// (las pruebas usan spawnSync y bloquearían un servidor del mismo proceso) e imita lo que usan de GitHub:
//   HEAD/GET /releases/latest              → 302 a /releases/tag/<lo que diga el archivo DIR/latest>
//   HEAD/GET /releases/tag/<v>             → 200
//   GET      /releases/download/<v>/<arch> → DIR/<v>/<arch>, o 404
// Anota cada pedido en DIR/pedidos.log. Imprime el puerto en una línea y queda escuchando.
//   node test/servidor-releases.ts DIR
import { appendFileSync, existsSync, readFileSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { join, normalize } from "node:path";

const dir = process.argv[2];
if (!dir) throw new Error("uso: servidor-releases.ts DIR");

const servidor = createServer((pedido, respuesta) => {
  const ruta = decodeURIComponent(new URL(pedido.url ?? "/", "http://x").pathname);
  appendFileSync(join(dir, "pedidos.log"), `${pedido.method} ${ruta}\n`);
  const fin = (codigo: number, cuerpo = "", cabeceras: Record<string, string> = {}) => {
    respuesta.writeHead(codigo, { "content-length": String(Buffer.byteLength(cuerpo)), ...cabeceras });
    respuesta.end(pedido.method === "HEAD" ? undefined : cuerpo);
  };
  if (ruta === "/releases/latest") {
    const ultimo = existsSync(join(dir, "latest")) ? readFileSync(join(dir, "latest"), "utf8").trim() : "";
    return ultimo ? fin(302, "", { location: `/releases/tag/${ultimo}` }) : fin(404, "sin releases");
  }
  if (/^\/releases\/tag\/[^/]+$/.test(ruta)) return fin(200, "release");
  const m = /^\/releases\/download\/([^/]+)\/([^/]+)$/.exec(ruta);
  if (m) {
    const archivo = normalize(join(dir, m[1]!, m[2]!));
    if (archivo.startsWith(normalize(dir)) && existsSync(archivo) && statSync(archivo).isFile()) {
      const datos = readFileSync(archivo);
      respuesta.writeHead(200, { "content-length": String(datos.length), "content-type": "application/octet-stream" });
      return respuesta.end(pedido.method === "HEAD" ? undefined : datos);
    }
  }
  fin(404, "no existe");
});
servidor.listen(0, "127.0.0.1", () => {
  const direccion = servidor.address();
  if (direccion && typeof direccion === "object") console.log(direccion.port);
});
process.on("SIGTERM", () => servidor.close(() => process.exit(0)));
