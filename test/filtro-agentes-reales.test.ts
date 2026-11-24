// Falsos positivos medidos sobre 2.888 resultados reales de herramientas (dos sesiones): 40 marcados
// de más, casi todos vocabulario de HTTP. Estos casos los fijan, sin perder los positivos del corpus
// cuando van dentro de un cuerpo serializado.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { screenAgentText } from "../src/filtro-agentes.ts";

type Case = { id: string; formato: string; text: string; mark: boolean };
const corpus = JSON.parse(readFileSync(new URL("./fixtures/filtro-agentes/corpus.json", import.meta.url), "utf8")) as Case[];

test("vocabulario de HTTP y cuerpos serializados no son órdenes", () => {
  const benign = [
    // Cabeceras de respuesta tal como las guarda un artefacto.
    '{\n "response": {\n  "headers": {\n   "vary": "User-Agent, Accept-Encoding",\n   "allow": "GET, POST"\n  }\n }\n}',
    "vary: User-Agent, accept-encoding",
    // Tabla de un sondeo: método, URL con «secrets» en la ruta, estado.
    "h642  POST    https://api.tienda.test/v3/share/secrets  401  131 B  application/json\nh648  POST    https://api.tienda.test/v3/configs/config/secrets  404  54 B  application/json",
    "h912 POST https://api.tienda.test/v3/configs/config/secrets · 256 ms · artefacto sha256:abc\nHTTP 200 · 2524 bytes",
    // Registro de actividad dentro del cuerpo serializado de un artefacto.
    `"body": ${JSON.stringify(JSON.stringify({ page: 1, logs: [{ id: "a1", text: "Was issued a personal auth token", user: { name: "Ana", email: "ana@x.test" } }, { id: "a2", text: "Updated the model settings and sent the report", html: "Show all workplace users" }] }))},`,
    JSON.stringify({ body: JSON.stringify({ logs: [{ text: "Was issued a personal auth token", user: "ana" }, { text: "Revealed secrets in config prd", by: "operator" }] }) }),
    // robots.txt corriente.
    "User-agent: *\nDisallow: /admin\nAllow: /\nSitemap: https://tienda.test/sitemap.xml",
  ];
  for (const text of benign) assert.equal(screenAgentText(text).removed, 0, text.slice(0, 80));
});

test("los positivos del corpus se siguen marcando dentro de un cuerpo serializado y junto a una tabla de sondeo", () => {
  const plain = corpus.filter((item) => item.mark && item.formato === "texto" && !item.text.includes("\n"));
  assert.ok(plain.length >= 20);
  let nested = 0, beside = 0;
  for (const item of plain) {
    // Como valor de un campo, dentro del cuerpo de una respuesta guardado en un artefacto.
    const artifact = JSON.stringify({ response: { status: 200, body: JSON.stringify({ status: "partial", note: item.text, total: 7 }) } });
    if (screenAgentText(artifact).removed) nested++;
    // En una línea aparte, después de líneas de sondeo corrientes.
    if (screenAgentText(`h1  GET  https://tienda.test/api/x  200  88 B  application/json\n${item.text}`).removed) beside++;
  }
  assert.ok(nested >= plain.length * 0.9, `serializado: ${nested} de ${plain.length}`);
  assert.ok(beside >= plain.length * 0.9, `junto a una tabla: ${beside} de ${plain.length}`);
});
