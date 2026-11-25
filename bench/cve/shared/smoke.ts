import { createLabHttp } from "./http.ts";

const [base, evidence] = process.argv.slice(2);
if (!base || !evidence) throw new Error("Uso: smoke.ts URL directorio-de-evidencia");
const lab = await createLabHttp(base, evidence);
try {
  const exchange = await lab.http.send({ url: new URL("/", base).toString(), timeoutMs: 10000 });
  const status = exchange.response?.status;
  if (status === undefined || status >= 500) throw new Error(`La portada no responde: ${exchange.error ?? status}`);
  console.log(JSON.stringify({ url: base, status, httpRequests: lab.http.count, artifact: exchange.artifact }));
} finally {
  lab.close();
}
