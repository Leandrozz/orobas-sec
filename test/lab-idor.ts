// Laboratorios locales para acceso cruzado y asignación masiva. Dos usuarios con token Bearer:
// ana (t-ana, id 1) y beto (t-beto, id 2).
//
// labIdor: pedidos con UUID cuyo detalle no comprueba dueño (vulnerable), notas con ObjectId que sí
// (404 al ajeno), enlaces compartidos públicos (cualquiera los lee, también sin credenciales), facturas
// que responden 200 con un error al ajeno (2xx con otro contenido, no es hallazgo) y un panel HTML.
//
// labAsignacion: /v (vulnerable: mezcla todo el cuerpo en el usuario), /i (ignora lo que no es «name»),
// /r (refleja el cuerpo en la respuesta pero sólo guarda «name»), /h (valida el primer «role» y aplica
// el último: HPP), y altas de proyectos en /v que aceptan plan y owner_id.
import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server } from "node:http";

const TOKENS: Record<string, number> = { "t-ana": 1, "t-beto": 2 };
const who = (req: IncomingMessage) => TOKENS[(req.headers.authorization ?? "").replace(/^Bearer\s+/i, "")];

/** ObjectId con sello de tiempo plausible. */
const objectId = (n: number) => `65f1a2b3c4d5e6f7a8b9${String(n).padStart(4, "0")}`;

export interface LabIdor {
  server: Server;
  orders: Record<number, string>;
  notes: Record<number, string>;
  shares: Record<number, string>;
  invoices: Record<number, string>;
}

export function labIdor(): LabIdor {
  const orders = { 1: randomUUID(), 2: randomUUID() } as Record<number, string>;
  const notes = { 1: objectId(1), 2: objectId(2) } as Record<number, string>;
  const shares = { 1: randomUUID() } as Record<number, string>;
  const invoices = { 1: randomUUID(), 2: randomUUID() } as Record<number, string>;
  const owner = (table: Record<number, string>, id: string) => Number(Object.entries(table).find(([, value]) => value === id)?.[0]) || undefined;
  const server = createServer((req, res) => {
    const url = new URL(req.url!, "http://x");
    const me = who(req);
    const json = (status: number, body: unknown, headers: Record<string, string> = {}) => res.writeHead(status, { "content-type": "application/json", ...headers }).end(JSON.stringify(body));
    const segments = url.pathname.split("/").filter(Boolean);
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      // Enlace compartido: público a propósito, con o sin credenciales.
      if (segments[1] === "shares" && segments[2]) {
        const id = owner(shares, segments[2]);
        return id ? json(200, { id: segments[2], title: `carpeta compartida de ${id}`, files: ["a.txt", "b.txt"] }) : json(404, { error: "no existe" });
      }
      if (!me) return json(401, { error: "sin token" });
      if (url.pathname === "/api/me") return json(200, { id: me, email: me === 1 ? "ana@x.test" : "beto@x.test", request_id: randomUUID(), session: { token: randomUUID() } });
      if (url.pathname === "/api/orders" && req.method === "GET") {
        return json(200, { data: [{ id: orders[me], owner_id: me, total: 100 * me, item: `pedido de ${me}`, links: { self: `/api/orders/${orders[me]}` } }], request_id: randomUUID() });
      }
      if (url.pathname === "/api/orders" && req.method === "POST") {
        const id = randomUUID();
        orders[100 + Object.keys(orders).length] = id;
        return json(201, { id }, { location: `/api/orders/${id}` });
      }
      if (segments[1] === "orders" && segments[2]) {
        // Vulnerable: el detalle no comprueba el dueño.
        const id = owner(orders, segments[2]);
        if (!id) return json(404, { error: "no existe" });
        return json(200, { id: segments[2], owner_id: id, total: 100 * id, item: `pedido de ${id}`, address: `calle ${id} 123` });
      }
      if (url.pathname === "/api/notes") return json(200, [{ _id: notes[me], text: `nota privada de ${me}` }]);
      if (segments[1] === "notes" && segments[2]) {
        const id = owner(notes, segments[2]);
        return id === me ? json(200, { _id: segments[2], text: `nota privada de ${id}` }) : json(404, { error: "no existe" });
      }
      if (url.pathname === "/api/shares") return json(200, { shares: shares[me] ? [{ id: shares[me] }] : [] });
      if (url.pathname === "/api/invoices") return json(200, { invoices: [{ id: invoices[me], amount: 10 * me, customer: `cliente ${me}` }] });
      if (segments[1] === "invoices" && segments[2]) {
        // 200 con un error para el ajeno: un 2xx que no es el objeto.
        const id = owner(invoices, segments[2]);
        return id === me ? json(200, { id: segments[2], amount: 10 * id, customer: `cliente ${id}` }) : json(200, { ok: false, error: "factura inexistente" });
      }
      if (url.pathname === "/panel") {
        return void res.writeHead(200, { "content-type": "text/html" }).end(`<!doctype html><html><body><h1>Panel de ${me}</h1><a href="/api/orders/${orders[me]}">mi pedido</a><div data-order-id="${orders[me]}" data-testid="777"></div><input type="hidden" name="csrf_token" value="${randomUUID()}"></body></html>`);
      }
      json(404, { error: "no existe" });
    });
  });
  return { server, orders, notes, shares, invoices };
}

type User = { id: number; email: string; name: string; role: string; plan: string; is_admin: boolean | string; [key: string]: unknown };

export interface LabAsignacion {
  server: Server;
  users: Record<string, Record<number, User>>;
  projects: Map<number, Record<string, unknown>>;
  reset(): void;
}

export function labAsignacion(): LabAsignacion {
  const fresh = (): Record<number, User> => ({
    1: { id: 1, email: "ana@x.test", name: "Ana", role: "user", plan: "free", is_admin: false },
    2: { id: 2, email: "beto@x.test", name: "Beto", role: "user", plan: "free", is_admin: false },
  });
  const lab: LabAsignacion = { server: undefined as unknown as Server, users: { v: fresh(), i: fresh(), r: fresh(), h: fresh() }, projects: new Map(), reset: () => { lab.users = { v: fresh(), i: fresh(), r: fresh(), h: fresh() }; lab.projects.clear(); } };
  let seq = 100;
  lab.server = createServer((req, res) => {
    const url = new URL(req.url!, "http://x");
    const me = who(req);
    const json = (status: number, body: unknown, headers: Record<string, string> = {}) => res.writeHead(status, { "content-type": "application/json", ...headers }).end(JSON.stringify(body));
    const [kind, , resource, id] = url.pathname.split("/").filter(Boolean);
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      if (!me) return json(401, { error: "sin token" });
      const users = lab.users[kind ?? ""];
      if (!users) return json(404, { error: "no existe" });
      const form = /x-www-form-urlencoded/.test(req.headers["content-type"] ?? "");
      let body: Record<string, unknown> = {};
      try { body = form ? Object.fromEntries(new URLSearchParams(raw)) : JSON.parse(raw || "{}"); } catch { return json(400, { error: "cuerpo inválido" }); }
      const user = users[me]!;
      if (resource === "me" && req.method === "GET") return json(200, { data: user });
      if (resource === "users" && id && req.method === "GET") return users[Number(id)] ? json(200, users[Number(id)]) : json(404, {});
      if (resource === "me" && (req.method === "PATCH" || req.method === "PUT")) {
        if (kind === "v") {
          const { id: _ignored, ...rest } = body;
          Object.assign(user, rest);
          return json(200, { data: user });
        }
        if (kind === "i") {
          if (typeof body.name === "string") user.name = body.name;
          return json(200, { data: user });
        }
        if (kind === "r") {
          if (typeof body.name === "string") user.name = body.name;
          return json(200, { data: { ...user, ...body } });
        }
        // h: el validador mira el primer «role» del texto crudo; el modelo usa el último.
        const roles = form ? new URLSearchParams(raw).getAll("role") : [...raw.matchAll(/"role"\s*:\s*"([^"]*)"/g)].map((match) => match[1]!);
        if (roles.length && roles[0] !== "user") return json(403, { error: "rol no permitido" });
        if (typeof body.name === "string") user.name = body.name;
        if (roles.length) user.role = String(body.role);
        return json(200, { data: user });
      }
      if (kind === "v" && resource === "projects" && !id && req.method === "POST") {
        const project = { id: ++seq, name: String(body.name ?? "sin nombre"), plan: String(body.plan ?? "free"), owner_id: body.owner_id === undefined ? me : Number(body.owner_id) };
        lab.projects.set(project.id, project);
        return json(201, project, { location: `/v/api/projects/${project.id}` });
      }
      // Una escritura que no es alta ni tiene lectura: no hay cómo confirmar nada.
      if (kind === "v" && resource === "feedback" && req.method === "POST") return json(200, { ok: true, ...body });
      if (kind === "v" && resource === "projects" && id && req.method === "GET") {
        const project = lab.projects.get(Number(id));
        return project ? json(200, project) : json(404, { error: "no existe" });
      }
      json(404, { error: "no existe" });
    });
  });
  return lab;
}
