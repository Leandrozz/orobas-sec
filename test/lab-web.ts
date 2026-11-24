// Servidor de laboratorio mínimo para las pruebas de herramientas web: dos usuarios, un recurso por
// id sin control de dueño, login con mensajes distintos, búsqueda que refleja y falla con comilla, OpenAPI.
import { createServer, type Server } from "node:http";

export function labServer(): Server {
  const users: Record<string, { id: number; password: string; token: string }> = {
    "ana@x.test": { id: 1, password: "ana-ok", token: "t-ana" },
    "beto@x.test": { id: 2, password: "beto-ok", token: "t-beto" },
  };
  return createServer((req, res) => {
    const url = new URL(req.url!, "http://x");
    const token = (req.headers.authorization ?? "").replace("Bearer ", "");
    const me = Object.values(users).find((u) => u.token === token);
    const json = (status: number, body: unknown) => res.writeHead(status, { "content-type": "application/json", server: "lab/1.0" }).end(JSON.stringify(body));
    const html = (status: number, body: string) => res.writeHead(status, { "content-type": "text/html" }).end(body);
    let raw = "";
    req.on("data", (chunk) => (raw += chunk));
    req.on("end", () => {
      if (url.pathname === "/browser") return html(200, `<!doctype html><html><head><title>Laboratorio JS</title></head><body>
        <h1>Navegador de prueba</h1><p id="identity">Cargando</p><p id="result"></p>
        <a href="/perfil">Ver perfil</a><button id="remember">Recordar</button><button id="refresh">Actualizar</button>
        <form id="search" action="/browser/save" method="post"><label>Término <input name="term"></label><input name="password" type="password"><button>Guardar</button></form>
        <script src="/browser/app.js"></script></body></html>`);
      if (url.pathname === "/browser/app.js") return void res.writeHead(200, { "content-type": "application/javascript" }).end(`
        async function refresh() {
          const echo = new URL(location.href).searchParams.has('echo');
          const data = await (await fetch('/browser/who' + (echo ? '?echo=1' : ''))).json();
          document.querySelector('#identity').textContent = 'Usuario: ' + data.user + '; cookie: ' + data.cookie + '; recordada: ' + data.remembered;
          if (echo) document.querySelector('#result').textContent = 'Eco: ' + data.authorization + ' ' + data.rawCookie;
        }
        document.querySelector('#remember').onclick = () => { document.cookie = 'remembered=yes; path=/'; refresh(); };
        document.querySelector('#refresh').onclick = refresh;
        document.querySelector('#search').onsubmit = async (event) => {
          event.preventDefault();
          const term = document.querySelector('[name=term]').value;
          const data = await (await fetch('/browser/save', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({term})})).json();
          document.querySelector('#result').textContent = 'Guardado: ' + data.term;
        };
        refresh();
        const external = new URL(location.href).searchParams.get('external');
        if (external) {
          fetch(external + '/directo').catch(() => {});
          fetch('/browser/redirect?url=' + encodeURIComponent(external + '/redirigido')).catch(() => {});
          fetch('/outside').catch(() => {});
          const img = document.createElement('img'); img.src = external + '/imagen'; document.body.append(img);
        }
      `);
      if (url.pathname === "/browser/who") return json(200, {
        user: me?.id ?? 0,
        cookie: Boolean(me && req.headers.cookie?.includes(`session=browser-${me.id}`)),
        remembered: Boolean(req.headers.cookie?.includes("remembered=yes")),
        ...(url.searchParams.has("echo") ? { authorization: req.headers.authorization, rawCookie: req.headers.cookie } : {}),
      });
      if (url.pathname === "/browser/save") return json(200, JSON.parse(raw || "{}"));
      if (url.pathname === "/browser/redirect") return void res.writeHead(302, { location: url.searchParams.get("url") ?? "/browser" }).end();
      if (url.pathname === "/") return html(200, '<a href="/perfil">perfil</a><form method="post" action="/api/login"><input name="email"><input name="password"></form><script src="/app.js"></script>');
      if (url.pathname === "/app.js") return void res.writeHead(200, { "content-type": "application/javascript" }).end('fetch("/api/items/" + id)');
      if (url.pathname === "/perfil") return html(200, "<p>perfil</p>");
      if (url.pathname === "/openapi.json") {
        return json(200, {
          openapi: "3.0.0",
          paths: {
            "/api/items/{id}": { get: { parameters: [{ name: "id", in: "path" }], security: [{}] } },
            "/api/login": { post: { requestBody: { content: { "application/json": { schema: { properties: { email: {}, password: {} } } } } } } },
          },
        });
      }
      if (url.pathname === "/api/login" && req.method === "POST") {
        const body = JSON.parse(raw || "{}");
        const user = users[body.email];
        if (!user) return json(401, { error: "usuario inexistente" });
        if (user.password !== body.password) return json(401, { error: "contraseña incorrecta" });
        return json(200, { token: user.token });
      }
      if (url.pathname === "/api/carrito" && req.method === "POST") {
        if (!me) return json(401, { error: "sin token" });
        const body = JSON.parse(raw || "{}");
        if (!body.productId) return json(400, { error: "falta productId" });
        const qty = Math.max(1, Number(body.qty ?? 1));
        return json(201, { ok: true, line: { productId: body.productId, qty, price: body.price ?? 1000 } });
      }
      const item = /^\/api\/items\/(\d+)$/.exec(url.pathname);
      if (item) {
        if (!me) return json(401, { error: "sin token" });
        return json(200, { id: Number(item[1]), owner: Number(item[1]), secret: `s${item[1]}` });
      }
      if (url.pathname === "/buscar") {
        const q = url.searchParams.get("q") ?? "";
        if (q.includes("'")) return json(500, { error: "SQLITE_ERROR: unrecognized token" });
        return html(200, `<h1>${q}</h1>`);
      }
      json(404, { error: "no" });
    });
  });
}
