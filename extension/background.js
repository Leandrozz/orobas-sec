// Puente entre este navegador y el agente orobas-sec de esta misma máquina.
// La extensión pregunta al agente (sólo en 127.0.0.1, con el código de emparejamiento) si tiene
// algo para hacer, lo hace y devuelve el resultado. No habla con ningún otro servidor.
// Un solo código sirve para varios cyber a la vez: se sondea todo el rango de puertos, un bucle por puerto.
// Cada orden trae las reglas del alcance: fuera de ellas no lista, no lee ni toca ninguna pestaña.
const FIRST_PORT = 47615;
const PORTS = 20;
const PARALLEL = 3; // órdenes a la vez por puerto
const MAX_WAIT = 15000; // espera máxima entre intentos si nadie escucha
const MAX_TRAFFIC = 300;
const traffic = new Map(); // tabId → peticiones observadas
const watched = new Set(); // pestañas que algún agente está usando
// Ownership por puerto y en memoria: se pierde si el service worker se suspende y un cyber nuevo en el mismo puerto la hereda.
const owner = new Map(); // tabId → puerto del cyber que la abrió o vigila
const running = new Set(); // puertos con bucle activo
let busy = 0; // órdenes en curso, sumando todos los puertos
let lastUse = 0; // última orden recibida de algún agente
const KEEPALIVE_MS = 20000; // < 30 s: el tiempo de inactividad tras el que Chrome duerme el service worker
const WATCH_AWAKE_MS = 10 * 60 * 1000; // con pestañas vigiladas, se sigue despierto hasta 10 min después de la última orden

const settings = () => chrome.storage.local.get({ token: "", paused: false });

// MV3 duerme el service worker tras 30 s sin eventos ni llamadas a la API, y con él se pierde lo que está en
// memoria (tráfico observado, dueños de pestañas) y se corta lo que estaba haciendo. Mientras haya órdenes en
// curso o pestañas vigiladas usadas hace poco, una llamada barata a la API cada 20 s lo mantiene despierto.
// Sin trabajo, se duerme como siempre y la alarma (cada 30 s) lo despierta.
let keepalive;
function stayAwake() {
  if (keepalive) return;
  keepalive = setInterval(() => {
    if (busy > 0 || (watched.size > 0 && Date.now() - lastUse < WATCH_AWAKE_MS)) chrome.runtime.getPlatformInfo().catch(() => {});
    else { clearInterval(keepalive); keepalive = undefined; }
  }, KEEPALIVE_MS);
}

// Esperas entre intentos que se pueden cortar: la alarma o el popup despiertan todos los bucles a la vez,
// así un agente recién abierto se encuentra en el acto y no al final de la espera creciente.
const naps = new Set();
function nap(ms) {
  return new Promise((resolve) => {
    const done = () => { clearTimeout(timer); naps.delete(done); resolve(); };
    const timer = setTimeout(done, ms);
    naps.add(done);
  });
}
const wakeAll = () => { for (const done of [...naps]) done(); };

/** ¿El alcance permite esta URL? Las exclusiones ganan. El agente lo vuelve a comprobar de su lado. */
function allowed(url, rules) {
  let parsed;
  try { parsed = new URL(url); } catch { return false; }
  if (!/^https?:$/.test(parsed.protocol)) return false;
  const host = parsed.hostname.toLowerCase();
  const match = (rule) => {
    if (rule.kind === "host") return host === rule.value;
    if (rule.kind === "wildcard") return host.endsWith(rule.value.slice(1)) && host !== rule.value.slice(2);
    if (rule.kind === "url") {
      try { const base = new URL(rule.value); return parsed.origin === base.origin && (parsed.pathname + "/").startsWith(base.pathname.replace(/\/?$/, "/")); } catch { return false; }
    }
    return false;
  };
  if ((rules.exclude || []).some(match)) return false;
  return (rules.include || []).some(match);
}

async function tabInScope(tabId, rules) {
  const tab = await chrome.tabs.get(tabId);
  if (!allowed(tab.url || "", rules)) throw new Error(`La pestaña ${tabId} está fuera del alcance: no se toca.`);
  return tab;
}

function waitLoaded(tabId, ms = 15000) {
  return new Promise((resolve) => {
    const done = () => { chrome.tabs.onUpdated.removeListener(listener); clearTimeout(timer); resolve(); };
    const listener = (id, info) => { if (id === tabId && info.status === "complete") done(); };
    const timer = setTimeout(done, ms);
    chrome.tabs.onUpdated.addListener(listener);
    chrome.tabs.get(tabId).then((tab) => { if (tab.status === "complete") done(); }).catch(done);
  });
}

// Corre dentro de la página. Devuelve lo que ve una persona: texto, formularios, enlaces. Nunca valores de contraseñas.
function pageView() {
  const text = (document.body?.innerText || "").replace(/\n{3,}/g, "\n\n").slice(0, 6000);
  const forms = [...document.forms].slice(0, 20).map((form) => ({
    action: form.action, method: (form.method || "get").toUpperCase(),
    fields: [...form.elements].filter((el) => el.name || el.id).slice(0, 30).map((el) => ({ name: el.name || el.id, type: el.type || el.tagName.toLowerCase(), value: /password|hidden/i.test(el.type || "") ? undefined : String(el.value || "").slice(0, 80) })),
  }));
  const links = [...new Set([...document.querySelectorAll("a[href]")].map((a) => a.href))].slice(0, 80);
  const buttons = [...document.querySelectorAll("button, [role=button], input[type=submit]")].map((el) => (el.innerText || el.value || el.getAttribute("aria-label") || "").trim().slice(0, 60)).filter(Boolean).slice(0, 60);
  return { url: location.href, title: document.title, text, forms, links, buttons };
}

// Corre dentro de la página. Ejecuta acciones como las haría una persona.
async function pageAct(actions) {
  const log = [];
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const RISKY = /\b(delete|remove|eliminar|borrar|quitar cuenta|cerrar cuenta|close account|pay|pagar|comprar|buy now|purchase|place order|confirmar compra|transfer|transferir)\b/i;
  const find = (action) => {
    if (action.selector) return document.querySelector(action.selector);
    if (action.text) {
      const wanted = action.text.trim().toLowerCase();
      const candidates = [...document.querySelectorAll("button, a, [role=button], input[type=submit], input[type=button], label, [onclick]")];
      return candidates.find((el) => (el.innerText || el.value || "").trim().toLowerCase() === wanted) || candidates.find((el) => (el.innerText || el.value || "").trim().toLowerCase().includes(wanted));
    }
    return null;
  };
  for (const action of actions) {
    try {
      if (action.type === "wait") { await sleep(Math.min(action.ms || 500, 10000)); log.push("wait: ok"); continue; }
      let el = null;
      for (let i = 0; i < 20 && !(el = find(action)); i++) await sleep(250);
      if (!el) { log.push(`${action.type}: no encontré ${action.selector || action.text}`); break; }
      const label = (el.innerText || el.value || el.getAttribute("aria-label") || "").trim().slice(0, 80);
      if (action.type === "click") {
        if (RISKY.test(label) && !action.confirmed) { log.push(`click: «${label}» parece borrar, pagar o transferir. No lo hago: que lo decida el operador.`); break; }
        el.scrollIntoView({ block: "center" }); el.click(); log.push(`click: «${label || action.selector}»`);
        await sleep(400);
      } else if (action.type === "fill") {
        if (/password/i.test(el.type || "")) { log.push("fill: es un campo de contraseña. No lo completo: la escribe el operador."); break; }
        el.focus();
        const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), "value")?.set;
        if (setter) setter.call(el, action.value ?? ""); else el.value = action.value ?? "";
        el.dispatchEvent(new Event("input", { bubbles: true })); el.dispatchEvent(new Event("change", { bubbles: true }));
        log.push(`fill: ${action.selector || action.text}`);
      } else if (action.type === "submit") {
        const form = el.closest("form") || el;
        if (form.requestSubmit) form.requestSubmit(); else form.submit();
        log.push("submit: ok"); await sleep(600);
      } else log.push(`${action.type}: acción desconocida`);
    } catch (error) { log.push(`${action.type}: ${String(error.message || error).slice(0, 120)}`); break; }
  }
  return log;
}

/** Una pestaña es del cyber que la abrió o la vigila primero; otro cyber no la toca. */
function claim(tabId, port) {
  const current = owner.get(tabId);
  if (current !== undefined && current !== port) throw new Error(`La pestaña ${tabId} la usa otro agente de orobas-sec: no se toca.`);
  owner.set(tabId, port);
}

function watch(tabId, port) {
  claim(tabId, port);
  watched.add(tabId);
  stayAwake();
  if (!traffic.has(tabId)) traffic.set(tabId, []);
  chrome.action.setBadgeText({ tabId, text: "ON" }).catch(() => {});
  chrome.action.setBadgeBackgroundColor({ tabId, color: "#c2410c" }).catch(() => {});
}

const handlers = {
  async tabs(_args, rules, port) {
    const tabs = await chrome.tabs.query({});
    return tabs.filter((tab) => allowed(tab.url || "", rules) && (owner.get(tab.id) ?? port) === port).map((tab) => ({ id: tab.id, url: tab.url, title: tab.title, active: tab.active }));
  },
  async open(args, rules, port) {
    if (!allowed(args.url, rules)) throw new Error("Esa URL está fuera del alcance.");
    const tab = await chrome.tabs.create({ url: args.url, active: false });
    watch(tab.id, port);
    await waitLoaded(tab.id);
    return handlers.read({ tab: tab.id }, rules, port);
  },
  async navigate(args, rules, port) {
    await tabInScope(args.tab, rules);
    if (!allowed(args.url, rules)) throw new Error("Esa URL está fuera del alcance.");
    claim(args.tab, port);
    watch(args.tab, port);
    await chrome.tabs.update(args.tab, { url: args.url });
    await waitLoaded(args.tab);
    return handlers.read({ tab: args.tab }, rules, port);
  },
  async read(args, rules, port) {
    await tabInScope(args.tab, rules);
    watch(args.tab, port);
    const [result] = await chrome.scripting.executeScript({ target: { tabId: args.tab }, func: pageView });
    return { tab: args.tab, ...result.result };
  },
  async act(args, rules, port) {
    await tabInScope(args.tab, rules);
    watch(args.tab, port);
    const [result] = await chrome.scripting.executeScript({ target: { tabId: args.tab }, func: pageAct, args: [args.actions] });
    await waitLoaded(args.tab, 4000);
    // Si una acción llevó la pestaña fuera del alcance, no se lee nada de ahí.
    const tab = await chrome.tabs.get(args.tab);
    if (!allowed(tab.url || "", rules)) return { tab: args.tab, log: result.result, left: tab.url ? new URL(tab.url).host : "otro sitio" };
    return { log: result.result, ...(await handlers.read({ tab: args.tab }, rules, port)) };
  },
  async cookies(args, rules, port) {
    const tab = await tabInScope(args.tab, rules);
    claim(args.tab, port);
    const cookies = await chrome.cookies.getAll({ url: tab.url });
    return { origin: new URL(tab.url).origin, cookie: cookies.map((c) => `${c.name}=${c.value}`).join("; "), count: cookies.length };
  },
  async traffic(args, rules, port) {
    await tabInScope(args.tab, rules);
    watch(args.tab, port);
    const list = (traffic.get(args.tab) || []).filter((entry) => allowed(entry.url, rules));
    if (args.clear) traffic.set(args.tab, []);
    return list;
  },
  async capture(args, rules, port) {
    const tab = await tabInScope(args.tab, rules);
    claim(args.tab, port);
    await chrome.tabs.update(args.tab, { active: true });
    await new Promise((r) => setTimeout(r, 300));
    return { png: await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" }) };
  },
  async release(args, _rules, port) {
    // Sin pestaña suelta sólo las de este cyber; con pestaña, sólo si es suya.
    for (const tabId of (args.tab ? [args.tab] : [...watched]).filter((id) => owner.get(id) === port)) {
      watched.delete(tabId); traffic.delete(tabId); owner.delete(tabId);
      chrome.action.setBadgeText({ tabId, text: "" }).catch(() => {});
    }
    return { ok: true };
  },
};

// Tráfico de las pestañas en uso: método, URL, estado y nombres de los campos del cuerpo (no los valores).
chrome.webRequest.onBeforeRequest.addListener((details) => {
  if (!watched.has(details.tabId) || !["xmlhttprequest", "main_frame", "sub_frame", "other"].includes(details.type)) return;
  const list = traffic.get(details.tabId) || [];
  let bodyKeys = [];
  const body = details.requestBody;
  if (body?.formData) bodyKeys = Object.keys(body.formData);
  else if (body?.raw?.[0]?.bytes) {
    try { const parsed = JSON.parse(new TextDecoder().decode(body.raw[0].bytes)); if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) bodyKeys = Object.keys(parsed); } catch {}
  }
  list.push({ id: details.requestId, method: details.method, url: details.url, type: details.type, bodyKeys });
  if (list.length > MAX_TRAFFIC) list.shift();
  traffic.set(details.tabId, list);
}, { urls: ["<all_urls>"] }, ["requestBody"]);
chrome.webRequest.onCompleted.addListener((details) => {
  const entry = (traffic.get(details.tabId) || []).find((item) => item.id === details.requestId);
  if (entry) entry.status = details.statusCode;
}, { urls: ["<all_urls>"] });
chrome.tabs.onRemoved.addListener((tabId) => { watched.delete(tabId); traffic.delete(tabId); owner.delete(tabId); });

const hex = (bytes) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function hmac(token, text) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(token), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text)));
}
const sha256 = async (bytes) => hex(await crypto.subtle.digest("SHA-256", bytes));
// El código nunca viaja: se pide un desafío y se firma con HMAC método, ruta, puerto, desafío y cuerpo; el puente firma de vuelta
// puerto, estado, nuestro desafío y la respuesta exacta. Nada se interpreta ni se ejecuta sin esa prueba (un relevo o un impostor no la tiene).
// Devuelve { status, text } sólo si el puente probó conocer el código; "wrong" si lo conoce otro código; undefined si no es un cyber (o es uno viejo).
async function signed(base, port, path, init, token) {
  const challenge = await fetch(`${base}/nonce`, { headers: { "x-orobas": "1" }, signal: AbortSignal.timeout(5000) });
  const offered = challenge.status === 200 ? await challenge.json().catch(() => ({})) : {};
  if (!/^[a-f0-9]{32}$/.test(offered.nonce || "")) return undefined;
  if (offered.proto !== 1) { await chrome.storage.local.set({ old: Date.now() }); return undefined; } // cyber viejo: «actualizá cyber» en el popup
  const method = init.method || "GET";
  const ours = hex(crypto.getRandomValues(new Uint8Array(16)));
  const sent = new TextEncoder().encode(init.body || "");
  const mac = await hmac(token, ["ext", port, method, path, offered.nonce, await sha256(sent)].join("\n"));
  const headers = { ...init.headers, "x-orobas": "1", "x-orobas-nonce": offered.nonce, "x-orobas-mac": mac, "x-orobas-ext": ours };
  const response = await fetch(`${base}${path}`, { ...init, headers, signal: init.signal || AbortSignal.timeout(25000) });
  if (response.status === 401) return "wrong";
  if (response.status !== 200 && response.status !== 204) return undefined;
  const bytes = new Uint8Array(await response.arrayBuffer());
  const proof = await hmac(token, ["srv", port, response.status, ours, await sha256(bytes)].join("\n"));
  return response.headers.get("x-orobas-proof") === proof ? { status: response.status, text: new TextDecoder().decode(bytes) } : undefined;
}

async function loop(port) {
  if (running.has(port)) return;
  running.add(port);
  const inflight = new Set();
  let failures = 0;
  try {
    for (;;) {
      const { token, paused } = await settings();
      if (!token || paused) break;
      if (inflight.size >= PARALLEL) { await Promise.race(inflight); continue; }
      const base = `http://127.0.0.1:${port}`;
      let command;
      try {
        const response = await signed(base, port, "/poll", {}, token);
        if (response === "wrong") { await chrome.storage.local.set({ wrong: Date.now() }); break; }
        if (!response) throw new Error("no es un cyber");
        failures = 0;
        await chrome.storage.local.set({ [`seen:${port}`]: Date.now(), ultimo: Date.now() });
        if (response.status !== 200) continue;
        command = JSON.parse(response.text);
      } catch {
        // Nadie escucha, o no es un cyber de verdad: espera creciente hasta MAX_WAIT (la alarma la corta).
        await chrome.storage.local.remove(`seen:${port}`);
        await nap(Math.min(1000 * 2 ** failures++, MAX_WAIT));
        continue;
      }
      busy++;
      lastUse = Date.now();
      stayAwake();
      const task = (async () => {
        let result;
        try {
          const handler = handlers[command.cmd];
          if (!handler) throw new Error(`Orden desconocida: ${command.cmd}`);
          result = { id: command.id, ok: true, data: await handler(command.args || {}, command.rules || {}, port) };
        } catch (error) { result = { id: command.id, ok: false, error: String(error.message || error).slice(0, 300) }; }
        await signed(base, port, "/result", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(result) }, token).catch(() => {});
      })().finally(() => { inflight.delete(task); busy--; lastUse = Date.now(); });
      inflight.add(task);
    }
  } finally { running.delete(port); }
}

const loopAll = () => { for (let i = 0; i < PORTS; i++) loop(FIRST_PORT + i); };

// El service worker se duerme: la alarma (30 s es el mínimo de MV3) lo despierta, corta las esperas y retoma el bucle.
chrome.alarms.create("orobas", { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener(() => { wakeAll(); loopAll(); });
chrome.runtime.onStartup.addListener(() => loopAll());
chrome.runtime.onInstalled.addListener(() => loopAll());
// Abrir el popup escribe «despertar»: el cambio despierta al service worker y busca agentes en el acto.
chrome.storage.onChanged.addListener((changes) => { if (changes.token || changes.paused || changes.despertar) { wakeAll(); loopAll(); } });
loopAll();
