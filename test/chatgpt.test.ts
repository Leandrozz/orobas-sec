import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { acceptNotice, beginChatgptLogin, chatgptAccessToken, chatgptModels, chatgptState, logoutChatgpt, MANAGE_USAGE, markChatgptLimit, noticePending, waitChatgptLogin } from "../src/chatgpt.ts";
import { chatgptResponses, toResponsesInput } from "../src/chatgpt-responses.ts";
import { Ledger } from "../src/ledger.ts";
import { chatgptReasoningCaps, resolveProvider } from "../src/providers.ts";
import { readSecret, writeSecret } from "../src/secretos.ts";
import { openStore, projectPaths } from "../src/store.ts";

const keyPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...keyPair.publicKey.export({ format: "jwk" }), kid: "prueba-1", alg: "RS256", use: "sig" };
const scope = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
const jwt = (claims: object, wrong = false) => {
  const head = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "prueba-1" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signed = sign("RSA-SHA256", Buffer.from(head + "." + body), keyPair.privateKey).toString("base64url");
  return head + "." + body + "." + (wrong ? (signed.startsWith("a") ? "b" : "a") + signed.slice(1) : signed);
};
const send = (response: any, status: number, body: object, headers: Record<string, string> = {}) => {
  response.writeHead(status, { "content-type": "application/json", "x-request-id": "req_local", ...headers });
  response.end(JSON.stringify(body));
};
const stream = (response: any, events: object[]) => {
  response.writeHead(200, { "content-type": "text/event-stream", "x-request-id": "req_local" });
  for (const event of events) response.write("data: " + JSON.stringify(event) + "\n\n");
  response.end();
};
/** Pedido HTTP crudo: fetch no deja mandar una URL malformada. */
const raw = (port: number, target: string) => new Promise<string>((resolve, reject) => {
  let data = "";
  const socket = connect(port, "127.0.0.1", () => socket.write("GET " + target + " HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"));
  socket.on("data", (chunk) => { data += String(chunk); });
  socket.on("close", () => resolve(data));
  socket.on("error", reject);
});
const request = () => ({
  model: resolveProvider("chatgpt/gpt-prueba").model,
  system: "Sos un asistente.",
  messages: [{ role: "user" as const, content: "hola", at: Date.now() }],
  tools: [{ name: "leer", description: "Lee un archivo", parameters: { type: "object", properties: { ruta: { type: "string" } } } }],
});

test("Sign in with ChatGPT funciona sólo contra OAuth y Responses simulados", async (t) => {
  const before = {
    CYBER_CREDENTIALS_DIR: process.env.CYBER_CREDENTIALS_DIR,
    CYBER_SECRETS_KEY: process.env.CYBER_SECRETS_KEY,
    CHATGPT_AUTH_URL: process.env.CHATGPT_AUTH_URL,
    CHATGPT_BASE_URL: process.env.CHATGPT_BASE_URL,
    CYBER_PROYECTO_HOST: process.env.CYBER_PROYECTO_HOST,
    CYBER_PUERTO_HOST: process.env.CYBER_PUERTO_HOST,
  };
  process.env.CYBER_CREDENTIALS_DIR = mkdtempSync(join(tmpdir(), "cyber-chatgpt-"));
  process.env.CYBER_SECRETS_KEY = randomBytes(32).toString("base64");
  let base = "";
  let nonce = "";
  let challenge = "";
  let badSignature = false;
  let invalidRefresh = false;
  let grantScope = scope;
  let mode = "ok";
  let codexCatalog = false;
  let retryAfter: string | undefined;
  let duringRefresh: (() => void) | undefined;
  let refreshes = 0;
  let revoked = 0;
  let exchanges = 0;
  let lastBody: any;
  let lastAuthorization = "";
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", base);
    if (url.pathname === "/.well-known/openid-configuration") return send(res, 200, {
      issuer: base,
      authorization_endpoint: base + "/api/accounts/authorize",
      token_endpoint: base + "/api/accounts/oauth/token",
      revocation_endpoint: base + "/api/accounts/oauth/revoke",
      jwks_uri: base + "/.well-known/jwks.json",
    });
    if (url.pathname === "/.well-known/jwks.json") return send(res, 200, { keys: [jwk] });
    if (url.pathname === "/api/accounts/oauth/revoke") { revoked++; return res.writeHead(200).end(); }
    if (url.pathname === "/api/accounts/oauth/token") {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(Buffer.from(chunk));
      const form = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
      if (form.get("grant_type") === "refresh_token") {
        refreshes++;
        if (invalidRefresh) return send(res, 400, { error: "invalid_grant" });
        assert.equal(form.get("client_id"), "oaiapp_prueba");
        assert.equal(form.get("resource"), "https://api.openai.com/v1");
        const hook = duringRefresh;
        duringRefresh = undefined;
        hook?.();
        return send(res, 200, { access_token: "acceso_" + refreshes, refresh_token: "renovado_" + refreshes, token_type: "Bearer", expires_in: 3600, scope: grantScope });
      }
      exchanges++;
      assert.equal(form.get("client_id"), "oaiapp_prueba");
      assert.equal(form.get("resource"), "https://api.openai.com/v1");
      assert.equal(createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url"), challenge);
      assert.equal(form.get("redirect_uri"), lastAuthorization);
      const token = jwt({ iss: base, aud: "oaiapp_prueba", sub: "sujeto-1", email: "prueba@example.test", nonce, exp: Math.floor(Date.now() / 1000) + 3600 }, badSignature);
      return send(res, 200, { access_token: "acceso_inicial", refresh_token: "renovable_inicial", id_token: token, token_type: "Bearer", expires_in: 3600, scope: grantScope });
    }
    // Formato público de /v1/models; el del backend de Codex queda como respaldo.
    if (url.pathname === "/v1/models") return send(res, 200, codexCatalog
      ? { models: [{ slug: "gpt-prueba", display_name: "GPT de prueba", visibility: "list" }, { slug: "interno", visibility: "hidden" }] }
      : { object: "list", data: [{ id: "gpt-prueba", object: "model", created: 1700000000, owned_by: "openai" }] });
    if (url.pathname === "/v1/responses") {
      assert.equal(req.method, "POST");
      assert.match(String(req.headers.authorization), /^Bearer acceso_/);
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(Buffer.from(chunk));
      lastBody = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      if (mode === "sin-resumen" && lastBody.reasoning?.summary) return send(res, 400, { error: { message: "Unknown parameter: 'reasoning.summary'.", type: "invalid_request_error" } });
      if (mode === "429") return send(res, 429, { error: { code: "subscription_sharing_usage_limit_exceeded", message: "no" } }, retryAfter ? { "retry-after": retryAfter } : {});
      if (mode === "403") return send(res, 403, { error: { code: "subscription_sharing_user_not_eligible" } });
      if (mode === "401") return send(res, 401, { error: { code: "subscription_sharing_invalid_user" } });
      if (mode === "failed") return stream(res, [{ type: "response.output_text.delta", delta: "parcial" }, { type: "response.failed", response: { error: { code: "subscription_sharing_usage_limit_exceeded" } } }]);
      if (mode === "cut") return stream(res, [{ type: "response.output_text.delta", delta: "parcial" }]);
      if (mode === "hang") {
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.write("data: " + JSON.stringify({ type: "response.created", response: { id: "resp_local" } }) + "\n\n");
        req.on("close", () => res.end());
        return;
      }
      return stream(res, [
        { type: "response.created", response: { id: "resp_local" } },
        { type: "response.output_text.delta", delta: "bien" },
        { type: "response.output_item.done", output_index: 1, item: { id: "fc_1", type: "function_call", call_id: "call_1", name: "orobas.leer", arguments: "{\"ruta\":\"a\"}" } },
        { type: "response.completed", response: { id: "resp_local", usage: { input_tokens: 20, input_tokens_details: { cached_tokens: 3 }, output_tokens: 8, output_tokens_details: { reasoning_tokens: 2 } } } },
      ]);
    }
    send(res, 404, {});
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  base = "http://127.0.0.1:" + address.port;
  process.env.CHATGPT_AUTH_URL = base;
  process.env.CHATGPT_BASE_URL = base + "/v1";
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    for (const [key, value] of Object.entries(before)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
  const begin = async (returning = false) => {
    const lines = await beginChatgptLogin({ openBrowser: () => {} });
    const url = new URL(lines[0]!.replace("Continue with ChatGPT: ", ""));
    assert.equal(url.searchParams.get("client_id"), returning ? "oaiapp_prueba" : "dynamic_agent_client");
    assert.equal(url.searchParams.get("ext_agent_host_id")?.startsWith("urn:uuid:"), true);
    assert.equal(url.searchParams.get("scope"), scope);
    assert.equal(url.searchParams.get("resource"), "https://api.openai.com/v1");
    assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    challenge = url.searchParams.get("code_challenge")!;
    nonce = url.searchParams.get("nonce")!;
    lastAuthorization = url.searchParams.get("redirect_uri")!;
    assert.match(lastAuthorization, /^http:\/\/127\.0\.0\.1:\d+\/auth\/callback$/);
    return url;
  };
  const callback = async (url: URL) => {
    const back = new URL(lastAuthorization);
    back.search = new URLSearchParams({ code: "codigo", state: url.searchParams.get("state")!, ...(!chatgptState().clientId ? { client_id: "oaiapp_prueba" } : {}) }).toString();
    await fetch(back);
  };
  await t.test("el aviso sobre términos aparece una sola vez antes de iniciar", async () => {
    assert.equal(noticePending(), true);
    await assert.rejects(beginChatgptLogin({ openBrowser: () => {} }), /términos de OpenAI/);
    await acceptNotice();
    assert.equal(noticePending(), false);
  });
  await t.test("state inválido o pedido malformado: 400, sin intercambio, y el ingreso sigue esperando", async () => {
    const url = await begin();
    const back = new URL(lastAuthorization);
    // Antes tiraba ERR_INVALID_URL sin capturar y mataba el proceso.
    assert.match(await raw(Number(back.port), "http://[::1/auth/callback"), /^HTTP\/1\.1 400/);
    back.search = new URLSearchParams({ code: "codigo", state: "malo", client_id: "oaiapp_prueba" }).toString();
    assert.equal((await fetch(back)).status, 400);
    back.search = new URLSearchParams({ code: "codigo", client_id: "oaiapp_prueba" }).toString();
    assert.equal((await fetch(back)).status, 400);
    assert.equal(exchanges, 0);
    // Sólo el callback con el state correcto termina el ingreso.
    back.search = new URLSearchParams({ error: "access_denied", state: url.searchParams.get("state")! }).toString();
    assert.equal((await fetch(back)).status, 200);
    await assert.rejects(waitChatgptLogin(), /rechazó el permiso: access_denied/);
    assert.equal(exchanges, 0);
    assert.ok(url.searchParams.get("code_challenge"));
  });
  await t.test("un ingreso nuevo reemplaza al pendiente abandonado", async () => {
    const first = await begin();
    const abandoned = new URL(lastAuthorization);
    const replaced = assert.rejects(waitChatgptLogin(), /reemplazó/);
    const second = await begin();
    await replaced;
    // El callback del enlace viejo ya no escucha y su state no sirve en el nuevo.
    abandoned.search = new URLSearchParams({ code: "codigo", state: first.searchParams.get("state")! }).toString();
    await assert.rejects(fetch(abandoned));
    const back = new URL(lastAuthorization);
    back.search = new URLSearchParams({ code: "codigo", state: first.searchParams.get("state")! }).toString();
    assert.equal((await fetch(back)).status, 400);
    back.search = new URLSearchParams({ error: "access_denied", state: second.searchParams.get("state")! }).toString();
    await fetch(back);
    await assert.rejects(waitChatgptLogin(), /rechazó el permiso/);
    assert.equal(exchanges, 0);
  });
  await t.test("la firma del ID token se verifica antes de guardar", async () => {
    const url = await begin();
    badSignature = true;
    await callback(url);
    await assert.rejects(waitChatgptLogin(), /Firma del ID token inválida/);
    badSignature = false;
    assert.equal(chatgptState().linked, false);
  });
  await t.test("registro dinámico, PKCE y secreto cifrado", async () => {
    const url = await begin();
    const verifier = "no está disponible en el navegador";
    assert.ok(!url.toString().includes(verifier));
    await callback(url);
    assert.match((await waitChatgptLogin())[0]!, /Conectado/);
    assert.equal(chatgptState().linked, true);
    const file = readFileSync(join(process.env.CYBER_CREDENTIALS_DIR!, "chatgpt.secreto"), "utf8");
    assert.doesNotMatch(file, /acceso_inicial|renovable_inicial|oaiapp_prueba/);
    assert.match(file, /"iv":/);
    assert.equal(resolveProvider("chatgpt/gpt-prueba").model.costSource, "plan de ChatGPT");
    assert.deepEqual(resolveProvider("chatgpt/gpt-prueba").model.cost, { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 });
  });
  await t.test("sin permiso directo no hay inferencia; reautorizar recupera el plan", async () => {
    grantScope = "openid profile email offline_access resource.invoke";
    const denied = await begin(true);
    await callback(denied);
    assert.match((await waitChatgptLogin())[0]!, /falta el permiso/);
    assert.equal(chatgptState().linked, false);
    grantScope = scope;
    const allowed = await begin(true);
    assert.equal(allowed.searchParams.get("prompt"), "consent");
    await callback(allowed);
    await waitChatgptLogin();
    assert.equal(chatgptState().linked, true);
  });
  await t.test("una reautorización con otro client_id se rechaza", async () => {
    const url = await begin(true);
    const back = new URL(lastAuthorization);
    back.search = new URLSearchParams({ code: "codigo", state: url.searchParams.get("state")!, client_id: "oaiapp_otro" }).toString();
    await fetch(back);
    await assert.rejects(waitChatgptLogin(), /otro cliente OAuth/);
    assert.equal(chatgptState().linked, true);
  });
  await t.test("catálogo visible y uso del modelo", async () => {
    assert.deepEqual(await chatgptModels(), [{ slug: "gpt-prueba", name: "gpt-prueba" }]);
    const value = JSON.parse(readSecret("chatgpt")!);
    value.accounts[0].modelsAt = 0;
    writeSecret("chatgpt", JSON.stringify(value), { requireEncryption: true });
    codexCatalog = true;
    assert.deepEqual(await chatgptModels(), [{ slug: "gpt-prueba", name: "GPT de prueba" }]);
    codexCatalog = false;
    const got = await chatgptResponses(request());
    assert.equal(got.stopReason, "toolUse");
    assert.equal(got.content, "bien");
    assert.deepEqual(got.toolCalls, [{ id: "call_1", name: "leer", arguments: "{\"ruta\":\"a\"}" }]);
    assert.deepEqual(got.usage, { input: 17, cacheRead: 3, cacheWrite: 0, output: 8, reasoning: 2 });
    assert.equal(lastBody.store, false);
    assert.equal(lastBody.stream, true);
    assert.equal(lastBody.tools[0].type, "namespace");
    assert.equal(lastBody.tools[0].tools[0].name, "leer");
    assert.equal(lastBody.instructions, "Sos un asistente.");
    assert.equal(lastBody.temperature, undefined);
    assert.equal(lastBody.max_output_tokens, undefined);
    assert.equal(lastBody.previous_response_id, undefined);
  });
  await t.test("el ledger guarda costo cero incluso si falta el uso", async () => {
    const db = openStore(projectPaths(mkdtempSync(join(tmpdir(), "cyber-chatgpt-ledger-"))));
    try {
      const ledger = new Ledger(db);
      const model = resolveProvider("chatgpt/gpt-prueba").model;
      const ctx = { sessionId: "chatgpt-local", account: "prueba", worker: "principal", model };
      const complete = await chatgptResponses(request());
      assert.equal(ledger.record(complete, ctx), true);
      assert.equal(ledger.record({ ...complete, requestId: "corte-local", usage: undefined, stopReason: "aborted" }, ctx), true);
      const rows = db.prepare("select input, price_json, cost_input, cost_output from requests order by rowid").all() as Array<{ input: number | null; price_json: string; cost_input: string; cost_output: string }>;
      assert.equal(rows[0]?.input, 17);
      assert.equal(rows[1]?.input, null);
      assert.equal(JSON.parse(rows[1]!.price_json).source, "plan de ChatGPT");
      assert.equal(rows[1]?.cost_input, "0");
      assert.equal(rows[1]?.cost_output, "0");
      assert.equal(ledger.totals().knownPico, 0n);
      assert.equal(ledger.totals().unknownRequests, 1); // Los tokens del corte siguen siendo desconocidos.
    } finally { db.close(); }
  });
  await t.test("el callback usa el puerto publicado del puente del navegador", async () => {
    const probe = createServer();
    await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
    const address = probe.address();
    assert.ok(address && typeof address !== "string");
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    const { chromeBridge } = await import("../src/chrome.ts");
    const bridge = chromeBridge();
    bridge.port = address.port;
    process.env.CYBER_PROYECTO_HOST = "/proyecto-local";
    process.env.CYBER_PUERTO_HOST = String(address.port);
    try {
      const url = await begin(true);
      assert.equal(new URL(lastAuthorization).port, String(address.port));
      // El puente comparte el puerto: una URL malformada no lo tumba.
      assert.match(await raw(address.port, "http://[::1/auth/callback"), /^HTTP\/1\.1 4\d\d/);
      await callback(url);
      assert.match((await waitChatgptLogin())[0]!, /Conectado/);
    } finally {
      bridge.close();
      if (before.CYBER_PROYECTO_HOST === undefined) delete process.env.CYBER_PROYECTO_HOST;
      else process.env.CYBER_PROYECTO_HOST = before.CYBER_PROYECTO_HOST;
      if (before.CYBER_PUERTO_HOST === undefined) delete process.env.CYBER_PUERTO_HOST;
      else process.env.CYBER_PUERTO_HOST = before.CYBER_PUERTO_HOST;
    }
  });
  await t.test("el refresh rota con candado y se reutiliza el cliente", async () => {
    const value = JSON.parse(readSecret("chatgpt")!);
    value.accounts[0].tokens.expiresAt = Date.now() - 1;
    writeSecret("chatgpt", JSON.stringify(value), { requireEncryption: true });
    const tokens = await Promise.all([chatgptAccessToken(), chatgptAccessToken()]);
    assert.deepEqual(tokens, ["acceso_1", "acceso_1"]);
    assert.equal(refreshes, 1);
    assert.equal(JSON.parse(readSecret("chatgpt")!).accounts[0].tokens.refresh, "renovado_1");
    const url = await begin(true);
    assert.equal(url.searchParams.has("agent_name_hint"), false);
    await callback(url);
    await waitChatgptLogin();
    assert.equal(chatgptState().clientId, "oaiapp_prueba");
  });
  await t.test("la renovación relee antes de guardar y los demás escritores esperan el candado", async () => {
    const value = JSON.parse(readSecret("chatgpt")!);
    value.accounts[0].tokens.expiresAt = Date.now() - 1;
    writeSecret("chatgpt", JSON.stringify(value), { requireEncryption: true });
    let marked: Promise<void> | undefined;
    duringRefresh = () => {
      // Mientras la renovación espera la red, otro proceso guarda una cuenta y un pedido marca el tope.
      const current = JSON.parse(readSecret("chatgpt")!);
      current.accounts.push({ clientId: "oaiapp_otra", subject: "sujeto-2" });
      writeSecret("chatgpt", JSON.stringify(current), { requireEncryption: true });
      marked = markChatgptLimit();
    };
    const token = await chatgptAccessToken();
    await marked;
    assert.equal(token, "acceso_" + refreshes);
    const saved = JSON.parse(readSecret("chatgpt")!);
    assert.equal(saved.accounts.find((item: any) => item.clientId === "oaiapp_prueba").tokens.refresh, "renovado_" + refreshes);
    assert.ok(saved.accounts.some((item: any) => item.clientId === "oaiapp_otra"));
    assert.equal(chatgptState().limitReached, true);
    saved.accounts = saved.accounts.filter((item: any) => item.clientId !== "oaiapp_otra");
    delete saved.accounts[0].limitUntil;
    writeSecret("chatgpt", JSON.stringify(saved), { requireEncryption: true });
  });
  await t.test("actualizar el catálogo no vuelve a guardar el refresh token ya usado", async () => {
    const value = JSON.parse(readSecret("chatgpt")!);
    value.accounts[0].tokens.expiresAt = Date.now() - 1;
    value.accounts[0].modelsAt = 0;
    writeSecret("chatgpt", JSON.stringify(value), { requireEncryption: true });
    const before = refreshes;
    assert.deepEqual(await chatgptModels(), [{ slug: "gpt-prueba", name: "gpt-prueba" }]);
    assert.equal(refreshes, before + 1);
    const saved = JSON.parse(readSecret("chatgpt")!).accounts[0];
    assert.equal(saved.tokens.refresh, "renovado_" + refreshes);
    assert.ok(saved.tokens.expiresAt > Date.now());
    assert.ok(saved.modelsAt > 0);
    // Con el token rotado guardado no hace falta otra renovación (que fallaría con refresh_token_reused).
    assert.equal(await chatgptAccessToken(), "acceso_" + refreshes);
    assert.equal(refreshes, before + 1);
  });
  await t.test("errores 401, 403 y 429; response.failed también frena el plan", async () => {
    for (const [kind, phrase] of [["401", "validar"], ["403", "no puede"], ["429", "Manage usage"]] as const) {
      mode = kind;
      const got = await chatgptResponses(request());
      assert.equal(got.stopReason, "error");
      assert.match(got.errorMessage ?? "", new RegExp(phrase));
      assert.equal(got.retryable, undefined);
      if (kind === "429") {
        assert.equal(chatgptState().limitReached, true);
        assert.match((await chatgptResponses(request())).errorMessage ?? "", /Manage usage/);
      }
    }
    const value = JSON.parse(readSecret("chatgpt")!);
    delete value.accounts[0].limitUntil;
    writeSecret("chatgpt", JSON.stringify(value), { requireEncryption: true });
    mode = "failed";
    const failed = await chatgptResponses(request());
    assert.equal(failed.stopReason, "error");
    assert.match(failed.errorMessage ?? "", /Manage usage/);
    assert.equal(chatgptState().limitReached, true);
    assert.equal(MANAGE_USAGE, "https://chatgpt.com/settings/usage");
  });
  await t.test("un stream sin response.completed no es éxito", async () => {
    const value = JSON.parse(readSecret("chatgpt")!);
    delete value.accounts[0].limitUntil;
    writeSecret("chatgpt", JSON.stringify(value), { requireEncryption: true });
    mode = "cut";
    const got = await chatgptResponses(request());
    assert.equal(got.stopReason, "error");
    assert.equal(got.retryable, true);
    mode = "hang";
    const controller = new AbortController();
    const cancel = chatgptResponses({ ...request(), signal: controller.signal });
    setTimeout(() => controller.abort(), 20);
    assert.equal((await cancel).stopReason, "aborted");
  });
  await t.test("el tope de uso vence (Retry-After o 15 min) y la primera respuesta buena lo borra", async () => {
    const limitUntil = () => JSON.parse(readSecret("chatgpt")!).accounts[0].limitUntil;
    const expire = () => {
      const value = JSON.parse(readSecret("chatgpt")!);
      value.accounts[0].limitUntil = Date.now() - 1;
      writeSecret("chatgpt", JSON.stringify(value), { requireEncryption: true });
    };
    mode = "429";
    retryAfter = "120";
    let start = Date.now();
    assert.match((await chatgptResponses(request())).errorMessage ?? "", /Manage usage/);
    assert.ok(limitUntil() >= start + 120_000 && limitUntil() <= Date.now() + 120_000);
    assert.equal(chatgptState().limitReached, true);
    // Mientras dura, el pedido no sale.
    const sent = lastBody;
    mode = "ok";
    assert.match((await chatgptResponses(request())).errorMessage ?? "", /Manage usage/);
    assert.equal(lastBody, sent);
    // Sin Retry-After, una pausa corta.
    expire();
    mode = "429";
    retryAfter = undefined;
    start = Date.now();
    await chatgptResponses(request());
    assert.ok(limitUntil() >= start + 15 * 60_000 && limitUntil() <= Date.now() + 15 * 60_000);
    // Vencido el plazo, el pedido sale sin volver a entrar y la respuesta buena borra la marca.
    expire();
    mode = "ok";
    assert.equal(chatgptState().limitReached, false);
    assert.equal((await chatgptResponses(request())).stopReason, "toolUse");
    assert.equal(lastBody === sent, false);
    assert.equal(limitUntil(), undefined);
  });
  await t.test("los GPT que razonan mandan esfuerzo alto y piden el resumen; sin el resumen, se repite una vez", async () => {
    const pensante = (reasoning?: boolean | "low" | "medium" | "high" | "max") => ({ ...request(), model: { ...request().model, id: "gpt-6-sol", ...chatgptReasoningCaps("gpt-6-sol"), reasoning } });
    mode = "ok";
    await chatgptResponses(pensante());
    assert.deepEqual(lastBody.reasoning, { effort: "high", summary: "auto" });
    await chatgptResponses(pensante("max"));
    assert.equal(lastBody.reasoning.effort, "xhigh");
    await chatgptResponses(pensante(false));
    assert.equal(lastBody.reasoning.effort, "low");
    // Un modelo sin niveles sigue sin mandar razonamiento salvo que el operador lo prenda.
    await chatgptResponses(request());
    assert.equal(lastBody.reasoning, undefined);
    mode = "sin-resumen";
    const got = await chatgptResponses(pensante());
    assert.equal(got.stopReason, "toolUse");
    assert.deepEqual(lastBody.reasoning, { effort: "high" });
    mode = "ok";
    await chatgptResponses(pensante());
    assert.deepEqual(lastBody.reasoning, { effort: "high" });
  });
  await t.test("invalid_grant desconecta; logout preserva el registro del cliente", async () => {
    const value = JSON.parse(readSecret("chatgpt")!);
    value.accounts[0].tokens.expiresAt = Date.now() - 1;
    writeSecret("chatgpt", JSON.stringify(value), { requireEncryption: true });
    invalidRefresh = true;
    await assert.rejects(chatgptAccessToken(), /desconectó/);
    assert.equal(chatgptState().linked, false);
    assert.equal(chatgptState().clientId, "oaiapp_prueba");
    invalidRefresh = false;
    const url = await begin(true);
    await callback(url);
    await waitChatgptLogin();
    assert.match((await logoutChatgpt())[0]!, /revocada/);
    assert.equal(revoked, 1);
    assert.equal(chatgptState().linked, false);
    assert.equal(chatgptState().clientId, "oaiapp_prueba");
  });
  await t.test("no usa el login ni los endpoints de Codex", () => {
    for (const file of ["src/chatgpt.ts", "src/chatgpt-responses.ts", "src/providers.ts"]) {
      const source = readFileSync(new URL("../" + file, import.meta.url), "utf8");
      assert.doesNotMatch(source, /\.codex|CODEX_HOME|auth\.json|backend-api/);
    }
    assert.deepEqual(toResponsesInput(request().messages), [{ type: "message", role: "user", content: [{ type: "input_text", text: "hola" }] }]);
  });
});
