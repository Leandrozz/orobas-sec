import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { once } from "node:events";
import { homedir } from "node:os";
import { join } from "node:path";
import { existsSync, readFileSync } from "node:fs";
import { t } from "../idioma.ts";
import type { CommandIO } from "./comandos.ts";

export type GeminiGrant = { clientId: string; clientSecret: string; refreshToken: string; project: string };

async function exchange(fields: Record<string, string>) {
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", body: new URLSearchParams(fields), redirect: "error", signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw new Error(t("Google rechazó la autorización", "Google rejected authorization") + " · HTTP " + response.status);
  const tokens = await response.json();
  if (typeof tokens.access_token !== "string" || !tokens.access_token) throw new Error("Google OAuth · access_token");
  return tokens;
}

export async function authorizeGemini(io: Pick<CommandIO, "input" | "notice">): Promise<GeminiGrant | undefined> {
  const file = process.env.GEMINI_OAUTH_CLIENT_FILE || join(homedir(), "Descargas", "orobas-google.json");
  if (!existsSync(file)) throw new Error(t("El login de Google todavía no está configurado en Orobas. Configurá GEMINI_OAUTH_CLIENT_FILE con el cliente OAuth de escritorio de la aplicación o elegí API key.", "Google sign-in is not configured in Orobas yet. Set GEMINI_OAUTH_CLIENT_FILE to the application's desktop OAuth client file or choose API key."));
  const { installed } = JSON.parse(readFileSync(file, "utf8"));
  if (!installed?.client_id || !installed.client_secret || !installed.project_id) throw new Error(t("Se necesita un cliente OAuth de escritorio con proyecto.", "A desktop OAuth client with a project is required."));

  const verifier = randomBytes(48).toString("base64url");
  const state = randomBytes(32).toString("base64url");
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") { server.close(); throw new Error("OAuth loopback"); }
  const redirect = `http://127.0.0.1:${address.port}/`;
  let code: string;
  try {
    const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    url.search = new URLSearchParams({
      client_id: installed.client_id, response_type: "code", redirect_uri: redirect,
      scope: "https://www.googleapis.com/auth/cloud-platform", state, access_type: "offline", prompt: "consent",
      code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256",
    }).toString();
    code = await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(t("El login de Google venció.", "Google sign-in timed out."))), 180000);
      server.once("close", () => clearTimeout(timer));
      server.on("request", (req, res) => {
        const callback = new URL(req.url || "/", redirect);
        if (req.method !== "GET" || callback.origin + callback.pathname !== redirect || callback.searchParams.get("state") !== state) {
          res.writeHead(400).end(); return;
        }
        const value = callback.searchParams.get("code");
        res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" }).end(t("Volvé a Orobas.", "Return to Orobas."));
        if (value) resolve(value);
        else reject(new Error(t("Google canceló el acceso.", "Google sign-in was cancelled.")));
      });
      io.notice?.({ title: "Google OAuth", lines: [t("Autorizá el acceso en tu navegador. Si no se abre, usá este enlace:", "Authorize in your browser. If it does not open, use this link:"), url.href] });
      if (process.platform === "linux" || process.platform === "darwin")
        execFile(process.platform === "darwin" ? "open" : "xdg-open", [url.href], () => {});
    });
  } finally {
    server.close();
  }
  const tokens = await exchange({ client_id: installed.client_id, client_secret: installed.client_secret, code, code_verifier: verifier, redirect_uri: redirect, grant_type: "authorization_code" });
  if (typeof tokens.refresh_token !== "string" || !tokens.refresh_token) throw new Error("Google OAuth · refresh_token");
  return { clientId: installed.client_id, clientSecret: installed.client_secret, project: installed.project_id, refreshToken: tokens.refresh_token };
}

export async function geminiToken(grant: GeminiGrant): Promise<string> {
  return (await exchange({ client_id: grant.clientId, client_secret: grant.clientSecret, refresh_token: grant.refreshToken, grant_type: "refresh_token" })).access_token;
}
