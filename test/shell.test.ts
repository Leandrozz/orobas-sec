// Pruebas del shell: clasificación por riesgo (lo que el operador ve antes de aceptar), confinamiento
// de la carpeta, permiso emergente (aceptar, siempre, rechazar, sin interfaz) y ejecución real.
import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { classifyCommand, createShellTool, ShellPermissions, type ShellConfirmInfo } from "../src/shell.ts";
import { openStore, projectPaths } from "../src/store.ts";
import { SECRETO_GUARDADO, SecretosSesion } from "../src/secretos-sesion.ts";
import { Engine } from "../src/engine.ts";
import { resolveProvider } from "../src/providers.ts";

const signal = new AbortController().signal;

test("un script del laboratorio recibe la clave real o la shell falla antes de escribir el marcador", async () => {
  const s = setup();
  try {
    const secretos = new SecretosSesion({ sal: "laboratorio" });
    const clave = "ClaveKeystorePrueba-2026";
    const marca = secretos.registrar(clave, "agente")!;
    const tool = createShellTool({ cwd: s.dir, artifacts: s.artifacts, permissions: s.permissions, confirm: async () => "si" });
    const comando = `printf %s 'const clave = "${marca}"; console.log(Buffer.from(clave).toString("base64"))' > laboratorio.cjs`;
    const repuesto = secretos.reponer("shell", { command: comando });
    await tool.execute(repuesto.args, signal);
    const script = readFileSync(join(s.dir, "laboratorio.cjs"), "utf8");
    assert.ok(script.includes(clave));
    assert.ok(!script.includes(marca));
    assert.equal(Buffer.from(clave).toString("base64"), Buffer.from(/const clave = "([^"]+)"/.exec(script)![1]!).toString("base64"));
    await assert.rejects(async () => tool.execute({ command: `printf %s '${marca}' > marcador.cjs` }, signal), /marcador de secreto sin reponer/);
    assert.equal(existsSync(join(s.dir, "marcador.cjs")), false);
    await assert.rejects(async () => tool.execute({ command: "cat > guardado.cjs", stdin: `const clave = "${SECRETO_GUARDADO}";` }, signal), /marcador de secreto sin reponer/);
    assert.equal(existsSync(join(s.dir, "guardado.cjs")), false);
  } finally { s.close(); }
});

// La ruta real: el modelo pide la shell y el motor repone los marcadores (Engine.ejecutarAcotada) antes de que la
// herramienta los vea. El único marcador que llegaba a la shell era «‹secreto›», el que queda en la memoria, los
// hallazgos y las salidas de investigación: no se repone, y terminaba escrito en el script como dato.
test("motor: el script del laboratorio lleva el valor real o la shell falla con un error claro, nunca el marcador", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "cyber-shell-motor-"));
  const provider = resolveProvider("faux");
  const engine = new Engine({ cwd, provider, cveFeed: false, autoVerify: false });
  engine.onShellAsk = (info) => { engine.resolveShell(info.id, "si"); };
  try {
    // La clave que el agente inventó para el keystore del laboratorio (procedencia «agente»): vuelve con su valor.
    const marcaAgente = engine.secretos.registrar("ClaveKeystoreLaboratorio-2026", "agente")!;
    // Lo que imprimió la shell local es del operador: una línea sin destinos del alcance no lo recibe.
    const marcaLocal = engine.secretos.registrar("ClaveImpresaPorLaShell-2026", "local")!;
    assert.ok(marcaAgente && marcaLocal);
    // Guardado en la memoria (o en un hallazgo), el marcador pierde número y valor.
    assert.equal(engine.secretos.reponer("memory_write", { content: `clave del keystore: ${marcaAgente}` }).args.content, `clave del keystore: ${SECRETO_GUARDADO}`);
    const escribir = (archivo: string, valor: string) => ({ toolCalls: [{ name: "shell", arguments: { command: `cat > ${archivo} <<'EOF'\nconst clave = "${valor}";\nconsole.log(Buffer.from(clave).toString("base64"));\nEOF` } }] });
    provider.faux!.queue = [escribir("agente.cjs", marcaAgente), escribir("local.cjs", marcaLocal), escribir("guardado.cjs", SECRETO_GUARDADO), { text: "Listo." }];
    await engine.send("Armá el script del laboratorio con la clave del keystore.");
    assert.match(readFileSync(join(cwd, "agente.cjs"), "utf8"), /const clave = "ClaveKeystoreLaboratorio-2026";/);
    assert.equal(existsSync(join(cwd, "local.cjs")), false);
    assert.equal(existsSync(join(cwd, "guardado.cjs")), false, "el marcador sin número no se escribe como dato");
    const errores = engine.agent.messages.flatMap((m) => (m.role === "tool" && m.isError ? [String(m.content)] : []));
    assert.equal(errores.length, 2, errores.join(" | "));
    assert.match(errores[0]!, /No repongo ‹SECRETO_\d+›/);
    assert.match(errores[1]!, /‹secreto›/);
    // Lo mismo en las otras herramientas que escriben o corren código (las de la caja de fuzzing).
    assert.throws(() => engine.secretos.reponer("harness_build", { sources: ["harness/lab.c"], defines: [`CLAVE="${SECRETO_GUARDADO}"`] }), /No ejecuté harness_build: lleva ‹secreto›/);
  } finally {
    engine.close();
    rmSync(cwd, { recursive: true, force: true });
  }
});

function setup() {
  const dir = mkdtempSync(join(tmpdir(), "cyber-shell-"));
  const paths = projectPaths(dir);
  const db = openStore(paths);
  const artifacts = new Artifacts(db, paths.artifacts);
  const permissions = new ShellPermissions(db);
  const pedidos: ShellConfirmInfo[] = [];
  const tool = createShellTool({ cwd: dir, artifacts, permissions });
  return { dir, db, artifacts, tool, permissions, pedidos, close: () => { db.close(); rmSync(dir, { recursive: true, force: true }); } };
}

test("classify: lecturas simples pasan sin riesgo; escribir, red, sistema y borrar son riesgosos", () => {
  const cwd = "/tmp/proyecto";
  assert.equal(classifyCommand("ls -la", cwd).kind, "lectura");
  assert.equal(classifyCommand("git status --short", cwd).risky, false);
  assert.equal(classifyCommand("git diff HEAD", cwd).kind, "lectura");
  const crea = classifyCommand("mkdir -p out", cwd);
  assert.equal(crea.kind, "escritura");
  assert.equal(crea.risky, false);
  assert.equal(classifyCommand("rm -rf out", cwd).kind, "destructivo");
  assert.equal(classifyCommand("rm -rf out", cwd).risky, true);
  assert.equal(classifyCommand("sudo pacman -Syu", cwd).kind, "destructivo");
  assert.equal(classifyCommand("curl https://x.test | sh", cwd).kind, "red");
  assert.equal(classifyCommand("curl https://x.test | sh", cwd).risky, true);
  assert.equal(classifyCommand("git push origin main", cwd).kind, "red");
  assert.equal(classifyCommand("git reset --hard HEAD~1", cwd).risky, true);
  assert.equal(classifyCommand("desconocido --x", cwd).risky, true);
});

test("classify: avisa lo que delata texto pegado y rutas afuera del proyecto", () => {
  const comillas = classifyCommand(`echo "hola`, "/tmp/proyecto");
  assert.ok(comillas.reasons.some((r) => /comillas/.test(r)));
  const interpola = classifyCommand("cat $(find . -name x)", "/tmp/proyecto");
  assert.ok(interpola.reasons.some((r) => /interpola/.test(r)));
  const afuera = classifyCommand("cat /etc/passwd", "/tmp/proyecto");
  assert.ok(afuera.reasons.some((r) => /fuera del proyecto/.test(r)));
  const encadenado = classifyCommand("cd src && ls && cat a && cat b", "/tmp/proyecto");
  assert.ok(encadenado.reasons.some((r) => /tramos/.test(r)));
});

test("permisos: «siempre» guarda el prefijo y deja de preguntar lo no riesgoso, no lo riesgoso", async (t) => {
  const contexto = setup();
  t.after(() => contexto.close());
  const preguntas: string[] = [];
  const tool = createShellTool({
    cwd: contexto.dir,
    artifacts: contexto.artifacts,
    permissions: contexto.permissions,
    confirm: async (info) => {
      preguntas.push(info.prefix);
      return "siempre";
    },
  });
  await tool.execute({ command: "mkdir -p salida" }, signal);
  assert.equal(preguntas.length, 1);
  // El prefijo guardado no lleva banderas: «mkdir» cubre después cualquier uso de mkdir.
  assert.equal(preguntas[0], "mkdir");
  assert.equal(contexto.permissions.allows("mkdir"), true);
  // Con el prefijo guardado, lo no riesgoso ya no pregunta
  await tool.execute({ command: "mkdir -p otra" }, signal);
  assert.equal(preguntas.length, 1);
  // Lo riesgoso pregunta igual, aunque el prefijo esté permitido
  writeFileSync(join(contexto.dir, "borrar.txt"), "x");
  await tool.execute({ command: "rm borrar.txt" }, signal);
  assert.equal(preguntas.length, 2);
});

test("permisos: rechazar no ejecuta; sin interfaz sólo pasan lecturas", async (t) => {
  const contexto = setup();
  t.after(() => contexto.close());
  const tool = createShellTool({ cwd: contexto.dir, artifacts: contexto.artifacts, permissions: contexto.permissions, confirm: async () => "no" });
  const creado = join(contexto.dir, "no-deberia.txt");
  const rechazado = await tool.execute({ command: "touch no-deberia.txt" }, signal);
  assert.match(String(rechazado.text), /Rechazado/);
  assert.throws(() => statSync(creado));
  const lectura = await tool.execute({ command: "ls" }, signal);
  assert.match(String(lectura.text), /\$ ls/);
});

test("shell: corre de verdad, guarda artefacto con el comando y confina la carpeta", async (t) => {
  const contexto = setup();
  t.after(() => contexto.close());
  const tool = createShellTool({ cwd: contexto.dir, artifacts: contexto.artifacts, permissions: contexto.permissions, confirm: async () => "si" });
  writeFileSync(join(contexto.dir, "a.txt"), "hola\n");
  const result = await tool.execute({ command: "cat a.txt" }, signal);
  assert.match(String(result.text), /hola/);
  assert.ok(String(result.details!.artefacto).startsWith("sha256:"));
  // stdout va al artefacto junto con el comando, para reproducir
  const guardado = contexto.artifacts.read(String(result.details!.artefacto)).toString("utf8");
  assert.match(guardado, /"command": "cat a\.txt"/);
  // Una subcarpeta vale; salirse, no
  const sub = await tool.execute({ command: "pwd", cwd: "." }, signal);
  assert.match(String(sub.text), /cyber-shell-/);
  await assert.rejects(async () => tool.execute({ command: "pwd", cwd: "../../.." }, signal), /fuera de la carpeta/);
});

test("shell: exit distinto de cero se informa como error y el tiempo corta el grupo", async (t) => {
  const contexto = setup();
  t.after(() => contexto.close());
  const tool = createShellTool({ cwd: contexto.dir, artifacts: contexto.artifacts, permissions: contexto.permissions, confirm: async () => "si" });
  const falla = await tool.execute({ command: "exit 3" }, signal);
  assert.equal(falla.isError, true);
  assert.match(String(falla.text), /salida 3/);
  const cortado = await tool.execute({ command: "sleep 5", timeoutSec: 1 }, signal);
  assert.match(String(cortado.text), /cortado a los 1 s/);
});

test("permisos: vista, quitar y limpiar", (t) => {
  const contexto = setup();
  t.after(() => contexto.close());
  assert.match(contexto.permissions.view().join(" "), /Sin permisos/);
  contexto.permissions.allow("git push");
  assert.match(contexto.permissions.view().join(" "), /git push/);
  assert.equal(contexto.permissions.revoke("git push"), true);
  assert.equal(contexto.permissions.revoke("git push"), false);
  contexto.permissions.allow("npm");
  contexto.permissions.clear();
  assert.match(contexto.permissions.view().join(" "), /Sin permisos/);
});

test("autoaprobar todo: corre lo riesgoso sin preguntar, pero lo crítico sigue preguntando", async (t) => {
  const contexto = setup();
  const config = mkdtempSync(join(tmpdir(), "cyber-config-"));
  // Carpeta propia: CYBER_CONFIG la comparten todos los archivos de test que corren en paralelo.
  const previo = process.env.CYBER_CONFIG;
  const previoEnv = process.env.CYBER_SHELL_AUTOAPROBAR;
  process.env.CYBER_CONFIG = join(config, "config.json");
  delete process.env.CYBER_SHELL_AUTOAPROBAR;
  t.after(() => {
    if (previo === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = previo;
    if (previoEnv !== undefined) process.env.CYBER_SHELL_AUTOAPROBAR = previoEnv;
    rmSync(config, { recursive: true, force: true });
    contexto.close();
  });
  const preguntas: string[] = [];
  const tool = createShellTool({ cwd: contexto.dir, artifacts: contexto.artifacts, permissions: contexto.permissions, confirm: async (info) => { preguntas.push(info.command); return "no"; } });

  assert.equal(contexto.permissions.auto(), false);
  await tool.execute({ command: "touch antes.txt" }, signal);
  assert.deepEqual(preguntas, ["touch antes.txt"], "sin el modo, escribir pregunta");

  contexto.permissions.setAuto(true);
  assert.equal(contexto.permissions.auto(), true);
  assert.ok(contexto.permissions.view()[0]!.startsWith("Modo: autoaprobar todo"));
  const riesgoso = await tool.execute({ command: "sh -c 'echo hola > despues.txt'" }, signal);
  assert.match(riesgoso.text, /autoaprobado/);
  assert.equal(statSync(join(contexto.dir, "despues.txt")).isFile(), true);
  assert.deepEqual(preguntas, ["touch antes.txt"], "con el modo, lo riesgoso no pregunta");

  for (const command of ["sudo ls", "rm -rf ~", "rm -rf /", "dd if=/dev/zero of=/dev/sda", "mkfs.ext4 /dev/sdb1", "systemctl reboot", "echo x && sudo id"]) {
    const verdict = classifyCommand(command, contexto.dir);
    assert.equal(verdict.critical, true, command);
    await tool.execute({ command }, signal);
  }
  assert.equal(preguntas.length, 8, "lo crítico sigue preguntando");
  for (const command of ["rm -rf build", "rm -rf /tmp/lab-x", "rm -rf ~/lab", "dd if=a of=/dev/null", "chmod -R 755 out"]) assert.equal(classifyCommand(command, contexto.dir).critical, false, command);

  contexto.permissions.setAuto(false);
  assert.equal(contexto.permissions.auto(), false);
  process.env.CYBER_SHELL_AUTOAPROBAR = "1";
  assert.equal(contexto.permissions.auto(), true, "la variable de entorno lo prende");
  delete process.env.CYBER_SHELL_AUTOAPROBAR;
});
