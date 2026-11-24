import "./datos-tmp.ts";
// Orquestación: el agente lanza otros harnesses sobre worktrees del repo, con permiso del operador,
// los espera, lee su diff y limpia. Un harness falso (script) hace de Claude Code.
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Artifacts } from "../src/artifacts.ts";
import { exec } from "../src/exec.ts";
import { commandLine, createOrquestaTools, HARNESSES, harnessStatus, Orquesta, ultraPrompt } from "../src/orquesta.ts";
import { ShellPermissions } from "../src/shell.ts";
import { openStore, projectPaths } from "../src/store.ts";

const git = async (args: string[], cwd: string) => { const r = await exec({ argv: ["git", ...args], cwd, timeoutMs: 20_000 }); assert.equal(r.exitCode, 0, r.stderr); return r.stdout; };

async function repo(): Promise<string> {
  const dir = mkdtempSync(join(tmpdir(), "cyber-orq-"));
  await git(["init", "-q", "-b", "main"], dir);
  await git(["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "inicio"], dir);
  writeFileSync(join(dir, "README.md"), "hola\n");
  await git(["add", "."], dir);
  await git(["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "readme"], dir);
  return dir;
}

/** Un Claude Code de mentira: anota sus argumentos, escribe un archivo en el cwd y termina. */
function fakeHarness(dir: string, body: string): string {
  const path = join(dir, "claude-falso");
  writeFileSync(path, `#!/bin/sh\nprintf '%s\\n' "$@" > "$PWD/argv.txt"\n${body}\n`);
  chmodSync(path, 0o755);
  return path;
}

test("harness_run: worktree y rama propios, permiso con la línea exacta, espera, diff y limpieza", async () => {
  const cwd = await repo();
  const bin = fakeHarness(mkdtempSync(join(tmpdir(), "cyber-bin-")), 'echo "trabajando…"; echo "listo: cambié hola.txt" > hola.txt; echo "fin"');
  const db = openStore(projectPaths(cwd));
  const paths = projectPaths(cwd);
  const asked: string[] = [];
  const saved = process.env.CYBER_HARNESS_CLAUDE;
  process.env.CYBER_HARNESS_CLAUDE = bin;
  try {
    const orq = new Orquesta({ cwd, root: paths.root, db, artifacts: new Artifacts(db, paths.artifacts), permissions: new ShellPermissions(db), confirm: async (info) => { asked.push(info.command); return "siempre"; }, sessionId: () => "s1" });
    const [run, wait, status, result, , cleanup] = createOrquestaTools(orq);
    const call = (tool: any, args: object) => tool.execute(args, new AbortController().signal);
    const started = await call(run, { harness: "claude", task: "Agregá hola.txt con un saludo" });
    assert.match(started.text, /Lanzado #[0-9a-f]{6} \(Claude Code\) en .*worktrees\/[0-9a-f]{6}, rama orobas\/agrega-hola-txt-con-un-s-/);
    const id = started.details.id as string;
    assert.equal(asked.length, 1);
    assert.match(asked[0]!, /claude-falso -p --output-format text --permission-mode acceptEdits 'Agregá hola.txt con un saludo'/, "el operador ve la línea exacta");
    const waited = await call(wait, { ids: [id], timeoutSec: 30 });
    assert.match(waited.text, /terminado/);
    const res = await call(result, { id });
    assert.match(res.text, /salida 0/);
    assert.match(res.text, /hola\.txt/, "el diff muestra el archivo nuevo");
    assert.match(res.text, /trabajando…[\s\S]*fin/, "la cola de la salida");
    assert.match(res.text, /artefacto: sha256:[0-9a-f]{12,}/);
    const worktree = started.details.worktree as string;
    assert.ok(existsSync(join(worktree, "hola.txt")) && !existsSync(join(cwd, "hola.txt")), "trabajó en el worktree, no en el proyecto");
    assert.match(readFileSync(join(worktree, "argv.txt"), "utf8"), /^-p\n--output-format\ntext\n/);
    assert.match((await call(status, {})).text, /#\w+\s+claude\s+terminado/);
    assert.match(await git(["branch", "--list", "orobas/*"], cwd), /orobas\/agrega-hola-txt/);

    // Segunda corrida: el prefijo quedó aprobado «siempre» y no pregunta.
    const again = await call(run, { harness: "claude", task: "otra cosa" });
    assert.equal(asked.length, 1);
    await call(wait, { ids: [again.details.id], timeoutSec: 30 });

    const cleaned = await call(cleanup, { id, deleteBranch: true });
    assert.match(cleaned.text, /worktree .* quitado[\s\S]*rama orobas\/.* borrada/);
    assert.ok(!existsSync(worktree));
    assert.equal((db.prepare("select count(*) n from harness_runs").get() as { n: number }).n, 2, "quedan guardadas");
  } finally {
    if (saved === undefined) delete process.env.CYBER_HARNESS_CLAUDE; else process.env.CYBER_HARNESS_CLAUDE = saved;
    db.close();
  }
});

test("harness_run: sin permiso no corre y el worktree se deshace; harness_stop corta una corrida larga; sin repo no hay worktree", async () => {
  const cwd = await repo();
  const bin = fakeHarness(mkdtempSync(join(tmpdir(), "cyber-bin-")), "sleep 30");
  const db = openStore(projectPaths(cwd));
  const paths = projectPaths(cwd);
  const saved = process.env.CYBER_HARNESS_CODEX;
  process.env.CYBER_HARNESS_CODEX = bin;
  try {
    let decision: "si" | "no" = "no";
    const orq = new Orquesta({ cwd, root: paths.root, db, artifacts: new Artifacts(db, paths.artifacts), permissions: new ShellPermissions(db), confirm: async () => decision, sessionId: () => "s1" });
    const [run, , , , stop] = createOrquestaTools(orq);
    const call = (tool: any, args: object) => tool.execute(args, new AbortController().signal);
    await assert.rejects(call(run, { harness: "codex", task: "algo" }), /no autorizó lanzar Codex/);
    assert.equal((await git(["worktree", "list"], cwd)).trim().split("\n").length, 1, "el worktree del rechazo se deshizo");
    decision = "si";
    const started = await call(run, { harness: "codex", task: "algo largo" });
    const argvFile = join(started.details.worktree, "argv.txt");
    for (const start = Date.now(); !existsSync(argvFile) && Date.now() - start < 5000; ) await new Promise((r) => setTimeout(r, 20));
    assert.match(readFileSync(argvFile, "utf8"), /^exec\n-s\nworkspace-write\n-C\n/);
    const stopped = await call(stop, { id: started.details.id });
    assert.match(stopped.text, /detenido/);
    const run2 = orq.need(started.details.id);
    for (const start = Date.now(); run2.state !== "detenido" || !run2.endedAt; ) { if (Date.now() - start > 8000) break; await new Promise((r) => setTimeout(r, 20)); }
    assert.equal(run2.state, "detenido");
    assert.ok(run2.endedAt, "el proceso terminó");

    const plain = mkdtempSync(join(tmpdir(), "cyber-norepo-"));
    const db2 = openStore(projectPaths(plain));
    const orq2 = new Orquesta({ cwd: plain, root: projectPaths(plain).root, db: db2, artifacts: new Artifacts(db2, projectPaths(plain).artifacts), permissions: new ShellPermissions(db2), confirm: async () => "si", sessionId: () => "s1" });
    await assert.rejects(orq2.start({ harness: "codex", task: "x" }), /no es un repositorio git/);
    const direct = await orq2.start({ harness: "codex", task: "x", worktree: false, timeoutMin: 1 });
    assert.equal(direct.cwd, plain);
    orq2.stop(direct.id);
    await orq2.wait([direct.id], 8000);
    db2.close();
  } finally {
    if (saved === undefined) delete process.env.CYBER_HARNESS_CODEX; else process.env.CYBER_HARNESS_CODEX = saved;
    db.close();
  }
});

test("líneas de cada harness, estado de instalación y el encargo de /ultra", () => {
  assert.deepEqual(HARNESSES.pi.argv("hola", { cwd: "/x" }), ["-p", "hola"]);
  assert.deepEqual(HARNESSES.opencode.argv("hola", { cwd: "/x", model: "m" }), ["run", "--model", "m", "hola"]);
  assert.deepEqual(HARNESSES.cyber.argv("hola", { cwd: "/x" }), ["-C", "/x", "-p", "hola"]);
  assert.equal(commandLine("/usr/bin/claude", ["-p", "una tarea con espacios y 'comillas'"]), "/usr/bin/claude -p 'una tarea con espacios y '\\''comillas'\\'''");
  assert.ok(commandLine("x", ["a".repeat(300)]).length < 200, "la tarea larga se recorta en el aviso");
  assert.equal(harnessStatus().length, 5);
  const repo = ultraPrompt("migrar los tests a node:test", { harnesses: ["claude", "codex"], parts: 3 });
  assert.match(repo, /3 partes independientes/);
  assert.match(repo, /claude, codex/);
  assert.match(repo, /harness_run[\s\S]*harness_wait[\s\S]*harness_result[\s\S]*harness_cleanup/);
  const target = ultraPrompt("evaluar api.ejemplo.test", { mode: "objetivo", parts: 2 });
  assert.match(target, /2 frentes independientes/);
  assert.match(target, /delegate[\s\S]*harness=cyber/);
});
