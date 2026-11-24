import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { Engine } from "../src/engine.ts";
import { toolboxView } from "../src/daemon.ts";
import { binarioInstrumentado, clasificarReporte, compilarHarness, correrFuzzer, crashesConocidos, FUZZ, fuzzDisponible, fuzzEntorno, fuzzStatus, HERRAMIENTAS_FUZZ, limitesFuzz, palabrasComando, parsearFrame, pocRunner, reproducirPoc, runPoc, textoCorrida, type FuzzEntorno, type LimitesFuzz } from "../src/fuzzing.ts";
import { resolveProvider } from "../src/providers.ts";
import { findCommand } from "../src/tui/comandos.ts";
import { Registro } from "../src/tui/entradas.ts";
import { dibujar, dibujarPanel, PESTANA_CHAT, type Pestana } from "../src/tui/pestanas.ts";
import { stripAnsi, truncate, visibleWidth } from "../src/tui/text.ts";
import { fakeIO } from "./fake-io.ts";

// ─── Reportes de ejemplo, con la forma que imprimen ASan, UBSan, LSan y libFuzzer de LLVM 16 ───

const ASAN_HBO = String.raw`=================================================================
==4242==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000011 at pc 0x55d4a1 bp 0x7ffc10 sp 0x7ffc08
WRITE of size 4 at 0x602000000011 thread T0
    #0 0x55d4a1 in __asan_memcpy /src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:22:3
    #1 0x55d4b2 in parse_header /proyecto/lib/parser.c:42:13
    #2 0x55d4c3 in parse_doc /proyecto/lib/parser.c:90:7
    #3 0x55d4d4 in LLVMFuzzerTestOneInput /proyecto/harness/xml.c:8:3
    #4 0x55d4e5 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:611:15
    #5 0x7f0001 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f) (BuildId: 89c3cb85f9e55046776471fed05ec441581d1969)
    #6 0x55d4f6 in _start (/proyecto/harness/out/xml/xml+0x1f6)

0x602000000011 is located 0 bytes to the right of 1-byte region [0x602000000010,0x602000000011)
allocated by thread T0 here:
    #0 0x55d500 in malloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:69:3
    #1 0x55d511 in parse_header /proyecto/lib/parser.c:40:9

SCARINESS: 45 (4-byte-write-heap-buffer-overflow)
SUMMARY: AddressSanitizer: heap-buffer-overflow /proyecto/lib/parser.c:42:13 in parse_header
==4242==ABORTING`;

const UBSAN_SIO = String.raw`/proyecto/lib/parser.c:77:20: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
    #0 0x55d600 in compute_len /proyecto/lib/parser.c:77:20
    #1 0x55d611 in parse_doc /proyecto/lib/parser.c:95:3
    #2 0x55d622 in LLVMFuzzerTestOneInput /proyecto/harness/xml.c:8:3
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /proyecto/lib/parser.c:77:20 in`;

const TIMEOUT = String.raw`ALARM: working on the last Unit for 11 seconds
       and the timeout value is 10 (use -timeout=N to change)
==4242== ERROR: libFuzzer: timeout after 11 seconds
    #0 0x55d700 in __sanitizer_print_stack_trace /src/llvm-project/compiler-rt/lib/asan/asan_stack.cpp:87:3
    #1 0x55d711 in fuzzer::PrintStackTrace() /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerUtil.cpp:210:5
    #2 0x55d722 in skip_comments /proyecto/lib/parser.c:120:5
    #3 0x55d733 in parse_doc /proyecto/lib/parser.c:99:3
SUMMARY: libFuzzer: timeout`;

// ─── Dobles: un clang y un libFuzzer falsos (scripts de Node), con un registro de todo lo que les llega ───

const COMPILADOR = String.raw`#!__NODE__
import { appendFileSync, chmodSync, copyFileSync, readFileSync, writeFileSync } from "node:fs";
const args = process.argv.slice(2);
appendFileSync("__AUDIT__", JSON.stringify({ prog: "cc", args, env: Object.keys(process.env), cwd: process.cwd() }) + "\n");
const out = args[args.indexOf("-o") + 1];
if (args.includes("-c")) { writeFileSync(out, "objeto falso\n"); process.exit(0); }
const fuentes = args.filter((a) => /\.(c|cc|cpp)$/.test(a));
const texto = fuentes.map((f) => readFileSync(f, "utf8")).join("\n");
const f = fuentes[0];
if (texto.includes("ERROR_DE_COMPILACION")) {
  process.stderr.write(f + ":3:5: error: use of undeclared identifier 'ERROR_DE_COMPILACION'\n    3 |     ERROR_DE_COMPILACION;\n      |     ^\n" + f + ":4:7: warning: unused variable 'x' [-Wunused-variable]\n1 warning and 1 error generated.\n");
  process.exit(1);
}
if (texto.includes("SIMBOLO_FALTANTE")) {
  process.stderr.write("/usr/bin/ld: /tmp/falta-3a1b.o: in function " + String.fromCharCode(96) + "LLVMFuzzerTestOneInput':\n" + f + ":5: undefined reference to " + String.fromCharCode(96) + "xmlFaltante'\nclang: error: linker command failed with exit code 1 (use -v to see invocation)\n");
  process.exit(1);
}
copyFileSync("__FUZZER__", out);
chmodSync(out, 0o755);
`;

const FUZZER = String.raw`#!__NODE__
import { appendFileSync, existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
const args = process.argv.slice(2);
const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => /_OPTIONS$|^(PATH|HOME|TMPDIR)$|KEY|TOKEN|PROXY|CYBER/i.test(k)));
appendFileSync("__AUDIT__", JSON.stringify({ prog: "fuzzer", args, env, cwd: process.cwd() }) + "\n");
const flag = (name) => args.find((a) => a.startsWith("-" + name + "="))?.split("=").slice(1).join("=");
const pos = args.filter((a) => !a.startsWith("-"));
const sha = (x) => createHash("sha1").update(x).digest("hex");
const REPORTES = __REPORTES__;
const una = (contenido, ruta) => {
  if (contenido.includes("BOOM")) { process.stderr.write("INFO: Seed: 1\nRunning: " + ruta + "\n" + REPORTES.asan + "\n"); process.exit(1); }
  if (contenido.includes("UBSAN")) { process.stderr.write("INFO: Seed: 1\nRunning: " + ruta + "\n" + REPORTES.ubsan + "\n"); process.exit(1); }
  if (contenido.includes("LENTO")) { process.stderr.write("INFO: Seed: 1\nRunning: " + ruta + "\n" + REPORTES.timeout + "\n"); process.exit(70); }
  if (contenido.includes("FLAKY")) {
    const cuenta = join(process.env.TMPDIR, "cuenta-" + sha(ruta));
    const n = existsSync(cuenta) ? Number(readFileSync(cuenta, "utf8")) + 1 : 1;
    writeFileSync(cuenta, String(n));
    if (n % 2 === 1) { process.stderr.write(REPORTES.asan + "\n"); process.exit(1); }
  }
  process.stderr.write("INFO: Seed: 1\nRunning: " + ruta + "\nExecuted " + ruta + " in 1 ms\n");
  process.exit(0);
};
if (args.includes("-minimize_crash=1")) {
  const contenido = readFileSync(pos.at(-1), "utf8");
  writeFileSync(flag("exact_artifact_path"), contenido.includes("BOOM") ? "BOOM" : contenido.includes("UBSAN") ? "UBSAN" : contenido);
  process.stderr.write("CRASH_MIN: minimizing crash input\n");
  process.exit(0);
}
if (!pos.length) una(readFileSync(0, "utf8"), "stdin");
if (statSync(pos.at(-1)).isFile()) una(readFileSync(pos.at(-1), "utf8"), pos.at(-1));
const semillas = pos.flatMap((dir) => readdirSync(dir).map((name) => readFileSync(join(dir, name), "utf8")));
if (semillas.some((s) => s.includes("ROTO"))) { process.stderr.write("AddressSanitizer:DEADLYSIGNAL\nAddressSanitizer:DEADLYSIGNAL\nAddressSanitizer:DEADLYSIGNAL\n"); process.exit(1); }
process.stderr.write("INFO: Running with entropic power schedule (0xFF, 100).\nINFO: Seed: 1234\nINFO: Loaded 1 modules\n#2\tINITED cov: 10 ft: 10 corp: 1/1b exec/s: 0 rss: 30Mb\n");
if (semillas.some((s) => s.includes("COLGAR"))) await new Promise((done) => setTimeout(done, 60000));
const prefijo = flag("artifact_prefix");
const final = "stat::number_of_executed_units: 5000\nstat::average_exec_per_sec: 2500\nstat::new_units_added: 7\nstat::peak_rss_mb: 40\n";
if (semillas.some((s) => s.includes("BOOM"))) {
  const escribir = (tipo, contenido) => { const ruta = prefijo + tipo + "-" + sha(contenido); writeFileSync(ruta, contenido); return ruta; };
  const primero = escribir("crash", "xxxxBOOMyyyyzzzzwwwwvvvvuuuu");
  if (flag("fork")) { escribir("crash", "otra-variante-BOOM-con-mas-bytes"); escribir("crash", "aaUBSANbb"); escribir("timeout", "LENTO"); }
  process.stderr.write("#1024\tpulse  cov: 42 ft: 50 corp: 3/12b lim: 4 exec/s: 1024 rss: 31Mb\n" + REPORTES.asan + "\nMS: 1 ChangeByte-; base unit: 0\nartifact_prefix='" + prefijo + "'; Test unit written to " + primero + "\n" + final);
  process.exit(1);
}
writeFileSync(join(pos[0], "nuevo-" + Date.now()), "entrada nueva");
process.stderr.write("#1024\tpulse  cov: 42 ft: 50 corp: 3/12b lim: 4 exec/s: 1024 rss: 31Mb\nDone 5000 runs in 2 second(s)\n" + final);
`;

const HARNESS = "#include <stdint.h>\n#include <stddef.h>\n#include \"parser.h\"\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {\n  parse_doc((const char *)d, n);\n  return 0;\n}\n";

function laboratorio() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "cyber-fuzz-")));
  const cwd = join(root, "proyecto");
  const bin = join(root, "bin");
  for (const dir of [join(cwd, "harness"), join(cwd, "include"), join(cwd, "lib"), join(cwd, "semillas"), join(cwd, "semillas-limpias"), join(cwd, ".cyber"), join(root, "afuera"), bin]) mkdirSync(dir, { recursive: true });
  writeFileSync(join(cwd, "harness", "xml.c"), HARNESS);
  writeFileSync(join(cwd, "harness", "roto.c"), "#include <stddef.h>\nint LLVMFuzzerTestOneInput(const unsigned char *d, size_t n) {\n    ERROR_DE_COMPILACION;\n  int x;\n  return 0;\n}\n");
  writeFileSync(join(cwd, "harness", "falta.c"), "#include <stddef.h>\nint xmlFaltante(void);\nint LLVMFuzzerTestOneInput(const unsigned char *d, size_t n) {\n  /* SIMBOLO_FALTANTE */\n  return xmlFaltante();\n}\n");
  writeFileSync(join(cwd, "harness", "poc.c"), "#include <stdio.h>\nint main(int argc, char **argv) { FILE *f = fopen(argv[argc - 1], \"rb\"); return f == NULL; }\n");
  writeFileSync(join(cwd, "include", "parser.h"), "int parse_doc(const char *, unsigned long);\n");
  writeFileSync(join(cwd, "lib", "libparser.a"), "!<arch>\n");
  writeFileSync(join(cwd, "semillas", "hola"), "hola");
  writeFileSync(join(cwd, "semillas", "boom"), "xxBOOMyy");
  writeFileSync(join(cwd, "semillas-limpias", "hola"), "hola");
  writeFileSync(join(cwd, "flaky"), "FLAKY");
  writeFileSync(join(cwd, "limpio"), "nada raro");
  writeFileSync(join(cwd, "boom"), "BOOM");
  writeFileSync(join(cwd, ".cyber", "x.c"), "int x;\n");
  writeFileSync(join(cwd, "dict.txt"), "\"<?xml\"\n");
  writeFileSync(join(root, "afuera", "secreto.c"), "int secreto;\n");
  symlinkSync(join(root, "afuera"), join(cwd, "atajo"));
  const audit = join(root, "audit.jsonl");
  writeFileSync(audit, "");
  const fuzzer = join(bin, "fuzzer-falso.mjs");
  const reportes = JSON.stringify({ asan: ASAN_HBO, ubsan: UBSAN_SIO, timeout: TIMEOUT });
  writeFileSync(fuzzer, FUZZER.replace("__NODE__", process.execPath).replace("__AUDIT__", audit).replace("__REPORTES__", reportes));
  chmodSync(fuzzer, 0o755);
  const clang = join(bin, "clang");
  writeFileSync(clang, COMPILADOR.replace("__NODE__", process.execPath).replace("__AUDIT__", audit).replace("__FUZZER__", fuzzer));
  chmodSync(clang, 0o755);
  writeFileSync(join(bin, "llvm-symbolizer"), "#!/bin/sh\n");
  chmodSync(join(bin, "llvm-symbolizer"), 0o755);
  const records = () => readFileSync(audit, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line) as { prog: string; args: string[]; env: Record<string, string> | string[]; cwd: string });
  return {
    root, cwd, records,
    binarios: { clang, clangxx: clang, symbolizer: join(bin, "llvm-symbolizer"), pkgConfig: join(bin, "no-hay-pkg-config") },
    clean: () => rmSync(root, { recursive: true, force: true }),
  };
}

type Lab = ReturnType<typeof laboratorio>;
const motor = (lab: Lab, enCaja = true, limites: Partial<LimitesFuzz> = {}) =>
  new Engine({ cwd: lab.cwd, provider: resolveProvider("faux"), autoVerify: false, rea: false, fuzzing: { enCaja, binarios: lab.binarios, limites } });
const call = (name: string, args: object) => ({ toolCalls: [{ name, arguments: args }] });
const signal = new AbortController().signal;

async function conMotor(fn: (lab: Lab, engine: Engine, entorno: FuzzEntorno) => Promise<void>, limites: Partial<LimitesFuzz> = {}) {
  const lab = laboratorio();
  const engine = motor(lab, true, limites);
  try {
    assert.ok(engine.fuzzing, "en la caja hay entorno de fuzzing");
    await fn(lab, engine, engine.fuzzing);
  } finally {
    await engine.close();
    lab.clean();
  }
}

test("harness_build: compila con los sanitizers pedidos, enlaza el corte de red y guarda comando y log", () => conMotor(async (lab, engine, entorno) => {
  const result = await compilarHarness(entorno, { sources: ["harness/xml.c"], include_dirs: ["include"], link: ["lib/libparser.a"], libs: ["z"], defines: ["HAVE_CONFIG_H"], flags: ["-std=c11", "-O2"] }, signal);
  assert.equal(result.ok, true, JSON.stringify(result.errores));
  assert.equal(result.tipo, "fuzzer", "lo deduce de LLVMFuzzerTestOneInput");
  assert.equal(result.binario, join(lab.cwd, "harness", "out", "xml", "xml"));
  const manifiesto = JSON.parse(readFileSync(join(lab.cwd, "harness", "out", "xml", "build.json"), "utf8"));
  assert.equal(manifiesto.sha256, result.manifiesto!.sha256);
  assert.equal(manifiesto.binario, "harness/out/xml/xml");
  assert.deepEqual(manifiesto.fuentes.map((item: { ruta: string }) => item.ruta), ["harness/xml.c"]);
  assert.ok(existsSync(join(lab.cwd, "harness", "out", "xml", "build.log")));
  assert.equal(readFileSync(join(lab.cwd, "harness", "out", "xml", "sin-red.c"), "utf8"), readFileSync(FUZZ.sinRed, "utf8"));
  const [corte, harness] = lab.records();
  assert.ok(corte!.args.includes("-c") && corte!.args.some((arg) => arg.endsWith("sin-red.c")));
  assert.ok(corte!.args.includes("-fsanitize=address,undefined"), "el corte va con los mismos sanitizers, sin libFuzzer");
  for (const expected of ["-fsanitize=fuzzer,address,undefined", "-fno-sanitize-recover=undefined", "-Wl,--export-dynamic-symbol=socket", "-DHAVE_CONFIG_H", "-std=c11", "-O2", "-lz", `-I${join(lab.cwd, "include")}`, join(lab.cwd, "lib", "libparser.a"), join(lab.cwd, "harness", "out", "xml", "sin-red.o")]) {
    assert.ok(harness!.args.includes(expected), `falta ${expected} en ${harness!.args.join(" ")}`);
  }
  assert.ok(harness!.args.indexOf("-std=c11") > harness!.args.indexOf("-O1"), "lo del modelo va después de lo de fábrica");
  for (const record of lab.records()) assert.ok(!(record.env as string[]).some((key) => /KEY|TOKEN|PROXY|CYBER|OROBAS/i.test(key)), `entorno mínimo: ${String(record.env)}`);
  const log = JSON.parse(engine.artifacts.read(result.artefacto).toString());
  assert.equal(log.comando, result.comando);
  assert.match(log.salida, /\$ .*-fsanitize=fuzzer,address,undefined/);
  // Un PoC con main: los sanitizers sin libFuzzer.
  const poc = await compilarHarness(entorno, { sources: ["harness/poc.c"], sanitizers: ["address"] }, signal);
  assert.equal(poc.tipo, "poc");
  assert.ok(lab.records().at(-1)!.args.includes("-fsanitize=address"));
  await assert.rejects(compilarHarness(entorno, { sources: ["harness/xml.c"], sanitizers: ["memory", "address"] }, signal), /MSan \(memory\) no se combina con ASan/);
  const msan = await compilarHarness(entorno, { sources: ["harness/xml.c"], name: "xml-msan", sanitizers: ["memory", "undefined"] }, signal);
  assert.ok(lab.records().at(-1)!.args.includes("-fsanitize-memory-track-origins"));
  assert.equal(msan.ok, true);
}));

test("harness_build: errores compactos, símbolos sin definir y no queda corriendo el binario viejo", () => conMotor(async (lab, engine, entorno) => {
  assert.equal((await compilarHarness(entorno, { sources: ["harness/xml.c"] }, signal)).ok, true);
  const roto = await compilarHarness(entorno, { sources: ["harness/roto.c"], name: "xml" }, signal);
  assert.equal(roto.ok, false);
  assert.deepEqual(roto.errores, ["harness/roto.c:3:5: use of undeclared identifier 'ERROR_DE_COMPILACION'"], "rutas relativas al proyecto");
  assert.equal(roto.advertencias, 1);
  assert.ok(!existsSync(join(lab.cwd, "harness", "out", "xml", "xml")) && !existsSync(join(lab.cwd, "harness", "out", "xml", "build.json")), "el que falló no deja el anterior");
  await assert.rejects(correrFuzzer(entorno, { harness: "xml" }, signal), /No hay un harness «xml» compilado/);
  const falta = await compilarHarness(entorno, { sources: ["harness/falta.c"] }, signal);
  assert.deepEqual(falta.indefinidos, ["xmlFaltante"]);
  assert.deepEqual(falta.errores, [], "el «linker command failed» no repite lo mismo");
  // Por la herramienta: la causa en la primera línea (la que muestra la TUI).
  const tool = engine.catalog.available.get("harness_build")!;
  const result = await tool.execute({ sources: ["harness/roto.c"] }, signal);
  assert.equal(result.isError, true);
  assert.match(result.text, /^No compiló roto \(salida 1\)\. Comando exacto y log completo en sha256:[0-9a-f]{64}\.\nErrores:\n- harness\/roto\.c:3:5: use of undeclared/);
  for (const flags of [["-Wl,-rpath,/tmp"], ["-fplugin=x.so"], ["-o"], ["@opciones"], ["-B/usr/bin"], ["-fsanitize=thread"], ["-mllvm"], ["-include", "x.h"], ["-isystem/usr/include"]]) {
    await assert.rejects(compilarHarness(entorno, { sources: ["harness/xml.c"], flags }, signal), /flags: .* no se acepta/, flags.join(" "));
  }
  await assert.rejects(compilarHarness(entorno, { sources: ["harness/xml.c"], defines: ["X=\"a b\""] }, signal), /defines/);
  await assert.rejects(compilarHarness(entorno, { sources: ["harness/xml.c"], libs: ["../../etc/x"] }, signal), /libs/);
  await assert.rejects(compilarHarness(entorno, { sources: ["harness/xml.c"], pkg_config: ["libxml-2.0"] }, signal), /pkg-config no está/);
}));

test("rutas fuera del proyecto: se rechazan sin compilar ni correr nada", () => conMotor(async (lab, _engine, entorno) => {
  const antes = lab.records().length;
  const fuera = /fuera de la carpeta del proyecto|\.cyber/;
  for (const pedido of [
    { sources: ["../afuera/secreto.c"] }, { sources: ["/etc/passwd"] }, { sources: ["atajo/secreto.c"] }, { sources: [".cyber/x.c"] }, { sources: ["~/x.c"] },
    { sources: ["harness/xml.c"], include_dirs: ["/usr/include"] }, { sources: ["harness/xml.c"], include_dirs: ["atajo"] },
    { sources: ["harness/xml.c"], link: ["/etc/passwd"] }, { sources: ["harness/xml.c"], lib_dirs: ["../afuera"] },
  ]) await assert.rejects(compilarHarness(entorno, pedido, signal), fuera, JSON.stringify(pedido));
  assert.equal(lab.records().length, antes, "el compilador nunca arrancó");
  assert.equal((await compilarHarness(entorno, { sources: ["harness/xml.c"] }, signal)).ok, true);
  const compilado = lab.records().length;
  for (const pedido of [{ harness: "xml", corpus: ["../afuera"] }, { harness: "xml", corpus: ["atajo"] }, { harness: "xml", dict: "/etc/passwd" }, { binary: "/bin/ls" }, { binary: "atajo/secreto.c" }]) {
    await assert.rejects(correrFuzzer(entorno, pedido, signal), fuera, JSON.stringify(pedido));
  }
  await assert.rejects(correrFuzzer(entorno, { binary: "harness/xml.c" }, signal), /no lo compiló harness_build ni tiene sanitizers/);
  await assert.rejects(correrFuzzer(entorno, { harness: "../afuera" }, signal), /no es un nombre de harness/);
  await assert.rejects(reproducirPoc(entorno, { harness: "xml", input: "atajo/secreto.c" }, signal), fuera);
  await assert.rejects(reproducirPoc(entorno, { harness: "xml", input: "/etc/passwd" }, signal), fuera);
  assert.equal(lab.records().length, compilado, "ni el fuzzer arrancó");
  assert.equal((await compilarHarness(entorno, { sources: ["harness/poc.c"] }, signal)).ok, true);
  for (const args of [["--salida=/etc/x", "@@"], ["../../afuera/secreto.c"], ["~/.ssh/id_rsa"], ["-o/etc/x", "@@"], ["/etc/@@"], ["--log=../afuera/x"]]) {
    await assert.rejects(reproducirPoc(entorno, { harness: "poc", input: "limpio", args }, signal), /sale de la carpeta del proyecto/, args.join(" "));
  }
  // Un ELF con sanitizers del proyecto (el CLI del objetivo armado con ASan) sí se acepta; uno sin, no.
  assert.equal(binarioInstrumentado(Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.from("....__asan_init....")])), true);
  assert.equal(binarioInstrumentado(Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.from("....main....")])), false);
  assert.equal(binarioInstrumentado(Buffer.from("#!/bin/sh\n__asan_init")), false);
  // harness/out apuntando afuera del proyecto: no se sigue.
  const otro = laboratorio();
  const engine = motor(otro);
  try {
    symlinkSync(join(otro.root, "afuera"), join(otro.cwd, "harness", "out"));
    await assert.rejects(compilarHarness(engine.fuzzing!, { sources: ["harness/xml.c"] }, signal), fuera);
    assert.ok(!existsSync(join(otro.root, "afuera", "xml")), "no creó nada afuera");
  } finally {
    await engine.close();
    otro.clean();
  }
}));

test("fuzz_run: un crash simulado se clasifica, se minimiza, se deduplica y queda como artefacto", () => conMotor(async (lab, engine, entorno) => {
  assert.equal((await compilarHarness(entorno, { sources: ["harness/xml.c"] }, signal)).ok, true);
  const corrida = await correrFuzzer(entorno, { harness: "xml", seconds: 30, corpus: ["semillas"], dict: "dict.txt" }, signal);
  assert.equal(corrida.fin, "crash");
  assert.equal(corrida.ejecuciones, 5000);
  assert.equal(corrida.porSegundo, 2500);
  assert.equal(corrida.cobertura, 42);
  assert.equal(corrida.crashes.length, 1);
  const crash = corrida.crashes[0]!;
  assert.equal(crash.nuevo, true);
  assert.equal(crash.tipo, "heap-buffer-overflow");
  assert.equal(crash.clase, "memoria");
  assert.equal(crash.reproduce, true);
  assert.deepEqual(crash.reporte!.acceso, { op: "WRITE", bytes: 4 });
  assert.equal(crash.linea, "heap-buffer-overflow (WRITE de 4) en parse_header parser.c:42 ← parse_doc parser.c:90 ← LLVMFuzzerTestOneInput xml.c:8");
  assert.match(crash.impacto, /^Escritura fuera de límites/);
  assert.equal(crash.enHarness, false);
  assert.equal(crash.minimizado, true);
  assert.equal(crash.bytes, 4);
  assert.equal(crash.bytesOriginal, 28);
  const dir = join(lab.cwd, crash.carpeta);
  assert.equal(crash.carpeta, `harness/out/xml/crashes/${crash.firma}`);
  assert.equal(readFileSync(join(dir, "input.min"), "utf8"), "BOOM");
  assert.equal(readFileSync(join(dir, "input"), "utf8"), "xxxxBOOMyyyyzzzzwwwwvvvvuuuu");
  assert.match(readFileSync(join(dir, "reporte.txt"), "utf8"), /SUMMARY: AddressSanitizer: heap-buffer-overflow/);
  assert.ok(statSync(join(dir, "repro.sh")).mode & 0o100, "repro.sh es ejecutable");
  assert.match(readFileSync(join(dir, "repro.sh"), "utf8"), /cd "\$\(dirname "\$0"\)\/\.\.\/\.\.\/\.\.\/\.\.\/\.\." \|\| exit 1\nASAN_OPTIONS=\S+ UBSAN_OPTIONS=\S+ MSAN_OPTIONS=\S+ harness\/out\/xml\/xml -timeout=10 .*harness\/out\/xml\/crashes\/[0-9a-f]{12}\/input\.min\n$/);
  const artefacto = JSON.parse(engine.artifacts.read(crash.artefacto).toString());
  assert.equal(Buffer.from(artefacto.input.base64, "base64").toString(), "BOOM");
  assert.equal(artefacto.input.bytes_original, 28);
  assert.equal(artefacto.tipo, "heap-buffer-overflow");
  assert.match(artefacto.reproducir, /input\.min$/);
  assert.match(artefacto.reporte, /parse_header/);
  assert.match(engine.artifacts.read(corrida.log).toString(), /^\$ .*-max_total_time=30/);
  // Lo que recibió el fuzzer: topes, prefijo, corpus propio primero, sin red ni secretos en el entorno.
  const fuzz = lab.records().filter((item) => item.prog === "fuzzer");
  const principal = fuzz[0]!;
  for (const expected of ["-max_total_time=30", "-timeout=10", "-rss_limit_mb=2048", "-malloc_limit_mb=2048", "-print_final_stats=1", `-dict=${join(lab.cwd, "dict.txt")}`]) assert.ok(principal.args.includes(expected), expected);
  assert.ok(principal.args.some((arg) => arg.startsWith(`-artifact_prefix=${join(lab.cwd, "harness", "out", "xml", "corridas")}`)));
  assert.deepEqual(principal.args.slice(-2), [join(lab.cwd, "harness", "out", "xml", "corpus"), join(lab.cwd, "semillas")]);
  const env = principal.env as Record<string, string>;
  assert.match(env.ASAN_OPTIONS!, /detect_leaks=1/);
  assert.match(env.ASAN_OPTIONS!, new RegExp(`external_symbolizer_path=${lab.binarios.symbolizer}`));
  assert.match(env.UBSAN_OPTIONS!, /halt_on_error=1/);
  assert.equal(env.HOME, join(lab.cwd, "harness", "out", "xml"));
  assert.ok(!Object.keys(env).some((key) => /KEY|TOKEN|PROXY|CYBER/i.test(key)), Object.keys(env).join(","));
  assert.equal(fuzz.filter((item) => item.args.includes("-minimize_crash=1")).length, 1);
  assert.ok(fuzz.find((item) => item.args.includes("-minimize_crash=1"))!.args.some((arg) => arg === `-exact_artifact_path=${join(dir, "input.min")}`));
  // Otra corrida: el mismo crash ya está visto, no se vuelve a minimizar.
  const segunda = await correrFuzzer(entorno, { harness: "xml", seconds: 30, corpus: ["semillas"] }, signal);
  assert.equal(segunda.crashes[0]!.nuevo, false);
  assert.equal(segunda.crashes[0]!.vistas, 2);
  assert.equal(segunda.crashes[0]!.firma, crash.firma);
  assert.equal(lab.records().filter((item) => item.args.includes("-minimize_crash=1")).length, 1);
  assert.deepEqual(crashesConocidos(entorno, "xml").map((item) => item.firma), [crash.firma]);
  // Con procesos en paralelo (-fork): dos variantes del mismo crash, uno de UBSan y un timeout.
  const fork = await correrFuzzer(entorno, { harness: "xml", seconds: 30, corpus: ["semillas"], workers: 2 }, signal);
  assert.ok(lab.records().filter((item) => item.prog === "fuzzer").some((item) => item.args.includes("-fork=2") && item.args.includes("-ignore_crashes=1")));
  assert.deepEqual(fork.crashes.map((item) => [item.tipo, item.nuevo]), [["signed-integer-overflow", true], ["timeout", true], ["heap-buffer-overflow", false]]);
  const ub = fork.crashes[0]!;
  assert.equal(ub.clase, "ub");
  assert.match(ub.impacto, /^Overflow aritmético/);
  assert.equal(readFileSync(join(lab.cwd, ub.input), "utf8"), "UBSAN", "el de UBSan también se minimizó");
  assert.equal(fork.crashes[1]!.minimizado, false, "un timeout no se minimiza");
  assert.equal(fork.timeouts, 1);
  const text = textoCorrida(fork);
  assert.match(text, /^Fuzzing de xml: 30 s, 5000 ejecuciones \(2500\/s\), cobertura 42, corpus \+7 en harness\/out\/xml\/corpus\.\n2 crashes distintos \(1 nuevo\) · 1 timeout · 0 oom\./);
  assert.match(text, /- nuevo · signed-integer-overflow en compute_len parser\.c:77 ← parse_doc parser\.c:95 ← LLVMFuzzerTestOneInput xml\.c:8 · firma [0-9a-f]{12}/);
  assert.match(text, /- ya visto \(3 veces\) · heap-buffer-overflow \(WRITE de 4\)/);
  assert.match(text, /reproducir: harness\/out\/xml\/xml -timeout=10 /);
  assert.match(text, /Siguiente: poc_run \{ harness: "xml", crash: "[0-9a-f]{12}" \}/);
}, { procesosMax: 2 }));

test("fuzz_run: sin crashes, un binario que no arranca y la cancelación del turno", () => conMotor(async (lab, engine, entorno) => {
  assert.equal((await compilarHarness(entorno, { sources: ["harness/xml.c"] }, signal)).ok, true);
  const limpia = await correrFuzzer(entorno, { harness: "xml", seconds: 10, corpus: ["semillas-limpias"] }, signal);
  assert.equal(limpia.fin, "tiempo");
  assert.equal(limpia.crashes.length, 0);
  assert.equal(limpia.corpusNuevo, 7);
  assert.match(textoCorrida(limpia), /Sin crashes\.\n.*\nSin crashes no prueba nada/);
  writeFileSync(join(lab.cwd, "semillas-limpias", "roto"), "ROTO");
  const tool = engine.catalog.available.get("fuzz_run")!;
  const roto = await tool.execute({ harness: "xml", seconds: 10, corpus: ["semillas-limpias"] }, signal);
  assert.equal(roto.isError, true);
  assert.match(roto.text, /^xml no arrancó\.\nEl binario no llegó a correr entradas \(sanitizer-no-arranca: .*\)\. Es el entorno, no el objetivo: .*vm\.mmap_rnd_bits=32/);
  rmSync(join(lab.cwd, "semillas-limpias", "roto"));
  writeFileSync(join(lab.cwd, "semillas-limpias", "colgar"), "COLGAR");
  const controller = new AbortController();
  const started = Date.now();
  setTimeout(() => controller.abort(), 600);
  const cancelada = await correrFuzzer(entorno, { harness: "xml", seconds: 600, corpus: ["semillas-limpias"] }, controller.signal);
  assert.equal(cancelada.fin, "cancelado");
  assert.ok(Date.now() - started < 15_000, `tardó ${Date.now() - started} ms en cortar`);
  // Los topes del modelo no pasan los del operador.
  const tope = await correrFuzzer(entorno, { harness: "xml", seconds: 99_999, memory_mb: 999_999, corpus: ["semillas"], minimize: false, leaks: false }, signal);
  const ultimo = lab.records().filter((item) => item.prog === "fuzzer" && item.args.some((arg) => arg.startsWith("-max_total_time="))).at(-1)!;
  assert.ok(ultimo.args.includes(`-max_total_time=${entorno.limites.fuzzSegMax}`) && ultimo.args.includes(`-rss_limit_mb=${entorno.limites.memoriaMbMax}`) && ultimo.args.includes("-detect_leaks=0"));
  assert.equal(tope.segundos, entorno.limites.fuzzSegMax);
}));

test("poc_run: determinista, no determinista y no reproduce; la firma esperada; un PoC con argumentos o stdin", () => conMotor(async (lab, engine, entorno) => {
  assert.equal((await compilarHarness(entorno, { sources: ["harness/xml.c"] }, signal)).ok, true);
  const corrida = await correrFuzzer(entorno, { harness: "xml", seconds: 10, corpus: ["semillas"] }, signal);
  const firma = corrida.crashes[0]!.firma;
  const det = await reproducirPoc(entorno, { harness: "xml", crash: firma.slice(0, 8) }, signal);
  assert.equal(det.veredicto, "determinista");
  assert.equal(det.veces, 5);
  assert.equal(det.corridas, 5);
  assert.equal(det.reproduce, true);
  assert.equal(det.exitCode, 1);
  assert.equal(det.input, `harness/out/xml/crashes/${firma}/input.min`);
  assert.deepEqual(det.esperada, { firma, coincide: true });
  assert.equal(det.reporte!.tipo, "heap-buffer-overflow");
  const flaky = await reproducirPoc(entorno, { harness: "xml", input: "flaky", runs: 5 }, signal);
  assert.equal(flaky.veredicto, "no determinista");
  assert.equal(flaky.veces, 3);
  const limpio = await reproducirPoc(entorno, { harness: "xml", input: "limpio", runs: 3 }, signal);
  assert.equal(limpio.veredicto, "no reproduce");
  assert.deepEqual([limpio.corridas, limpio.reproduce, limpio.exitCode], [3, false, 0]);
  assert.match(limpio.salida, /Executed .*limpio in 1 ms/, "sin crash, la salida de la última corrida");
  const otra = await reproducirPoc(entorno, { harness: "xml", input: "boom", firma: "ffffffffffff" }, signal);
  assert.equal(otra.veredicto, "determinista");
  assert.deepEqual(otra.esperada, { firma: "ffffffffffff", coincide: false });
  await assert.rejects(reproducirPoc(entorno, { harness: "xml", input: "boom", crash: firma }, signal), /uno solo/);
  await assert.rejects(reproducirPoc(entorno, { harness: "xml", input: "boom", args: ["@@"] }, signal), /args y stdin son para PoCs/);
  await assert.rejects(compilarHarness(entorno, { sources: ["harness/xml.c"], sanitizers: "address" as never }, signal).then((item) => assert.deepEqual(item.sanitizers, ["address"])).then(() => { throw new Error("texto suelto aceptado como lista"); }), /texto suelto aceptado como lista/);
  await assert.rejects(reproducirPoc(entorno, { harness: "xml", crash: "abcdef" }, signal), /no tiene un crash abcdef/);
  // Por la herramienta, como la ve el modelo y la TUI.
  const tool = engine.catalog.available.get("poc_run")!;
  const result = await tool.execute({ harness: "xml", input: "flaky", runs: 4 }, signal);
  assert.match(result.text, /^poc_run xml sobre flaky: reproduce 2 de 4: no determinista \([0-9a-f]{12}×2, sin crash×2\)\./);
  assert.match(result.text, /buscá estado global, hilos, tiempo o aleatoriedad/);
  assert.deepEqual(result.details, { reproduce: true, corridas: 4, exitCode: 1, artefacto: result.details!.artefacto }, "lo que lee /investigar: reproduce, corridas y exitCode (de la última corrida)");
  // Un PoC con main: argumentos con @@, tope de memoria del sanitizer y la entrada por stdin.
  assert.equal((await compilarHarness(entorno, { sources: ["harness/poc.c"] }, signal)).ok, true);
  const poc = await reproducirPoc(entorno, { harness: "poc", input: "boom", args: ["--entrada", "@@"], runs: 2 }, signal);
  assert.equal(poc.veredicto, "determinista");
  const ultimo = lab.records().at(-1)!;
  assert.deepEqual(ultimo.args, ["--entrada", join(lab.cwd, "boom")]);
  assert.match((ultimo.env as Record<string, string>).ASAN_OPTIONS!, /hard_rss_limit_mb=2048/);
  const stdin = await reproducirPoc(entorno, { harness: "poc", input: "boom", stdin: true, runs: 1 }, signal);
  assert.equal(stdin.veredicto, "determinista");
  assert.deepEqual(lab.records().at(-1)!.args, [], "por stdin, sin el archivo como argumento");
  assert.match(stdin.command, /harness\/out\/poc\/poc < boom$/);
  // fuzz_run con un PoC: lo corre sobre cada entrada del corpus.
  const sobreCorpus = await correrFuzzer(entorno, { harness: "poc", corpus: ["semillas"], seconds: 30 }, signal);
  assert.equal(sobreCorpus.tipo, "poc");
  assert.equal(sobreCorpus.ejecuciones, 2);
  assert.deepEqual(sobreCorpus.crashes.map((item) => [item.tipo, item.minimizado]), [["heap-buffer-overflow", false]]);
  await assert.rejects(correrFuzzer(entorno, { harness: "poc" }, signal), /Un PoC no muta entradas/);
}));

test("command: lo que devuelven fuzz_run y poc_run se vuelve a correr con poc_run y runPoc, sin shell", () => conMotor(async (lab, engine, entorno) => {
  const build = await compilarHarness(entorno, { sources: ["harness/xml.c"] }, signal);
  const corrida = await correrFuzzer(entorno, { harness: "xml", seconds: 10, corpus: ["semillas"] }, signal);
  const crash = corrida.crashes[0]!;
  // Los artefactos de las tres herramientas traen command: el de la corrida es el del crash principal.
  assert.equal(corrida.command, crash.reproducir);
  const resumen = JSON.parse(engine.artifacts.read(corrida.artefacto).toString());
  assert.equal(resumen.command, crash.reproducir);
  assert.match(resumen.fuzz_command, /-max_total_time=10/);
  assert.equal(resumen.crashes[0].command, crash.reproducir);
  assert.equal(JSON.parse(engine.artifacts.read(crash.artefacto).toString()).command, crash.reproducir);
  assert.equal(JSON.parse(engine.artifacts.read(build.artefacto).toString()).command, build.comando, "el de harness_build reproduce la compilación");
  const poc = await compilarHarness(entorno, { sources: ["harness/poc.c"] }, signal);
  assert.match(JSON.parse(engine.artifacts.read(poc.artefacto).toString()).run_command, /^ASAN_OPTIONS=\S+ UBSAN_OPTIONS=\S+ MSAN_OPTIONS=\S+ harness\/out\/poc\/poc$/);
  // El command del crash, tal cual, desde la raíz del proyecto.
  const otra = await reproducirPoc(entorno, { command: crash.reproducir, runs: 3 }, signal);
  assert.deepEqual([otra.veredicto, otra.corridas, otra.exitCode, otra.reproduce, Object.keys(otra.firmas)], ["determinista", 3, 1, true, [crash.firma]]);
  assert.equal(otra.input, crash.input);
  assert.equal(otra.cwd, ".");
  assert.equal(otra.command, crash.reproducir, "el command que devuelve es el mismo que recibió");
  const json = JSON.parse(engine.artifacts.read(otra.artefacto).toString());
  assert.deepEqual([json.command, json.reproduce, json.corridas, json.exitCode], [crash.reproducir, true, 3, 1]);
  // runPoc, la forma corta para inyectar en la verificación: { exitCode, reproduce, corridas, salida }.
  const corto = await runPoc(entorno, { command: crash.reproducir, cwd: ".", runs: 2, timeoutMs: 5_000, signal });
  assert.deepEqual([corto.exitCode, corto.reproduce, corto.corridas], [1, true, 2]);
  assert.match(corto.salida, /SUMMARY: AddressSanitizer: heap-buffer-overflow/);
  assert.ok(lab.records().at(-1)!.args.includes("-timeout=5"), "timeoutMs llega como tope por corrida");
  const limpio = await pocRunner(entorno)({ command: "harness/out/xml/xml -timeout=3 limpio", runs: 1 });
  assert.deepEqual([limpio.exitCode, limpio.reproduce, limpio.corridas, limpio.veredicto], [0, false, 1, "no reproduce"]);
  // Desde otra carpeta, con rutas relativas a ella; y un PoC con argumentos y con «<».
  const desde = await reproducirPoc(entorno, { command: `./xml crashes/${crash.firma}/input.min`, cwd: "harness/out/xml", runs: 1 }, signal);
  assert.deepEqual([desde.veredicto, desde.cwd], ["determinista", "harness/out/xml"]);
  assert.match(desde.command, new RegExp(`MSAN_OPTIONS=\\S+ xml -timeout=\\d+ .* crashes/${crash.firma}/input\\.min$`));
  const argumentos = await reproducirPoc(entorno, { command: "harness/out/poc/poc --entrada boom", runs: 1 }, signal);
  assert.deepEqual([argumentos.veredicto, argumentos.input], ["determinista", "boom"]);
  assert.deepEqual(lab.records().at(-1)!.args, ["--entrada", "boom"]);
  const conStdin = await reproducirPoc(entorno, { command: "ASAN_OPTIONS=detect_leaks=0 harness/out/poc/poc < 'boom'", runs: 1 }, signal);
  assert.equal(conStdin.veredicto, "determinista");
  assert.match((lab.records().at(-1)!.env as Record<string, string>).ASAN_OPTIONS!, /detect_leaks=0/, "las opciones del command que importan se respetan");
  assert.match(conStdin.command, / harness\/out\/poc\/poc < boom$/);
  // Por la herramienta, como la llama /investigar.
  const tool = engine.catalog.available.get("poc_run")!;
  const result = await tool.execute({ command: crash.reproducir, cwd: "." }, signal);
  assert.deepEqual([result.details!.reproduce, result.details!.corridas, result.details!.exitCode], [true, 5, 1]);
  assert.match(result.text, /^poc_run xml sobre harness\/out\/xml\/crashes\/[0-9a-f]{12}\/input\.min: reproduce 5 de 5: determinista/);
  // Lo que necesitaría un shell, un binario que no es de prueba o rutas de afuera: nada corre.
  const antes = lab.records().length;
  for (const [command, error] of [
    ["harness/out/xml/xml boom | cat", /«\|» no se acepta/], ["harness/out/xml/xml boom; id", /«;» no se acepta/], ["harness/out/xml/xml $(id)", /«\$» no se acepta/], ["harness/out/xml/xml boom > /tmp/x", /«>» no se acepta/],
    ["harness/out/xml/xml 'boom", /comillas sin cerrar/], ["LD_PRELOAD=/tmp/x.so harness/out/xml/xml boom", /LD_PRELOAD no/], ["/bin/ls boom", /fuera de la carpeta del proyecto/], ["harness/xml.c boom", /no lo compiló harness_build ni tiene sanitizers/],
    ["harness/out/xml/xml", /acá hay 0/], ["harness/out/xml/xml boom limpio", /acá hay 2/], ["harness/out/xml/xml < boom", /no por «<»/], ["harness/out/poc/poc /etc/passwd", /sale de la carpeta del proyecto/], ["harness/out/poc/poc < boom < limpio", /un solo «< archivo»/],
  ] as Array<[string, RegExp]>) await assert.rejects(reproducirPoc(entorno, { command }, signal), error, command);
  await assert.rejects(reproducirPoc(entorno, { command: crash.reproducir, harness: "xml" }, signal), /command va solo/);
  await assert.rejects(reproducirPoc(entorno, { command: "xml boom", cwd: "../afuera" }, signal), /fuera de la carpeta del proyecto/);
  await assert.rejects(reproducirPoc(entorno, { harness: "xml", input: "boom", cwd: "." }, signal), /cwd va con command/);
  assert.equal(lab.records().length, antes, "ningún command rechazado llegó a correr");
  assert.deepEqual(palabrasComando(`A_OPTIONS='x y' "./a b" c\\ d < 'e f'`), { palabras: ["A_OPTIONS=x y", "./a b", "c d"], stdin: "e f" });
}));

test("fuera de la caja no se ofrece nada y el núcleo de herramientas no cambia", async () => {
  const lab = laboratorio();
  const provider = resolveProvider("faux");
  const afuera = new Engine({ cwd: lab.cwd, provider, autoVerify: false, rea: false, fuzzing: { enCaja: false, binarios: lab.binarios } });
  const apagado = new Engine({ cwd: lab.cwd, provider: resolveProvider("faux"), autoVerify: false, rea: false, fuzzing: false });
  const adentro = motor(lab, true);
  try {
    assert.equal(afuera.fuzzing, undefined);
    for (const name of HERRAMIENTAS_FUZZ) {
      assert.ok(!afuera.catalog.available.has(name), `${name} no está afuera`);
      assert.ok(adentro.catalog.available.has(name), `${name} está en la caja`);
      assert.ok(!adentro.catalog.loaded().includes(name), `${name} es por demanda, no del núcleo`);
    }
    // El núcleo (lo que ve el modelo sin pedir nada) es el mismo adentro y afuera; afuera, el prompt también.
    const nucleo = (engine: Engine) => engine.agent.tools.map((tool) => tool.name);
    assert.deepEqual(nucleo(adentro), nucleo(afuera));
    assert.deepEqual(nucleo(afuera), nucleo(apagado));
    assert.equal(afuera.agent.system, apagado.agent.system, "fuera de la caja el prompt queda igual que sin la función");
    assert.doesNotMatch(afuera.agent.system, /harness y fuzzing|harness-fuzzing|harness_build/);
    assert.match(adentro.catalog.summary(), /^harness y fuzzing: harness_build \((Compilar harness|Build harness)\), fuzz_run \((Correr fuzzer|Run fuzzer)\), poc_run \(PoC\)$/m);
    assert.match(adentro.agent.system, /^harness-fuzzing — Un objetivo en C\/C\+\+/m);
    // Pedirlas afuera: dice por qué no están y no arranca nada.
    provider.faux!.queue = [call("tools_load", { names: ["harness_build", "fuzz_run"] }), call("skill_load", { name: "harness-fuzzing" }), { text: "Listo." }];
    await afuera.send("Compilá un harness para el parser");
    const replies = afuera.agent.messages.filter((message) => message.role === "tool");
    assert.match(String(replies.find((message) => message.name === "tools_load")!.content), /No existen: harness_build, fuzz_run\. harness_build, fuzz_run y poc_run corren sólo dentro de la caja de Orobas/);
    assert.match(String(replies.find((message) => message.name === "skill_load")!.content), /No existe la habilidad «harness-fuzzing»/);
    // Adentro, la habilidad carga sus herramientas.
    const next = resolveProvider("faux");
    const conSkill = new Engine({ cwd: lab.cwd, provider: next, autoVerify: false, rea: false, fuzzing: { enCaja: true, binarios: lab.binarios } });
    try {
      next.faux!.queue = [call("skill_load", { name: "harness-fuzzing" }), { text: "Listo." }];
      await conSkill.send("Fuzzeá el parser");
      const skill = String(conSkill.agent.messages.filter((message) => message.role === "tool").find((message) => message.name === "skill_load")!.content);
      assert.match(skill, /Herramientas cargadas: harness_build, fuzz_run, poc_run, code_list, code_search, code_read, code_semgrep\./);
      assert.match(skill, /## Un crash sin ganancia no es un hallazgo/);
      assert.doesNotMatch(skill, /salida truncada/, "la habilidad entra entera en el tope de salida del harness");
    } finally {
      await conSkill.close();
    }
    assert.equal(lab.records().length, 0, "crear las sesiones no compiló ni corrió nada");
    assert.equal(fuzzDisponible(false, lab.binarios.clang), false);
    assert.equal(fuzzDisponible(true, join(lab.root, "no-hay-clang")), false);
    assert.equal(fuzzEntorno({ cwd: lab.cwd, artifacts: afuera.artifacts }, { enCaja: true, binarios: { clang: join(lab.root, "no-hay-clang") } }), undefined, "una caja vieja sin clang tampoco las ofrece");
    assert.match(fuzzStatus({ enCaja: false }).join("\n"), /^clang {6}· (sólo en la caja|box only)/);
  } finally {
    await afuera.close();
    await apagado.close();
    await adentro.close();
    lab.clean();
  }
});

test("clasificarReporte: ASan, UBSan, MSan, LSan y libFuzzer, con firma estable y sin el runtime", () => {
  const hbo = clasificarReporte(`INFO: Seed: 1\n${ASAN_HBO}`)!;
  assert.equal(hbo.sanitizer, "AddressSanitizer");
  assert.equal(hbo.scariness, "45 (4-byte-write-heap-buffer-overflow)");
  assert.equal(hbo.resumen, "AddressSanitizer: heap-buffer-overflow /proyecto/lib/parser.c:42:13 in parse_header");
  assert.deepEqual(hbo.propios.map((frame) => frame.funcion), ["parse_header", "parse_doc", "LLVMFuzzerTestOneInput"], "sin __asan_memcpy, libFuzzer, libc ni _start");
  // Otras direcciones, la misma firma; otra función arriba, otra firma.
  assert.equal(clasificarReporte(ASAN_HBO.replace(/0x[0-9a-f]+/g, "0xdeadbeef"))!.firma, hbo.firma);
  assert.notEqual(clasificarReporte(ASAN_HBO.replace("in parse_header /proyecto", "in parse_body /proyecto"))!.firma, hbo.firma);
  const segv = clasificarReporte("AddressSanitizer:DEADLYSIGNAL\n=================================================================\n==7==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x55 bp 0x7f sp 0x7f T0)\n==7==The signal is caused by a READ memory access.\n==7==Hint: address points to the zero page.\n    #0 0x55 in get_attr /src/lib/attr.c:12:10\n    #1 0x56 in main /src/harness/poc.c:20:3\nSUMMARY: AddressSanitizer: SEGV /src/lib/attr.c:12:10 in get_attr\n")!;
  assert.deepEqual([segv.tipo, segv.clase, segv.acceso?.op], ["SEGV", "memoria", "READ"]);
  assert.match(segv.impacto, /^Desreferencia de nulo/);
  const df = clasificarReporte("==9==ERROR: AddressSanitizer: attempting double-free on 0x602000000010 in thread T0:\n    #0 0x1 in free /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:52:3\n    #1 0x2 in node_free /src/lib/tree.c:88:5\n")!;
  assert.deepEqual([df.tipo, nombre(df)], ["double-free", "node_free"]);
  assert.match(df.impacto, /^Liberación inválida/);
  const uaf = clasificarReporte("==9==ERROR: AddressSanitizer: heap-use-after-free on address 0x6 at pc 0x1 bp 0x2 sp 0x3\nREAD of size 8 at 0x6 thread T0\n    #0 0x1 in cache_get /src/lib/cache.c:30:12\n")!;
  assert.match(uaf.impacto, /^Lectura de memoria liberada/);
  const leak = clasificarReporte("\n=================================================================\n==11==ERROR: LeakSanitizer: detected memory leaks\n\nDirect leak of 7 byte(s) in 1 object(s) allocated from:\n    #0 0x4 in malloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:69:3\n    #1 0x5 in LLVMFuzzerTestOneInput /proyecto/harness/xml.c:6:15\n\nSUMMARY: AddressSanitizer: 7 byte(s) leaked in 1 allocation(s).\n")!;
  assert.deepEqual([leak.tipo, leak.clase, leak.enHarness], ["leak", "leak", true], "la reserva que no se libera está en el harness");
  const msan = clasificarReporte("==12==WARNING: MemorySanitizer: use-of-uninitialized-value\n    #0 0x7 in decode_len /src/lib/der.c:41:7\n    #1 0x8 in LLVMFuzzerTestOneInput /proyecto/harness/der.c:9:3\n")!;
  assert.deepEqual([msan.tipo, msan.clase, nombre(msan)], ["use-of-uninitialized-value", "memoria", "decode_len"]);
  const ub = clasificarReporte(UBSAN_SIO)!;
  assert.deepEqual([ub.tipo, ub.clase, nombre(ub)], ["signed-integer-overflow", "ub", "compute_len"]);
  for (const [linea, tipo] of [["shift exponent 40 is too large for 32-bit type 'int'", "shift"], ["index 9 out of bounds for type 'int[8]'", "array-bounds"], ["applying non-zero offset 16 to null pointer", "pointer-overflow"], ["member access within null pointer of type 'struct node'", "null"], ["load of value 7, which is not a valid value for type 'bool'", "invalid-value"]] as Array<[string, string]>) {
    assert.equal(clasificarReporte(`x.c:1:2: runtime error: ${linea}\n`)!.tipo, tipo, linea);
  }
  assert.equal(clasificarReporte("main: runtime error: algo del programa\n"), undefined, "un mensaje del programa no es UBSan");
  const timeout = clasificarReporte(TIMEOUT)!;
  assert.deepEqual([timeout.tipo, timeout.clase, nombre(timeout)], ["timeout", "timeout", "skip_comments"]);
  assert.deepEqual([clasificarReporte("==1== ERROR: libFuzzer: out-of-memory (used: 2100Mb; exceeds: 2048Mb)\n")!.tipo, clasificarReporte("==1== ERROR: libFuzzer: out-of-memory (malloc(4294967296))\n")!.clase], ["oom-rss", "oom"]);
  assert.deepEqual([clasificarReporte("==1== ERROR: libFuzzer: fuzz target exited\n")!.clase, clasificarReporte("==1== ERROR: libFuzzer: deadly signal\n")!.clase], ["harness", "señal"]);
  assert.equal(clasificarReporte("==1==ERROR: AddressSanitizer: requested allocation size 0xffffffffff (0x100000000 after adjustments) exceeds maximum supported size of 0x10000000000 (thread T0)\n")!.clase, "oom");
  assert.equal(clasificarReporte("==1==ERROR: AddressSanitizer: hard rss limit exhausted (2048Mb vs 2100Mb)\n")!.tipo, "oom-rss");
  assert.equal(clasificarReporte("==1==LeakSanitizer has encountered a fatal error.\n")!.clase, "entorno");
  assert.equal(clasificarReporte("AddressSanitizer:DEADLYSIGNAL\nAddressSanitizer:DEADLYSIGNAL\n")!.clase, "entorno");
  assert.equal(clasificarReporte("INFO: Seed: 1\nDone 10 runs in 1 second(s)\n"), undefined);
  // Frames: con BuildId, sólo módulo y funciones de C++ con espacios.
  assert.deepEqual(parsearFrame("    #5 0x7f0001 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29d8f) (BuildId: 89c3cb85f9e5)"), { n: 5, funcion: "__libc_start_main", modulo: "libc.so.6+0x29d8f" });
  assert.deepEqual(parsearFrame("    #3 0x55d (/proyecto/harness/out/xml/xml+0x12f3)"), { n: 3, modulo: "xml+0x12f3" });
  assert.deepEqual(parsearFrame("    #4 0x55 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/FuzzerLoop.cpp:611:15"), { n: 4, funcion: "fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long)", archivo: "/src/FuzzerLoop.cpp", linea: 611 });
  assert.deepEqual(parsearFrame("    #1 0x55 in operator new(unsigned long)"), { n: 1, funcion: "operator new(unsigned long)" });
});

const nombre = (reporte: { propios: Array<{ funcion?: string }> }) => reporte.propios[0]?.funcion;

test("límites: los del operador por entorno, los de fábrica y los techos", () => {
  const base = limitesFuzz({}, {});
  assert.equal(base.fuzzSeg, 120);
  assert.equal(base.memoriaMb, 2048);
  const operador = limitesFuzz({}, { CYBER_FUZZ_SEG: "600", CYBER_FUZZ_SEG_MAX: "300", CYBER_FUZZ_MB: "512", CYBER_FUZZ_PROCESOS_MAX: "3", CYBER_FUZZ_MB_MAX: "nada" });
  assert.deepEqual([operador.fuzzSeg, operador.fuzzSegMax, operador.memoriaMb, operador.procesosMax, operador.memoriaMbMax], [300, 300, 512, 3, 8192], "lo pedido no pasa el techo; lo inválido se ignora");
});

test("imagen: clang 16 con libFuzzer y sanitizers, enlaces que usa el código y el corte de red probado al construir", () => {
  const docker = readFileSync(join(import.meta.dirname, "..", "distro", "Dockerfile"), "utf8");
  for (const paquete of [`clang-${FUZZ.llvm}`, `libclang-rt-${FUZZ.llvm}-dev`, `llvm-${FUZZ.llvm}`, "build-essential", "cmake", "autoconf", "automake", "libtool", "pkg-config", "meson", "ninja-build"]) assert.match(docker, new RegExp(`--no-install-recommends[^\\n]*(?:\\n[^\\n]*)?\\b${paquete.replace(/[+]/g, "\\+")}\\b`), paquete);
  assert.ok(docker.includes(`for tool in clang clang++ llvm-symbolizer llvm-cov llvm-profdata; do ln -sf /usr/lib/llvm-${FUZZ.llvm}/bin/$tool /usr/local/bin/$tool; done`));
  for (const path of [FUZZ.clang, FUZZ.clangxx, FUZZ.symbolizer]) assert.ok(path.startsWith("/usr/local/bin/"), path);
  assert.ok(docker.includes("COPY distro/fuzz/sin-red.c /opt/fuzz/sin-red.c"));
  assert.ok(docker.includes("-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined prueba.c sin-red.o -Wl,--export-dynamic-symbol=socket"), "la imagen prueba el mismo enlace que harness_build");
  assert.match(docker, /if \[ "\$\(dpkg --print-architecture\)" = amd64 \]; then ASAN_OPTIONS=detect_leaks=0 \.\/prueba -runs=3; fi/, "arm64 se construye emulado: sólo compila");
  assert.match(docker, /socket\(AF_INET, SOCK_STREAM, 0\) >= 0\) __builtin_trap\(\)/, "la prueba falla si el corte deja abrir un socket de red");
  const corte = readFileSync(FUZZ.sinRed, "utf8");
  assert.match(corte, /int socket\(int domain, int type, int protocol\) \{\n {2}if \(domain == 1 \/\* AF_UNIX \*\/\) return \(int\)syscall\(SYS_socket, domain, type, protocol\);\n {2}errno = EACCES;\n {2}return -1;\n\}/);
  assert.match(docker, /COPY distro \.\/distro/, "el código lee el corte desde distro/ en la imagen");
});

test("pantalla: harness y fuzzing en /herramientas a 80 columnas y una corrida en la conversación", async () => {
  for (const [lines, expected] of [[fuzzStatus({ enCaja: false }), /clang {6}· (sólo en la caja|box only)/], [fuzzStatus({ enCaja: true, instalado: true }), /clang {6}✓ LLVM 16 · libFuzzer, ASan, UBSan, MSan/], [fuzzStatus({ enCaja: true, instalado: false }), /clang {6}✗ (falta en esta imagen|missing from this image) · cyber --actualizar/]] as Array<[string[], RegExp]>) {
    const view = toolboxView(["rea        · sólo en la caja"], ["nmap       ✓ /usr/bin/nmap"], lines);
    const { io } = fakeIO({ toolbox: view }, [0]);
    const panel = (await findCommand("herramientas")!.run(io, ""))!;
    const rows = dibujarPanel(panel, 80).map(stripAnsi);
    const screen = rows.join("\n");
    assert.match(screen, expected);
    assert.match(screen, /HARNESS Y FUZZING \(habilidad harness-fuzzing\)|HARNESS AND FUZZING \(harness-fuzzing skill\)/);
    for (const row of rows) assert.ok(visibleWidth(row) <= 80, `más de 80 columnas: «${row}»`);
    for (const line of lines) assert.ok(visibleWidth(line) <= 72, line);
  }
  await conMotor(async (_lab, engine) => {
    const registro = new Registro(() => 0);
    const texts = new Map<string, string>();
    const runs: Array<[string, object]> = [["harness_build", { sources: ["harness/xml.c"] }], ["fuzz_run", { harness: "xml", seconds: 10, corpus: ["semillas"] }], ["poc_run", { harness: "xml", input: "boom", runs: 2 }], ["harness_build", { sources: ["harness/roto.c"] }]];
    for (const [index, [name, args]] of runs.entries()) {
      const tool = engine.catalog.available.get(name)!;
      const result = await tool.execute(args, signal);
      texts.set(`c${index}`, result.text);
      registro.evento({ type: "tool_start", id: `c${index}`, name: tool.name, label: tool.label } as never);
      registro.evento({ type: "tool_end", id: `c${index}`, name: tool.name, isError: result.isError === true, text: result.text, details: result.details ?? {} } as never);
    }
    const chat = PESTANA_CHAT as Pestana & { tipo: "conversacion" };
    const rows = dibujar(chat, registro.entradas(), { ancho: 80, expandidas: new Set<number>(), resultados: (e: { llamada?: string }) => texts.get(e.llamada ?? "") }).lineas.map((row) => stripAnsi(truncate(row, 80)));
    const screen = rows.join("\n");
    assert.match(screen, /(Compilar harness|Build harness) · harness xml · artefacto [0-9a-f]{12}$/m);
    assert.match(screen, /(Correr fuzzer|Run fuzzer) · crashes 1 · nuevos 1 · artefacto [0-9a-f]{12}$/m);
    assert.match(screen, /PoC · reproduce true · corridas 2 · exitCode 1 · artefacto [0-9a-f]{12}$/m);
    assert.match(screen, /(Compilar harness|Build harness) · No compiló roto \(salida 1\)/);
    assert.doesNotMatch(screen, /SUMMARY: AddressSanitizer/, "el reporte no se vuelca en la conversación");
  });
});
