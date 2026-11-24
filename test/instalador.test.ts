// install.sh de punta a punta contra un servidor de releases falso: releases armados con scripts/release/armar.sh y
// firmados con una clave de prueba generada acá. Instala en un HOME y un TMPDIR propios dentro de .pruebas/.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { appendFileSync, cpSync, existsSync, lstatSync, mkdirSync, readFileSync, readlinkSync, rmSync, writeFileSync } from "node:fs";
import { delimiter, join } from "node:path";
import { after, before, test } from "node:test";
import { aislado, BASICAS, borrar, carpetaPrueba, type Clave, ejecutable, firmar, hay, levantarServidor, marcarUltimo, nuevaClave, pathCon, publicar, repoFalso, sinTerminal, vacia } from "./releases-falsos.ts";

const skip = !hay("ssh-keygen") || !hay("curl") || !hay("git") ? "faltan ssh-keygen, curl o git" : false;
const IMAGEN = `ghcr.io/ejemplo/orobas@sha256:${"ab".repeat(32)}`;
let base = "";
let clave: Clave;
let otra: Clave;
let releases = "";

before(() => {
  if (skip) return;
  base = carpetaPrueba("instalador");
  clave = nuevaClave(base, "clave");
  otra = nuevaClave(base, "otra");
  const repo = repoFalso(base, clave, IMAGEN);
  releases = join(base, "releases");
  mkdirSync(releases);
  publicar(repo, releases, "v1.0.0", clave);
  publicar(repo, releases, "v1.1.0", clave);
});
after(() => {
  if (base) borrar(base);
});

let n = 0;
async function escenario(preparar?: (srv: string) => void) {
  const d = join(base, `e${++n}`);
  mkdirSync(d);
  const srv = join(d, "srv");
  cpSync(releases, srv, { recursive: true });
  marcarUltimo(srv, "v1.0.0");
  preparar?.(srv);
  const servidor = await levantarServidor(srv);
  const home = join(d, "home");
  const tmp = join(d, "tmp");
  mkdirSync(home);
  mkdirSync(tmp);
  const env: Record<string, string> = { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: home, TMPDIR: tmp, LANG: "es_AR.UTF-8", SHELL: "/bin/bash", CYBER_RELEASES_URL: servidor.url };
  const correr = (programa: string, args: string[], extra: Record<string, string> = {}) => {
    const [p, a] = sinTerminal(programa, args);
    return spawnSync(p, a, { encoding: "utf8", env: { ...env, ...extra }, cwd: d });
  };
  const instalar = (args: string[], extra: Record<string, string> = {}, script = join(srv, "v1.0.0/install.sh")) => correr("sh", [script, ...args], extra);
  const prefijo = join(home, ".local/share/orobas-sec");
  const bin = join(home, ".local/bin");
  const descargas = () => servidor.pedidos().filter((l) => l.startsWith("GET /releases/download/"));
  // Lo que no tiene que quedar después de una instalación que falló.
  const sinRestos = () => {
    assert.ok(!existsSync(join(home, ".local")), "no crea carpetas en el home");
    assert.ok(vacia(tmp), "no deja temporales");
  };
  return { d, srv, servidor, home, tmp, env, correr, instalar, prefijo, bin, descargas, sinRestos };
}

test("instalador: con firma y sumas válidas instala el modo nativo en el home, sin sudo, y el comando responde", { skip }, async () => {
  const e = await escenario();
  try {
    const r = e.instalar(["--si"]);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    // Primero dice qué va a hacer.
    assert.ok(r.stdout.indexOf("Voy a hacer esto") < r.stdout.indexOf("Firma y sumas verificadas"));
    assert.match(r.stdout, /Orobas v1\.0\.0 · modo nativo/);
    assert.match(r.stdout, /no instala herramientas de seguridad/);
    // bash en macOS usa ~/.bash_profile; en Linux, ~/.bashrc.
    assert.match(r.stdout, /no está en tu PATH[\s\S]*export PATH="\$HOME\/\.local\/bin:\$PATH"' >> ~\/\.bash(rc|_profile)/);
    assert.equal(readlinkSync(join(e.prefijo, "actual")), "versiones/v1.0.0");
    assert.ok(existsSync(join(e.prefijo, "versiones/v1.0.0/src/cli.ts")));
    assert.equal(readFileSync(join(e.prefijo, "install.sh"), "utf8"), readFileSync(join(e.srv, "v1.0.0/install.sh"), "utf8"));
    assert.match(readFileSync(join(e.prefijo, "instalacion.conf"), "utf8"), /^version=v1\.0\.0$[\s\S]*^modo=nativo$/m);
    const v = spawnSync(join(e.bin, "cyber"), ["--version"], { encoding: "utf8", env: e.env });
    assert.equal(v.stdout, "orobas-sec v1.0.0\n");
    assert.ok(vacia(e.tmp), "borra sus temporales");
    assert.ok(!r.stdout.includes("sudo ") && !existsSync(join(e.home, ".bashrc")), "no usa sudo ni toca el archivo de la shell");
  } finally {
    e.servidor.cerrar();
  }
});

test("instalador: correr dos veces la misma versión no cambia nada ni vuelve a bajar el paquete", { skip }, async () => {
  const e = await escenario();
  try {
    assert.equal(e.instalar(["--si"]).status, 0);
    const antes = readFileSync(join(e.bin, "cyber"), "utf8");
    const paquetes = () => e.descargas().filter((l) => l.endsWith(".tar.gz")).length;
    assert.equal(paquetes(), 1);
    const r = e.instalar(["--si"]);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /ya estaba extraída y verificada/);
    assert.equal(paquetes(), 1, "la segunda vez no baja el paquete");
    assert.equal(readFileSync(join(e.bin, "cyber"), "utf8"), antes);
    assert.ok(vacia(e.tmp));
  } finally {
    e.servidor.cerrar();
  }
});

const fallas: [string, (srv: string) => void, RegExp, string[]?][] = [
  ["una suma que no coincide", (srv) => appendFileSync(join(srv, "v1.0.0/orobas-sec-v1.0.0.tar.gz"), "x"), /La suma SHA-256 de orobas-sec-v1\.0\.0\.tar\.gz no coincide/],
  ["una firma alterada", (srv) => {
    const f = join(srv, "v1.0.0/SHA256SUMS.sig");
    const lineas = readFileSync(f, "utf8").split("\n");
    const i = 2;
    lineas[i] = lineas[i]!.slice(0, 10) + (lineas[i]![10] === "A" ? "B" : "A") + lineas[i]!.slice(11);
    writeFileSync(f, lineas.join("\n"));
  }, /La firma de SHA256SUMS de v1\.0\.0 no es válida/],
  ["una firma de otra clave", (srv) => firmar(otra, join(srv, "v1.0.0/SHA256SUMS")), /La firma de SHA256SUMS de v1\.0\.0 no es válida/],
  ["una lista cambiada sin volver a firmar", (srv) => {
    const f = join(srv, "v1.0.0/SHA256SUMS");
    writeFileSync(f, readFileSync(f, "utf8").replace(/^[0-9a-f]{64}(?=  install\.sh$)/m, "0".repeat(64)));
  }, /La firma de SHA256SUMS de v1\.0\.0 no es válida/],
  ["un release incompleto (la lista firmada no nombra install.sh)", (srv) => {
    const f = join(srv, "v1.0.0/SHA256SUMS");
    writeFileSync(f, readFileSync(f, "utf8").replace(/^.*  install\.sh\n/m, ""));
    firmar(clave, f);
  }, /no trae install\.sh en SHA256SUMS \(release incompleto\)/],
  ["un release incompleto (falta el paquete en el servidor)", (srv) => rmSync(join(srv, "v1.0.0/orobas-sec-v1.0.0.tar.gz")), /No pude bajar .*orobas-sec-v1\.0\.0\.tar\.gz/],
  ["un release sin firma", (srv) => rmSync(join(srv, "v1.0.0/SHA256SUMS.sig")), /No pude bajar .*SHA256SUMS\.sig/],
  ["la lista firmada de otra versión", (srv) => {
    for (const f of ["SHA256SUMS", "SHA256SUMS.sig"]) cpSync(join(srv, "v1.0.0", f), join(srv, "v1.1.0", f));
  }, /El SHA256SUMS firmado no es el de v1\.1\.0/, ["--version", "v1.1.0"]],
];
for (const [nombre, preparar, mensaje, args] of fallas) {
  test(`instalador: con ${nombre} no instala nada, no deja restos y sale con error`, { skip }, async () => {
    const e = await escenario(preparar);
    try {
      const r = e.instalar(["--si", ...(args ?? [])]);
      assert.equal(r.status, 1, r.stdout);
      assert.match(r.stderr, mensaje);
      e.sinRestos();
    } finally {
      e.servidor.cerrar();
    }
  });
}

test("instalador: una falla al actualizar deja la instalación anterior como estaba", { skip }, async () => {
  const e = await escenario((srv) => appendFileSync(join(srv, "v1.1.0/orobas-sec-v1.1.0.tar.gz"), "x"));
  try {
    assert.equal(e.instalar(["--si"]).status, 0);
    const conf = readFileSync(join(e.prefijo, "instalacion.conf"), "utf8");
    const comando = readFileSync(join(e.bin, "cyber"), "utf8");
    const r = e.instalar(["--si", "--version", "v1.1.0"]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /no coincide/);
    assert.equal(readFileSync(join(e.prefijo, "instalacion.conf"), "utf8"), conf);
    assert.equal(readFileSync(join(e.bin, "cyber"), "utf8"), comando);
    assert.equal(readlinkSync(join(e.prefijo, "actual")), "versiones/v1.0.0");
    assert.ok(!existsSync(join(e.prefijo, "versiones/v1.1.0")));
    assert.ok(vacia(e.tmp));
  } finally {
    e.servidor.cerrar();
  }
});

test("instalador: corrido con zsh (el shell de macOS) instala igual, y una falla sale con código de error", { skip: skip || (!hay("zsh") && "no hay zsh") }, async () => {
  const e = await escenario();
  try {
    const r = e.correr("zsh", [join(e.srv, "v1.0.0/install.sh"), "--si"]);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /Firma y sumas verificadas/);
    const v = spawnSync(join(e.bin, "cyber"), ["--version"], { encoding: "utf8", env: e.env });
    assert.equal(v.stdout, "orobas-sec v1.0.0\n");
    assert.ok(vacia(e.tmp));
  } finally {
    e.servidor.cerrar();
  }
  // Una falla en zsh tiene que salir con código distinto de 0 y sin restos (el trap lee $? real).
  const f = await escenario((srv) => appendFileSync(join(srv, "v1.0.0/orobas-sec-v1.0.0.tar.gz"), "x"));
  try {
    const r = f.correr("zsh", [join(f.srv, "v1.0.0/install.sh"), "--si"]);
    assert.equal(r.status, 1, `salió con ${r.status}: ${r.stderr}`);
    assert.match(r.stderr, /La suma SHA-256 de orobas-sec-v1\.0\.0\.tar\.gz no coincide/);
    f.sinRestos();
  } finally {
    f.servidor.cerrar();
  }
});

// El trap de limpieza está afuera de main() (por zsh), así que limpiar() puede correr antes de que main() asigne nada:
// lo que limpiar() mira no puede venir del entorno. Con PREFIX_CREADO=1, «--prefix ~» borraba el home entero.
for (const shell of ["sh", "bash", "zsh"]) {
  test(`instalador: con TMPD, NUEVA, PREFIX_CREADO y las demás en el entorno no borra nada ajeno (${shell})`, { skip: skip || (!hay(shell) && `no hay ${shell}`) }, async () => {
    const e = await escenario();
    try {
      // Una instalación previa de este instalador y tres carpetas ajenas con datos.
      mkdirSync(e.prefijo, { recursive: true });
      writeFileSync(join(e.prefijo, "instalacion.conf"), `# orobas-sec: instalacion hecha por install.sh\nformato=1\nversion=v1.0.0\nmodo=nativo\nbin=${e.bin}\nanterior=\n`);
      ejecutable(join(e.bin, "cyber"), "#!/bin/sh\n# orobas-sec: comando instalado por install.sh (modo nativo). Lo reescribe el instalador: no lo edites.\n");
      const ajenas = ["ajena1", "ajena2", "ajena3"].map((a) => join(e.d, a));
      for (const a of ajenas) {
        mkdirSync(a);
        writeFileSync(join(a, "dato"), "no se borra");
      }
      writeFileSync(join(ajenas[2]!, "instalacion.conf"), "esto no es del instalador\n");
      const veneno = { TMPD: ajenas[0]!, NUEVA: ajenas[1]!, PREFIX: ajenas[2]!, BIN: ajenas[2]!, PREFIX_CREADO: "1", BIN_CREADO: "1", COMANDO_CREADO: "1", codigo: "0" };
      const casos: [string[], number, RegExp][] = [
        [["--ayuda"], 0, /Instalador de Orobas/],
        [["--opcion-que-no-existe"], 1, /opción desconocida/],
        [["--modo", "raro"], 1, /modo desconocido: raro/],
        [["--prefix", ajenas[2]!], 1, /no es de este instalador: no lo toco/],
        [["--prefix", "~"], 1, /No uso .* como carpeta de instalación/],
        [["--version", "v9.9.9", "--si"], 1, /No pude bajar/],
      ];
      for (const [args, codigo, mensaje] of casos) {
        const r = e.correr(shell, [join(e.srv, "v1.0.0/install.sh"), ...args], veneno);
        const caso = `${shell} install.sh ${args.join(" ")}`;
        assert.equal(r.status, codigo, `${caso}: ${r.stderr}`);
        assert.match(r.stdout + r.stderr, mensaje, caso);
        for (const a of ajenas) assert.ok(existsSync(join(a, "dato")), `${caso} borró ${a}`);
        assert.ok(existsSync(join(e.prefijo, "instalacion.conf")), `${caso} borró la instalación (o el home)`);
        assert.ok(existsSync(join(e.bin, "cyber")), `${caso} borró el comando`);
        assert.ok(vacia(e.tmp), `${caso} dejó temporales`);
      }
    } finally {
      e.servidor.cerrar();
    }
  });
}

test("instalador: sin terminal y sin --si muestra el plan, no baja nada y no instala", { skip: skip || (!aislado && "sin setsid -w no se puede sacar la terminal") }, async () => {
  const e = await escenario();
  try {
    const r = e.instalar([]);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /Voy a hacer esto/);
    assert.match(r.stderr, /No hay una terminal para confirmar: .*--si/);
    assert.deepEqual(e.descargas(), []);
    e.sinRestos();
  } finally {
    e.servidor.cerrar();
  }
});

test("instalador: sin Node (modo nativo) o sin ssh-keygen y curl explica qué falta y no instala nada", { skip }, async () => {
  const e = await escenario();
  try {
    const sinNode = e.instalar(["--si"], { PATH: pathCon(join(e.d, "sin-node"), BASICAS) });
    assert.equal(sinNode.status, 1);
    assert.match(sinNode.stderr, /Node 22\.19 o más nuevo \(no está instalado\)\. No lo instalo yo: bajalo de https:\/\/nodejs\.org/);
    assert.match(sinNode.stderr, /--modo contenedor/);
    const pocas = pathCon(join(e.d, "pocas"), [...BASICAS.filter((h) => h !== "curl" && h !== "ssh-keygen"), "node"]);
    const sinCurl = e.instalar(["--si"], { PATH: pocas });
    assert.equal(sinCurl.status, 1);
    assert.match(sinCurl.stderr, /- curl:[\s\S]*- ssh-keygen \(OpenSSH 8\.1 o más nuevo\)/);
    // El modo contenedor no pide Node, pide Docker.
    const sinDocker = e.instalar(["--si", "--modo", "contenedor"], { PATH: pathCon(join(e.d, "sin-node"), BASICAS) });
    assert.equal(sinDocker.status, 1);
    assert.match(sinDocker.stderr, /Docker \(el modo contenedor/);
    assert.doesNotMatch(sinDocker.stderr, /Node/);
    assert.deepEqual(e.descargas(), []);
    e.sinRestos();
  } finally {
    e.servidor.cerrar();
  }
});

test("instalador: modo contenedor instala el lanzador del release, con su versión y la imagen fijada por digest", { skip }, async () => {
  const e = await escenario();
  try {
    ejecutable(join(e.d, "falsos/docker"), "#!/bin/sh\nexit 0\n");
    const r = e.instalar(["--si", "--modo", "contenedor"], { PATH: `${join(e.d, "falsos")}:${e.env.PATH}` });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, new RegExp(`Imagen fijada por este release: ${IMAGEN.replace(/[.]/g, "\\.")}`));
    const lanzador = readFileSync(join(e.bin, "cyber"), "utf8");
    assert.equal(lanzador, readFileSync(join(e.srv, "v1.0.0/cyber-lanzador.sh"), "utf8"));
    assert.match(lanzador, /^VERSION_LANZADOR='v1\.0\.0'$/m);
    assert.match(lanzador, new RegExp(`^IMAGEN_RELEASE='${IMAGEN}'$`, "m"));
    assert.ok(lstatSync(join(e.bin, "cyber")).mode & 0o100);
    assert.ok(!existsSync(join(e.prefijo, "versiones")), "el modo contenedor no instala el paquete nativo");
    assert.match(readFileSync(join(e.prefijo, "instalacion.conf"), "utf8"), /^modo=contenedor$/m);
  } finally {
    e.servidor.cerrar();
  }
});

test("instalador: un release sin imagen fijada no ofrece el modo contenedor", { skip }, async () => {
  const e = await escenario((srv) => {
    const f = join(srv, "v1.0.0/SHA256SUMS");
    writeFileSync(f, readFileSync(f, "utf8").replace(/^.*cyber-lanzador.*\n/gm, ""));
    firmar(clave, f);
  });
  try {
    ejecutable(join(e.d, "falsos/docker"), "#!/bin/sh\nexit 0\n");
    const r = e.instalar(["--si", "--modo", "contenedor"], { PATH: `${join(e.d, "falsos")}:${e.env.PATH}` });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /no trae el modo contenedor \(no fijó una imagen\): usá --modo nativo/);
    e.sinRestos();
  } finally {
    e.servidor.cerrar();
  }
});

test("instalador: no pisa un «cyber» que no instaló él", { skip }, async () => {
  const e = await escenario();
  try {
    ejecutable(join(e.bin, "cyber"), "#!/bin/sh\necho otro programa\n");
    const r = e.instalar(["--si"]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /Ya existe .*\/cyber y no lo instaló este instalador: no lo piso/);
    assert.equal(readFileSync(join(e.bin, "cyber"), "utf8"), "#!/bin/sh\necho otro programa\n");
    assert.ok(!existsSync(e.prefijo));
  } finally {
    e.servidor.cerrar();
  }
});

test("instalador: --prefix y --bin propios; --desinstalar saca sólo lo suyo y deja los datos", { skip }, async () => {
  const e = await escenario();
  try {
    const prefijo = join(e.d, "otro lugar/orobas");
    const bin = join(e.d, "mis bin");
    mkdirSync(bin);
    writeFileSync(join(bin, "otro"), "no es nuestro\n");
    const r = e.instalar(["--si", "--prefix", prefijo, `--bin=${bin}`]);
    assert.equal(r.status, 0, r.stderr);
    assert.ok(existsSync(join(prefijo, "versiones/v1.0.0")));
    const datos = join(e.home, ".local/share/elevate-cyber");
    mkdirSync(datos, { recursive: true });
    writeFileSync(join(datos, "sesion"), "mis datos\n");
    if (aislado) {
      const sin = e.correr("sh", [join(prefijo, "install.sh"), "--desinstalar", "--prefix", prefijo]);
      assert.equal(sin.status, 1, "sin --si y sin terminal no desinstala");
      assert.ok(existsSync(prefijo));
    }
    const d = e.correr("sh", [join(prefijo, "install.sh"), "--desinstalar", "--si", "--prefix", prefijo]);
    assert.equal(d.status, 0, d.stderr);
    assert.match(d.stdout, /No toco tus datos/);
    assert.ok(!existsSync(prefijo));
    assert.ok(!existsSync(join(bin, "cyber")));
    assert.equal(readFileSync(join(bin, "otro"), "utf8"), "no es nuestro\n");
    assert.equal(readFileSync(join(datos, "sesion"), "utf8"), "mis datos\n");
  } finally {
    e.servidor.cerrar();
  }
});

test("instalador: cyber --actualizar instala el último release verificado, no baja de versión y dice cuando está al día", { skip }, async () => {
  const e = await escenario();
  try {
    assert.equal(e.instalar(["--si"]).status, 0);
    const cyber = join(e.bin, "cyber");
    const igual = e.correr(cyber, ["--actualizar", "--si"]);
    assert.equal(igual.status, 0, igual.stderr);
    assert.match(igual.stdout, /Ya tenés la última versión publicada \(v1\.0\.0\)/);
    marcarUltimo(e.srv, "v1.1.0");
    // Sin terminal y sin --si no se actualiza solo.
    if (aislado) {
      const sola = e.correr(cyber, ["--actualizar"]);
      assert.equal(sola.status, 1);
      assert.match(sola.stderr, /No hay una terminal para confirmar/);
      assert.equal(spawnSync(cyber, ["--version"], { encoding: "utf8", env: e.env }).stdout, "orobas-sec v1.0.0\n");
    }
    const r = e.correr(cyber, ["--actualizar", "--si"]);
    assert.equal(r.status, 0, r.stderr + r.stdout);
    assert.match(r.stdout, /Orobas v1\.1\.0 · modo nativo[\s\S]*Instalada ahora: v1\.0\.0/);
    assert.equal(spawnSync(cyber, ["--version"], { encoding: "utf8", env: e.env }).stdout, "orobas-sec v1.1.0\n");
    assert.ok(existsSync(join(e.prefijo, "versiones/v1.0.0")), "queda la anterior para volver atrás");
    assert.match(readFileSync(join(e.prefijo, "instalacion.conf"), "utf8"), /^version=v1\.1\.0$[\s\S]*^anterior=v1\.0\.0$/m);
    marcarUltimo(e.srv, "v1.0.0");
    const atras = e.correr(cyber, ["--actualizar", "--si"]);
    assert.equal(atras.status, 0);
    assert.match(atras.stdout, /más viejo que el instalado \(v1\.1\.0\): no bajo de versión/);
    assert.equal(spawnSync(cyber, ["--version"], { encoding: "utf8", env: e.env }).stdout, "orobas-sec v1.1.0\n");
  } finally {
    e.servidor.cerrar();
  }
});

test("instalador: una copia sin la clave real, una URL http fuera de esta máquina o una versión mal escrita no instalan", { skip }, async () => {
  const e = await escenario();
  try {
    const copia = join(e.d, "install-desarrollo.sh");
    writeFileSync(copia, readFileSync(join(e.srv, "v1.0.0/install.sh"), "utf8").replace(/^CLAVE_PUBLICA='.*'$/m, `CLAVE_PUBLICA='ssh-ed25519 ${"REEMPLAZAR"}-X'`));
    const dev = e.instalar(["--si"], {}, copia);
    assert.equal(dev.status, 1);
    assert.match(dev.stderr, /no trae la clave pública de los releases/);
    const http = e.instalar(["--si"], { CYBER_RELEASES_URL: "http://ejemplo.invalid/releases" });
    assert.equal(http.status, 1);
    assert.match(http.stderr, /tiene que ser https/);
    const mala = e.instalar(["--si", "--version", "1.0"]);
    assert.equal(mala.status, 1);
    assert.match(mala.stderr, /versión inválida: 1\.0/);
    e.sinRestos();
  } finally {
    e.servidor.cerrar();
  }
});

test("instalador: armar.sh escribe SHA256SUMS en formato «suma  nombre» aunque sha256sum marque binario con «*»", { skip }, () => {
  const d = join(base, "armar-estrella");
  mkdirSync(d, { recursive: true });
  const repo = repoFalso(d, clave, IMAGEN);
  const falsos = join(d, "falsos");
  const real = spawnSync("sh", ["-c", "command -v sha256sum"], { encoding: "utf8" }).stdout.trim();
  ejecutable(join(falsos, "sha256sum"), `#!/bin/sh\n"${real}" "$@" | sed 's/^\\([0-9a-f]\\{64\\}\\)  /\\1 */'\n`);
  const salida = join(d, "srv/v1.0.0");
  const r = spawnSync("sh", [join(repo, "scripts/release/armar.sh"), "v1.0.0", salida], {
    cwd: repo,
    encoding: "utf8",
    env: { ...process.env, PATH: falsos + delimiter + process.env.PATH, npm_config_offline: "true", npm_config_update_notifier: "false", npm_config_audit: "false", npm_config_fund: "false" },
  });
  assert.equal(r.status, 0, r.stderr + r.stdout);
  const sumas = readFileSync(join(salida, "SHA256SUMS"), "utf8").trim().split("\n");
  assert.ok(sumas.length >= 4, "el release trae varios archivos");
  for (const l of sumas) assert.match(l, /^[0-9a-f]{64}  \S+$/, `formato canónico: ${l}`);
});
