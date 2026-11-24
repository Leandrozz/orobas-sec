import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { abrirProyecto, ajustes, arregloGuardado, guardarArreglo, elegirIdioma, guardarAjuste, guardarMouse, guardarPestanas, guardarTema, guardarDescifrado, temaGuardado, descifradoGuardado, idiomaGuardado, mouseGuardado, pestanasGuardadas, ultraGuardado, guardarUltra, ULTRA_POR_DEFECTO } from "../src/tui/ajustes.ts";
import { PESTANA_CHAT, validarPestanas } from "../src/tui/pestanas.ts";

test("ajustes: se recuerdan por ruta de proyecto, sin pisar otros proyectos ni el resto de la configuración", () => {
  const prev = { c: process.env.CYBER_CONFIG, l: process.env.LC_ALL };
  process.env.CYBER_CONFIG = join(mkdtempSync(join(tmpdir(), "cyber-ajustes-")), "config.json");
  const read = () => JSON.parse(readFileSync(process.env.CYBER_CONFIG!, "utf8"));
  try {
    abrirProyecto("");
    guardarAjuste("model", "glm");
    assert.deepEqual(ajustes(), {}, "sin proyecto no se guarda nada");
    elegirIdioma("en");
    assert.equal(read().idioma, "en", "sin proyecto, el idioma va a la parte general");

    abrirProyecto("/a");
    assert.match(process.env.LC_ALL ?? "", /^en/, "un proyecto sin elección usa el idioma general");
    guardarAjuste("model", "glm");
    guardarAjuste("budget", "5");
    elegirIdioma(undefined);
    assert.equal(idiomaGuardado(), undefined, "«sistema» en el proyecto gana sobre el general");
    assert.deepEqual(ajustes(), { model: "glm", budget: "5", idioma: "sistema" });

    abrirProyecto("/b");
    assert.deepEqual(ajustes(), {});
    guardarAjuste("model", "qwen");
    guardarAjuste("budget", undefined);
    assert.deepEqual(read().proyectos, { "/a": { model: "glm", budget: "5", idioma: "sistema" }, "/b": { model: "qwen" } });
    assert.equal(read().idioma, "en");
  } finally {
    abrirProyecto("");
    if (prev.c === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev.c;
    if (prev.l === undefined) delete process.env.LC_ALL; else process.env.LC_ALL = prev.l;
  }
});

test("pestañas: por defecto «Chat» con todo, inválidas caen al defecto, valen para todos los proyectos", () => {
  const prev = process.env.CYBER_CONFIG;
  process.env.CYBER_CONFIG = join(mkdtempSync(join(tmpdir(), "cyber-pestanas-")), "config.json");
  try {
    abrirProyecto("/p");
    assert.deepEqual(pestanasGuardadas(), [PESTANA_CHAT]);
    assert.deepEqual(validarPestanas("x"), [PESTANA_CHAT]);
    assert.deepEqual(validarPestanas([]), [PESTANA_CHAT]);
    assert.deepEqual(validarPestanas([{ nombre: "Perú", tipo: "conversacion", contenido: ["comandos", "nada"], detalle: "completo" }, { tipo: "vista", vista: "otra" }]),
      [{ nombre: "Perú", tipo: "conversacion", contenido: ["comandos"], detalle: "completo" }]);
    guardarPestanas([PESTANA_CHAT, { nombre: "Hallazgos", tipo: "vista", vista: "hallazgos" }]);
    assert.equal(pestanasGuardadas()[1]!.nombre, "Hallazgos");
    assert.equal(mouseGuardado(), true);
    assert.equal(mouseGuardado({ CYBER_CONSOLE: "conhost" }), false);
    assert.equal(mouseGuardado({ TERM_PROGRAM: "Apple_Terminal" }), false);
    assert.equal(mouseGuardado({ WT_SESSION: "x" }), true);
    guardarMouse(false);
    assert.equal(mouseGuardado(), false);
    guardarMouse(true);
    assert.equal(mouseGuardado({ CYBER_CONSOLE: "conhost" }), true, "lo guardado manda");
    guardarMouse(false);
    abrirProyecto("/otro");
    assert.equal(pestanasGuardadas()[1]!.nombre, "Hallazgos", "otro proyecto ve las mismas pestañas");
    assert.equal(arregloGuardado().pestanas[0]![1]!.nombre, "Hallazgos");
    guardarArreglo({ forma: "lado", pestanas: [[PESTANA_CHAT], [PESTANA_CHAT]], divisores: { x: 0.6 }, lista: true });
    abrirProyecto("/tercero");
    assert.equal(arregloGuardado().forma, "lado", "las ventanas también");
    assert.equal(arregloGuardado().divisores.x, 0.6);
  } finally {
    abrirProyecto("");
    if (prev === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev;
  }
});

test("ventanas: un arreglo viejo guardado en el proyecto se usa mientras no haya uno general", () => {
  const prev = process.env.CYBER_CONFIG;
  process.env.CYBER_CONFIG = join(mkdtempSync(join(tmpdir(), "cyber-ventanas-")), "config.json");
  try {
    writeFileSync(process.env.CYBER_CONFIG, JSON.stringify({ proyectos: { "/viejo": { ventanas: { forma: "tres", pestanas: [], divisores: {}, lista: false } } } }));
    abrirProyecto("/viejo");
    assert.equal(arregloGuardado().forma, "tres");
    abrirProyecto("/nuevo");
    assert.equal(arregloGuardado().forma, "una", "otro proyecto sin general: el defecto");
    guardarArreglo({ forma: "cuatro", pestanas: [], divisores: {}, lista: false });
    abrirProyecto("/viejo");
    assert.equal(arregloGuardado().forma, "cuatro", "una vez guardado en general, manda el general");
  } finally {
    abrirProyecto("");
    if (prev === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev;
  }
});

test("ajustes: una escritura que falla devuelve el aviso, no tira, y el cambio vale en la sesión", () => {
  const prev = process.env.CYBER_CONFIG;
  const archivo = join(mkdtempSync(join(tmpdir(), "cyber-ajustes-")), "f");
  writeFileSync(archivo, "");
  const ruta = join(archivo, "config.json"); // un archivo común hace de carpeta: ENOTDIR
  process.env.CYBER_CONFIG = ruta;
  try {
    abrirProyecto("/p");
    const aviso = guardarMouse(false);
    assert.ok(aviso?.includes(ruta));
    assert.equal(mouseGuardado(), false);
    assert.match(elegirIdioma("en") ?? "", /config\.json/);
    assert.equal(idiomaGuardado(), "en");
  } finally {
    if (prev === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev;
    process.env.CYBER_CONFIG = join(mkdtempSync(join(tmpdir(), "cyber-ajustes-")), "config.json");
    abrirProyecto("");
    guardarAjuste("model", undefined);
    elegirIdioma(undefined);
  }
});

test("ajustes: un config con BOM se lee, y uno ilegible no se pisa al guardar", () => {
  const prev = process.env.CYBER_CONFIG;
  const path = join(mkdtempSync(join(tmpdir(), "cyber-ajustes-")), "config.json");
  process.env.CYBER_CONFIG = path;
  try {
    writeFileSync(path, "﻿" + JSON.stringify({ idioma: "en" }));
    abrirProyecto("");
    assert.equal(idiomaGuardado(), "en");
    writeFileSync(path, "{ roto");
    abrirProyecto("/q");
    assert.match(guardarMouse(false) ?? "", /JSON/);
    assert.equal(readFileSync(path, "utf8"), "{ roto");
  } finally {
    if (prev === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev;
    abrirProyecto("");
  }
});

test("ajustes: tras un guardado fallido y el archivo arreglado a mano, el próximo guardado conserva los proveedores", () => {
  const prev = process.env.CYBER_CONFIG;
  const path = join(mkdtempSync(join(tmpdir(), "cyber-ajustes-")), "config.json");
  process.env.CYBER_CONFIG = path;
  try {
    writeFileSync(path, "{ roto");
    abrirProyecto("/r");
    assert.match(guardarMouse(false) ?? "", /JSON/);
    writeFileSync(path, JSON.stringify({ providers: [{ id: "x" }], mcp: { a: 1 }, proyectos: { "/otro": { mouse: true } } }));
    assert.equal(guardarMouse(true), undefined);
    const guardado = JSON.parse(readFileSync(path, "utf8"));
    assert.deepEqual(guardado.providers, [{ id: "x" }]);
    assert.deepEqual(guardado.mcp, { a: 1 });
    assert.equal(guardado.proyectos["/otro"].mouse, true);
    assert.equal(guardado.proyectos["/r"].mouse, true);
  } finally {
    if (prev === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev;
    abrirProyecto("");
  }
});

test("tema: se recuerda y es el mismo en dos proyectos", () => {
  const prev = process.env.CYBER_CONFIG;
  process.env.CYBER_CONFIG = join(mkdtempSync(join(tmpdir(), "cyber-tema-")), "config.json");
  try {
    abrirProyecto("/a");
    guardarTema("hornero");
    guardarDescifrado(false);
    abrirProyecto("/b");
    assert.equal(temaGuardado(), "hornero");
    assert.equal(descifradoGuardado(), false);
    writeFileSync(process.env.CYBER_CONFIG, JSON.stringify({ tema: "xyz" }));
    assert.equal(temaGuardado(), "orobas");
    assert.equal(descifradoGuardado(), false, "se guarda en memoria: no relee el archivo en cada consulta");
    abrirProyecto("/b");
    assert.equal(descifradoGuardado(), true, "al abrir el proyecto se relee");
  } finally {
    abrirProyecto("");
    if (prev === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev;
  }
});

test("tema: con el archivo ilegible se aplica igual, avisa y no lo pisa", () => {
  const prev = process.env.CYBER_CONFIG;
  process.env.CYBER_CONFIG = join(mkdtempSync(join(tmpdir(), "cyber-tema-")), "config.json");
  try {
    abrirProyecto("/a");
    writeFileSync(process.env.CYBER_CONFIG, "{roto");
    const aviso = guardarTema("hacker");
    assert.ok(aviso?.includes(process.env.CYBER_CONFIG));
    assert.equal(readFileSync(process.env.CYBER_CONFIG, "utf8"), "{roto");
    assert.equal(temaGuardado(), "hacker");
    assert.ok(guardarDescifrado(false));
    assert.equal(descifradoGuardado(), false);
    assert.equal(temaGuardado(), "hacker");
  } finally {
    abrirProyecto("");
    if (prev === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev;
  }
});

test("ultra: se recuerda en general y se ignora lo inválido", () => {
  const prev = process.env.CYBER_CONFIG;
  process.env.CYBER_CONFIG = join(mkdtempSync(join(tmpdir(), "cyber-ultra-")), "config.json");
  const escribir = (ultra: unknown) => writeFileSync(process.env.CYBER_CONFIG!, JSON.stringify({ ultra }));
  try {
    abrirProyecto("/uno");
    assert.deepEqual(ultraGuardado(), { partes: "auto", modo: "repo" });
    const elegido = { harnesses: ["claude", "codex"], partes: 3, modo: "objetivo" as const };
    guardarUltra(elegido);
    abrirProyecto("/otro");
    assert.deepEqual(ultraGuardado(), elegido, "es general, no por proyecto");
    escribir({ harnesses: ["claude", 7, "Mal!"], partes: 9, modo: "x" });
    assert.deepEqual(ultraGuardado(), { harnesses: ["claude"], partes: "auto", modo: "repo" });
    escribir("basura");
    assert.deepEqual(ultraGuardado(), ULTRA_POR_DEFECTO);
  } finally {
    abrirProyecto("");
    if (prev === undefined) delete process.env.CYBER_CONFIG; else process.env.CYBER_CONFIG = prev;
  }
});
