import "./datos-tmp.ts";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { TerminalImages } from "../src/tui/images.ts";
import { decodeAsset, encodeSixel, resizeRaster, textRaster } from "../src/tui/raster.ts";
import { Sigil } from "../src/tui/sigil.ts";
import { detectTerminal, ImageReplies, imageProtocol } from "../src/tui/terminal.ts";
import { stripAnsi, visibleWidth } from "../src/tui/text.ts";

const png = readFileSync(new URL("../src/tui/assets/orobas/frames-transparentes/011.png", import.meta.url));

test("terminal: capacidad según protocolo, con alternativa visible en Windows y en terminales sin imágenes", () => {
  assert.equal(imageProtocol(detectTerminal({ TERM: "xterm-kitty" })), "kitty");
  assert.equal(imageProtocol(detectTerminal({ TERM_PROGRAM: "ghostty" })), "kitty");
  assert.equal(imageProtocol(detectTerminal({ TERM_PROGRAM: "iTerm.app" })), "iterm2");
  assert.equal(imageProtocol(detectTerminal({ TERM_PROGRAM: "WezTerm" })), "iterm2");
  assert.equal(imageProtocol(detectTerminal({ TERM_FEATURES: "T1BSx" })), "sixel");
  assert.equal(imageProtocol(detectTerminal({ WT_SESSION: "windows-session" })), "braille", "Windows antiguo no se trata como si soportara imágenes");
  assert.equal(imageProtocol(detectTerminal({ TERM: "xterm-256color", TMUX: "socket" })), "braille");
  assert.equal(imageProtocol(detectTerminal({ TERM: "dumb" })), "ascii");
  const plain = detectTerminal({ TERM: "xterm-kitty", NO_COLOR: "1" });
  assert.equal(imageProtocol(plain), "braille");
  assert.equal(plain.color, false);
});

test("Windows Terminal: DA1 con Sixel selecciona imagen; respuesta fragmentada y teclas quedan separadas", () => {
  const terminal = detectTerminal({ WT_SESSION: "windows-session" });
  const replies = new ImageReplies();
  assert.equal(replies.consume("hola\x1b[?65;1;", terminal).input, "hola");
  assert.equal(replies.consume("4;22cmundo", terminal).input, "mundo");
  assert.equal(imageProtocol(terminal), "sixel");
  assert.equal(replies.consume(`\x1b_Gi=${replies.queryId};ENOTSUP\x1b\\`, terminal).input, "");
  assert.equal(imageProtocol(terminal), "sixel");
  assert.equal(replies.consume("\x1b[6;18;9t/", terminal).input, "/");
  assert.equal(terminal.cellHeight, 18);
  assert.equal(terminal.cellWidth, 9);
});

test("una variable de Kitty heredada por otra terminal no prevalece sobre las capacidades consultadas", () => {
  const terminal = detectTerminal({ KITTY_WINDOW_ID: "heredado", TERM: "xterm" });
  assert.equal(imageProtocol(terminal), "kitty");
  new ImageReplies().consume("\x1b[?63;1;4;22c", terminal);
  assert.equal(imageProtocol(terminal), "sixel");
});

test("iTerm: reconoce las capacidades con BEL o ST sin insertarlas en el editor; forzar texto respeta la elección", () => {
  const terminal = detectTerminal({});
  const replies = new ImageReplies();
  assert.equal(replies.consume("\x1b]1337;Capabilities=T1BF", terminal).input, "");
  assert.equal(replies.consume("\x07texto", terminal).input, "texto");
  assert.equal(imageProtocol(terminal), "iterm2");
  const text = detectTerminal({ CYBER_GRAPHICS: "braille" });
  replies.consume("\x1b[?65;4c", text);
  assert.equal(imageProtocol(text), "braille");
});

test("respuestas fragmentadas byte a byte, incluso ESC y terminador, no se convierten en teclas", () => {
  const terminal = detectTerminal({});
  const replies = new ImageReplies();
  const response = `\x1b_Gi=${replies.queryId};OK\x1b\\\x1b[6;22;10t\x1b[?65;4c\x1b]1337;Capabilities=T1BF\x07`;
  for (const char of response) assert.equal(replies.consume(char, terminal).input, "");
  assert.equal(imageProtocol(terminal), "kitty");
  assert.equal(terminal.cellHeight, 22);
  assert.equal(replies.consume("hola", terminal).input, "hola");
  replies.consume("\x1b_Gincompleto", terminal);
  assert.equal(replies.flush(), "", "una respuesta truncada se descarta sin contaminar el prompt");
  assert.equal(replies.consume("texto", terminal).input, "texto");
});

test("PNG: la decodificación de los recursos conserva todos los canales RGBA aprobados", () => {
  const decoded = decodeAsset(png);
  assert.deepEqual([decoded.width, decoded.height], [820,700]);
  assert.equal(createHash("sha256").update(decoded.data).digest("hex"), "d6c1983560717445f9fa64a8b134b5260c089d70d34e8d11c4d834bb0661eae4");
  const small = resizeRaster(decoded, 100, 85);
  assert.equal(small.data.length, 100*85*4);
  assert.ok(small.data.some((value) => value > 0));
  assert.throws(() => decodeAsset(Buffer.from("no es png")), /firma PNG/);
});

test("alternativa universal: mismo sello en Braille/ASCII, acotado al tamaño y sin escapes de imagen", () => {
  const sigil = new Sigil(false);
  for (const mode of ["braille", "ascii"] as const) {
    const terminal = detectTerminal({ CYBER_GRAPHICS: mode });
    const view = sigil.view(60, 22, terminal);
    assert.equal(view.image, undefined);
    assert.equal(view.lines.length, 22);
    assert.ok(view.lines.every((line) => visibleWidth(line) <= 60));
    const plain = view.lines.map(stripAnsi).join("\n");
    assert.match(plain, /OROBAS/);
    if (mode === "braille") assert.match(plain, /[\u2801-\u28ff]/);
    else assert.ok([...plain].every((char) => char.charCodeAt(0) < 128));
    assert.doesNotMatch(view.lines.join(""), /\x1b_G|\x1bP/);
  }
  const monochrome = textRaster(decodeAsset(png), 40, 16, false);
  assert.doesNotMatch(monochrome.join(""), /\x1b/);
});

test("Sixel e iTerm: protocolos distintos, con el PNG original en inline y Sixel de dimensiones reales", () => {
  const sigil = new Sigil(false), transport = new TerminalImages();
  const sixel = sigil.view(60, 22, detectTerminal({ CYBER_GRAPHICS: "sixel", CYBER_CELL_SIZE: "10x20" })).image!;
  const encoded = transport.place(sixel);
  assert.match(encoded, /^\x1bP0;1;0q"1;1;\d+;\d+#/);
  assert.ok(encoded.endsWith("\x1b\\"));
  assert.doesNotMatch(encoded, /\x1b_G/);
  assert.ok(sixel.pixelHeight! <= sixel.rows*20);
  const inline = sigil.view(60, 22, detectTerminal({ CYBER_GRAPHICS: "iterm2" })).image!;
  const command = transport.place(inline);
  assert.match(command, /^\x1b\]1337;File=inline=1;/);
  const payload = command.slice(command.indexOf(":")+1,-1);
  assert.deepEqual(Buffer.from(payload,"base64"), png);
});

test("Sixel sin tamaño de celda: muestra Braille hasta recibir una medida real, para no invadir el editor", () => {
  const terminal = detectTerminal({ CYBER_GRAPHICS: "sixel" });
  const sigil = new Sigil(false);
  assert.equal(sigil.view(60,22,terminal).image, undefined);
  const replies = new ImageReplies();
  terminal.columns = 100; terminal.rows = 40;
  replies.consume("\x1b[4;680;800t", terminal);
  assert.equal(terminal.cellHeight,17);
  assert.equal(terminal.cellWidth,8);
  assert.equal(sigil.view(60,22,terminal).image?.protocol, "sixel");
});

test("Sixel: un píxel transparente no se pinta y los bits de cada banda representan la coordenada vertical", () => {
  const pixels = Buffer.alloc(2*6*4);
  for (const [x,y] of [[0,0],[1,5]]) {
    const i = (y!*2+x!)*4;
    pixels[i] = 212; pixels[i+1] = 226; pixels[i+2] = 238; pixels[i+3] = 255;
  }
  const sixel = encodeSixel({ width:2,height:6,data:pixels },2,6);
  assert.match(sixel, /#31@_\x1b\\$/); // 63 + bit0 = '@'; 63 + bit5 = '_'
});

test("CYBER_CONSOLE=conhost fuerza el sello ASCII aunque TERM diga xterm-256color", () => {
  const terminal = detectTerminal({ TERM: "xterm-256color", CYBER_CONSOLE: "conhost" });
  assert.equal(imageProtocol(terminal), "ascii");
  assert.equal(terminal.graphics, false);
});
