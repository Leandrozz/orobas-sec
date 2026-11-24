const $ = (id) => document.getElementById(id);
const ago = (ms) => { const s = Math.round((Date.now() - ms) / 1000); return s < 60 ? `hace ${s} s` : s < 3600 ? `hace ${Math.round(s / 60)} min` : s < 172800 ? `hace ${Math.round(s / 3600)} h` : `hace ${Math.round(s / 86400)} días`; };
async function render() {
  const stored = await chrome.storage.local.get(null);
  const { token = "", paused = false, wrong = 0, old = 0, ultimo = 0 } = stored;
  const connected = Object.entries(stored).filter(([key, at]) => key.startsWith("seen:") && Date.now() - at < 40000).length;
  const [status, hint] = !token ? ["sin emparejar", "Corré «orobas-sec extension» (o «cyber extension») en tu terminal, pegá acá el código que muestra y tocá Conectar. Es una sola vez por máquina."]
    : paused ? ["en pausa", "Ningún agente usa este navegador hasta que toques Reanudar."]
    : connected ? [`${connected} ${connected === 1 ? "cyber conectado" : "cyber conectados"}`, "Listo. El agente sólo usa este navegador en los proyectos donde lo autorizaste (/navegador si) y sólo en sitios del alcance."]
    : Date.now() - old < 40000 ? ["actualizá cyber (habla un protocolo viejo)", "Corré «cyber --actualizar» y volvé a abrir el agente."]
    : Date.now() - wrong < 40000 ? ["código incorrecto", "El código no coincide con el del agente: corré «orobas-sec extension» de nuevo y pegá el código que muestra."]
    : ["esperando al agente", `No hay ningún orobas-sec usando este navegador en esta máquina ahora${ultimo ? ` (el último habló ${ago(ultimo)})` : ""}. No hace falta hacer nada: se conecta solo cuando abrís un proyecto que lo tiene autorizado (/navegador si en la TUI) o cuando el agente lo pide. En la TUI, /navegador dice qué falta.`];
  $("status").textContent = status;
  $("hint").textContent = hint;
  $("pause").textContent = paused ? "Reanudar" : "Pausar";
  $("token").placeholder = token ? "emparejado (pegá otro para cambiarlo)" : "lo muestra «cyber extension»";
}
$("save").onclick = async () => { const token = $("token").value.trim(); if (token) await chrome.storage.local.set({ token, paused: false, wrong: 0 }); $("token").value = ""; setTimeout(render, 1500); };
$("pause").onclick = async () => { const { paused } = await chrome.storage.local.get({ paused: false }); await chrome.storage.local.set({ paused: !paused }); render(); };
// Abrir el popup despierta a la extensión (si estaba dormida) para que busque agentes ya; el estado se refresca solo.
chrome.storage.local.set({ despertar: Date.now() }).catch(() => {});
render();
setInterval(render, 2000);
