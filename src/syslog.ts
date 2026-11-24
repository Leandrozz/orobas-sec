// Canal syslog de laboratorio (modo purple): UDP en la IP que declaró el operador. Cada línea que
// llega se guarda (últimas 400), va a artefacto y se matchea contra las señales esperadas del
// ledger: la que coincide se marca como detectada (hit automático). La aguja es el texto de la
// señal (id de regla «sigma:sql-error» o etiqueta del operador), insensible a mayúsculas. El
// modelo no abre ni cierra el canal: lo abre el operador (comando) o el runner.
import { createSocket, type Socket } from "node:dgram";
import type { AddressInfo } from "node:net";
import type { DetectionLedger, DetectionSignal } from "./deteccion.ts";

export interface SyslogConfig {
  host: string;
  port?: number;
}

export interface SyslogHit {
  at: string;
  from: string;
  line: string;
  señal: string;
}

export interface SyslogChannel {
  port: number;
  lines: string[];
  hits: SyslogHit[];
  /** Avisa al motor cuando una línea activa una señal esperada: evento y aviso al operador. */
  onHit?: (hit: SyslogHit) => void;
  close(): Promise<void>;
}

export function startSyslogChannel(config: SyslogConfig, ledger: DetectionLedger, onHit?: (hit: { at: string; from: string; line: string; señal: string }) => void): Promise<SyslogChannel> {
  if (!/^(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]+)$/i.test(config.host) || ["0.0.0.0", "::"].includes(config.host)) {
    throw new Error("El canal syslog necesita una IP local concreta declarada por el operador; no admite comodines ni nombres");
  }
  const lines: string[] = [];
  const hits: SyslogHit[] = [];
  const socket = createSocket("udp4");
  const channel: SyslogChannel = {
    port: 0,
    lines,
    hits,
    close: () => new Promise((resolve) => socket.close(() => resolve())),
  };
  return new Promise((resolve, reject) => {
    socket.on("error", (error) => reject(error));
    socket.on("message", (buffer, remote) => {
      const line = buffer.toString("utf8").slice(0, 4_000).trim();
      if (!line) return;
      lines.push(`${new Date().toISOString()} ${remote.address} ${line}`);
      if (lines.length > 400) lines.splice(0, lines.length - 400);
      // La señal esperada es un texto (id de regla o etiqueta): el match es por subcadena insensible.
      const lower = line.toLowerCase();
      const pending = ledger.signals().filter((signal) => !signal.detectada);
      const matched = pending.find((signal) => lower.includes(signal.esperada.trim().toLowerCase()));
      if (matched) {
        ledger.hit(matched.accion);
        const hit: SyslogHit = { at: new Date().toISOString(), from: remote.address, line: line.slice(0, 200), señal: matched.esperada };
        hits.push(hit);
        onHit?.(hit);
      }
    });
    socket.bind(config.port ?? 0, config.host, () => {
      channel.port = (socket.address() as AddressInfo).port;
      resolve(channel);
    });
  });
}