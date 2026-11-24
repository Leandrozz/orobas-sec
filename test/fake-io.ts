import type { CommandIO, CycleResult, Panel } from "../src/tui/comandos.ts";

/** Interfaz simulada: registra lo que se pidió al daemon y responde con lo programado. */
export function fakeIO(answers: Record<string, string[]>, picks: Array<number | undefined> = [], inputs: Array<string | undefined> = []) {
  const calls: Array<{ op: string; payload: object }> = [];
  const picked: Array<{ title: string; labels: string[]; hints: Array<string | undefined>; at?: number; footer?: string; cycle?: (index: number, step: 1 | -1) => Promise<CycleResult> }> = [];
  const notices: Panel[] = [];
  const confirms: string[] = [];
  const io: CommandIO = {
    ask: async (op, payload = {}) => { calls.push({ op, payload }); return answers[`${op}:${JSON.stringify(payload)}`] ?? answers[op] ?? [`${op} ok`]; },
    view: async (name, arg = "") => { calls.push({ op: `view:${name}`, payload: { arg } }); return answers[`view:${name}`] ?? [`${name} ${arg}`.trim()]; },
    pick: async (title, rows, options) => { picked.push({ title, labels: rows.map((row) => (typeof row === "string" ? row : row.label)), hints: rows.map((row) => (typeof row === "string" ? undefined : row.hint)), at: options?.at, footer: options?.footer, cycle: options?.cycle }); return picks.shift(); },
    input: async () => inputs.shift(),
    confirm: async (question) => { confirms.push(question); return picks.shift() === 0; },
    status: () => ({ model: "orobas/x" }),
    clear: () => void calls.push({ op: "clear", payload: {} }),
    exit: () => void calls.push({ op: "exit", payload: {} }),
    resume: () => void calls.push({ op: "resume", payload: {} }),
    keys: () => ["Enter envía"],
    notice: (panel) => void notices.push(panel),
  };
  return { io, calls, picked, notices, confirms };
}
