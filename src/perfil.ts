// Perfil de capacidades del proyecto: qué arsenal aplica, según el tipo de trabajo. Lo decide el
// operador (hablando o con /perfil); el modelo no lo cambia. El alcance lo aplica el ejecutor: el
// perfil añade (o quita) permisos sobre lo que el alcance ya autoriza, nunca lo amplía.
import type { DatabaseSync } from "node:sqlite";

export const PROFILES = ["bounty", "pentest", "laboratorio", "defensa", "full-blast"] as const;
export type CapabilityProfile = (typeof PROFILES)[number];

export const PROFILE_NOTES: Record<CapabilityProfile, string> = {
  bounty: "Programa de bug bounty: comportamiento estándar; escáneres dependen de /escaneres y de la política del programa; destructivos siempre detrás de guarda.",
  pentest: "Pentest autorizado por contrato: habilita payloads extensos y upload_probe con archivos vivos; sqlmap fuerte apagado por defecto, lo enciende el operador.",
  laboratorio: "Laboratorio (IPs privadas/localhost confirmadas por alcance): habilita post-explotación de laboratorio contra Fénix u objetivos propios; nada de esto toca terceros.",
  defensa: "Ciberdefensa: el arsenal ofensivo corre contra infra propia declarada por el operador para validar detección; un ataque exitoso sin señal detectada es un hallazgo de gap de detección.",
  "full-blast": "Full-blast: todo el arsenal contra cualquier host que el alcance autorice, sin restricción de laboratorio. El operador decide cuándo usarlo: el alcance y el tope de gasto son la única red.",
};

/** Permisos que un perfil habilita. Todos default false: bounty es el retrocompatible. */
export interface ProfileGrants {
  /** Payloads extensos (librería completa de clases y variantes). */
  payloadsExtensive: boolean;
  /** Subir archivos vivos con upload_probe (pentest en adelante). */
  uploadLive: boolean;
  /** Post-explotación de laboratorio (src/postex.ts): sólo laboratorio y defensa. */
  postexLab: boolean;
  /** Modo detección (purple): registra expected_signal y abre la categoría «detección». */
  detection: boolean;
}

export const PROFILE_GRANTS: Record<CapabilityProfile, ProfileGrants> = {
  bounty: { payloadsExtensive: false, uploadLive: false, postexLab: false, detection: false },
  pentest: { payloadsExtensive: true, uploadLive: true, postexLab: false, detection: false },
  laboratorio: { payloadsExtensive: true, uploadLive: true, postexLab: true, detection: true },
  defensa: { payloadsExtensive: true, uploadLive: true, postexLab: true, detection: true },
  "full-blast": { payloadsExtensive: true, uploadLive: true, postexLab: true, detection: true },
};

export function parseProfile(text: string): CapabilityProfile | undefined {
  const value = text.trim().toLowerCase();
  if (!PROFILES.includes(value as CapabilityProfile)) return undefined;
  return value as CapabilityProfile;
}

/** ¿El perfil levanta la guarda de host-de-laboratorio en la post-explotación? */
export function postexAnyHost(profile: CapabilityProfile): boolean {
  return profile === "full-blast";
}

/** Perfil guardado por proyecto en la tabla meta; «bounty» si nunca se eligió. */
export class ProfileStore {
  private readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
  }

  current(): CapabilityProfile {
    const row = this.db.prepare("select value from meta where key='profile'").get() as { value: string } | undefined;
    const value = row ? parseProfile(row.value) : undefined;
    return value ?? "bounty";
  }

  grants(): ProfileGrants {
    return PROFILE_GRANTS[this.current()];
  }

  set(profile: CapabilityProfile): void {
    this.db.prepare("insert into meta(key,value) values('profile',?) on conflict(key) do update set value=excluded.value").run(profile);
  }
}

/** Línea para /perfil y el arranque del daemon: qué perfil corre y qué habilita. */
export function profileLine(profile: CapabilityProfile): string {
  const grants = PROFILE_GRANTS[profile];
  const on = (label: string, value: boolean) => `${label}: ${value ? "sí" : "no"}`;
  return [`perfil ${profile} — ${PROFILE_NOTES[profile]}`, on("payloads extensos", grants.payloadsExtensive), on("upload vivo", grants.uploadLive), on("post-ex lab", grants.postexLab), on("detección", grants.detection)].join(" · ");
}