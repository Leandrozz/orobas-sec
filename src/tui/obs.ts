// OBS lee este archivo como fuente de texto. Sólo contiene los cuatro campos de la pantalla pública.
import { closeSync, fstatSync, ftruncateSync, lstatSync, openSync, unlinkSync, writeSync } from "node:fs";

export class FuenteOBS {
  private readonly archivo: string;
  private readonly fd: number;
  private ultimo = "";

  constructor(archivo: string) {
    this.archivo = archivo;
    // Un archivo por transmisión. Ni siquiera un enlace a una traza existente se puede pisar.
    this.fd = openSync(archivo, "wx", 0o600);
  }

  mostrar(tarea: string, modelo: string, segundos: number, hallazgos?: number) {
    this.escribir(`Tarea: ${tarea}\nModelo: ${modelo}\nTiempo: ${Math.floor(segundos / 60)} min ${segundos % 60} s\nHallazgos: ${hallazgos ?? "…"}\n`);
  }

  private escribir(texto: string) {
    if (texto === this.ultimo) return;
    const datos = Buffer.from(texto);
    // La fuente nunca mezcla el final del estado anterior con el nuevo.
    ftruncateSync(this.fd, 0);
    if (datos.length) writeSync(this.fd, datos, 0, datos.length, 0);
    this.ultimo = texto;
  }

  tapar() { this.escribir(""); }

  cerrar() {
    try {
      this.tapar();
      const propio = fstatSync(this.fd), actual = lstatSync(this.archivo);
      if (propio.dev === actual.dev && propio.ino === actual.ino) unlinkSync(this.archivo);
    } finally { closeSync(this.fd); }
  }
}
