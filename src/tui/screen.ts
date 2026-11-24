// Tipo de salida de la terminal que comparten Pantalla y Foco.
export interface Output {
  write(data: string): void;
  columns: number;
  rows: number;
}
