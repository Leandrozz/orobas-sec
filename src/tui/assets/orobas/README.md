# Sello Orobas aprobado

Los 12 PNG transparentes provienen del GIF `orobas_boot_demo.gif` aportado por
el usuario. Se extrajeron los cuadros de reconstrucción y pintado, sin redibujar
el Braille, alterar las proporciones ni conservar el dashboard de demostración.
La procedencia, los tiempos y el hash del GIF están en `animation.json`.

Cada cuadro mide 820 × 700 px. La secuencia dura 2540 ms, incluyendo una pausa
final de 1020 ms. El cuadro 011 es también la imagen estática del chat vacío.
`braille.txt` conserva el archivo original elegido por el usuario. La alternativa
de texto adapta los mismos PNG a Braille (o ASCII) y mantiene todos los elementos
del emblema; la resolución y la fuente de cada terminal limitan el detalle visible.

El fondo se volvió transparente eliminando solamente el color uniforme
`#090e16`. Los RGB de los puntos y bordes suavizados se conservaron. Sobre un
fondo similar al original el resultado coincide con el demo.

Estos recursos viven dentro de `src/` para que la distribución tar.gz y Docker
los incluyan sin depender de archivos personales en Descargas.
