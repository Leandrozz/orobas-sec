---
name: canarios
description: Envenenar el registro. Sembrar un canario único en cada campo que se guarda para encontrar dónde reaparece (otra página, otro rol, una exportación) y si sale sin escapar: XSS almacenado o de segundo orden.
tools: canary_new, canary_list
---

## Cuándo

- La aplicación guarda texto del usuario que después se muestra en otro lado: perfil, nombre visible, bio, dirección, comentarios, tickets, nombres de archivo o de proyecto, cabeceras que se registran (User-Agent en un panel de auditoría).
- Hay vistas que no ves con la misma cuenta: un panel de administración, la vista de otro usuario, un listado público, una exportación a CSV o PDF, un correo.
- Una sonda de inyección no muestra nada en su propia respuesta: el efecto puede estar en otra pantalla.

## Cómo

1. **Un canario por campo.** canary_new con el campo y la ruta donde lo sembrás. Te da tres formas: con caracteres de prueba (`<"'>` pegados), simple y de email. Usá la de caracteres de prueba siempre que el campo la acepte: es la que dice si la salida escapa.
2. **Sembrá en todos los campos que se guardan** de un mismo formulario, cada uno con su canario, en una sola escritura si se puede.
3. **Recorré las vistas** donde ese dato puede salir, con cada identidad que tengas: listados, perfiles, paneles, exportaciones. No hace falta buscar el canario a mano: el harness mira cada respuesta y te avisa cuando aparece en otra ruta o ante otra identidad.
4. **Leé el aviso.** «Sin escapar en HTML» es XSS almacenado probable: confirmalo con una carga inofensiva en ese mismo campo y registralo con la siembra y la reaparición como evidencia. «Escapado» es una defensa que funciona: queda como evidencia de que la inyección se probó. «Parcial» y «codificado» dependen del contexto: mirá el artefacto.
5. **Encadená.** Un XSS almacenado que ve otro rol es más grave que uno propio: vinculalo y seguí con la escalada de sesión (habilidad cadenas).

## Lo que no se hace

- No se siembran cargas que ejecuten algo en el navegador de otra persona real: el canario es inerte a propósito. La carga de confirmación se prueba con tus identidades.
- No se siembra en campos que disparan acciones hacia terceros (enviar correos o SMS a direcciones reales).
- Lo que se sembró queda en el objetivo: el informe lista lo creado para limpiar.
