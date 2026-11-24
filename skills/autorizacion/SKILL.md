---
name: autorizacion
description: Probar permisos por objeto, función y rol con identidades propias, rutas reales y cambios de estado observables.
tools: access_matrix, ids_harvest, path_probe, body_probe, http_identities, finding_record, finding_update
---

## Cuándo

Hay dos cuentas propias, distintos roles, identificadores de objeto o una función que la interfaz oculta. También cuando una lectura da 403: otra operación de la misma familia puede tener un control distinto.

## Método

1. Identificá en la interfaz, el contrato o el tráfico real qué significa cada rol, permiso y campo. Un número o una bandera sin esa fuente no prueba privilegios. Prepará identidades propias con `http_identities` y un recurso creado por cada una; no uses datos ajenos reales.
2. Armá la matriz anónimo / dueño / otra cuenta / rol distinto. `access_matrix` compara las mismas rutas y operaciones; `ids_harvest` toma los ids entregados a una identidad y prueba su uso con otra. Releé cada resultado desde la identidad correspondiente.
3. Sobre 401, 403 o 404, `path_probe` verifica si la forma de la ruta cambia el control. Para una función vedada en la pantalla, localizá su API y probala con el rol limitado. Un rechazo de lectura no demuestra rechazo de crear, convertir, mover, asignar, duplicar, compartir o cambiar estado: recorré esas operaciones con el mismo id, también en el cuerpo.
4. En escrituras que funcionan, `body_probe` prueba campos de dueño, rol, plan o saldo sobre **tu recurso**; usá los modos `agregar` o `hpp` y confirmá el efecto con una relectura. Un estado archivado, bloqueado, cerrado, congelado, cancelado, pagado o publicado exige probar las escrituras que debería impedir. Hacé cambios mínimos y reversibles; no borres datos ajenos.
5. Compará prueba y control: mismo pedido autorizado con dueño y rechazado con la otra cuenta, o viceversa. El efecto es una lectura indebida o un estado cambiado y reconsultado, no un 500 ni una pantalla ausente.

## Registro y severidad

`finding_record` como **pista** si sólo hay diferencia de respuestas o contrato; **candidato** si el acceso o cambio indebido tiene artefactos y control. `finding_update` deja la operación, identidad, id propio y efecto observado, sin copiar secretos. Si un acceso nuevo habilitó otra lectura, es consecuencia del mismo hallazgo. La severidad típica va de baja a alta según datos y cambios acreditados; calculá el vector con la habilidad [severidad](../severidad/SKILL.md), sin subirlo por una cadena imaginada.
