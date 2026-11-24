---
name: severidad
description: Asignar CVSS 3.1 a un hallazgo a partir de la evidencia guardada y revisar las exclusiones del programa antes de informarlo.
tools: finding_list, artifact_read, finding_record, finding_update
---

## Del artefacto al vector

Identificá el componente vulnerable, el componente afectado y la autoridad que controla cada uno. Para cada métrica anotá el valor, el hecho que lo sostiene y el identificador del artefacto. Conservá esas referencias en el resumen y en la evidencia del hallazgo. Si falta un dato decisivo, guardá la estimación y nombrá la métrica pendiente en `limits`. Usá `cvss` cuando estén sustentadas las ocho métricas base.

| Métrica | Qué tiene que mostrar la evidencia |
| --- | --- |
| AV, vía de acceso | N si la función es alcanzable por red enrutada. A si exige compartir un segmento o dominio de red restringido. L si requiere acceso local o que el componente abra un archivo local. P si exige contacto físico. Citá la interfaz y la condición de acceso. |
| AC, complejidad | L si el efecto se da bajo condiciones ordinarias de la configuración afectada. H si depende de una condición específica fuera del control de quien inicia la acción. Identificá esa condición en la traza o el diseño. |
| PR, privilegios previos | N si el efecto parte de una identidad sin privilegios. L si la evidencia requiere una cuenta ordinaria. H si requiere administrar el componente. Citá el rol efectivo inicial. Una cuenta de alta libre también puede tener PR:L. |
| UI, intervención de otra persona | N si el efecto ocurre sin otra persona. R si otra persona debe realizar una acción, por ejemplo abrir un documento. Identificá esa acción y su autor. |
| S, alcance de seguridad | U si una misma autoridad de seguridad controla el componente vulnerable y el afectado. C sólo si el efecto cruza un límite entre autoridades. Nombrá ambas y citá la evidencia del cruce. Cambiar de usuario o de host por sí solo es insuficiente. |
| C, confidencialidad | N si la evidencia descarta divulgación. L para acceso limitado a información restringida. H para pérdida total de confidencialidad o exposición con consecuencia directa grave. Identificá qué datos, su sensibilidad y su alcance, con valores redactados. |
| I, integridad | N si los datos conservan su integridad. L para cambios limitados. H para pérdida total de integridad o un cambio de consecuencia directa grave. Citá el estado anterior y el posterior y qué registros quedaron afectados. |
| A, disponibilidad | N si el servicio sigue disponible. L si hay una degradación medida. H si una medición demuestra indisponibilidad total sostenida o una consecuencia directa grave. Citá duración, población afectada y medición de referencia. Una estimación de costo o una única respuesta 500 resulta insuficiente. |

## Ejemplos de clasificación

Cada fila describe un supuesto específico. Reemplazá sus valores por los de la evidencia del caso. Los ejemplos usan métricas base.

| Caso observado | Vector de ejemplo |
| --- | --- |
| IDOR de lectura. Una cuenta ordinaria ve campos privados limitados de otra cuenta. | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` |
| IDOR de escritura. Una cuenta ordinaria cambia un atributo ajeno de impacto limitado. | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` |
| XSS reflejado. Entrada anónima, intervención de otra persona, efecto limitado sobre datos y contenido en su navegador. | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| XSS almacenado. Publica una cuenta ordinaria y otra persona debe abrir la vista. Se observaron los mismos efectos limitados en el navegador. | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` |
| SSRF. Una cuenta ordinaria obtuvo un dato restringido, de alcance limitado, en la misma autoridad. | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` |
| Inyección. El expediente acredita lectura total dentro de la misma autoridad, sin cambios ni interrupción y sin privilegios iniciales. | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| Subida de archivos. Una cuenta ordinaria altera un recurso de publicación de impacto limitado bajo la misma autoridad. | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` |
| Toma de cuenta. Sin privilegios iniciales ni intervención de la víctima, se acredita acceso total a sus datos sensibles y cambios de consecuencia grave. | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| Precio mal cobrado en un modelo de recursos. Una cuenta ordinaria altera un importe acotado en el registro de facturación. | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` |

En el ejemplo de precio, asentá por separado el importe, la moneda, la cantidad de recursos y el período observados. Una tarifa comercial discutible puede tener impacto económico sin alterar la integridad de un registro.

## Revisión antes de subir

Si ya hay hallazgos vinculados, citá los artefactos que demuestran que los efectos corresponden a la misma secuencia y documentá sus condiciones iniciales. Recalculá las métricas sólo para el impacto conjunto acreditado. Sumar puntajes o contar el mismo dato dos veces distorsiona la severidad. Si falta evidencia de un vínculo, conservá los vectores individuales.

Antes de subir la severidad o presentar el hallazgo, copiá textual la lista de fuera de alcance vigente del programa en la revisión. Dejá la fuente y la fecha. Escribí una oración que identifique el activo, la categoría y el motivo por el que el caso queda fuera de esas exclusiones. Si falta la política o esa oración no se puede justificar, conservá la severidad anterior y dejá el informe en borrador.

El puntaje y el estado de verificación se registran por separado. [Especificación CVSS 3.1 de FIRST](https://www.first.org/cvss/v3.1/specification-document) · [Ejemplos oficiales](https://www.first.org/cvss/v3.1/examples)
