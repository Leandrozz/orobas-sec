---
name: inyecciones
description: Probar SQL, NoSQL, plantillas, comandos, expresiones y rutas con controles inertes y evidencia de efecto.
tools: param_probe, sqlmap_scan, payload_list, payload_get, finding_record, finding_update
---

## Cuándo

Una entrada llega a una consulta, filtro, plantilla, comando, XPath, JSONPath, fórmula, lenguaje de expresiones o ruta de archivo. Un error de sintaxis o un 500 por sí solos no demuestran inyección.

## Método

1. Tomá el parámetro y pedido reales del tráfico. Identificá el contexto de interpretación sin suponerlo; `payload_list` y `payload_get` muestran cargas por clase. Elegí valores inertes y dentro de alcance, con un control literal equivalente.
2. `param_probe` compara respuesta normal, mutación y control para SQL, NoSQL o traversal. Una diferencia estable tiene que explicar un efecto observable: dato propio adicional, cambio lógico en una condición o archivo propio leído.
3. Si el programa permite escáneres y el ritmo lo admite, `sqlmap_scan` ayuda a confirmar SQL con una prueba acotada. Su reporte es candidato hasta reproducir el efecto con una petición propia; nunca uses volcado masivo ni operaciones destructivas.
4. En plantillas, comandos y expresiones (XPath, JSONPath, fórmulas, filtros), comprobá evaluación con una operación inocua y un resultado distinguible. Si el lenguaje ofrece lectura de archivos o URLs, probá sólo recursos propios autorizados; una lista de funciones bloqueadas puede ser incompleta. Para rutas, compará una ruta válida propia, la variante y un control inexistente.
5. Repetí lo mínimo necesario para separar caché, errores de herramienta y comportamiento del objetivo. No ejecutes comandos de daño, lectura de secretos ni rutas fuera del alcance.

## Registro y severidad

`finding_record` como **pista** ante errores o diferencias no explicadas; **candidato** con evaluación, lectura o efecto demostrado y artefactos de control. `finding_update` detalla parámetro, contexto y resultado sin incluir secretos. La severidad puede ir de media a crítica según el efecto medido; asigná CVSS con la habilidad [severidad](../severidad/SKILL.md), sin inferir ejecución de código desde un error.
