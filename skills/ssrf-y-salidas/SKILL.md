---
name: ssrf-y-salidas
description: Probar webhooks, importadores de URL y vistas previas con un receptor propio y límites de alcance.
tools: outbound_probe, canary_new, scope_check, finding_record, finding_update
---

## Cuándo

El objetivo acepta una URL para webhook, importación, vista previa, imagen, documento o callback. Querés saber si el servidor hace una salida de red o si sólo la procesa el navegador.

## Método

1. Confirmá que la función y el destino de prueba están autorizados con `scope_check`. Usá un receptor que controlás; `canary_new` identifica cada campo y pedido. No conviertas una URL observada en permiso para tocarla.
2. `outbound_probe` envía una URL única a la función real y observa la recepción: método, origen, tiempo y canario. Compará un pedido de control sin URL o con una URL inerte. Una respuesta de la aplicación sin recepción no prueba SSRF.
3. Si hay redirecciones, resolución DNS o encabezados controlables, probá variantes sólo hacia tu receptor. Diferenciá una salida del servidor de una carga del navegador y registrá qué dato volvió al objetivo.
4. Metadata de nube, loopback del objetivo y servicios internos requieren alcance explícito para esos destinos. Si faltan, detené esa escalada y documentá el límite; no uses endpoints de metadata como atajo.

## Registro y severidad

`finding_record` como **pista** si sólo acepta la URL; **candidato** con petición recibida y control que demuestra origen servidor. `finding_update` registra el canario, el pedido y el efecto, sin tokens ni datos ajenos. Una salida ciega suele tener impacto bajo o medio; lectura interna acreditada puede subirlo. Calculá el vector con la habilidad [severidad](../severidad/SKILL.md) y sólo por el impacto observado.
