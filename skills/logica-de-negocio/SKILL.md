---
name: logica-de-negocio
description: Probar precios, cupones, saldos, límites, transiciones de estado y carreras sobre recursos propios.
tools: body_probe, race_probe, http_identities, finding_record, finding_update
---

## Cuándo

Una operación calcula precios o saldo, aplica cupones, consume un límite, cambia estado o promete inmutabilidad. También cuando dos operaciones simultáneas podrían romper una regla visible del producto.

## Método

1. Documentá la regla con interfaz, contrato o tráfico real: precio, moneda, cantidad, cupón, límite, saldo y estado inicial. Creá recursos propios y un control que siga el flujo normal.
2. Repetí la petición real con `body_probe` para variar un solo campo por vez: cantidad, precio, descuento, dueño o estado. No adivines cuerpos de escritura; obtené el contrato primero. Releé el registro final y compará importe cobrado, saldo o estado; una respuesta 200 no prueba impacto.
3. Para estados archivado, bloqueado, cerrado, congelado, cancelado, pagado o publicado, probá las operaciones que la regla impide aun cuando la interfaz no las ofrezca. Usá `http_identities` si la regla depende del rol o dueño.
4. Si el estado previo se valida por separado de la escritura, `race_probe` manda un lote acotado sobre tus propios datos. Compará secuencial frente a concurrente, reconsultá el estado final y contá operaciones aceptadas. No satures el servicio ni hagas compras o cobros reales.

## Registro y severidad

`finding_record` como **pista** si el servidor acepta un campo o devuelve algo anómalo; **candidato** cuando el estado, saldo o importe final viola la regla y hay control. `finding_update` guarda antes/después, cantidad, moneda y período. La severidad depende del efecto económico o de integridad realmente medido, usualmente media y a veces alta. Usá la habilidad [severidad](../severidad/SKILL.md) para el vector; una tarifa discutible no es por sí misma una falla de integridad.
