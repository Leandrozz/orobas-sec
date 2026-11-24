---
name: autenticacion
description: Probar login, sesiones, JWT, OAuth/OIDC/SSO, recuperación y segundo factor con cuentas y correo propios.
tools: auth_probe, jwt_inspect, reset_probe, mail_address, mail_wait, http_identities, finding_record, finding_update
---

## Cuándo

Hay login, tokens, cookies de sesión, registro, recuperación de contraseña, vínculo OAuth/OIDC/SSO o un segundo factor. Un desafío de autenticación también merece controles con credenciales inventadas si no tenés cuenta.

## Método

1. Si el registro está abierto, creá dos identidades propias. `mail_address` da una dirección por cuenta y `mail_wait` recibe sus enlaces y códigos. Si no hay casilla vinculada, pedile al operador `/correo`. No pruebes reset ni mensajes a direcciones ajenas.
2. Con `auth_probe`, compará usuario inexistente, secreto vacío, credenciales incorrectas y válidas según la política del programa. Si autoriza esas pruebas, incluí contraseñas comunes en cuentas administrativas de laboratorio, con el ritmo y tope vigentes. No presupongas que un desafío implica validación. Registrá diferencias de estado, mensajes y límites; el ruido solo no es un hallazgo.
3. Con `http_identities`, comprobá inicio, cierre, rotación de sesión, caducidad y rechazo de una sesión de la otra cuenta. `jwt_inspect` lee estructura, algoritmo, expiración y claims; un claim visible o editable es pista hasta que el servidor acepte un token alterado en una petición propia.
4. Para OAuth/OIDC/SSO, seguí authorize, callback, `state`, `nonce`, emisor, audiencia y `redirect_uri` en el flujo real de **tus cuentas**. Un callback o un vínculo de identidad se demuestra con sesión o cuenta final observada, no con una redirección hipotética. Para segundo factor, compará el estado antes y después de completarlo y las rutas que deberían exigirlo.
5. `reset_probe` compara únicamente dos direcciones propias: emisión, uso único, expiración, vínculo con la cuenta y efecto tras cambiar la contraseña. Confirmá en login cuál secreto sirve después.

## Registro y severidad

`finding_record` como **pista** para diferencias o tokens sospechosos; **candidato** sólo con acceso, sesión o cambio de credencial probado y control negativo. `finding_update` consigna cuentas propias, intercambios y qué barrera se saltó. La toma de cuenta demostrada suele ser alta; enumeración o sesiones con impacto limitado suelen ser bajas o medias. Fundamentá el vector y las exclusiones con la habilidad [severidad](../severidad/SKILL.md).
