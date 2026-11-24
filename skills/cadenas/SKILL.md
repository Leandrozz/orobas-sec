---
name: cadenas
description: Encadenar hallazgos. Un hallazgo bajo o medio (open redirect, XSS, CSRF, IDOR de lectura, SSRF) tiene una escalada conocida que lo vuelve alto; cómo probarla sin salirte del alcance, cómo vincular los eslabones y cómo cerrar la escalada cuando no se puede.
tools: finding_list, finding_update, csrf_check, outbound_probe, canary_new, canary_list
---

## Cuándo

- Registraste (o encontrás en finding_list) un hallazgo bajo o medio de una de estas clases. Antes de darlo por terminado, pensá qué otro paso lo haría grave.
- La regla de cierre te objetó «una escalada conocida sin intentar»: es la misma idea, con la acción ya elegida.
- Tenés dos hallazgos que juntos dicen más que por separado (uno da el acceso, el otro el efecto).

## Escaladas conocidas

| Partís de | Escala a | Qué probar |
| --- | --- | --- |
| Open redirect | Robo del code o token de OAuth | Sólo si el sitio tiene un flujo OAuth (authorize, client_id, redirect_uri). Con tu cuenta de prueba, redirect_uri que pase por la ruta del redirect dentro del dominio aceptado; sin seguir redirecciones, mirá si el code o el token terminan en el Location hacia afuera. |
| XSS reflejado o almacenado | Sesión robable | Set-Cookie del login: ¿la cookie de sesión tiene HttpOnly? ¿El valor cambia al iniciar sesión? Sin HttpOnly, el script la lee; si no rota, hay fijación. |
| CSRF | Toma de cuenta | La operación que cambia el email: ¿también pasa sin token o desde otro origen? Si pasa, el reset de contraseña va al email nuevo. Sólo con tu cuenta de prueba. |
| IDOR de lectura | Escritura ajena | En la misma familia de rutas y con el mismo id ajeno: PUT o PATCH con un cambio mínimo y reversible, o la operación que la API ofrezca (archivar, asignar, cambiar estado). Nunca borrar lo ajeno. |
| SSRF | Metadata o servicios internos | Sólo si el alcance incluye esos destinos (scope_check). Si no, no los pruebes: pedile al operador que decida y marcá la escalada «limitada». |

## Cómo

1. **Una acción, la más chica.** Elegí la observación que demuestra el siguiente eslabón sin daño: leer una cabecera, ver un Location, comparar dos respuestas. Si para demostrarlo hay que robar algo de otra persona, borrar, o salir del alcance, no: queda como límite.
2. **Registrá el eslabón nuevo vinculado.** finding_record del hallazgo escalado con `related: [{id: <el bajo>, role: "escala"}]`. Si la escalada no salió, igual dejá constancia: finding_update del hallazgo bajo con `escalation: "intentada"` y una nota con lo que dio.
3. **Si no se puede, decilo.** finding_update con `escalation: "limitada"` (qué faltó y por qué: no hay flujo OAuth, el alcance no incluye la metadata, no hay segunda cuenta) o `"no aplica"`. Eso cierra la objeción.
4. **La severidad de la cadena es la del eslabón más alto, y sólo vale con todos verificados.** No subas la severidad del hallazgo bajo: el alto es otro hallazgo, con su evidencia. El verificador comprueba cada eslabón por separado.

## Lo que no se hace

- No se amplía el alcance para completar una cadena. Lo que esté afuera se le pide al operador.
- No se usan cuentas, sesiones ni tokens de otras personas: la cadena se demuestra entre tus identidades de prueba.
- No se infla un hallazgo con una escalada «posible»: si no la observaste, va en límites, no en la severidad.
