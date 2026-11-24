# Changelog

Los cambios relevantes de Elevate AI Cyber se anotan acá, siguiendo la idea de [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).

## [0.1.0] - primera publicación

Primera versión abierta del código, bajo la licencia Apache-2.0. El historial de desarrollo anterior queda en el repositorio de origen; este repositorio empieza acá.

- Agente con subagentes y verificador independiente, sobre un daemon por proyecto y la TUI Foco.
- Alcance autorizado que el código aplica en cada petición, cliente HTTP con identidades y sondas propias.
- Caja de herramientas de escáneres, navegador por identidad y extensión de Chromium para usar el navegador del operador.
- Integración con HackerOne, Bugcrowd, Intigriti y plataformas de nube; hallazgos con evidencia por hash e informes en Markdown.
- Proveedores de modelos intercambiables (la suscripción de Elevate AI, OpenAI, Anthropic, DeepSeek, OpenRouter, Ollama o cualquier API compatible) y contabilidad del uso con tope de gasto.
- Imagen de Docker y lanzadores para Linux, macOS y Windows. El lanzador sólo se reemplaza a sí mismo con una suma SHA-256 esperada.
- Integración continua (`cyber ci` y una GitHub Action): alcance autorizado por huella y sellado, topes duros de gasto y tiempo, sólo hallazgos verificados hacen fallar el job, SARIF 2.1.0, JSON propio, comentario del PR, JUnit, supresiones con vencimiento, comparación, retest y modo «sólo lo que cambió». Ver docs/ci.md.
