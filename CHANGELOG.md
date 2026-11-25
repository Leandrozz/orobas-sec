# Changelog

Los cambios relevantes de Elevate AI Cyber se anotan acá, siguiendo la idea de [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).

## [0.1.1] - Windows con Docker Desktop y sin telemetría por defecto

- Sin telemetría por defecto: las trazas pasan a `no` (antes venían en `compartir`). Guardarlas en tu PC (`/datos local`) o compartirlas con Elevate AI (`/datos compartir`) es opcional. Las herramientas que corre el agente, los agentes que lanza y la imagen de Docker van con `DO_NOT_TRACK` y con las métricas y los chequeos de versión apagados (semgrep, ProjectDiscovery con `-duc`, npm, Next.js, Claude Code). Un consentimiento sin cuenta de orobas ya no genera ningún pedido al servicio.
- Windows: el release trae el modo contenedor. `install.ps1` instala el lanzador `cyber` (`cyber-lanzador.ps1` y `cyber.cmd`, los dos en el `SHA256SUMS` firmado) con Docker Desktop, y la primera vez que corrés `cyber` baja la imagen. En 0.1.0 `install.ps1` no instalaba nada porque el release no fijaba una imagen.
- La imagen del modo contenedor es pública: `ghcr.io/leandrozz/orobas-sec`, para linux/amd64 y linux/arm64. La arma el workflow de release de este repositorio desde el mismo commit del tag y fija su digest en los lanzadores del release; `install.sh --modo contenedor` también la usa.
- Los lanzadores bajan la imagen pública sin login: no piden un token de GitHub, y si ghcr.io la rechaza por una sesión vencida explican `docker logout ghcr.io`. El de Windows muestra el avance de la primera bajada.
- `install.ps1` instala el `cyber.cmd` firmado del release en vez de escribirlo él.
- Iniciar sesión con ChatGPT (`cyber login chatgpt`): los modelos de tu plan de ChatGPT por el flujo oficial (OAuth con PKCE), con las credenciales cifradas y el razonamiento en alto por defecto en los modelos que razonan.
- Reglas del programa en el alcance: `/alcance reglas exclusion|honesto|atacante <cita>` guarda las exclusiones y el modelo de confianza con su fuente, y cada candidato tiene que justificar por qué no le aplica la exclusión más cercana.
- Detector de bucles por sesión, y `cyber mejoras` (o `/mejoras`), que diagnostica las trazas locales y la base del proyecto y propone cambios.
- Banco público de ocho CVE reproducibles: casos con imágenes fijadas por digest, semillas, oráculos y control con la versión corregida; corre con el Docker local o por SSH. Ver docs/benchmark.md.

## [0.1.0] - primera publicación

Primera versión abierta del código, bajo la licencia Apache-2.0. El historial de desarrollo anterior queda en el repositorio de origen; este repositorio empieza acá.

- Agente con subagentes y verificador independiente, sobre un daemon por proyecto y la TUI Foco.
- Alcance autorizado que el código aplica en cada petición, cliente HTTP con identidades y sondas propias.
- Caja de herramientas de escáneres, navegador por identidad y extensión de Chromium para usar el navegador del operador.
- Integración con HackerOne, Bugcrowd, Intigriti y plataformas de nube; hallazgos con evidencia por hash e informes en Markdown.
- Proveedores de modelos intercambiables (la suscripción de Elevate AI, OpenAI, Anthropic, DeepSeek, OpenRouter, Ollama o cualquier API compatible) y contabilidad del uso con tope de gasto.
- Imagen de Docker y lanzadores para Linux, macOS y Windows. El lanzador sólo se reemplaza a sí mismo con una suma SHA-256 esperada.
- Integración continua (`cyber ci` y una GitHub Action): alcance autorizado por huella y sellado, topes duros de gasto y tiempo, sólo hallazgos verificados hacen fallar el job, SARIF 2.1.0, JSON propio, comentario del PR, JUnit, supresiones con vencimiento, comparación, retest y modo «sólo lo que cambió». Ver docs/ci.md.
