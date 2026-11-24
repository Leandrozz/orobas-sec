@setlocal
@set "L=%~dp0cyber-lanzador.ps1"
@if not exist "%L%" set "L=%~dp0cyber.ps1"
@powershell -NoProfile -ExecutionPolicy Bypass -File "%L%" %*
