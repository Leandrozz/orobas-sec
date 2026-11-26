# Lanzador de Windows de elevate-cyber: cyber [--instalar | --actualizar [--si] | args de cyber]
# Se instala con install.ps1 desde un release firmado (README, «Instalar»), nunca desde main.
# Este archivo va con BOM UTF-8: Windows PowerShell 5.1 lo necesita para leer las tildes.
$ErrorActionPreference = 'Continue'  # con Stop, 2>&1 sobre un exe rompe en PS 5.1
$VersionLanzador = ''  # la completa el release (scripts/release/armar.sh); vacía en una copia de desarrollo
$ImagenRelease = ''    # la imagen que fija ese release, por digest; vacía en una copia de desarrollo
$Imagen = if ($env:CYBER_IMAGE) { $env:CYBER_IMAGE } elseif ($ImagenRelease) { $ImagenRelease } else { 'ghcr.io/leandrozz/orobas-sec:latest' }
# La imagen pública (la que arma el workflow de release del repositorio público) se baja sin login: con ella el lanzador
# nunca pide un token de GitHub. Con una imagen privada de ghcr.io lo pide la primera vez.
$ImagenPublica = 'ghcr.io/leandrozz/orobas-sec'
# --actualizar sólo reemplaza este archivo por el del último release, después de verificar la firma de su
# SHA256SUMS con esta clave (ssh-keygen -Y verify) y la suma del lanzador. CYBER_RELEASES_URL cambia de dónde baja.
$ReleasesUrl = if ($env:CYBER_RELEASES_URL) { $env:CYBER_RELEASES_URL } else { 'https://github.com/Leandrozz/orobas-sec/releases' }
$ReleasesUrl = $ReleasesUrl.TrimEnd('/')
$ClavePublica = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFfKpWK3+u7xt/H1nXdYudXF4DWUorU16LWu7ACfcP+R'
$EspacioFirma = 'orobas-sec-release'
$EsWin = ($PSVersionTable.PSEdition -eq 'Desktop') -or ($IsWindows -eq $true)
$Es = (Get-UICulture).TwoLetterISOLanguageName -eq 'es'
function t($es, $en) { if ($Es) { $es } else { $en } }
function Salir($msg) { Write-Host $msg; CerrarDocker; RestaurarEntorno; exit 1 }
$Abri = $false  # true si este lanzador abrió Docker Desktop
$Vig = $null    # el vigilante del contenedor en marcha
function Pregunta($msg) { (Read-Host "$msg $(t '[S/n]' '[Y/n]')") -match '^(|s|si|sí|y|yes)$' }  # Enter = sí
# Lo que el lanzador pone en el entorno no debe quedar en la sesión de PowerShell que lo llamó (la llave sobre todo).
$EntornoOrig = @{}
foreach ($n in 'CYBER_SECRETS_KEY', 'CYBER_PROYECTO_HOST', 'CYBER_DATOS_HOST', 'CYBER_CREDENCIALES_HOST', 'LANG') { $EntornoOrig[$n] = [Environment]::GetEnvironmentVariable($n) }
function RestaurarEntorno { foreach ($n in $EntornoOrig.Keys) { [Environment]::SetEnvironmentVariable($n, $EntornoOrig[$n]) } }
function Terminar($codigo) {
  # El vigilante no se mata acá: tras una salida normal sigue solo y puede esperar para cerrar Docker.
  CerrarDocker
  RestaurarEntorno
  exit $codigo
}
function Dk { & docker @args 2>&1 }
# Un Docker Desktop colgado no debe colgar el lanzador: docker info con 10 s de límite.
function DockerAndando {
  $j = Start-Job { & docker info 2>&1 | Out-Null; $LASTEXITCODE }
  $ok = $false
  if (Wait-Job $j -Timeout 10) { $ok = (@(Receive-Job $j)[-1] -eq 0) }
  Remove-Job $j -Force
  $ok
}

$Cred = Join-Path $env:APPDATA 'elevate-cyber'
$Datos = Join-Path $env:LOCALAPPDATA 'elevate-cyber'
$Bin = Join-Path $Datos 'bin'

# Preferencia de cerrar Docker Desktop al salir si lo abrió el lanzador: CYBER_CERRAR_DOCKER=0|1 gana sobre lanzador.conf; por defecto sí.
$Conf = Join-Path $Cred 'lanzador.conf'
function CerrarPref {
  if ($env:CYBER_CERRAR_DOCKER -eq '0') { return $false }
  if ($env:CYBER_CERRAR_DOCKER -eq '1') { return $true }
  -not ((Test-Path $Conf) -and (Get-Content $Conf) -contains 'cerrar_docker=no')
}
# Guarda una clave de lanzador.conf sin pisar las otras.
function GuardarConf($clave, $valor) {
  New-Item -ItemType Directory -Force $Cred | Out-Null
  $resto = if (Test-Path $Conf) { @(Get-Content $Conf | Where-Object { $_ -and -not $_.StartsWith("$clave=") }) } else { @() }
  Set-Content $Conf (@($resto) + "$clave=$valor") -Encoding ASCII
}
# docker ps -q (con filtro opcional) y 10 s de límite: devuelve error, ocupado o vacio ('' si no respondió).
function EstadoDocker($filtro = $null) {
  $j = Start-Job { param($f) $a = @('ps'); if ($f) { $a += '--filter', $f }; $o = (& docker @a -q 2>$null | Out-String).Trim(); if ($LASTEXITCODE -ne 0) { 'error' } elseif ($o) { 'ocupado' } else { 'vacio' } } -ArgumentList $filtro
  $r = if (Wait-Job $j -Timeout 10) { (Receive-Job $j | Out-String).Trim() } else { '' }
  Remove-Job $j -Force
  $r
}
# Cierra Docker Desktop solo si lo abrió este lanzador, la preferencia lo permite y no queda ningún contenedor corriendo.
function CerrarDocker {
  if (-not $script:Abri -or -not (CerrarPref)) { return }
  if ((EstadoDocker) -ne 'vacio') { return }
  & docker desktop stop 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) {
    $cli = Join-Path $env:ProgramFiles 'Docker\Docker\DockerCli.exe'
    if (Test-Path $cli) { & $cli -Shutdown } else { Stop-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue }
  }
  Write-Host (t 'Cerré Docker Desktop porque lo había abierto cyber (desactivalo con: cyber --cerrar-docker no).' 'I closed Docker Desktop because cyber had opened it (turn it off with: cyber --cerrar-docker no).')
}
# Vigilante (el propio script, en una ventana oculta): si el lanzador muere, despide su ventana en el contenedor compartido (no lo detiene).
# Si el lanzador abrió Docker Desktop, espera a que no quede ningún cyber-p-* y recién ahí lo cierra.
if ($args[0] -eq '--vigilar') {
  Wait-Process -Id $args[1] -ErrorAction SilentlyContinue
  & docker exec $args[2] /opt/elevate-cyber/bin/cyber despedir-ventana $args[3] 2>&1 | Out-Null  # un contenedor que ya no existe da error y se ignora
  $Abri = ($args[4] -eq '1')
  if ($Abri) {
    while ((EstadoDocker 'name=cyber-p-') -eq 'ocupado') { Start-Sleep 30 }
    CerrarDocker
  }
  exit 0
}
$pos = [array]::IndexOf(@($args), '--cerrar-docker')
if ($pos -ge 0) {
  $v = if ($pos + 1 -lt $args.Count) { $args[$pos + 1] } else { '' }
  if ($v -eq 'si' -or $v -eq 'no') {
    GuardarConf 'cerrar_docker' $v
    Write-Host ((t 'Guardado: cerrar Docker Desktop al salir, si lo abrió cyber: ' 'Saved: close Docker Desktop on exit, if cyber opened it: ') + $v)
  } else {
    $e = if (CerrarPref) { t 'sí' 'yes' } else { 'no' }
    Write-Host ((t 'Cerrar Docker Desktop al salir, si lo abrió cyber: ' 'Close Docker Desktop on exit, if cyber opened it: ') + "$e ($(t 'cambiar con' 'change with') cyber --cerrar-docker si|no)")
  }
  exit 0
}

# Se instala como cyber-lanzador.ps1 (y cyber.cmd lo llama así): al escribir «cyber», PowerShell prefiere un cyber.ps1 del PATH al cyber.cmd y la política de ejecución lo bloquea.
# Un cyber.cmd instalado que no llama a cyber-lanzador.ps1 es de una versión vieja: se reescribe acá (no se copia, desde $Bin no hay uno nuevo al lado) y el script pasa al nombre nuevo.
# El cyber.cmd sale de acá (no hace falta tenerlo al lado): así alcanza con bajar este archivo para instalar.
function EscribirCmd($ruta) {
  $lineas = '@setlocal', '@set "L=%~dp0cyber-lanzador.ps1"', '@if not exist "%L%" set "L=%~dp0cyber.ps1"', '@powershell -NoProfile -ExecutionPolicy Bypass -File "%L%" %*'
  [IO.File]::WriteAllText($ruta, (($lineas -join "`r`n") + "`r`n"), [Text.Encoding]::ASCII)
}
function ActualizarCmd {
  $viejo = Join-Path $Bin 'cyber.cmd'
  if (-not (Test-Path $viejo) -or ((Get-Content $viejo -Raw) -match 'cyber-lanzador\.ps1')) { return }
  Copy-Item $PSCommandPath (Join-Path $Bin 'cyber-lanzador.ps1') -Force
  EscribirCmd $viejo
  Remove-Item (Join-Path $Bin 'cyber.ps1') -Force -ErrorAction SilentlyContinue
}
# --- común: verificación de releases (idéntico en install.ps1 y distro/lanzador/cyber.ps1; lo exige test/instalador-windows.test.ts) ---
# https siempre; http sólo hacia esta máquina (pruebas). La seguridad está en la firma, no en la URL.
function UrlValida($url) { "$url" -match '^https://' -or "$url" -match '^http://(127\.0\.0\.1|localhost)(:\d+)?/' }
# El último release publicado: GitHub redirige /releases/latest a /releases/tag/vX.Y.Z.
function UltimoRelease {
  if (-not (UrlValida "$ReleasesUrl/")) { throw ((t 'CYBER_RELEASES_URL tiene que ser https: ' 'CYBER_RELEASES_URL must be https: ') + $ReleasesUrl) }
  $q = [Net.HttpWebRequest]::Create("$ReleasesUrl/latest")
  $q.Method = 'HEAD'
  $q.AllowAutoRedirect = $true
  $q.Timeout = 60000
  $r = $q.GetResponse()
  try { $u = $r.ResponseUri.AbsoluteUri } finally { $r.Close() }
  $v = ("$u" -split '/tag/')[-1]
  if (-not (UrlValida $u) -or $v -notmatch '^v\d+\.\d+\.\d+$') { throw ((t 'No entendí cuál es el último release: ' 'Could not tell the latest release: ') + $u) }
  $v
}
# ¿La versión $a es anterior a la $b? (vX.Y.Z; lo que sigue a «-» no cuenta). Una versión vacía es anterior a todas.
function VersionMenor($a, $b) {
  if (-not $a) { return $true }
  if (-not $b) { return $false }
  $x = @((("$a".TrimStart('v') -split '-')[0] -split '\.') | ForEach-Object { [int]$_ })
  $y = @((("$b".TrimStart('v') -split '-')[0] -split '\.') | ForEach-Object { [int]$_ })
  for ($i = 0; $i -lt 3; $i++) {
    if ($x[$i] -lt $y[$i]) { return $true }
    if ($x[$i] -gt $y[$i]) { return $false }
  }
  $false
}
function BajarArchivo($url, $destino) {
  if (-not (UrlValida $url)) { throw ((t 'Sólo bajo por https: ' 'I only download over https: ') + $url) }
  $ProgressPreference = 'SilentlyContinue'  # en PS 5.1 la barra de progreso hace lentísima la descarga
  Invoke-WebRequest $url -OutFile $destino -UseBasicParsing -TimeoutSec 600 -ErrorAction Stop
}
# Los ssh-keygen que hay: el del PATH, el de Windows (OpenSSH 8.1 o más nuevo en Windows 11) y el de Git for Windows.
function SshKeygens {
  $c = @(Get-Command ssh-keygen -All -CommandType Application -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
  if ($env:WINDIR) { $c += Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keygen.exe' }
  if ($env:ProgramFiles) { $c += (Join-Path $env:ProgramFiles 'Git\usr\bin\ssh-keygen.exe'), (Join-Path $env:ProgramFiles 'OpenSSH\ssh-keygen.exe') }
  @($c | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)
}
# Corre $exe con $argumentos y el contenido exacto de $entrada por stdin (un pipe de PowerShell le agregaría un fin de línea).
function CorrerConEntrada($exe, [string[]]$argumentos, $entrada) {
  $psi = New-Object Diagnostics.ProcessStartInfo $exe
  $psi.Arguments = ($argumentos | ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' }) -join ' '
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $p = [Diagnostics.Process]::Start($psi)
  $bytes = [IO.File]::ReadAllBytes($entrada)
  # Si el proceso murió sin leer stdin (p.ej. ssh-keygen sin SYSTEMROOT), escribirle falla: se informa lo que dijo
  # el proceso en vez de «The pipe is being closed», y una entrada que no llegó entera nunca cuenta como éxito.
  $entera = $false
  try {
    $p.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
    $entera = $true
  } catch { }
  try { $p.StandardInput.Close() } catch { }
  $salida = $p.StandardOutput.ReadToEnd() + $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  $codigo = $p.ExitCode
  if (-not $entera -and $codigo -eq 0) { $codigo = 1 }
  @{ Codigo = $codigo; Salida = $salida }
}
# La suma que el SHA256SUMS de $dir da para $nombre (exactamente una línea «suma  nombre»), o $null.
function SumaFirmada($dir, $nombre) {
  $s = @(Get-Content (Join-Path $dir 'SHA256SUMS') | ForEach-Object { if ($_ -cmatch '^([0-9a-f]{64})  (\S+)$' -and $Matches[2] -ceq $nombre) { $Matches[1] } })
  if ($s.Count -eq 1) { $s[0] } else { $null }
}
function SumaDe($archivo) { (Get-FileHash -Algorithm SHA256 $archivo).Hash.ToLowerInvariant() }
# Verifica la firma de $dir\SHA256SUMS (con $dir\SHA256SUMS.sig) con la clave de este archivo, y que la lista sea la de $version.
function VerificarLista($dir, $version) {
  if ($ClavePublica -match 'REEMPLAZAR') { throw (t 'Esta copia no trae la clave pública de los releases (es de desarrollo): no puedo verificar nada.' 'This copy has no release public key (it is a development copy): I cannot verify anything.') }
  $firmantes = Join-Path $dir 'firmantes'
  [IO.File]::WriteAllText($firmantes, "orobas-sec namespaces=""$EspacioFirma"" $ClavePublica`n", (New-Object Text.UTF8Encoding $false))
  $ok = $false
  $viejo = $false
  foreach ($kg in (SshKeygens)) {
    $r = CorrerConEntrada $kg @('-Y', 'verify', '-f', $firmantes, '-I', 'orobas-sec', '-n', $EspacioFirma, '-s', (Join-Path $dir 'SHA256SUMS.sig')) (Join-Path $dir 'SHA256SUMS')
    if ($r.Codigo -eq 0) { $ok = $true; break }
    if ($r.Salida -match 'illegal option|unknown option|invalid option') { $viejo = $true; continue }
    throw (t "La firma de SHA256SUMS de $version no es válida para la clave de este archivo. No instalo nada." "The signature of SHA256SUMS for $version is not valid for this file's key. Nothing installed.")
  }
  if (-not $ok) {
    if ($viejo) { throw (t 'Tu ssh-keygen no verifica firmas (-Y verify): hace falta OpenSSH 8.1 o más nuevo (viene con Windows 11 y con Git for Windows).' 'Your ssh-keygen cannot verify signatures (-Y verify): OpenSSH 8.1 or newer is needed (it ships with Windows 11 and Git for Windows).') }
    throw (t 'Falta ssh-keygen (el cliente de OpenSSH de Windows, o Git for Windows): sin él no puedo verificar la firma.' 'ssh-keygen is missing (the Windows OpenSSH client, or Git for Windows): without it I cannot verify the signature.')
  }
  if (-not (SumaFirmada $dir "orobas-sec-$version.tar.gz")) { throw (t "El SHA256SUMS firmado no es el de $version. No instalo nada." "The signed SHA256SUMS is not the one for $version. Nothing installed.") }
}
# --- fin común ---
# --actualizar: busca el último release; si es más nuevo, baja SHA256SUMS y su firma, la verifica con la clave
# de arriba, baja cyber-lanzador.ps1, compara su suma con la firmada y revisa la sintaxis; recién entonces pregunta
# y se reemplaza. Cualquier falla deja el que está y sale con error. Sin consola no se reemplaza solo, salvo con --si.
function ActualizarLanzador($conSi) {
  if (-not $conSi -and [Console]::IsInputRedirected) {
    Write-Host (t 'Sin consola no reemplazo el lanzador (sólo actualizo la imagen). Para hacerlo igual: cyber --actualizar --si' 'Without a console I do not replace the launcher (only the image). To do it anyway: cyber --actualizar --si')
    return
  }
  # Copia de desarrollo: no la completó un release (o le falta la clave). Reemplazarla pisaría el archivo del repo.
  if (-not $VersionLanzador -or $ClavePublica -match 'REEMPLAZAR') {
    Write-Host (t 'Este lanzador es una copia de desarrollo (no viene de un release): no se reemplaza solo. Instalá uno de un release (README).' 'This launcher is a development copy (not from a release): it does not replace itself. Install one from a release (README).')
    return
  }
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $dir = Join-Path ([IO.Path]::GetTempPath()) "cyber-actualizar-$PID"
  New-Item -ItemType Directory -Force $dir | Out-Null
  $reemplazado = $false
  try {
    $nuevo = UltimoRelease
    if ($nuevo -eq $VersionLanzador) { Write-Host ((t 'El lanzador ya está al día' 'The launcher is up to date') + " ($nuevo)."); return }
    if (VersionMenor $nuevo $VersionLanzador) { Write-Host ((t 'El último release publicado es más viejo que este lanzador; no bajo de versión: ' 'The latest published release is older than this launcher; not downgrading: ') + "$nuevo < $VersionLanzador"); return }
    $base = "$ReleasesUrl/download/$nuevo"
    BajarArchivo "$base/SHA256SUMS" (Join-Path $dir 'SHA256SUMS')
    BajarArchivo "$base/SHA256SUMS.sig" (Join-Path $dir 'SHA256SUMS.sig')
    VerificarLista $dir $nuevo
    $esperada = SumaFirmada $dir 'cyber-lanzador.ps1'
    if (-not $esperada) { throw (t "el release $nuevo no trae el lanzador (cyber-lanzador.ps1)" "release $nuevo has no launcher (cyber-lanzador.ps1)") }
    $tmp = Join-Path $dir 'cyber-lanzador.ps1'
    BajarArchivo "$base/cyber-lanzador.ps1" $tmp
    if ((SumaDe $tmp) -ne $esperada) { throw (t 'el lanzador que bajó no coincide con la suma firmada' 'the downloaded launcher does not match the signed checksum') }
    $errores = $null
    [void][Management.Automation.Language.Parser]::ParseFile($tmp, [ref]$null, [ref]$errores)
    if ($errores -or -not ((Get-Content $tmp -TotalCount 1) -match 'Lanzador de Windows de elevate-cyber')) { throw (t 'lo que bajó no es el lanzador' 'the download is not the launcher') }
    if (-not $conSi -and -not (Pregunta ((t '¿Actualizo el lanzador de ' 'Update the launcher from ') + $(if ($VersionLanzador) { $VersionLanzador } else { t 'desarrollo' 'development' }) + (t ' a ' ' to ') + "$nuevo?"))) { return }
    # Al lado del instalado y con Move-Item: nunca queda a medio escribir.
    $destino = Join-Path (Split-Path $PSCommandPath) ".cyber-lanzador-nuevo-$PID.ps1"
    Copy-Item $tmp $destino -Force -ErrorAction Stop
    Move-Item $destino $PSCommandPath -Force -ErrorAction Stop
    ActualizarCmd
    Write-Host ((t 'Lanzador actualizado a ' 'Launcher updated to ') + "$nuevo.")
    $reemplazado = $true
  } catch {
    Write-Host ((t 'No actualicé el lanzador; sigue el que tenés: ' 'Launcher not updated; keeping the current one: ') + $_.Exception.Message)
    Terminar 1
  } finally {
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
  }
  if (-not $reemplazado) { return }
  # El lanzador nuevo baja su imagen (la que fija su release) sin volver a buscarse.
  $exe = if ($EsWin) { 'powershell' } else { 'pwsh' }
  & $exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath --actualizar-imagen
  Terminar $LASTEXITCODE
}
function Instalar {
  New-Item -ItemType Directory -Force $Bin | Out-Null
  $nuevoPs1 = Join-Path $Bin 'cyber-lanzador.ps1'
  $nuevoCmd = Join-Path $Bin 'cyber.cmd'
  # Copiar un archivo sobre sí mismo da error: solo si origen y destino difieren.
  if ($PSCommandPath -ne $nuevoPs1) { Copy-Item $PSCommandPath $nuevoPs1 -Force }
  EscribirCmd $nuevoCmd
  # El cyber.ps1 de instalaciones viejas se borra solo si el cyber.cmd instalado ya llama al nombre nuevo (si no, «cyber» quedaría roto).
  if ((Test-Path $nuevoPs1) -and (Test-Path $nuevoCmd) -and ((Get-Content $nuevoCmd -Raw) -match 'cyber-lanzador\.ps1')) { Remove-Item (Join-Path $Bin 'cyber.ps1') -Force -ErrorAction SilentlyContinue }
  $ruta = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (($ruta -split ';') -notcontains $Bin) {
    [Environment]::SetEnvironmentVariable('Path', (($ruta, $Bin | Where-Object { $_ }) -join ';'), 'User')
  }
  Write-Host (t "Instalado en $Bin. Abrí una terminal nueva y escribí: cyber" "Installed in $Bin. Open a new terminal and type: cyber")
  # Una función o un alias «cyber» en un perfil de PowerShell (la guía vieja usaba docker run) le gana al lanzador sin que se note: se avisa.
  $docs = [Environment]::GetFolderPath('MyDocuments')
  foreach ($perfil in @(foreach ($d in 'WindowsPowerShell', 'PowerShell') { foreach ($f in 'profile.ps1', 'Microsoft.PowerShell_profile.ps1') { Join-Path (Join-Path $docs $d) $f } })) {
    if ((Test-Path $perfil) -and ((Get-Content $perfil -Raw) -match '(?im)^\s*(function\s+(global:)?cyber\b|(Set|New)-Alias\s+(-Name\s+)?cyber\b)')) {
      Write-Host (t "Ojo: $perfil define su propio «cyber», que le gana al lanzador. Borralo de ese archivo y abrí una terminal nueva." "Note: $perfil defines its own ""cyber"", which wins over the launcher. Remove it from that file and open a new terminal.")
    }
  }
}
if ($args -contains '--instalar') { Instalar; exit 0 }
if ($args -contains '--actualizar') { ActualizarLanzador ($args -contains '--si') }
# Desde fuera de $Bin se ofrece instalar (solo en una corrida normal) una sola vez (la respuesta, sí o no, queda en lanzador.conf). Sin consola interactiva no se pregunta.
if ($PSScriptRoot -ne $Bin -and -not ($args | Where-Object { $_ -in '--actualizar', '--actualizar-imagen', '--resumen', '--vigilar', '--cerrar-docker', '--instalar' }) -and -not [Console]::IsInputRedirected -and -not ((Test-Path $Conf) -and (@(Get-Content $Conf) -match '^instalar='))) {
  if (Pregunta (t '¿Instalo cyber para usarlo desde cualquier terminal?' 'Install cyber to use it from any terminal?')) { GuardarConf 'instalar' 'si'; Instalar } else { GuardarConf 'instalar' 'no' }
}

# Desde conhost se relanza en Windows Terminal si ya está instalado (más colores y mouse). CYBER_PRUEBA_WT=<build> es solo para pruebas: lo habilita fuera de Windows y con la entrada redirigida.
# conhost nunca define TERM ni SSH_*; Alacritty, WezTerm, mintty y el SSH sí.
function EsConhost { -not $env:WT_SESSION -and -not $env:TERM_PROGRAM -and $env:ConEmuANSI -ne 'ON' -and -not $env:SSH_CONNECTION -and -not $env:SSH_CLIENT -and -not $env:TERM }
# Solo se relanza/pregunta si va a abrirse la TUI: no con un comando (jobs, findings…), ni con -p, --continuar, --detach, -h, ni con la salida redirigida.
function AbreTui($a) {
  if (-not $env:CYBER_PRUEBA_WT -and [Console]::IsOutputRedirected) { return $false }
  $conValor = '-s', '--session', '-m', '--model', '-b', '--presupuesto', '-r', '--peticiones', '--ritmo', '--agente', '--obs', '-C', '--dir'
  for ($i = 0; $i -lt $a.Count; $i++) {
    $x = "$($a[$i])"
    if ($x -cmatch '^(-p|--print|--continuar|--detach|-h|--help)(=|$)') { return $false }
    if ($conValor -ccontains $x) { $i++ } elseif (-not $x.StartsWith('-')) { return $false }
  }
  $true
}
function BuscarWt {
  $c = Get-Command wt.exe -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  $p = if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\wt.exe' }
  if ($p -and (Test-Path $p)) { $p } else { $null }
}
function AbrirEnWt($wt, $resto) {
  # wt separa comandos con «;», por eso se escapa en la carpeta y en los argumentos.
  $esc = { param($x) "$x" -replace ';', '\;' }
  $global:LASTEXITCODE = $null
  & $wt -d (& $esc (Get-Location).ProviderPath) powershell -NoProfile -ExecutionPolicy Bypass -File (& $esc $PSCommandPath) @($resto | ForEach-Object { & $esc $_ })
  if (-not $? -or $LASTEXITCODE) { Write-Host (t 'No pude abrir Windows Terminal; sigo en esta consola.' 'Could not open Windows Terminal; continuing in this console.'); return }
  Write-Host (t 'Abro cyber en Windows Terminal.' 'Opening cyber in Windows Terminal.')
  Terminar 0
}
$wtBuild = if ($env:CYBER_PRUEBA_WT) { [int]$env:CYBER_PRUEBA_WT } elseif ($EsWin -and -not [Console]::IsInputRedirected) { [Environment]::OSVersion.Version.Build } else { 0 }
if ($wtBuild -and (EsConhost) -and (AbreTui $args) -and -not ($args | Where-Object { $_ -in '--actualizar', '--actualizar-imagen', '--resumen' })) {
  if ($wt = BuscarWt) { AbrirEnWt $wt @($args) }
  elseif ($wtBuild -ge 19041 -and -not ((Test-Path $Conf) -and (@(Get-Content $Conf) -contains 'windows_terminal=no'))) {
    # Sin wt.exe (y Windows 10 2004 o más nuevo, que es donde existe) se ofrece instalarlo; Enter = sí.
    $r = Read-Host (t 'Estás en la consola clásica de Windows: cyber se ve mucho mejor en Windows Terminal. ¿Lo instalo? [S]í / [N]o, esta vez no / [D]ejá de preguntar' 'You are in the classic Windows console: cyber looks much better in Windows Terminal. Install it? [Y]es / [N]o, not now / [D]on''t ask again')
    if ($r -match '^(d|dej[aá].*|don''?t.*)$') { GuardarConf 'windows_terminal' 'no' }
    elseif ($r -match '^(|s|si|sí|y|yes)$') {
      if (Get-Command winget -ErrorAction SilentlyContinue) {
        & winget install --id Microsoft.WindowsTerminal -e --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -ne 0) { Write-Host (t 'No pude instalar Windows Terminal; sigo en esta consola.' 'Could not install Windows Terminal; continuing in this console.') }
        elseif ($wt = BuscarWt) { AbrirEnWt $wt @($args) }
        else { Write-Host (t 'Windows Terminal quedó instalado: volvé a abrir cyber.' 'Windows Terminal is installed: open cyber again.') }
      } else {
        Start-Process 'ms-windows-store://pdp/?productid=9N0DX20HK701' -ErrorAction SilentlyContinue
        if ($?) { Write-Host (t 'Abrí Windows Terminal en la Store: cuando termine de instalarse, volvé a abrir cyber.' 'I opened Windows Terminal in the Store: when it finishes installing, open cyber again.') }
        else { Write-Host (t 'No pude abrir la Store; instalá Windows Terminal desde https://aka.ms/terminal y volvé a abrir cyber.' 'Could not open the Store; install Windows Terminal from https://aka.ms/terminal and open cyber again.') }
      }
    }
  }
}

# 1. Docker instalado y andando
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Salir (t 'Docker no está instalado. Instalá Docker Desktop: https://www.docker.com/products/docker-desktop/' 'Docker is not installed. Install Docker Desktop: https://www.docker.com/products/docker-desktop/')
}
if (-not (DockerAndando)) {
  if (-not (Pregunta (t 'Docker no está andando. ¿Lo abro?' 'Docker is not running. Start it?'))) { Salir (t 'Abrí Docker Desktop y volvé a correr cyber.' 'Start Docker Desktop and run cyber again.') }
  $Abri = $true
  Start-Process (Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe')
  $arranco = $false
  for ($i = 0; $i -lt 60 -and -not $arranco; $i++) { Start-Sleep 2; $arranco = DockerAndando }
  if (-not $arranco) { Salir (t 'Docker no arrancó a tiempo.' 'Docker did not start in time.') }
}

# 2 y 3. Imagen: la primera vez se baja entera (varios GB) mostrando el avance; login en ghcr.io sólo si no es la pública; actualización con confirmación
function EsPublica { "$Imagen" -match ('^' + [regex]::Escape($ImagenPublica) + '([:@]|$)') }
function Bajar {
  Write-Host ((t 'Bajando la imagen ' 'Pulling the image ') + $Imagen + (t ' (la primera vez son varios GB)...' ' (several GB the first time)...'))
  $s = Dk pull $Imagen | ForEach-Object { $l = "$_"; Write-Host $l; $l } | Out-String
  if ($LASTEXITCODE -ne 0 -and $s -match 'unauthorized|denied' -and (EsPublica)) {
    Salir (t 'ghcr.io rechazó la descarga de la imagen pública, que se baja sin login. Si iniciaste sesión en ghcr.io con un token que ya no sirve, cerrala (docker logout ghcr.io) y volvé a correr cyber.' 'ghcr.io refused the public image, which needs no login. If you logged in to ghcr.io with a token that no longer works, log out (docker logout ghcr.io) and run cyber again.')
  }
  if ($LASTEXITCODE -ne 0 -and $s -match 'unauthorized|denied') {
    Write-Host (t 'Creá un token (read:packages) en https://github.com/settings/tokens/new?scopes=read:packages' 'Create a token (read:packages) at https://github.com/settings/tokens/new?scopes=read:packages')
    $u = Read-Host (t 'Usuario de GitHub' 'GitHub username')
    $msg = t 'Token de GitHub (read:packages)' 'GitHub token (read:packages)'
    if ([Console]::IsInputRedirected) { $plano = Read-Host $msg }  # sin consola no hay lectura oculta posible
    else { $plano = [Net.NetworkCredential]::new('', (Read-Host $msg -AsSecureString)).Password }
    $plano | & docker login ghcr.io -u $u --password-stdin | Out-Null  # el token va por stdin, no por argv
    if ($LASTEXITCODE -ne 0) { Salir (t 'No pude iniciar sesión en ghcr.io.' 'Could not log in to ghcr.io.') }
    $s = Dk pull $Imagen | ForEach-Object { $l = "$_"; Write-Host $l; $l } | Out-String
  }
  if ($LASTEXITCODE -ne 0) { Salir (t 'No pude bajar la imagen (el error está arriba).' 'Could not pull the image (the error is above).') }
}
# --actualizar: el lanzador ya se actualizó (o no hacía falta) al principio; acá sólo queda la imagen.
if ($args | Where-Object { $_ -in '--actualizar', '--actualizar-imagen' }) {
  Bajar
  Terminar 0
}
$local = Dk image inspect --format '{{json .RepoDigests}}' $Imagen | Out-String
if ($LASTEXITCODE -ne 0) { Bajar }
elseif ($local -notmatch 'sha256:[0-9a-f]+') { }  # imagen local sin digest (construida a mano): no hay con qué comparar
elseif ($Imagen -match '@sha256:') { }  # fijada por digest (la de un release): no cambia; lo nuevo llega con cyber --actualizar
elseif (-not $env:CYBER_NO_UPDATE) {
  # Primero el digest de arriba del manifiesto con buildx (el que queda en RepoDigests, también con un índice); si no hay buildx, el primer Descriptor.
  $remoto = $null
  # {{.Manifest.Digest}} da el de la plataforma con un índice; en el JSON el primer "digest" es el de arriba.
  $job = Start-Job { param($i) $d = & docker buildx imagetools inspect $i --format '{{json .Manifest}}' 2>$null; if ($LASTEXITCODE -eq 0) { $d } } -ArgumentList $Imagen
  if (Wait-Job $job -Timeout 15) { if ((Receive-Job $job | Out-String) -match '"digest"\s*:\s*"(sha256:[0-9a-f]+)"') { $remoto = $Matches[1] } }
  Remove-Job $job -Force
  if (-not $remoto) {
    $job = Start-Job { param($i) & docker manifest inspect --verbose $i 2>$null } -ArgumentList $Imagen
    if (Wait-Job $job -Timeout 15) {
      # regex y no ConvertFrom-Json: en PS 5.1 un arreglo JSON llega como un solo objeto y el digest sale como arreglo
      if ((Receive-Job $job | Out-String) -match '(?s)"Descriptor"\s*:\s*\{[^}]*?"digest"\s*:\s*"(sha256:[0-9a-f]+)"') { $remoto = $Matches[1] }
    }
    Remove-Job $job -Force
  }
  if (-not $remoto) { Write-Host (t 'No pude buscar actualizaciones.' 'Could not check for updates.') }
  elseif (-not $local.Contains($remoto) -and (Pregunta (t 'Hay una imagen nueva. ¿Actualizo?' 'A new image is available. Update?'))) { Bajar }
}

# 4. Llave de cifrado, protegida con DPAPI del usuario
New-Item -ItemType Directory -Force $Cred, $Datos | Out-Null
if ($EsWin) {
  icacls $Cred /inheritance:r /grant:r "$($env:USERDOMAIN)\$($env:USERNAME):(OI)(CI)F" | Out-Null
  if ($LASTEXITCODE -ne 0) { Write-Host (t "Aviso: no pude restringir los permisos de $Cred." "Warning: could not restrict permissions on $Cred.") }
}
$archivoLlave = Join-Path $Cred 'llave.dpapi'
if (-not (Test-Path $archivoLlave)) {
  $b = New-Object byte[] 32
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  $nueva = [Convert]::ToBase64String($b)
  # shortcut: fuera de Windows (solo pruebas) no hay DPAPI y se guarda en claro; el lanzador es solo para Windows
  if ($EsWin) { $nueva | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Set-Content $archivoLlave }
  else { Set-Content $archivoLlave $nueva }
}
$guardada = (Get-Content $archivoLlave -Raw).Trim()
# Desde acá la llave está en el entorno: pase lo que pase (Ctrl+C, error) se limpia al salir.
try {
$env:CYBER_SECRETS_KEY = if ($EsWin) { [Net.NetworkCredential]::new('', (ConvertTo-SecureString $guardada)).Password } else { $guardada }

# 5. Contenedor del proyecto
# Nombre fijo por carpeta: todas las ventanas del mismo proyecto comparten un contenedor (y un daemon). En Windows la ruta no distingue mayúsculas.
function NombreProyecto($proyecto) {
  $ruta = $proyecto.TrimEnd('\', '/')
  if (-not $ruta) { $ruta = $proyecto }
  if ($EsWin) { $ruta = $ruta.ToLowerInvariant() }
  $h = [Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($ruta))
  $script:Nombre = 'cyber-p-' + ((-join ($h | ForEach-Object { $_.ToString('x2') })).Substring(0, 12))
}
# ¿Corre el contenedor del proyecto?
function Corre { @(Dk ps --filter "name=^$($script:Nombre)`$" --format '{{.Names}}' | ForEach-Object { "$_".Trim() }) -contains $script:Nombre }
# Con $chequeo corre la imagen sola (sin nombre, puerto ni llave) para ver si el lanzador la entiende; si no, el daemon del proyecto con -d.
function ArgsCrear($proyecto, $puerto = $null, $chequeo = $false) {
  $env:CYBER_PROYECTO_HOST = $proyecto
  $env:CYBER_CREDENCIALES_HOST = $Cred
  $env:CYBER_DATOS_HOST = $Datos  # para que los avisos del contenedor muestren rutas del host
  $a = if ($chequeo) { @('run', '--rm', '-i') } else { @('run', '-d', '--rm', '--init', '--name', $script:Nombre) }
  $a += '--add-host=host.docker.internal:host-gateway'
  if ($puerto) { $a += '-p', "127.0.0.1:${puerto}:47615", '-e', "CYBER_PUERTO_HOST=${puerto}" }  # la extensión del navegador entra por acá
  $a += '-v', "${proyecto}:/proyecto", '-v', "${Cred}:/home/node/.config/elevate-cyber", '-v', "${Datos}:/home/node/.local/share/elevate-cyber"
  $nombres = 'CYBER_PROYECTO_HOST', 'CYBER_DATOS_HOST', 'CYBER_CREDENCIALES_HOST', 'LANG', 'LC_ALL'
  if (-not $chequeo) { $nombres += 'CYBER_SECRETS_KEY' }
  foreach ($n in $nombres) { $a += '-e', $n }
  $a += '-e', 'CYBER_COMPARTIDO=1'
  if ($env:OROBAS_API_KEY -and -not $chequeo) { $a += '-e', 'OROBAS_API_KEY' }
  if ($env:CYBER_TRAZAS -and -not $chequeo) { $a += '-e', 'CYBER_TRAZAS' }  # el modo de trazas; sin ella rige config.json
  $a + $Imagen + $(if ($chequeo) { '--chequeo' } else { 'daemon' })
}

# Nueva ventana por lanzamiento (el vigilante la encuentra por CYBER_VENTANA) y un vigilante aparte: cerrar la terminal dejaría la ventana colgada dentro del contenedor.
function NuevaVentana { $script:Ventana = -join (1..4 | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) }) }
function Vigilar {
  # Solo recibe pid, contenedor, ventana y si abrimos Docker: se sacan del entorno la llave y la clave de orobas mientras nace.
  $guardado = @{}
  foreach ($n in 'CYBER_SECRETS_KEY', 'OROBAS_API_KEY') { $guardado[$n] = [Environment]::GetEnvironmentVariable($n); [Environment]::SetEnvironmentVariable($n, $null) }
  try {
    $exe = if ($EsWin) { 'powershell' } else { 'pwsh' }
    $sp = @{ PassThru = $true; ArgumentList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '--vigilar', $PID, $script:Nombre, $script:Ventana, $(if ($Abri) { '1' } else { '0' })) }
    if ($EsWin) { $sp.WindowStyle = 'Hidden' }  # -WindowStyle no existe fuera de Windows (solo pruebas)
    $script:Vig = Start-Process $exe @sp
  } finally { foreach ($n in $guardado.Keys) { [Environment]::SetEnvironmentVariable($n, $guardado[$n]) } }
}

# docker run -d del contenedor del proyecto con puerto para la extensión: el primer P de 47615 a 47634 que no publique otro cyber-* (según docker ps); si el puerto falla («port is already allocated» u otro proceso que lo tenga: «Only one usage…», «forbidden by its access permissions»)
# (otra ventana ganó la carrera) se prueba el siguiente. Si el nombre ya existe, otra ventana ganó la carrera y vale como éxito. stderr va a un archivo para poder leer esos errores; se muestra si falla.
function Crear($proyecto) {
  $usados = @([regex]::Matches((Dk ps --filter 'name=cyber-' --format '{{.Ports}}' | Out-String), ':(\d+)->47615/tcp') | ForEach-Object { [int]$_.Groups[1].Value })
  $p = 47615
  $errArch = Join-Path ([IO.Path]::GetTempPath()) "cyber-err-$PID.txt"
  while ($true) {
    while ($p -le 47634 -and $usados -contains $p) { $p++ }
    $pub = if ($p -le 47634) { $p } else { $null }
    if (-not $pub) { Write-Host (t 'No hay un puerto libre (47615-47634) para la extensión del navegador: en esta ventana no va a andar.' 'No free port (47615-47634) for the browser extension: it will not work in this window.') }
    $global:LASTEXITCODE = $null
    & docker @(ArgsCrear $proyecto $pub) 2>$errArch | Out-Null
    $codigo = $LASTEXITCODE
    $err = if (Test-Path $errArch) { (Get-Content $errArch -Raw) } else { '' }
    Remove-Item $errArch -Force -ErrorAction SilentlyContinue
    if ($codigo -and $err -match '(?s)container name.*is already in use') { $script:Codigo = 0; return }
    if ($codigo -and $pub -and $err -match 'port is already allocated|address already in use|Only one usage|forbidden by its access permissions') {
      if (-not (Corre)) { Dk rm -f $script:Nombre | Out-Null }  # por si quedó creado sin arrancar; si corre es de otra ventana y no se toca
      $p++; continue
    }
    # PS 5.1 guarda el stderr redirigido como ErrorRecord: se sacan las líneas decorativas («At …», «+ …», CategoryInfo) y el prefijo «docker : »
    if ($codigo -and $err) { Write-Host ((($err -split "`r?`n") | Where-Object { $_.Trim() -and $_ -notmatch '^\s*(At |\+ |CategoryInfo|FullyQualifiedErrorId)' } | ForEach-Object { $_ -replace '^docker\s*: ', '' }) -join "`n") }
    $script:Codigo = $codigo
    return
  }
}

# Entra al contenedor del proyecto con una ventana propia. CYBER_CONSOLE=conhost es de esta terminal, no del contenedor: va acá y no en el run -d.
function Entrar($usuario) {
  $global:LASTEXITCODE = $null
  $a = @('exec', $(if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { '-i' } else { '-it' }), '-e', "CYBER_VENTANA=$($script:Ventana)")
  # conhost clásico solo si nada delata otra terminal (Windows Terminal, VS Code/WezTerm por TERM_PROGRAM, ConEmu). shortcut: no se consulta el modo VT de la consola (GetConsoleMode), alcanza con el entorno.
  if (EsConhost) { $a += '-e', 'CYBER_CONSOLE=conhost' }
  foreach ($n in 'LANG', 'LC_ALL', 'TERM', 'COLORTERM', 'TERM_PROGRAM', 'KITTY_WINDOW_ID', 'WT_SESSION', 'CYBER_STREAMER', 'CYBER_STREAMER_HOSTS', 'CYBER_STREAMER_PUBLICOS', 'CYBER_STREAMER_USO', 'CYBER_STREAMER_OBS') { $a += '-e', $n }
  & docker @a $script:Nombre /opt/elevate-cyber/bin/cyber -C /proyecto @usuario
  $script:Codigo = $LASTEXITCODE  # no se devuelve: capturar la salida de la función le sacaría la consola a docker
}

if (-not $env:LANG) { $env:LANG = if ($Es) { 'es_ES.UTF-8' } else { 'en_US.UTF-8' } }  # Windows no define LANG; el contenedor sigue a Get-Culture
$proyecto = (Get-Location).ProviderPath
$usuario = @($args)
$chequeo = & docker @(ArgsCrear $proyecto $null $true) 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) {
  if ($chequeo -match 'ERR_PARSE_ARGS_UNKNOWN_OPTION|nknown option') { Write-Host (t 'Tu imagen local es vieja para este lanzador: corré cyber --actualizar' 'Your local image is too old for this launcher: run cyber --actualizar') }
  else { Write-Host $chequeo }
  Terminar 1
}
# Una imagen que entiende --chequeo pero no imprime «compartido» es anterior al modo compartido: se trata igual que una imagen vieja.
if ($chequeo -notmatch '(?m)^compartido\s*$') {
  Write-Host (t 'Tu imagen local es vieja para este lanzador: corré cyber --actualizar' 'Your local image is too old for this launcher: run cyber --actualizar')
  Terminar 1
}

# 6. Reabrir en otro proyecto/sesión: código 75 y la orden queda en reabrir.txt de la carpeta de datos
$reabrirTxt = Join-Path $Datos 'reabrir.txt'
Remove-Item $reabrirTxt -Force -ErrorAction SilentlyContinue  # un resto de una sesión caída no debe reabrir un destino viejo
$reintento = $false  # propio: corrido desde una sesión, no hereda un $reintento de afuera
while ($true) {
  NombreProyecto $proyecto
  NuevaVentana
  if (Corre) {
    $ni = (Dk inspect -f '{{.Image}}' $script:Nombre | Out-String).Trim()
    $li = (Dk image inspect -f '{{.Id}}' $Imagen | Out-String).Trim()
    if ($ni -and $li -and $ni -ne $li) { Write-Host (t 'Hay otra ventana de este proyecto con la versión anterior; cerralas para usar la nueva.' 'Another window of this project runs the previous version; close them to use the new one.') }
  } else {
    Crear $proyecto
    if ($script:Codigo -ne 0) { Terminar $(if ($script:Codigo) { $script:Codigo } else { 1 }) }
    # Si otra ventana ganó la carrera, su contenedor puede estar creado y todavía no corriendo: se espera un poco antes del exec.
    for ($n = 0; -not (Corre); $n++) {
      if ($n -ge 15) { Write-Host (t 'El contenedor del proyecto no arrancó.' 'The project container did not start.'); Terminar 1 }
      Start-Sleep 1
    }
  }
  Vigilar
  Entrar $usuario
  $codigo = $script:Codigo
  if ($null -eq $codigo) { Terminar 1 }  # docker no pudo ni arrancar
  # Carrera de cierre: la última ventana de otra terminal apagó el contenedor justo antes del exec; se lo recrea una sola vez y se vuelve a entrar.
  if ($codigo -ne 0 -and $codigo -ne 75 -and -not $reintento -and -not (Corre)) {
    $reintento = $true
    if ($script:Vig) { Stop-Process -Id $script:Vig.Id -ErrorAction SilentlyContinue }
    continue
  }
  $reintento = $false
  if ($codigo -ne 75) { Terminar $codigo }
  # En la salida normal el vigilante sigue solo (puede esperar para cerrar Docker); al reabrir se lanza otro.
  if ($script:Vig) { Stop-Process -Id $script:Vig.Id -ErrorAction SilentlyContinue }
  $partes = if (Test-Path $reabrirTxt) { (Get-Content $reabrirTxt -Raw -Encoding UTF8).Trim() -split "`t" } else { @() }
  Remove-Item $reabrirTxt -Force -ErrorAction SilentlyContinue
  if ($partes.Count -ne 2 -or -not $partes[0] -or -not $partes[1]) {
    Write-Host (t 'El contenedor pidió reabrir pero no dejó destino válido (reabrir.txt).' 'The container asked to reopen but left no valid target (reabrir.txt).')
    Terminar 75
  }
  if (-not (Test-Path -LiteralPath $partes[0] -PathType Container)) {
    Write-Host ((t 'No existe la carpeta a reabrir: ' 'The folder to reopen does not exist: ') + $partes[0])
    Terminar 75
  }
  $proyecto = $partes[0]
  $usuario = @('-s', $partes[1])
}
} finally { RestaurarEntorno }
