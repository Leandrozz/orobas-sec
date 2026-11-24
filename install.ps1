# Instalador de Orobas (orobas-sec) para Windows: instala el lanzador «cyber» del modo contenedor (el agente corre
# en la imagen de Docker, con Docker Desktop) en tu perfil, sin permisos de administrador.
#
# Instala una versión FIJA desde un release con tag: baja SHA256SUMS y su firma, verifica la firma con la clave
# pública de abajo (ssh-keygen -Y verify, del cliente de OpenSSH) y la suma SHA-256 (Get-FileHash) de cada
# archivo, y recién entonces instala. Ante cualquier falla no instala nada, no deja restos y sale con error.
#
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 [-Version vX.Y.Z] [-Prefix DIR] [-Bin DIR] [-Si]
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -Desinstalar [-Si]
#   Actualizar: cyber --actualizar (el lanzador verifica el release nuevo igual que este instalador).
#
# El modo nativo (Node en Windows) no existe: el agente usa sockets Unix. Sin Docker, usá install.sh dentro de WSL.
# Este archivo va con BOM UTF-8: Windows PowerShell 5.1 lo necesita para leer las tildes.
param(
  [string]$Version,
  [string]$Prefix,
  [string]$Bin,
  [switch]$Si,
  [switch]$Desinstalar,
  [switch]$Ayuda
)
$ErrorActionPreference = 'Stop'
$VersionInstalador = ''  # la completa scripts/release/armar.sh con el tag del release
$ReleasesUrlOrigen = 'https://github.com/Leandrozz/orobas-sec/releases'
$ReleasesUrl = if ($env:CYBER_RELEASES_URL) { $env:CYBER_RELEASES_URL } else { $ReleasesUrlOrigen }
$ReleasesUrl = $ReleasesUrl.TrimEnd('/')
# Clave pública que firma SHA256SUMS de cada release. Es la misma en install.sh, install.ps1 y los dos lanzadores:
# scripts/release/fijar-clave.sh la cambia en todos.
$ClavePublica = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFfKpWK3+u7xt/H1nXdYudXF4DWUorU16LWu7ACfcP+R'
$EspacioFirma = 'orobas-sec-release'
$EsWin = ($PSVersionTable.PSEdition -eq 'Desktop') -or ($IsWindows -eq $true)
$Es = (Get-UICulture).TwoLetterISOLanguageName -eq 'es'
function t($es, $en) { if ($Es) { $es } else { $en } }
function Morir($msg) { Write-Host "install.ps1: $msg"; exit 1 }

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

function Confirmar($pregunta) {
  if ($Si) { return }
  if ([Console]::IsInputRedirected) { Morir (t 'No hay una consola para confirmar: revisá lo de arriba y volvé a correr con -Si.' 'No console to confirm: review the above and run again with -Si.') }
  if ((Read-Host "$pregunta [S/n]") -notmatch '^(|s|si|sí|y|yes)$') { Write-Host (t 'No hice nada.' 'Nothing done.'); exit 1 }
}
# ¿Lo que hay en $ruta lo puso este instalador o el lanzador?
function EsNuestro($ruta) {
  if (-not (Test-Path -LiteralPath $ruta -PathType Leaf)) { return $false }
  $cabeza = (Get-Content -LiteralPath $ruta -TotalCount 3) -join "`n"
  $cabeza -match 'Lanzador de Windows de elevate-cyber|cyber-lanzador\.ps1'
}
# Las carpetas que New-Item -Force crea para llegar a $rutas: cada una y sus padres que todavía no existen.
# Una carpeta que ya existe no entra nunca en la lista, así que la limpieza no la puede tocar.
function CarpetasNuevas([string[]]$rutas) {
  $nuevas = @()
  foreach ($r in $rutas) {
    $c = $r
    while ($c -and -not (Test-Path -LiteralPath $c)) {
      if ($nuevas -notcontains $c) { $nuevas += $c }
      $c = Split-Path $c -Parent
    }
  }
  $nuevas
}
# Borra las carpetas de $carpetas que quedaron vacías, de la más honda a la más alta. Nunca borra contenido:
# Directory.Delete sin recursión falla si la carpeta tiene algo adentro (o ya no está), y esa falla se ignora.
function BorrarSiVacias([string[]]$carpetas) {
  foreach ($c in @($carpetas | Where-Object { $_ } | Sort-Object Length -Descending)) {
    try { [IO.Directory]::Delete($c) } catch { }
  }
}
function EscribirCmd($ruta) {
  $lineas = '@setlocal', '@set "L=%~dp0cyber-lanzador.ps1"', '@if not exist "%L%" set "L=%~dp0cyber.ps1"', '@powershell -NoProfile -ExecutionPolicy Bypass -File "%L%" %*'
  [IO.File]::WriteAllText($ruta, (($lineas -join "`r`n") + "`r`n"), [Text.Encoding]::ASCII)
}

if ($Ayuda) {
  Write-Host 'install.ps1 [-Version vX.Y.Z] [-Prefix DIR] [-Bin DIR] [-Si] | -Desinstalar [-Si]'
  Write-Host (t "Por defecto: la versión de este instalador, -Prefix %LOCALAPPDATA%\orobas-sec, -Bin %LOCALAPPDATA%\elevate-cyber\bin. CYBER_RELEASES_URL cambia de dónde baja (por defecto $ReleasesUrlOrigen)." "Defaults: this installer's version, -Prefix %LOCALAPPDATA%\orobas-sec, -Bin %LOCALAPPDATA%\elevate-cyber\bin. CYBER_RELEASES_URL changes where it downloads from (default $ReleasesUrlOrigen).")
  exit 0
}
if (-not $EsWin -and -not $env:CYBER_PRUEBA_WINDOWS) { Morir (t 'Esto es para Windows. En Linux y macOS usá install.sh.' 'This is for Windows. On Linux and macOS use install.sh.') }
if (-not $env:LOCALAPPDATA) { Morir 'LOCALAPPDATA no está definido.' }
if (-not $Prefix) { $Prefix = Join-Path $env:LOCALAPPDATA 'orobas-sec' }
if (-not $Bin) { $Bin = Join-Path (Join-Path $env:LOCALAPPDATA 'elevate-cyber') 'bin' }  # el $Bin del lanzador
$Prefix = [IO.Path]::GetFullPath($Prefix).TrimEnd('\', '/')
$Bin = [IO.Path]::GetFullPath($Bin).TrimEnd('\', '/')
# Como install.sh: ni la raíz de un disco ni tu perfil (o LOCALAPPDATA/APPDATA enteros), porque -Desinstalar borra -Prefix entero.
$noUsar = @($env:USERPROFILE, $env:HOME, $env:LOCALAPPDATA, $env:APPDATA | Where-Object { $_ } | ForEach-Object { try { [IO.Path]::GetFullPath($_).TrimEnd('\', '/') } catch { } })
foreach ($r in $Prefix, $Bin) {
  if (-not $r -or $r -match '^[A-Za-z]:$' -or $noUsar -contains $r) { Morir "$(t 'No uso esta carpeta para instalar; elegí una propia:' 'I will not install into this folder; choose one of its own:') $(if ($r) { $r } else { '/' })" }
}
$Conf = Join-Path $Prefix 'instalacion.conf'
$Lanzador = Join-Path $Bin 'cyber-lanzador.ps1'
$Cmd = Join-Path $Bin 'cyber.cmd'
$Previa = $null
if (Test-Path -LiteralPath $Conf) {
  if ((Get-Content -LiteralPath $Conf -TotalCount 1) -ne '# orobas-sec: instalacion hecha por install.ps1') { Morir "$Conf $(t 'no es de este instalador: no lo toco.' 'is not from this installer: leaving it alone.')" }
  $Previa = (@(Get-Content -LiteralPath $Conf) -match '^version=' | Select-Object -First 1) -replace '^version=', ''
}

if ($Desinstalar) {
  if (-not $Previa) { Morir ((t 'No hay una instalación de este instalador en ' 'No installation from this installer in ') + $Prefix) }
  Write-Host "Orobas $Previa ($(t 'modo contenedor' 'container mode')), $Prefix"
  Write-Host ''
  Write-Host (t 'Voy a borrar:' 'I will remove:')
  Write-Host "  - $Prefix"
  foreach ($f in $Lanzador, $Cmd) { if (EsNuestro $f) { Write-Host "  - $f" } }
  Write-Host ''
  Write-Host (t 'No toco tus datos (sesiones, hallazgos, configuración, credenciales), que están en:' 'Your data (sessions, findings, settings, credentials) stays, in:')
  Write-Host "  $(Join-Path $env:APPDATA 'elevate-cyber')"
  Write-Host "  $(Join-Path $env:LOCALAPPDATA 'elevate-cyber')"
  Write-Host (t "Tampoco las imágenes de Docker (docker image ls) ni $Bin en tu PATH de usuario." "Nor the Docker images (docker image ls) or $Bin in your user PATH.")
  Write-Host ''
  Confirmar (t '¿Desinstalo?' 'Uninstall?')
  foreach ($f in $Lanzador, $Cmd) { if (EsNuestro $f) { Remove-Item -LiteralPath $f -Force } }
  Remove-Item -LiteralPath $Prefix -Recurse -Force
  Write-Host (t 'Desinstalado.' 'Uninstalled.')
  exit 0
}

if (-not $Version) { $Version = $VersionInstalador }
if (-not $Version) { Morir (t 'Este instalador no viene de un release: decí qué versión instalar con -Version vX.Y.Z.' 'This installer does not come from a release: choose a version with -Version vX.Y.Z.') }
if ($Version -notmatch '^v\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$') { Morir ((t 'versión inválida: ' 'invalid version: ') + $Version) }

# Lo que falta, todo junto y con cómo conseguirlo; no se instala nada a la fuerza.
$falta = @()
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { $falta += (t '  - Docker Desktop (el agente corre en un contenedor): https://www.docker.com/products/docker-desktop/' '  - Docker Desktop (the agent runs in a container): https://www.docker.com/products/docker-desktop/') }
if (-not (SshKeygens)) { $falta += (t '  - ssh-keygen (cliente de OpenSSH 8.1+, para verificar la firma): viene con Windows 11 (Configuración > Sistema > Características opcionales > Cliente OpenSSH) y con Git for Windows.' '  - ssh-keygen (OpenSSH client 8.1+, to verify the signature): it ships with Windows 11 (Settings > System > Optional features > OpenSSH Client) and with Git for Windows.') }
if ($falta) { Morir ((t "Antes de instalar falta:`n" "Missing before installing:`n") + ($falta -join "`n")) }
foreach ($f in $Lanzador, $Cmd) {
  if ((Test-Path $f) -and -not (EsNuestro $f)) { Morir "$f $(t 'existe y no lo puso este instalador: no lo piso. Movelo o elegí otra carpeta con -Bin.' 'exists and was not created by this installer: not overwriting it. Move it or choose another folder with -Bin.')" }
}

Write-Host "Orobas $Version · $(t 'modo contenedor' 'container mode') · Windows"
if ($Previa) { Write-Host "$(t 'Instalada ahora' 'Installed now'): $Previa" }
Write-Host ''
Write-Host (t 'Voy a hacer esto:' 'I will do this:')
Write-Host "  1. $(t 'Bajar de' 'Download from') $ReleasesUrl/download/$Version/"
Write-Host '       SHA256SUMS, SHA256SUMS.sig, cyber-lanzador.ps1, install.ps1'
Write-Host "     $(t 'y verificar la firma y la suma SHA-256 de cada uno.' 'and verify the signature and the SHA-256 of each one.')"
Write-Host "  2. $(t 'Instalar el lanzador en' 'Install the launcher in') $Bin (cyber-lanzador.ps1 $(t 'y' 'and') cyber.cmd)."
Write-Host "  3. $(t 'Guardar este instalador en' 'Keep this installer in') $Prefix ($(t 'para' 'for') -Desinstalar)."
Write-Host ''
Write-Host (t 'Sin permisos de administrador. La primera vez que corras «cyber» baja la imagen de Docker (varios GB), con las herramientas adentro del contenedor.' 'No administrator rights. The first time you run "cyber" it pulls the Docker image (several GB), with the tools inside the container.')
Write-Host ''
Confirmar (t '¿Sigo?' 'Continue?')

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("orobas-sec-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $tmp | Out-Null
$prefixCreado = -not (Test-Path -LiteralPath $Prefix)
$binCreado = -not (Test-Path -LiteralPath $Bin)
# Los padres que New-Item va a crear junto con $Bin y $Prefix: si la instalación falla se borran, pero sólo los que
# creó esta corrida y sólo si quedaron vacíos (una carpeta que ya existía no está en la lista).
$padresCreados = @(CarpetasNuevas @((Split-Path $Bin -Parent), (Split-Path $Prefix -Parent)))
$hecho = $false
try {
  $base = "$ReleasesUrl/download/$Version"
  BajarArchivo "$base/SHA256SUMS" (Join-Path $tmp 'SHA256SUMS')
  BajarArchivo "$base/SHA256SUMS.sig" (Join-Path $tmp 'SHA256SUMS.sig')
  VerificarLista $tmp $Version
  foreach ($f in 'cyber-lanzador.ps1', 'install.ps1') {
    $esperada = SumaFirmada $tmp $f
    if (-not $esperada) { throw ((t "el release $Version no trae $f en SHA256SUMS (release incompleto o sin modo contenedor). No instalo nada." "release $Version has no $f in SHA256SUMS (incomplete release or no container mode). Nothing installed.")) }
    BajarArchivo "$base/$f" (Join-Path $tmp $f)
    if ((SumaDe (Join-Path $tmp $f)) -ne $esperada) { throw ((t "la suma SHA-256 de $f no coincide con la firmada. No instalo nada." "the SHA-256 of $f does not match the signed one. Nothing installed.")) }
  }
  $errores = $null
  [void][Management.Automation.Language.Parser]::ParseFile((Join-Path $tmp 'cyber-lanzador.ps1'), [ref]$null, [ref]$errores)
  if ($errores) { throw (t 'el lanzador del release no es un script de PowerShell válido' 'the release launcher is not a valid PowerShell script') }
  Write-Host (t 'Firma y sumas verificadas.' 'Signature and checksums verified.')

  New-Item -ItemType Directory -Force $Bin, $Prefix | Out-Null
  Copy-Item (Join-Path $tmp 'cyber-lanzador.ps1') "$Lanzador.nuevo" -Force
  Move-Item "$Lanzador.nuevo" $Lanzador -Force
  EscribirCmd "$Cmd.nuevo"
  Move-Item "$Cmd.nuevo" $Cmd -Force
  $viejo = Join-Path $Bin 'cyber.ps1'  # el lanzador de instalaciones viejas; un cyber.ps1 que no es nuestro no se toca
  if (EsNuestro $viejo) { Remove-Item -LiteralPath $viejo -Force -ErrorAction SilentlyContinue }
  Copy-Item (Join-Path $tmp 'install.ps1') (Join-Path $Prefix 'install.ps1') -Force
  Set-Content "$Conf.nuevo" @('# orobas-sec: instalacion hecha por install.ps1', 'formato=1', "version=$Version", 'modo=contenedor', "bin=$Bin", "anterior=$Previa") -Encoding ASCII
  Move-Item "$Conf.nuevo" $Conf -Force
  $hecho = $true
} catch {
  Write-Host "install.ps1: $($_.Exception.Message)"
} finally {
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
  if (-not $hecho) {
    # $Prefix y $Bin, enteros sólo si los creó esta corrida (lo de adentro es todo suyo); sus padres nuevos, sólo vacíos.
    if ($prefixCreado) { Remove-Item -LiteralPath $Prefix -Recurse -Force -ErrorAction SilentlyContinue }
    if ($binCreado) { Remove-Item -LiteralPath $Bin -Recurse -Force -ErrorAction SilentlyContinue }
    BorrarSiVacias $padresCreados
  }
}
if (-not $hecho) { exit 1 }

Write-Host ''
Write-Host "$(t 'Listo' 'Done'): Orobas $Version. $(t 'Abrí una terminal nueva y escribí' 'Open a new terminal and type'): cyber"
$ruta = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($ruta -split ';') -notcontains $Bin) {
  $agregar = "[Environment]::SetEnvironmentVariable('Path', ([Environment]::GetEnvironmentVariable('Path', 'User') + ';$Bin'), 'User')"
  if (-not $Si -and -not [Console]::IsInputRedirected -and ((Read-Host ((t '¿Agrego ' 'Add ') + $Bin + (t ' a tu PATH de usuario? [S/n]' ' to your user PATH? [Y/n]'))) -match '^(|s|si|sí|y|yes)$')) {
    [Environment]::SetEnvironmentVariable('Path', (($ruta, $Bin | Where-Object { $_ }) -join ';'), 'User')
    Write-Host (t 'Agregado. Abrí una terminal nueva.' 'Added. Open a new terminal.')
  } else {
    Write-Host ((t "$Bin no está en tu PATH. Para agregarlo (sólo a tu usuario):" "$Bin is not in your PATH. To add it (for your user only):") + "`n  $agregar")
  }
}
# Una función o un alias «cyber» en un perfil de PowerShell (la guía vieja usaba docker run) le gana al lanzador sin que se note: se avisa.
$docs = [Environment]::GetFolderPath('MyDocuments')
if ($docs) {
  foreach ($perfil in @(foreach ($d in 'WindowsPowerShell', 'PowerShell') { foreach ($f in 'profile.ps1', 'Microsoft.PowerShell_profile.ps1') { Join-Path (Join-Path $docs $d) $f } })) {
    if ((Test-Path $perfil) -and ((Get-Content $perfil -Raw) -match '(?im)^\s*(function\s+(global:)?cyber\b|(Set|New)-Alias\s+(-Name\s+)?cyber\b)')) {
      Write-Host (t "Ojo: $perfil define su propio «cyber», que le gana al lanzador. Borralo de ese archivo." "Note: $perfil defines its own ""cyber"", which wins over the launcher. Remove it from that file.")
    }
  }
}
Write-Host "$(t 'Actualizar' 'Update'): cyber --actualizar"
Write-Host "$(t 'Desinstalar' 'Uninstall'): powershell -ExecutionPolicy Bypass -File `"$(Join-Path $Prefix 'install.ps1')`" -Desinstalar"
