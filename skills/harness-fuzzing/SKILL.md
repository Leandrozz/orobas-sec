---
name: harness-fuzzing
description: Un objetivo en C/C++ con código fuente (libxml2, expat, GStreamer, GnuTLS, CUPS, OpenLiteSpeed…) o una hipótesis de memoria salida de leer código: escribir un harness, compilarlo con sanitizers, fuzzearlo en la caja y demostrar el bug ejecutándolo, no razonándolo.
tools: harness_build, fuzz_run, poc_run, code_list, code_search, code_read, code_semgrep
---

## La regla

Una hipótesis estática («este `memcpy` desborda si `len` viene de la entrada») no vale hasta que un ejecutable la dispara con un sanitizer mirando. Leer código elige dónde apuntar; la prueba es el crash reproducible; el hallazgo es lo que ese crash le da a un atacante. Sólo en la caja; los binarios no tienen red (sólo AF_UNIX) y cada corrida tiene topes.

## Tres niveles

1. **Función aislada**: un `LLVMFuzzerTestOneInput` que le pasa los bytes a una función de entrada. Miles de ejecuciones por segundo; ahí aparece casi todo. Empezá siempre acá.
2. **Varios componentes**: cuando el bug pide estado previo (sesión, configuración, varias llamadas en orden, alimentar de a pedazos, un pipeline de decodificación). Los primeros bytes eligen opciones u operaciones y el resto son datos. También cuenta el CLI del objetivo compilado con ASan (como `xmllint`) corrido con `poc_run`.
3. **Punta a punta**: el programa entero como lo usa el atacante (ver «Laboratorio»).

## Elegir la función de entrada

Con `code_search`, lo que procesa bytes de afuera y hace cuentas con ellos: **parsers** (XML, cabeceras HTTP y MIME, IPP, URLs, configuraciones), **decodificadores** (ASN.1/DER, base64, códecs y demuxers, imágenes, compresión), **aritmética de tamaños antes de reservar o copiar** (`malloc(n * size)`, `len + header`, restas que dan negativo, un largo de 64 bits guardado en `int`, `memcpy` con un largo sacado del dato) y **lectores incrementales** con buffer propio.

Preferí la API pública que usa el programa real (buffer y largo) a una función interna: la interna asume validaciones de su llamador, y saltarlas fabrica crashes falsos.

## Harness y compilación

```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > (1 << 20)) return 0;
  doc_t *doc = objetivo_parse_memory((const char *)data, size, OPCIONES_DEL_PROGRAMA);
  if (doc) objetivo_free(doc);   /* liberar todo: si no, el leak es del harness */
  return 0;
}
```

Determinista (sin hora, azar ni estado que sobreviva entre entradas; lo único va en `LLVMFuzzerInitialize`), sin `exit`, sin escribir `data`, con las mismas opciones que usa el programa real, archivos con `fmemopen` o en `TMPDIR`.

El objetivo se compila con la shell, mismos sanitizers, estático: `CC=clang CFLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined,fuzzer-no-link" ./configure --disable-shared && make -j2` (en cmake, `-DCMAKE_C_COMPILER=clang` y `-DBUILD_SHARED_LIBS=OFF`; en meson, `-Db_sanitize=address,undefined -Ddefault_library=static`). Después `harness_build` con `sources`, `include_dirs` y la `.a` en `link`; un símbolo sin definir es algo que falta en `link`. MSan es otro binario y sólo sirve con todo instrumentado.

## Fuzzear

Primero 60 a 120 s: con menos de unas cien ejecuciones por segundo el harness es lento; arreglalo antes. Semillas: los archivos de prueba del proyecto; `dict` con los tokens del formato. Si la cobertura no crece, cambiá semillas, diccionario u opciones; más tiempo con lo mismo rara vez ayuda.

## Validar antes de creer

1. **Determinista**: `poc_run` con `crash` da el mismo crash siempre. Si no, buscá estado global, hilos o tiempo, y reportalo con la tasa.
2. **En el objetivo**: si arriba de la pila está `LLVMFuzzerTestOneInput` o un archivo de `harness/` (la herramienta lo marca), el bug es tuyo; un leak reservado en el harness, también.
3. **Alcanzable desde una entrada real**: seguí a los llamadores reales con `code_search` y comprobá que dejan pasar ese input (largos validados antes, NUL al final, opciones por defecto, orden de inicialización). Si el harness pasó algo que el programa nunca pasaría, es un artefacto.
4. **Por la puerta real**: el mismo archivo por el CLI con ASan (`poc_run` con `binary`) o en el laboratorio. Ése es el PoC del reporte.
5. **Vigente**: sigue en la última versión o en HEAD y no está ya reportado.

## Un crash sin ganancia no es un hallazgo

Leak, timeout, consumo de memoria, nulo, `assert` o recursión sin tope son DoS: para muchos programas no pagan. Mostrá la **primitiva o el impacto**: escritura fuera de límites o tras liberar con control de dónde, qué y cuánto; lectura fuera de límites cuyos bytes salen del proceso; overflow de enteros que termina en reserva chica y copia grande. Para la explotabilidad, `deep_reason` con el artefacto del crash. Pista mientras falte; candidato con `poc_run` determinista, alcance real y la primitiva con sus límites; nunca confirmado.

## Laboratorio (nivel 3)

El patrón del lab de httpd armado a mano: el objetivo con ASan instalado en un prefijo del proyecto (`--prefix=$PWD/lab/<objetivo>/prefix`, `make install`) y un `lab/<objetivo>/repro.sh <prefijo> [puerto]` que arma una configuración mínima en una carpeta temporal, levanta el servidor en `127.0.0.1` como usuario sin privilegios, manda la entrada (`curl`, `printf … | nc`) y lo baja al salir (`trap`). `ASAN_OPTIONS=log_path=lab/<objetivo>/asan` deja el reporte en el proyecto. Corre con la shell (pide permiso): `fuzz_run` y `poc_run` no tienen red a propósito. Sin VM ni QEMU por ahora.

## No

Fuzzers fuera de la caja o por la shell (sin topes ni corte de red); red en un harness; reportar un crash del harness, uno que no reproduce o uno sin primitiva; ASan y MSan juntos; publicar inputs de un bug sin divulgar.
