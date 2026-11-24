/*
 * Orobas: los harnesses y PoCs que compila harness_build no salen a la red (src/fuzzing.ts).
 * Este socket() se enlaza en cada binario y gana sobre el de libc para el programa y las bibliotecas
 * que lo llaman: sólo deja sockets locales (AF_UNIX); cualquier otra familia falla con EACCES.
 * La imagen (distro/Dockerfile) lo compila y prueba al construirse. No cubre lo que libc resuelve por
 * dentro (DNS de getaddrinfo) ni syscalls directas: es un corte del harness, no una jaula.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

int socket(int domain, int type, int protocol) {
  if (domain == 1 /* AF_UNIX */) return (int)syscall(SYS_socket, domain, type, protocol);
  errno = EACCES;
  return -1;
}

#ifdef __cplusplus
}
#endif
