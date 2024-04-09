#define _GNU_SOURCE

#define SAFE_CONFIG_LOCATION "/etc/safe_hosts.conf"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <dlfcn.h>

#include <stdio.h>

int getaddrinfo(const char *restrict node,
               const char *restrict service,
               const struct addrinfo *restrict hints,
               struct addrinfo **restrict res)
{
  puts("Hello World!");
  int (*original_getaddrinfo)(const char *restrict node,
                               const char *restrict service,
                               const struct addrinfo *restrict hints,
                               struct addrinfo **restrict res);
  original_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
  return (*original_getaddrinfo)(node, service, hints, res);
  return 0;
}
