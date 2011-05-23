#include "accounts.h"

#include <string.h>

int site_uses_tls_login(char* host) {
  return (strcmp(host, "tls-srp.test.trustedhttp.org") == 0);
}
