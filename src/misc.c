#include "misc.h"

#include <stdlib.h>
#include <string.h>

#define DEFAULT_SSL_PORT 443

void parse_hostport(char* hostport, char** host, int* port) {
  int i;
  *host = hostport;
  for (i = 0; i < strlen(hostport); i++) {
    if (hostport[i] == ':') {
      hostport[i] = '\0';
      *port = atoi(&hostport[i+1]);
      return;
    }
  }
  /* else no port */
  *port = DEFAULT_SSL_PORT;
}
