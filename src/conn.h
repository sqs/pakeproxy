#ifndef CONN_H
#define CONN_H

#include <gnutls/gnutls.h>

int do_proxy(gnutls_session_t session_client);
int tcp_connect(char* host, int port);

#endif // CONN_H
