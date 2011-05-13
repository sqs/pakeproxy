#ifndef CONN_H
#define CONN_H

#include <gnutls/gnutls.h>

int do_https_tunnel(gnutls_session_t session);

#endif // CONN_H
