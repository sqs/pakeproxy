#ifndef CONN_H
#define CONN_H

#include <gnutls/gnutls.h>
#include "pakeproxy.h"

int do_proxy(gnutls_session_t session_client, pp_proxy_type_t proxy_type);

#endif // CONN_H
