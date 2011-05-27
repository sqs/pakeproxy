#ifndef GNUTLS_SUPPORT_H
#define GNUTLS_SUPPORT_H

#include "pakeproxy.h"
#include <gnutls/gnutls.h>

void init_gnutls(pp_config_t *cfg);
int initialize_tls_session(gnutls_session_t *session);
void global_deinit();

extern gnutls_priority_t priority_cache;


#endif // GNUTLS_SUPPORT_H
