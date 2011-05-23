#ifndef CACHE_H
#define CACHE_H

#include <gnutls/gnutls.h>

int global_init_cache();
void global_deinit_cache();

int session_init_cache(gnutls_session_t session);

#endif // CACHE_H
