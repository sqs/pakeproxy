#include "gnutls_support.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>

#include <gnutls/extra.h>
#include <gnutls/x509.h>

#include "cert.h"
#include "daemon.h"

gnutls_priority_t priority_cache;

void init_gnutls(pp_config_t *cfg) {
  int ret;

  ret = gnutls_global_init();
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_global_init: %s", gnutls_strerror(ret));

  ret = gnutls_global_init_extra();
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_global_init_extra: %s", gnutls_strerror(ret));

  ret = gnutls_priority_init(&priority_cache, cfg->client_priority, NULL);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_priority_init: %s", gnutls_strerror(ret));
}

int initialize_tls_session(gnutls_session_t *session) {
  int ret;
  gnutls_certificate_credentials_t *cred;

  *session = 0;

  ret = gnutls_init(session, GNUTLS_SERVER);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "gnutls_init: %s", gnutls_strerror(ret));
    goto err;
  }

  ret = gnutls_priority_set(*session, priority_cache);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "gnutls_priority_set: %s", gnutls_strerror(ret));
    goto err;
  }

  cred = malloc(sizeof(gnutls_certificate_credentials_t));
  if (cred == NULL) {
    fprintf(stderr, "malloc gnutls_certificate_credentials_t");
    goto err;
  }
  
  ret = gnutls_certificate_allocate_credentials(cred);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "gnutls_certificate_allocate_credentials: %s",
            gnutls_strerror(ret));
    goto err;
  }

  /* GnuTLS BUG: need both of these, but the server one is deprecated */
  gnutls_certificate_set_retrieve_function(*cred, retrieve_server_cert);
  gnutls_certificate_server_set_retrieve_function(
      *cred,
      (gnutls_certificate_server_retrieve_function *)retrieve_server_cert);

  ret = gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, *cred);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "gnutls_credentials_set: %s", gnutls_strerror(ret));
    goto err;
  }

err:
  if (*session && ret != GNUTLS_E_SUCCESS)
    gnutls_deinit(*session);
  return ret;
}

void global_deinit() {
  gnutls_priority_deinit(priority_cache);
  gnutls_global_deinit();
}
