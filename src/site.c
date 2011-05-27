#include "site.h"

#include <stdio.h>
#include <unistd.h>

#include <gnutls/gnutls.h>
#include <gnutls/extra.h>

#include "conn.h"

#define MAX_BUF 1024

int site_uses_tls_srp(char *host, int port) {
  int ret;
  int sd;
  gnutls_session_t session;
  gnutls_srp_client_credentials_t srp_cred;

  gnutls_srp_allocate_client_credentials(&srp_cred);
  gnutls_srp_set_client_credentials(srp_cred, "dummy", "dummy");

  sd = tcp_connect(host, port);
  gnutls_init(&session, GNUTLS_CLIENT);

  /* only SRP */
  gnutls_priority_set_direct(session, "NONE:+AES-256-CBC:+AES-128-CBC:+SRP:+SHA1:+COMP-NULL:+VERS-TLS1.1:+VERS-TLS1.0:+VERS-SSL3.0", NULL);

  gnutls_credentials_set(session, GNUTLS_CRD_SRP, srp_cred);

  gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t)(long)sd);

  ret = gnutls_handshake(session);

  if (ret >= 0)
    ret = 1; /* success */
  if (gnutls_alert_get(session) == GNUTLS_A_HANDSHAKE_FAILURE) {
    ret = 0;
  } else {
    ret = 1;
  }

  printf("- Host %s TLS-SRP support: %s (%s)\n", host, ret ? "YES" : "NO", gnutls_alert_get_name(gnutls_alert_get(session)));

  gnutls_bye(session, GNUTLS_SHUT_RDWR);
  close(sd);
  gnutls_deinit(session);
  gnutls_srp_free_client_credentials(srp_cred);

  return ret;
}
