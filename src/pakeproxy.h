#ifndef PAKEPROXY_H
#define PAKEPROXY_H

#include <gnutls/x509.h>

typedef struct {
  char *connect_host;
  int connect_port;
} proxy_stream_t;

typedef struct {
  proxy_stream_t *proxy_stream;
} pakeproxy_session_t;

typedef struct {
  gnutls_x509_crt_t crt;
  gnutls_x509_privkey_t key;
} pakeproxy_ca_t;

#endif // PAKEPROXY_H
