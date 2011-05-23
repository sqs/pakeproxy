#ifndef PAKEPROXY_H
#define PAKEPROXY_H

#include <gnutls/x509.h>

typedef enum {
  PP_PLAIN_PROXY = 0,
  PP_HTTPS_TUNNEL
} pp_proxy_type_t;

typedef struct {
  const char *listen_host;
  int listen_port;
  const char *ca_cert_file;
  const char *ca_key_file;
  const char *client_priority;
  pp_proxy_type_t proxy_type;
  int session_cache;
} pp_config_t;

typedef struct {
  pp_config_t *cfg;
  char *target_host;
  int target_port;
} pp_session_t;

typedef struct {
  gnutls_x509_crt_t crt;
  gnutls_x509_privkey_t key;
} pp_ca_t;

#endif // PAKEPROXY_H
