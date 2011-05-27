#ifndef PAKEPROXY_H
#define PAKEPROXY_H

#include <gnutls/x509.h>

typedef struct {
  const char *listen_host;
  int listen_port;
  const char *ca_cert_file;
  const char *ca_key_file;
  const char *cert_cache_path;
  const char *client_priority;
  char *accounts_inline;
} pp_config_t;

typedef struct {
  pp_config_t *cfg;
  char *target_host;
  int target_port;
  char *srp_user;
  char *srp_passwd;
} pp_session_t;

typedef struct {
  gnutls_x509_crt_t crt;
  gnutls_x509_privkey_t key;
} pp_ca_t;

extern pp_ca_t global_ca;
extern pp_config_t cfg;

#endif // PAKEPROXY_H
