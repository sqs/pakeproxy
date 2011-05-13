#ifndef CERT_H
#define CERT_H

#include "pakeproxy.h"

void load_ca_cert_and_key(pakeproxy_ca_t* ca,
                          char* ca_cert_file,
                          char* ca_key_file);

int create_x509_for_host_and_user(gnutls_session_t session,
                                  pakeproxy_ca_t* ca,
                                  gnutls_x509_crt_t* crt,
                                  gnutls_x509_privkey_t* key);
#endif // CERT_H
