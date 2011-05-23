#ifndef CERT_H
#define CERT_H

#include "pakeproxy.h"

void load_ca_cert_and_key(pp_ca_t* ca,
                          const char* ca_cert_file,
                          const char* ca_key_file);

int get_x509_crt(gnutls_session_t session,
                 pp_ca_t* ca,
                 gnutls_x509_crt_t* crt,
                 gnutls_x509_privkey_t* key);
#endif // CERT_H
