#ifndef CERT_H
#define CERT_H

#include <gnutls/abstract.h>
#include <gnutls/x509.h>

void load_ca_cert_and_key(char* ca_cert_file, gnutls_x509_crt_t* ca_crt,
                          char* ca_key_file, gnutls_x509_privkey_t* ca_key);

#endif // CERT_H
