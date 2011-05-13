#include "cert.h"

#include <err.h>
#include <stdlib.h>
#include <stdio.h>

#include <gnutls/gnutls.h>

static gnutls_datum_t load_file(const char *file);
static void unload_file(gnutls_datum_t data);

void load_ca_cert_and_key(char* ca_cert_file, gnutls_x509_crt_t* ca_crt,
                          char* ca_key_file, gnutls_x509_privkey_t* ca_key) {
  int ret;
  gnutls_datum_t data;

  /* CA cert */
  data = load_file(ca_cert_file);
  if (data.data == NULL)
    err(1, "error loading ca_cert_file: %s", ca_cert_file);

  ret = gnutls_x509_crt_init(ca_crt);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_crt_init: %s", gnutls_strerror(ret));

  ret = gnutls_x509_crt_import(*ca_crt, &data, GNUTLS_X509_FMT_PEM);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_crt_import: %s", gnutls_strerror(ret));

  unload_file(data);

  /* CA key */
  data = load_file(ca_key_file);
  if (data.data == NULL)
    err(1, "error loading ca_key_file: %s", ca_key_file);

  ret = gnutls_x509_privkey_init(ca_key);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_privkey_init: %s", gnutls_strerror(ret));

  ret = gnutls_x509_privkey_import(*ca_key, &data, GNUTLS_X509_FMT_PEM);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_privkey_import: %s", gnutls_strerror(ret));

  unload_file(data);
}

/* Helper functions to load a certificate and key
 * files into memory. From gnutls ex-cert-select.c.
 */
static gnutls_datum_t load_file(const char *file) {
  FILE *f;
  gnutls_datum_t loaded_file = {NULL, 0};
  long filelen;
  void *ptr;

  if (!(f = fopen(file, "r"))
      || fseek(f, 0, SEEK_END) != 0
      || (filelen = ftell(f)) < 0
      || fseek(f, 0, SEEK_SET) != 0
      || !(ptr = malloc((size_t) filelen))
      || fread (ptr, 1, (size_t)filelen, f) < (size_t)filelen) {
    return loaded_file;
  }

  loaded_file.data = ptr;
  loaded_file.size = (unsigned int)filelen;
  return loaded_file;
}

static void unload_file(gnutls_datum_t data) {
  free(data.data);
}

