#include "cert.h"

#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gnutls/gnutls.h>

#include "pakeproxy.h"

#define SERVER_NAME_BUFFER_SIZE 1024

static gnutls_datum_t load_file(const char *file);
static void unload_file(gnutls_datum_t data);
static char* make_fake_common_name(gnutls_session_t session);
static gnutls_x509_privkey_t generate_private_key_int();

void load_ca_cert_and_key(pp_ca_t* ca,
                          const char* ca_cert_file,
                          const char* ca_key_file) {
  int ret;
  gnutls_datum_t data;

  /* CA cert */
  data = load_file(ca_cert_file);
  if (data.data == NULL)
    err(1, "error loading ca_cert_file: %s", ca_cert_file);

  ret = gnutls_x509_crt_init(&ca->crt);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_crt_init: %s", gnutls_strerror(ret));

  ret = gnutls_x509_crt_import(ca->crt, &data, GNUTLS_X509_FMT_PEM);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_crt_import: %s", gnutls_strerror(ret));

  unload_file(data);

  /* CA key */
  data = load_file(ca_key_file);
  if (data.data == NULL)
    err(1, "error loading ca_key_file: %s", ca_key_file);

  ret = gnutls_x509_privkey_init(&ca->key);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_privkey_init: %s", gnutls_strerror(ret));

  ret = gnutls_x509_privkey_import(ca->key, &data, GNUTLS_X509_FMT_PEM);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_privkey_import: %s", gnutls_strerror(ret));

  unload_file(data);
}

int create_x509_for_host_and_user(gnutls_session_t session,
                                  pp_ca_t* ca,
                                  gnutls_x509_crt_t* crt,
                                  gnutls_x509_privkey_t* key) {
  int ret;
  char *common_name;

  *key = generate_private_key_int();

  ret = gnutls_x509_crt_init(crt);
  if (ret < 0)
    errx(ret, "gnutls_x509_crt_init: %s", gnutls_strerror(ret));

  common_name = make_fake_common_name(session);  
  gnutls_x509_crt_set_dn_by_oid(*crt, GNUTLS_OID_X520_COMMON_NAME, 0,
                                common_name, strlen(common_name));
  if (ret < 0)
    errx(ret, "gnutls_x509_crt_set_dn_by_oid common name: %s", gnutls_strerror(ret));

  ret = gnutls_x509_crt_set_key(*crt, *key);
  if (ret < 0)
    errx(ret, "gnutls_x509_crt_set_key: %s", gnutls_strerror(ret));

  gnutls_x509_crt_set_version(*crt, 1);
  int crt_serial = rand();
  gnutls_x509_crt_set_serial(*crt, &crt_serial, sizeof(int));

  gnutls_x509_crt_set_activation_time(*crt, time(NULL));
  /* 10 days */
  ret = gnutls_x509_crt_set_expiration_time(*crt, time(NULL) + 10*24*60*60);
  if (ret < 0)
    errx(ret, "gnutls_x509_crt_set_expiration_time: %s", gnutls_strerror(ret));

  ret = gnutls_x509_crt_set_basic_constraints(*crt, 0, -1);
  if (ret < 0)
    errx(ret, "gnutls_x509_crt_set_basic_constraints: %s", gnutls_strerror(ret));

  ret = gnutls_x509_crt_set_key_purpose_oid (*crt, GNUTLS_KP_TLS_WWW_SERVER, 0);
  if (ret < 0)
    errx(ret, "gnutls_x509_crt_set_key_purpose_oid GNUTLS_KP_TLS_WWW_SERVER: %s",
         gnutls_strerror(ret));

  ret = gnutls_x509_crt_sign2(*crt, ca->crt, ca->key, GNUTLS_DIG_SHA256, 0);
  if (ret < 0)
    errx(ret, "gnutls_x509_crt_sign2: %s", gnutls_strerror(ret));

  return 0;
}

static gnutls_x509_privkey_t generate_private_key_int() {
  gnutls_x509_privkey_t key;
  int ret, key_type, bits;

  key_type = GNUTLS_PK_RSA;

  ret = gnutls_x509_privkey_init(&key);
  if (ret < 0)
    errx(ret, "privkey_init: %s", gnutls_strerror(ret));

  bits = gnutls_sec_param_to_pk_bits(key_type, GNUTLS_SEC_PARAM_LOW);

  fprintf(stderr, "Generating a %d bit %s private key...\n",
          bits, gnutls_pk_algorithm_get_name(key_type));

  ret = gnutls_x509_privkey_generate(key, key_type, bits, 0);
  if (ret < 0)
    errx(ret, "privkey_generate: %s", gnutls_strerror(ret));

  return key;
}

static char* make_fake_common_name(gnutls_session_t session) {
  int ret;
  char *user;
  char *common_name_buf;
  pp_session_t *ppsession;
  static const int kCommonNameBufferSize = 1000;

  user = "sqs";
  ppsession = gnutls_session_get_ptr(session);

  if (ppsession->target_host == NULL) {
    char server_name[SERVER_NAME_BUFFER_SIZE];
    size_t server_name_size = SERVER_NAME_BUFFER_SIZE;
    unsigned int server_name_type;
    ret = gnutls_server_name_get(session, &server_name, &server_name_size,
                                 &server_name_type, 0);
    if (ret != GNUTLS_E_SUCCESS)
      err(1, "gnutls_server_name_get: %s", gnutls_strerror(ret));
  }

  common_name_buf = malloc(kCommonNameBufferSize);
  if (common_name_buf == NULL)
    errx(1, "malloc kCommonNameBufferSize");

  snprintf(common_name_buf, kCommonNameBufferSize,
           "%s@%s (SRP)", user, ppsession->target_host);
  return common_name_buf;
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

