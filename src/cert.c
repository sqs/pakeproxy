#include "cert.h"

#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <gnutls/gnutls.h>

#include "pakeproxy.h"

#define SERVER_NAME_BUFFER_SIZE 1024
#define X509_DISPLAY_NAME_BUFFER_SIZE 1024
#define SERIAL_BUFFER_SIZE 1024
#define CRT_EXT "crt"
#define KEY_EXT "key"

static gnutls_datum_t load_file(const char *file);
static void unload_file(gnutls_datum_t data);
static void save_datum(gnutls_datum_t data, const char* file);
static char* get_display_name(char* server_name, char* username);
static gnutls_x509_privkey_t generate_private_key_int();
static int find_x509_crt(char* server_name,
                         char* username,
                         gnutls_x509_crt_t* crt,
                         gnutls_x509_privkey_t* key);
static int create_x509_crt(char* server_name,
                           char* username,
                           pp_ca_t* ca,
                           gnutls_x509_crt_t* crt,
                           gnutls_x509_privkey_t* key);
static void save_x509(char* server_name,
                      char* username,
                      gnutls_x509_crt_t crt,
                      gnutls_x509_privkey_t key);

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

int get_x509_crt(gnutls_session_t session,
                 pp_ca_t* ca,
                 gnutls_x509_crt_t* crt,
                 gnutls_x509_privkey_t* key) {
  pp_session_t* ppsession;
  char* server_name;
  char* username;
  int ret;

  ppsession = gnutls_session_get_ptr(session);
  server_name = ppsession->target_host;
  username = ppsession->srp_user;

  ret = find_x509_crt(server_name, username, crt, key);
  if (ret != GNUTLS_E_SUCCESS) {
    ret = create_x509_crt(server_name, username, ca, crt, key);
    if (ret != GNUTLS_E_SUCCESS) {
      errx(ret, "get_x509_crt: failed to create: %s", gnutls_strerror(ret));
    }
  }

  return GNUTLS_E_SUCCESS;
}

static char* filename_for_x509(char* server_name,
                               char* username,
                               const char* ext) {
  char *filename;
  size_t len;

  len = strlen(cfg.cert_cache_path) + strlen("/") + strlen(server_name)
      + strlen("_") + strlen(username) + strlen(".") + strlen(ext) + 1;
  filename = malloc(len);
  if (filename == NULL)
    err(1, "malloc filename");

  snprintf(filename, len, "%s/%s_%s.%s",
           cfg.cert_cache_path, server_name, username, ext);
  return filename;  
}

static int find_x509_crt(char* server_name,
                         char* username,
                         gnutls_x509_crt_t* crt,
                         gnutls_x509_privkey_t* key) {
  int ret;
  char* crtfile;
  char* keyfile;
  gnutls_datum_t crtdata;
  gnutls_datum_t keydata;

  crtfile = filename_for_x509(server_name, username, CRT_EXT);
  keyfile = filename_for_x509(server_name, username, KEY_EXT);

  crtdata = load_file(crtfile);
  keydata = load_file(keyfile);

  if (crtdata.data == NULL || keydata.data == NULL) {
    ret = GNUTLS_E_FILE_ERROR;
    goto done;
  }

  ret = gnutls_x509_crt_init(crt);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_crt_init: %s", gnutls_strerror(ret));

  ret = gnutls_x509_crt_import(*crt, &crtdata, GNUTLS_X509_FMT_PEM);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_crt_import: %s", gnutls_strerror(ret));

  ret = gnutls_x509_privkey_init(key);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_privkey_init: %s", gnutls_strerror(ret));

  ret = gnutls_x509_privkey_import(*key, &keydata, GNUTLS_X509_FMT_PEM);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_privkey_import: %s", gnutls_strerror(ret));

  unload_file(crtdata);
  unload_file(keydata);
  ret = GNUTLS_E_SUCCESS;

done:
  free(crtfile);
  free(keyfile);
  return ret;
}

static int create_x509_crt(char* server_name,
                           char* username,
                           pp_ca_t* ca,
                           gnutls_x509_crt_t* crt,
                           gnutls_x509_privkey_t* key) {
  int ret;
  char *display_name;

  fprintf(stderr, "- Generating X509 pair for %s@%s\n", username, server_name);

  *key = generate_private_key_int();

  ret = gnutls_x509_crt_init(crt);
  if (ret < 0)
    errx(ret, "gnutls_x509_crt_init: %s", gnutls_strerror(ret));

  ret = gnutls_x509_crt_set_dn_by_oid(*crt, GNUTLS_OID_X520_COMMON_NAME, 0,
                                      server_name, strlen(server_name));
  if (ret < 0)
    errx(ret, "gnutls_x509_crt_set_dn_by_oid common name: %s", gnutls_strerror(ret));

  display_name = get_display_name(server_name, username);
  ret = gnutls_x509_crt_set_dn_by_oid(*crt, GNUTLS_OID_X520_ORGANIZATION_NAME, 0,
                                      display_name, strlen(display_name));
  if (ret < 0)
    errx(ret, "gnutls_x509_crt_set_dn_by_oid display name: %s", gnutls_strerror(ret));
  
  ret = gnutls_x509_crt_set_key(*crt, *key);
  if (ret < 0)
    errx(ret, "gnutls_x509_crt_set_key: %s", gnutls_strerror(ret));

  gnutls_x509_crt_set_version(*crt, 1);
  
  int crt_serial = rand();
  printf("CRT SERIAL = %d\n", crt_serial);
  gnutls_x509_crt_set_serial(*crt, &crt_serial, sizeof(int));

  gnutls_x509_crt_set_activation_time(*crt, time(NULL));
  /* 10 days */
  ret = gnutls_x509_crt_set_expiration_time(*crt, time(NULL) + 1000*24*60*60);
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

  save_x509(server_name, username, *crt, *key);

  return 0;
}

static void save_x509(char* server_name,
                      char* username,
                      gnutls_x509_crt_t crt,
                      gnutls_x509_privkey_t key) {
  int ret;
  char* crtfile;
  char* keyfile;
  gnutls_datum_t crtdata;
  gnutls_datum_t keydata;

  crtfile = filename_for_x509(server_name, username, CRT_EXT);
  keyfile = filename_for_x509(server_name, username, KEY_EXT);

  gnutls_x509_crt_export(crt, GNUTLS_X509_FMT_PEM,
                         NULL, (size_t*)&crtdata.size);
  crtdata.data = malloc(crtdata.size);
  ret = gnutls_x509_crt_export(crt, GNUTLS_X509_FMT_PEM,
                               crtdata.data, (size_t*)&crtdata.size);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_crt_export: %s", gnutls_strerror(ret));

  ret = gnutls_x509_privkey_export(key, GNUTLS_X509_FMT_PEM,
                                   NULL, (size_t*)&keydata.size);
  keydata.data = malloc(keydata.size);
  ret = gnutls_x509_privkey_export(key, GNUTLS_X509_FMT_PEM,
                                   keydata.data, (size_t*)&keydata.size);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_privkey_export: %s", gnutls_strerror(ret));

  save_datum(crtdata, crtfile);
  save_datum(keydata, keyfile);

  free(crtdata.data);
  free(keydata.data);
  free(crtfile);
  free(keyfile);
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

static char* get_display_name(char* server_name, char* username) {
  char *buf;
  size_t len;
  len = strlen(server_name) + strlen("@") + strlen(username) + strlen(" (SRP)") + 1;
  buf = malloc(len);
  if (buf == NULL)
    errx(1, "malloc get_display_name buf");
  snprintf(buf, len, "%s@%s (SRP)", username, server_name);
  return buf;
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

static void save_datum(gnutls_datum_t data, const char* file) {
  FILE *f;
  int ret;

  f = fopen(file, "w");
  if (f == NULL)
    err(1, "fopen in save_datum ('%s')", file);

  ret = fwrite(data.data, data.size, 1, f);
  if (ret != 1)
    err(1, "fwrite(...) != 1");

  ret = fclose(f);
  if (ret != 0)
    err(1, "fclose");
}
