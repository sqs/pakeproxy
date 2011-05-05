#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>


#define CA_CERT_FILE "/home/sqs/src/pakeproxy/data/ca-cert.pem"
#define CA_KEY_FILE "/home/sqs/src/pakeproxy/data/ca-key.pem"

const int kListenPort = 4443;

#define SA struct sockaddr
#define SOCKET_ERR(err,s) if(err==-1) {perror(s);return(1);}
#define MAX_BUF 1024
#define SERVER_NAME_BUFFER_SIZE 1024
#define DH_BITS 1024

/* These are global */
gnutls_priority_t priority_cache;
static gnutls_x509_crt_t ca_crt;
static gnutls_x509_privkey_t ca_key;

/* Helper functions to load a certificate and key
 * files into memory. From gnutls ex-cert-select.c.
 */
static gnutls_datum_t
load_file (const char *file)
{
  FILE *f;
  gnutls_datum_t loaded_file = { NULL, 0 };
  long filelen;
  void *ptr;

  if (!(f = fopen (file, "r"))
      || fseek (f, 0, SEEK_END) != 0
      || (filelen = ftell (f)) < 0
      || fseek (f, 0, SEEK_SET) != 0
      || !(ptr = malloc ((size_t) filelen))
      || fread (ptr, 1, (size_t) filelen, f) < (size_t) filelen)
    {
      return loaded_file;
    }

  loaded_file.data = ptr;
  loaded_file.size = (unsigned int) filelen;
  return loaded_file;
}

static void
unload_file (gnutls_datum_t data)
{
  free (data.data);
}

static void load_ca_cert_and_key() {
  int ret;
  gnutls_datum_t data;

  /* CA cert */
  data = load_file(CA_CERT_FILE);
  if (data.data == NULL)
    err(1, "error loading CA_CERT_FILE: " CA_CERT_FILE);

  ret = gnutls_x509_crt_init(&ca_crt);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_crt_init: %s", gnutls_strerror(ret));

  ret = gnutls_x509_crt_import(ca_crt, &data, GNUTLS_X509_FMT_PEM);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_crt_import: %s", gnutls_strerror(ret));

  unload_file(data);

  /* CA key */
  data = load_file(CA_KEY_FILE);
  if (data.data == NULL)
    err(1, "error loading CA_KEY_FILE: " CA_KEY_FILE);

  ret = gnutls_x509_privkey_init(&ca_key);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_privkey_init: %s", gnutls_strerror(ret));

  ret = gnutls_x509_privkey_import(ca_key, &data, GNUTLS_X509_FMT_PEM);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_x509_privkey_import: %s", gnutls_strerror(ret));

  unload_file(data);

  printf("- loaded CA cert and key\n");
}

static gnutls_digest_algorithm_t get_dig (gnutls_x509_crt crt) {
  gnutls_digest_algorithm_t dig;
  int ret;
  unsigned int mand;

  printf("** get_dig: crt@%p\n", &crt);

  return GNUTLS_DIG_SHA256;

  ret = gnutls_pubkey_get_preferred_hash_algorithm((gnutls_pubkey_t)crt, &dig, &mand);
  if (ret != 0)
    errx (ret, "crl_preferred_hash_algorithm: %s", gnutls_strerror (ret));

  return dig;
}

static gnutls_x509_privkey_t
generate_private_key_int (void)
{
  gnutls_x509_privkey_t key;
  int ret, key_type, bits;

  key_type = GNUTLS_PK_RSA;

  ret = gnutls_x509_privkey_init (&key);
  if (ret < 0)
    errx (ret, "privkey_init: %s", gnutls_strerror (ret));

  bits = gnutls_sec_param_to_pk_bits(key_type, GNUTLS_SEC_PARAM_NORMAL);

  fprintf (stderr, "Generating a %d bit %s private key...\n",
           bits, gnutls_pk_algorithm_get_name (key_type));

  ret = gnutls_x509_privkey_generate (key, key_type, bits, 0);
  if (ret < 0)
    errx (ret, "privkey_generate: %s", gnutls_strerror (ret));

  return key;
}

static char* make_fake_common_name(gnutls_session_t session) {
  int ret;
  char *common_name;
  char *user;
  char server_name[SERVER_NAME_BUFFER_SIZE];
  size_t server_name_size = SERVER_NAME_BUFFER_SIZE;
  unsigned int server_name_type;
  char *common_name_buf;
  static const int kCommonNameBufferSize = 1000;

  user = "sqs";
  
  ret = gnutls_server_name_get(session, &server_name, &server_name_size,
                               &server_name_type, 0);
  if (ret != GNUTLS_E_SUCCESS)
    err(1, "gnutls_server_name_get: %s", gnutls_strerror(ret));

  common_name_buf = malloc(kCommonNameBufferSize);
  if (common_name_buf == NULL)
    errx(1, "malloc kCommonNameBufferSize");

  snprintf(common_name_buf, kCommonNameBufferSize,
           "%s@%s (SRP)", user, server_name);
  return common_name_buf;
}

static int create_x509_for_host_and_user(gnutls_session_t session,
                                         gnutls_x509_crt_t *crt,
                                         gnutls_x509_privkey_t *key) {
  int ret;
  char *common_name;

  *key = generate_private_key_int();

  ret = gnutls_x509_crt_init(crt);
  if (ret < 0)
    errx(ret, "gnutls_x509_crt_init: %s", gnutls_strerror(ret));

  common_name = make_fake_common_name(session);  
  gnutls_x509_crt_set_dn_by_oid(*crt, GNUTLS_OID_X520_COMMON_NAME, 0, common_name, strlen(common_name));
  if (ret < 0)
    errx(ret, "gnutls_x509_crt_set_dn_by_oid common name: %s", gnutls_strerror(ret));

  ret = gnutls_x509_crt_set_key(*crt, *key);
  if (ret < 0)
    errx(ret, "gnutls_x509_crt_set_key: %s", gnutls_strerror(ret));

  gnutls_x509_crt_set_version(*crt, 1);
  int crt_serial = 123;
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

  fprintf(stderr, "Signing certificate...\n");

  ret = gnutls_x509_crt_sign2(*crt, ca_crt, ca_key, get_dig(ca_crt), 0);
  if (ret < 0)
    errx(ret, "gnutls_x509_crt_sign2: %s", gnutls_strerror(ret));

  fprintf(stderr, "Signed certificate\n");

  return 0;
}

static int retrieve_server_cert(gnutls_session_t session,
                                const gnutls_datum_t* req_ca_dn,
                                int nreqs,
                                const gnutls_pk_algorithm_t* pk_algos,
                                int pk_algos_length,
                                gnutls_retr2_st* st) {
  gnutls_x509_privkey_t key;
  gnutls_x509_crt_t *crt;

  printf("*********** retrieve_server_cert: \n");
  
  crt = malloc(sizeof(gnutls_x509_crt_t));
  if (crt == NULL)
    errx(1, "malloc gnutls_x509_crt_t");

  create_x509_for_host_and_user(session, crt, &key);

  st->cert_type = GNUTLS_CRT_X509;
  st->key_type = GNUTLS_PRIVKEY_X509;

  st->cert.x509 = crt;
  st->ncerts = 1;
  
  st->key.x509 = key;

  st->deinit_all = 0;
  
  /* gnutls_certificate_set_x509_key(cred, &crt, 1, key); *//*TODO(sqs):whatfor?*/
  
  return 0;
}

static gnutls_session_t initialize_tls_session() {
  int ret;
  gnutls_certificate_credentials_t *cred;
  gnutls_session_t session;

  printf("initialize_tls_session\n");

  ret = gnutls_init(&session, GNUTLS_SERVER);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_init: %s", gnutls_strerror(ret));

  ret = gnutls_priority_set(session, priority_cache);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_priority_set: %s", gnutls_strerror(ret));

  cred = malloc(sizeof(gnutls_certificate_credentials_t));
  if (cred == NULL)
    errx(1, "malloc gnutls_certificate_credentials_t");
  
  ret = gnutls_certificate_allocate_credentials(cred);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_certificate_allocate_credentials: %s", gnutls_strerror(ret));

  gnutls_certificate_set_retrieve_function(*cred, retrieve_server_cert);
  gnutls_certificate_server_set_retrieve_function(*cred, (gnutls_certificate_server_retrieve_function *)retrieve_server_cert);
  ret = gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, *cred);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_credentials_set: %s", gnutls_strerror(ret));
  
  return session;
}

int main(int argc, char **argv) {
  int err, listen_sd;
  int sd, ret;
  struct sockaddr_in sa_serv;
  struct sockaddr_in sa_cli;
  socklen_t client_len;
  char topbuf[512];
  gnutls_session_t session;
  char buffer[MAX_BUF + 1];
  int optval = 1;

  ret = gnutls_global_init();
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_global_init: %s", gnutls_strerror(ret));

  load_ca_cert_and_key();
  
  ret = gnutls_priority_init(&priority_cache, "NORMAL", NULL);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_priority_init: %s", gnutls_strerror(ret));
  
  /* Socket operations
   */
  listen_sd = socket(AF_INET, SOCK_STREAM, 0);
  SOCKET_ERR(listen_sd, "socket");

  memset(&sa_serv, '\0', sizeof(sa_serv));
  sa_serv.sin_family = AF_INET;
  sa_serv.sin_addr.s_addr = INADDR_ANY;
  sa_serv.sin_port = htons(kListenPort);      /* Server Port number */

  setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR,(void *) &optval,
              sizeof(int));

  err = bind(listen_sd,(struct sockaddr *) & sa_serv, sizeof(sa_serv));
  SOCKET_ERR(err, "bind");
  err = listen(listen_sd, 1024);
  SOCKET_ERR(err, "listen");

  printf("listening on port %d.\n\n", kListenPort);

  client_len = sizeof(sa_cli);
  for (;;) {
    session = initialize_tls_session();

    sd = accept(listen_sd,(struct sockaddr *) & sa_cli, &client_len);

    printf("- connection from %s, port %d\n",
            inet_ntop(AF_INET, &sa_cli.sin_addr, topbuf,
                       sizeof(topbuf)), ntohs(sa_cli.sin_port));

    gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t)sd);

    ret = gnutls_handshake(session);
    if (ret != GNUTLS_E_SUCCESS) {
      close(sd);
      gnutls_deinit(session);
      fprintf(stderr, "handshake failed: %s\n\n", gnutls_strerror(ret));
      continue;
    }
    printf("handshake OK\n");

    /* see the Getting peer's information example */
    /* print_info(session); */

    for (;;)
    {
      memset(buffer, 0, MAX_BUF + 1);
      ret = gnutls_record_recv(session, buffer, MAX_BUF);

      if (ret == 0)
      {
        printf("\n- Peer has closed the GnuTLS connection\n");
        break;
      }
      else if (ret < 0)
      {
        fprintf(stderr, "\n*** Received corrupted "
                 "data(%d). Closing the connection.\n\n", ret);
        break;
      }
      else if (ret > 0)
      {
        /* echo data back to the client
         */
        gnutls_record_send(session, buffer, strlen(buffer));
      }
    }
    printf("\n");
    /* do not wait for the peer to close the connection.
     */
    gnutls_bye(session, GNUTLS_SHUT_WR);

    close(sd);
    gnutls_deinit(session);

  }
  close(listen_sd);

  gnutls_priority_deinit(priority_cache);

  gnutls_global_deinit();

  return 0;

}
