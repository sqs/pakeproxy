#include "daemon.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <gnutls/extra.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#include "pakeproxy.h"
#include "cert.h"
#include "gnutls_support.h"
#include "conn.h"
#include "cert.h"


static struct in_addr get_listen_addr(const char *listen_host);
int retrieve_server_cert(gnutls_session_t session,
                         const gnutls_datum_t* req_ca_dn,
                         int nreqs,
                         const gnutls_pk_algorithm_t* pk_algos,
                         int pk_algos_length,
                         gnutls_retr2_st* st) {
  gnutls_x509_privkey_t key;
  gnutls_x509_crt_t *crt;

  crt = malloc(sizeof(gnutls_x509_crt_t));
  if (crt == NULL)
    errx(1, "malloc gnutls_x509_crt_t");

  get_x509_crt(session, &global_ca, crt, &key);

  st->cert_type = GNUTLS_CRT_X509;
  st->key_type = GNUTLS_PRIVKEY_X509;

  st->cert.x509 = crt;
  st->ncerts = 1;
  
  st->key.x509 = key;

  st->deinit_all = 0;
  
  /* gnutls_certificate_set_x509_key(cred, &crt, 1, key); *//*TODO(sqs):whatfor?*/
  
  return 0;
}

int open_listen_socket(const char *host, int port) {
  struct sockaddr_in sa_serv;
  int optval = 1;
  int listen_sd;
  int ret;
  
  listen_sd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_sd == -1) {
    perror("socket");
    return -1;
  }

  memset(&sa_serv, '\0', sizeof(sa_serv));
  sa_serv.sin_family = AF_INET;
  sa_serv.sin_addr = get_listen_addr(host);
  sa_serv.sin_port = htons(port);

  setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (void *)&optval,
             sizeof(int));

  ret = bind(listen_sd, (struct sockaddr *)&sa_serv, sizeof(sa_serv));
  if (ret == -1) {
    perror("bind");
    return -1;
  }
  
  ret = listen(listen_sd, 1024);
  if (ret == -1) {
    perror("listen");
    return -1;
  }

  fprintf(stderr, "Listening on %s:%d\n", host, port);
  return listen_sd;
}

static struct in_addr get_listen_addr(const char *listen_host) {
  struct hostent *hp;

  hp = gethostbyname(listen_host);
  if (hp == NULL) {
    herror("gethostbyname");
    exit(1);
  }

  return *((struct in_addr *)hp->h_addr_list[0]);
}

int do_accept(int listen_sd) {
  struct sockaddr_in sa_cli;
  socklen_t client_len = sizeof(sa_cli);
  char topbuf[512];
  int sd;

  sd = accept(listen_sd, (struct sockaddr *)&sa_cli, &client_len);
  fprintf(stderr, "- Connection from %s:%d\n",
          inet_ntop(AF_INET, &sa_cli.sin_addr, topbuf,
                    sizeof(topbuf)), ntohs(sa_cli.sin_port));
  return sd;
}

void* connection_thread(void* arg) {
  int sd;
  gnutls_session_t session;
  pp_session_t ppsession;
  int ret;

  sd = (int)(long)arg;

  ret = initialize_tls_session(&session);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Error initializing TLS session\n");
    return (void *)(long)ret;
  }
  gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t)(long)sd);

  memset(&ppsession, '\0', sizeof(pp_session_t));
  ppsession.cfg = &cfg;
  gnutls_session_set_ptr(session, &ppsession);

  ret = do_proxy(session);
  if (ret != GNUTLS_E_SUCCESS)
    fprintf(stderr, "- Proxy exited with failure\n");

  close((int)(long)gnutls_transport_get_ptr(session));
  gnutls_deinit(session);

  return 0;
}
