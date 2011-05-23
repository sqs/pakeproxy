#include "pakeproxy.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <gnutls/gnutls.h>
#include <gnutls/extra.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#include "cert.h"
#include "conn.h"
#include "misc.h"

#define DEFAULT_CA_CERT_FILE "/home/sqs/src/pakeproxy/data/ca-cert.pem"
#define DEFAULT_CA_KEY_FILE "/home/sqs/src/pakeproxy/data/ca-key.pem"
#define DEFAULT_CLIENT_PRIORITY "NORMAL"

#define DH_BITS 1024
#define SERVER_NAME_BUFFER_SIZE 1024

/* These are global */
gnutls_priority_t priority_cache;
static pp_ca_t global_ca;
static pp_config_t cfg;

static void set_target_hostport(gnutls_session_t session, pp_session_t* ppsession);
static void init_gnutls();
static int open_listen_socket(const char *host, int port);
static struct in_addr get_listen_addr(const char *listen_host);
static int do_accept(int listen_sd,
                     gnutls_session_t *session,
                     pp_config_t *cfg);

static int retrieve_server_cert(gnutls_session_t session,
                                const gnutls_datum_t* req_ca_dn,
                                int nreqs,
                                const gnutls_pk_algorithm_t* pk_algos,
                                int pk_algos_length,
                                gnutls_retr2_st* st) {
  gnutls_x509_privkey_t key;
  gnutls_x509_crt_t *crt;
  pp_session_t* ppsession;

  crt = malloc(sizeof(gnutls_x509_crt_t));
  if (crt == NULL)
    errx(1, "malloc gnutls_x509_crt_t");

  /* fill in target host/port */
  ppsession = gnutls_session_get_ptr(session);
  if (cfg.proxy_type != PP_HTTPS_TUNNEL) {
    set_target_hostport(session, ppsession);
  }

  if (ppsession->target_host == NULL ||
      ppsession->target_port == 0) {
    fprintf(stderr, "- Couldn't determine server name\n");
    return -1;
  }

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

static void set_target_hostport(gnutls_session_t session, pp_session_t* ppsession) {
  char *server_name;
  size_t server_name_size;
  unsigned int server_name_type;
  int ret;

  server_name_size = SERVER_NAME_BUFFER_SIZE;
  server_name = malloc(server_name_size + 1);
  if (server_name == NULL)
    err(1, "malloc server_name");

  ret = gnutls_server_name_get(session, server_name, &server_name_size,
                               &server_name_type, 0);
  if (ret != GNUTLS_E_SUCCESS)
    err(1, "gnutls_server_name_get: %s", gnutls_strerror(ret));

  parse_hostport(server_name, &ppsession->target_host,
                 &ppsession->target_port);
  printf("server_name = '%s'\n", server_name);
}

static int initialize_tls_session(gnutls_session_t *session) {
  int ret;
  gnutls_certificate_credentials_t *cred;

  *session = 0;

  ret = gnutls_init(session, GNUTLS_SERVER);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "gnutls_init: %s", gnutls_strerror(ret));
    goto err;
  }

  ret = gnutls_priority_set(*session, priority_cache);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "gnutls_priority_set: %s", gnutls_strerror(ret));
    goto err;
  }

  cred = malloc(sizeof(gnutls_certificate_credentials_t));
  if (cred == NULL) {
    fprintf(stderr, "malloc gnutls_certificate_credentials_t");
    goto err;
  }
  
  ret = gnutls_certificate_allocate_credentials(cred);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "gnutls_certificate_allocate_credentials: %s",
            gnutls_strerror(ret));
    goto err;
  }

  gnutls_certificate_set_retrieve_function(*cred, retrieve_server_cert);
  gnutls_certificate_server_set_retrieve_function(
      *cred,
      (gnutls_certificate_server_retrieve_function *)retrieve_server_cert);

  ret = gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, *cred);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "gnutls_credentials_set: %s", gnutls_strerror(ret));
    goto err;
  }

err:
  if (*session && ret != GNUTLS_E_SUCCESS)
    gnutls_deinit(*session);
  return ret;
}

int main(int argc, char **argv) {
  int listen_sd;
  int ret;
  int c;
  pid_t pid;
  gnutls_session_t session;

  cfg.listen_host = "127.0.0.1";
  cfg.listen_port = 8443;
  cfg.ca_cert_file = DEFAULT_CA_CERT_FILE;
  cfg.ca_key_file = DEFAULT_CA_KEY_FILE;
  cfg.client_priority = DEFAULT_CLIENT_PRIORITY;
  cfg.proxy_type = PP_PLAIN_PROXY;

  while ((c = getopt(argc, argv, "t")) != -1) {
    switch (c) {
      case 't':
        cfg.proxy_type = PP_HTTPS_TUNNEL;
        break;
      case '?':
        if (isprint(optopt))
          fprintf(stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf(stderr,
                   "Unknown option character `\\x%x'.\n",
                   optopt);
        return 1;
      default:
        abort();
    }
  }

  init_gnutls(&cfg);
  load_ca_cert_and_key(&global_ca, cfg.ca_cert_file, cfg.ca_key_file);

  listen_sd = open_listen_socket(cfg.listen_host, cfg.listen_port);
  if (listen_sd == -1)
    exit(1);

  for (;;) {
    ret = do_accept(listen_sd, &session, &cfg);
    if (ret != GNUTLS_E_SUCCESS)
      break;

    pid = fork();
    if (pid == -1) {
      perror("fork");
      exit(1);
    } else if (pid != 0) {
      /* in parent */
      fprintf(stderr, "- Forked child %d\n", pid);
      continue;
    }

    srand(time(NULL) + 10000*getpid());
    
    ret = do_proxy(session, cfg.proxy_type);
    if (ret != GNUTLS_E_SUCCESS)
      break;

    gnutls_bye(session, GNUTLS_SHUT_WR);
    close((int)(long)gnutls_transport_get_ptr(session));
    gnutls_deinit(session);

    if (pid == 0)
      break;
  }

  close(listen_sd);
  gnutls_priority_deinit(priority_cache);
  gnutls_global_deinit();

  return 0;
}

static void init_gnutls(pp_config_t *cfg) {
  int ret;

  ret = gnutls_global_init();
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_global_init: %s", gnutls_strerror(ret));

  ret = gnutls_global_init_extra();
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_global_init_extra: %s", gnutls_strerror(ret));

  ret = gnutls_priority_init(&priority_cache, cfg->client_priority, NULL);
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_priority_init: %s", gnutls_strerror(ret));
}

static int open_listen_socket(const char *host, int port) {
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

static int do_accept(int listen_sd,
                     gnutls_session_t *session,
                     pp_config_t *cfg) {
  struct sockaddr_in sa_cli;
  socklen_t client_len = sizeof(sa_cli);
  char topbuf[512];
  pp_session_t *ppsession;
  int sd;
  int ret;

  sd = accept(listen_sd, (struct sockaddr *)&sa_cli, &client_len);
  fprintf(stderr, "- Connection from %s:%d\n",
          inet_ntop(AF_INET, &sa_cli.sin_addr, topbuf,
                    sizeof(topbuf)), ntohs(sa_cli.sin_port));

  ret = initialize_tls_session(session);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Error initializing TLS session\n");
    return ret;
  }
  gnutls_transport_set_ptr(*session, (gnutls_transport_ptr_t)(long)sd);

  ppsession = malloc(sizeof(pp_session_t));
  if (ppsession == NULL)
    err(1, "malloc pakeproxy_session_t");
  memset(ppsession, '\0', sizeof(pp_session_t));
  ppsession->cfg = cfg;
  gnutls_session_set_ptr(*session, ppsession);

  return GNUTLS_E_SUCCESS;
}
