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

#include <gnutls/gnutls.h>
#include <gnutls/extra.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#include "cert.h"

#define CA_CERT_FILE "/home/sqs/src/pakeproxy/data/ca-cert.pem"
#define CA_KEY_FILE "/home/sqs/src/pakeproxy/data/ca-key.pem"
#define CAFILE CA_CERT_FILE
#define SRPUSER "user"
#define SRPPASSWD "secret"

const int kListenPort = 8443;

#define SA struct sockaddr
#define SOCKET_ERR(err,s) if(err==-1) {perror(s);return(1);}
#define MAX_BUF 1024
#define SERVER_NAME_BUFFER_SIZE 1024
#define DH_BITS 1024

/* These are global */
gnutls_priority_t priority_cache;
static pakeproxy_ca_t global_ca;

void read_http_connect(int sd, char** host, int* port) {
  char buf[MAX_BUF];
  char *cur = buf;
  ssize_t len;
  ssize_t total_len = 0;
  int i;

  for (;;) {
    len = recv(sd, cur, MAX_BUF - (cur - buf), 0);
    if (len == -1)
      break;
    cur += len;
    total_len += len;
    printf("recv %u\n", len);
    //printf("cur - 4 = '%s'\n", cur-4);
    if (strncmp(cur - 4, "\r\n\r\n", 4) == 0)
      break;
  }

  buf[MAX_BUF-1] = '\0';
  // printf("recv %u bytes: <<<%s>>>\n", total_len, buf);
  
  if (strncmp(buf, "CONNECT ", strlen("CONNECT ")) == 0) {
    *host = buf + strlen("CONNECT ");
    for (i = 0; i < total_len; i++) {
      if ((*host)[i] == ':') {
        (*host)[i] = '\0';
        *port = atoi(&(*host)[i+1]);
        break;
      }
    }
    *host = strdup(*host);
    printf("HOST = '%s' port %d\n", *host, *port);

    strcpy(buf, "HTTP/1.1 200 OK\r\n\r\n");
    len = send(sd, buf, strlen(buf), 0);
    if (len != strlen(buf))
      fprintf(stderr, "couldnt send full buf\n");
  }
}

int
tcp_connect2 (char *server)
{
  const char *PORT = "443";
  int err, sd;
  struct sockaddr_in sa;
  struct hostent *hp;

  /* connects to server
   */
  sd = socket (AF_INET, SOCK_STREAM, 0);

  memset (&sa, '\0', sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (atoi (PORT));

  hp = gethostbyname(server);
  if (hp == NULL)
    errx(1, "gethostbyname error");

  if (hp->h_addr_list[0] == NULL)
    errx(1, "gethostbyname empty h_addr_list");
  sa.sin_addr = *(struct in_addr *)hp->h_addr_list[0];

  err = connect (sd, (struct sockaddr *) & sa, sizeof (sa));
  if (err < 0)
    {
      fprintf (stderr, "Connect error\n");
      exit (1);
    }

  return sd;
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

  create_x509_for_host_and_user(session, &global_ca, crt, &key);

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

int srp_cred_callback(gnutls_session_t session, char **username, char **password) {
  *username = SRPUSER;
  *password = SRPPASSWD;
  return 0;
}

int main(int argc, char **argv) {
  int err, listen_sd;
  int ret, sd, sd2;
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

  ret = gnutls_global_init_extra();
  if (ret != GNUTLS_E_SUCCESS)
    errx(ret, "gnutls_global_init_extra: %s", gnutls_strerror(ret));

  load_ca_cert_and_key(&global_ca, CA_CERT_FILE, CA_KEY_FILE);
  
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

    pakeproxy_session_t ppsession;
    proxy_stream_t pstream;
    ppsession.proxy_stream = &pstream;
    read_http_connect(sd, &pstream.connect_host, &pstream.connect_port);

    gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t)sd);
    gnutls_session_set_ptr(session, &ppsession);

    ret = gnutls_handshake(session);
    if (ret != GNUTLS_E_SUCCESS) {
      close(sd);
      gnutls_deinit(session);
      fprintf(stderr, "CLIENT handshake failed: %s\n\n", gnutls_strerror(ret));
      continue;
    }
    printf("handshake OK\n");

    /* see the Getting peer's information example */
    /* print_info(session); */

    /**** SRP ****/
    gnutls_session_t session2;
    gnutls_srp_client_credentials_t srp_cred2;
    gnutls_certificate_credentials_t cert_cred2;

    gnutls_srp_allocate_client_credentials (&srp_cred2);
    gnutls_certificate_allocate_credentials (&cert_cred2);
    gnutls_certificate_set_x509_trust_file (cert_cred2, CAFILE,
                                            GNUTLS_X509_FMT_PEM);

    //    ret = gnutls_srp_set_client_credentials(srp_cred2, SRPUSER, SRPPASSWD);
      /*   if (ret != GNUTLS_E_SUCCESS) */
      /* errx(1, "gnutls_srp_set_client_credentials: %s", gnutls_strerror(ret)); */
    gnutls_srp_set_client_credentials_function(srp_cred2, srp_cred_callback);
    
    sd2 = tcp_connect2(ppsession.proxy_stream->connect_host);
    gnutls_init(&session2, GNUTLS_CLIENT);
    gnutls_priority_set_direct(session2, "NONE:+AES-256-CBC:+AES-128-CBC:+SRP:+SHA1:+COMP-NULL:+VERS-TLS1.1:+VERS-TLS1.0", NULL);
    
    ret = gnutls_credentials_set(session2, GNUTLS_CRD_SRP, srp_cred2);
    if (ret != GNUTLS_E_SUCCESS)
      errx(1, "gnutls_credentials_set SRP: %s", gnutls_strerror(ret));
    
    ret = gnutls_credentials_set (session2, GNUTLS_CRD_CERTIFICATE, cert_cred2);
    if (ret != GNUTLS_E_SUCCESS)
      errx(1, "gnutls_credentials_set CRT: %s", gnutls_strerror(ret));

    gnutls_server_name_set(session2, GNUTLS_NAME_DNS, ppsession.proxy_stream->connect_host, strlen(ppsession.proxy_stream->connect_host));
    gnutls_transport_set_ptr(session2, (gnutls_transport_ptr_t)sd2);
    ret = gnutls_handshake(session2);
    if (ret < 0) {
      fprintf(stderr, "*** proxy<->server handshake failed\n");
      gnutls_perror(ret);
      exit(1);
    } else {
      printf("- completed SRP handshake\n");
    }

    /*************/

    for (;;)
    {
      fd_set rfds;
      int nfds;
      FD_ZERO(&rfds);
      FD_SET(sd, &rfds);
      FD_SET(sd2, &rfds);
      nfds = (sd > sd2 ? sd : sd2);

      ret = select(nfds+1, &rfds, NULL, NULL, NULL);

      if (ret == -1 && errno == EINTR) {
        warnx("select interrupted\n");
        continue;
      }

      if (ret == -1) {
        errx(1, "select()");
      }
      
      printf("loop\n");
      /* SEND FROM CLIENT TO HOST */
      memset(buffer, 0, MAX_BUF + 1);
      if (FD_ISSET(sd, &rfds)) {
        printf("- RECV from CLIENT\n");
        ret = gnutls_record_recv(session, buffer, MAX_BUF);
        if (ret == 0)
        {
          printf("\n- CLIENT has closed the GnuTLS connection\n");
          break;
        }
        else if (ret < 0)
        {
          fprintf(stderr, "\n*** Received corrupted "
                  "data(%d) from CLIENT. Closing the connection.\n\n", ret);
          break;
        }
        else if (ret > 0)
        {
          gnutls_record_send(session2, buffer, strlen(buffer));
        }
      }

      /* SEND FROM HOST TO CLIENT */
      memset(buffer, 0, MAX_BUF + 1);
      if (FD_ISSET(sd2, &rfds)) {
        printf("RECV from server\n");
        ret = gnutls_record_recv(session2, buffer, MAX_BUF);
        if (ret == 0)
        {
          printf("\n- HOST has closed the GnuTLS connection\n");
          break;
        }
        else if (ret < 0)
        {
          fprintf(stderr, "\n*** Received corrupted "
                  "data(%d) from HOST. Closing the connection.\n\n", ret);
          break;
        }
        else if (ret > 0)
        {
          printf("- send %u bytes to CLIENT\n", strlen(buffer));
          gnutls_record_send(session, buffer, strlen(buffer));
        }
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
