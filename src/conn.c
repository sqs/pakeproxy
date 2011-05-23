#include "conn.h"

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#include "pakeproxy.h"
#include "misc.h"

#define MAX_BUFFER_SIZE 4096
#define RECORD_BUFFER_SIZE MAX_BUFFER_SIZE
#define HTTP_CONNECT_BUFFER_SIZE MAX_BUFFER_SIZE

/* TODO(sqs): parameterize these constants */
#define SRPUSER "user"
#define SRPPASSWD "secret"

static int do_http_connect(int sd, char** host, int* port);
static int do_connect_target(gnutls_session_t* session_target,
                             pp_session_t* ppsession_target);
static int srp_cred_callback(gnutls_session_t session,
                             char** username,
                             char** password);
static int tcp_connect(char* host, int port);
static int do_tunnel(gnutls_session_t session_client,
                     gnutls_session_t session_target);

int do_https_tunnel(gnutls_session_t session_client) {
  int ret;
  int sd_client = 0;
  gnutls_session_t session_target = 0;
  pp_session_t *ppsession;

  sd_client = (int)(long)gnutls_transport_get_ptr(session_client);
  ppsession = gnutls_session_get_ptr(session_client);
  
  ret = do_http_connect(sd_client, &ppsession->target_host,
                        &ppsession->target_port);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Failed to parse HTTP CONNECT\n");
    goto err;
  }

  ret = gnutls_handshake(session_client);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Client handshake failed: %s\n", gnutls_strerror(ret));
    goto err;
  }

  ret = do_connect_target(&session_target, ppsession);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Connect to target failed: %s\n", gnutls_strerror(ret));
    goto err;
  }

  ret = do_tunnel(session_client, session_target);
  if (ret != GNUTLS_E_SUCCESS) {
    fprintf(stderr, "Tunneling failed: %s\n", gnutls_strerror(ret));
    goto err;
  }
  
  ret = GNUTLS_E_SUCCESS;

err:
  if (session_target)
    gnutls_deinit(session_target);
  return ret;
}

static int do_http_connect(int sd, char** host, int* port) {
  char buf[HTTP_CONNECT_BUFFER_SIZE];
  char *cur = buf;
  ssize_t len;
  ssize_t total_len = 0;

  for (;;) {
    len = recv(sd, cur, sizeof(buf) - (cur - buf), 0);
    if (len == -1)
      break;
    cur += len;
    total_len += len;
    if (strncmp(cur - 4, "\r\n\r\n", 4) == 0)
      break;
  }

  buf[sizeof(buf)-1] = '\0';
  // printf("recv %u bytes: <<<%s>>>\n", total_len, buf);
  
  if (strncmp(buf, "CONNECT ", strlen("CONNECT ")) == 0) {
    *host = buf + strlen("CONNECT ");
    parse_hostport(*host, host, port);
    *host = strdup(*host);
    fprintf(stderr, "- Client requested HTTP CONNECT %s:%d\n", *host, *port);

    strcpy(buf, "HTTP/1.1 200 OK\r\n\r\n");
    len = send(sd, buf, strlen(buf), 0);
    if (len != strlen(buf))
      fprintf(stderr, "couldnt send full buf\n");
  }

  return GNUTLS_E_SUCCESS;
}

static int do_connect_target(gnutls_session_t* session,
                             pp_session_t* ppsession) {
  gnutls_srp_client_credentials_t srp_cred;
  gnutls_certificate_credentials_t cert_cred;
  int ret;
  int sd;

  gnutls_srp_allocate_client_credentials(&srp_cred);
  gnutls_certificate_allocate_credentials(&cert_cred);
  gnutls_certificate_set_x509_trust_file(cert_cred, ppsession->cfg->ca_cert_file,
                                         GNUTLS_X509_FMT_PEM);
  gnutls_srp_set_client_credentials_function(srp_cred, srp_cred_callback);

  sd = tcp_connect(ppsession->target_host,
                   ppsession->target_port);

  gnutls_init(session, GNUTLS_CLIENT);
  gnutls_transport_set_ptr(*session, (gnutls_transport_ptr_t)(long)sd);

  gnutls_priority_set_direct(*session, "NONE:+AES-256-CBC:+AES-128-CBC:+SRP:+SHA1:+COMP-NULL:+VERS-TLS1.1:+VERS-TLS1.0", NULL);

  ret = gnutls_credentials_set(*session, GNUTLS_CRD_SRP, srp_cred);
  if (ret != GNUTLS_E_SUCCESS)
    errx(1, "gnutls_credentials_set SRP: %s", gnutls_strerror(ret));
    
  ret = gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, cert_cred);
  if (ret != GNUTLS_E_SUCCESS)
    errx(1, "gnutls_credentials_set CRT: %s", gnutls_strerror(ret));


  gnutls_server_name_set(*session, GNUTLS_NAME_DNS,
                         ppsession->target_host,
                         strlen(ppsession->target_host));

  ret = gnutls_handshake(*session);
  if (ret < 0) {
    fprintf(stderr, "Proxy-target TLS handshake failed: %s\n",
            gnutls_strerror(ret));
    return ret;
  }
  
  return GNUTLS_E_SUCCESS;
}

static int srp_cred_callback(gnutls_session_t session,
                             char** username,
                             char** password) {
  *username = strdup(SRPUSER);
  *password = strdup(SRPPASSWD);
  return 0;
}

int tcp_connect(char* host, int port) {
  int err, sd;
  struct sockaddr_in sa;
  struct hostent *hp;

  sd = socket(AF_INET, SOCK_STREAM, 0);

  memset(&sa, '\0', sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);

  hp = gethostbyname(host);
  if (hp == NULL)
    errx(1, "gethostbyname error");

  if (hp->h_addr_list[0] == NULL)
    errx(1, "gethostbyname empty h_addr_list");
  sa.sin_addr = *(struct in_addr *)hp->h_addr_list[0];

  err = connect(sd, (struct sockaddr *)&sa, sizeof(sa));
  if (err < 0) {
    fprintf(stderr, "Connect error\n");
    exit(1);
  }

  return sd;
}

static int do_tunnel(gnutls_session_t session_client,
                     gnutls_session_t session_target) {
  int ret;
  int sd_client;
  int sd_target;
  fd_set rfds;
  int nfds;
  char buffer[RECORD_BUFFER_SIZE+1];

  sd_client = (int)(long)gnutls_transport_get_ptr(session_client);
  sd_target = (int)(long)gnutls_transport_get_ptr(session_target);
  
  for (;;) {
    FD_ZERO(&rfds);
    FD_SET(sd_client, &rfds);
    FD_SET(sd_target, &rfds);
    nfds = (sd_client > sd_target ? sd_client : sd_target);

    ret = select(nfds+1, &rfds, NULL, NULL, NULL);

    if (ret == -1 && errno == EINTR) {
      warnx("select interrupted\n");
      continue;
    }

    if (ret == -1) {
      errx(1, "select()");
    }
      
    /* SEND FROM CLIENT TO HOST */
    memset(buffer, 0, sizeof(buffer));
    if (FD_ISSET(sd_client, &rfds)) {
      ret = gnutls_record_recv(session_client, buffer, RECORD_BUFFER_SIZE);
      if (ret == 0) {
        printf("- Client has closed the GnuTLS connection\n");
        break;
      } else if (ret < 0) {
        fprintf(stderr, "- Received corrupted "
                "data(%d) from client. Closing the connection.\n", ret);
        break;
      } else if (ret > 0) {
        gnutls_record_send(session_target, buffer, strlen(buffer));
      }
    }

    /* SEND FROM HOST TO CLIENT */
    memset(buffer, 0, sizeof(buffer));
    if (FD_ISSET(sd_target, &rfds)) {
      ret = gnutls_record_recv(session_target, buffer, RECORD_BUFFER_SIZE);
      if (ret == 0) {
        printf("- Target has closed the GnuTLS connection\n");
        break;
      } else if (ret < 0) {
        fprintf(stderr, "\n- Received corrupted "
                "data(%d) from target. Closing the connection.\n", ret);
        break;
      } else if (ret > 0) {
        gnutls_record_send(session_client, buffer, strlen(buffer));
      }
    }      
  }

  return GNUTLS_E_SUCCESS;
}
