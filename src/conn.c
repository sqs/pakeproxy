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
#include "accounts.h"

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
static int do_passthru(gnutls_session_t session_client);

int do_proxy(gnutls_session_t session_client, pp_proxy_type_t proxy_type) {
  int ret;
  int sd_client = 0;
  gnutls_session_t session_target = 0;
  pp_session_t *ppsession;

  sd_client = (int)(long)gnutls_transport_get_ptr(session_client);
  ppsession = gnutls_session_get_ptr(session_client);

  if (proxy_type == PP_HTTPS_TUNNEL) {
    ret = do_http_connect(sd_client, &ppsession->target_host,
                          &ppsession->target_port);
    if (ret != GNUTLS_E_SUCCESS) {
      fprintf(stderr, "Failed to parse HTTP CONNECT\n");
      goto err;
    }
  }

  if (site_uses_tls_login(ppsession->target_host)) {
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
  } else {
    ret = do_passthru(session_client);
    if (ret != GNUTLS_E_SUCCESS) {
      fprintf(stderr, "Passthru failed: %s\n", gnutls_strerror(ret));
      goto err;
    }
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

  sd = tcp_connect(ppsession->target_host,
                   ppsession->target_port);

  gnutls_init(session, GNUTLS_CLIENT);
  gnutls_transport_set_ptr(*session, (gnutls_transport_ptr_t)(long)sd);

  gnutls_certificate_allocate_credentials(&cert_cred);
  gnutls_certificate_set_x509_trust_file(cert_cred, ppsession->cfg->ca_cert_file,
                                         GNUTLS_X509_FMT_PEM);
  ret = gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, cert_cred);
  if (ret != GNUTLS_E_SUCCESS)
    errx(1, "gnutls_credentials_set CRT: %s", gnutls_strerror(ret));

  if (site_uses_tls_login(ppsession->target_host)) {
    gnutls_priority_set_direct(*session, "NONE:+AES-256-CBC:+AES-128-CBC:+SRP:+SHA1:+COMP-NULL:+VERS-TLS1.1:+VERS-TLS1.0", NULL);
    gnutls_srp_allocate_client_credentials(&srp_cred);
    gnutls_srp_set_client_credentials_function(srp_cred, srp_cred_callback);
    ret = gnutls_credentials_set(*session, GNUTLS_CRD_SRP, srp_cred);
    if (ret != GNUTLS_E_SUCCESS)
      errx(1, "gnutls_credentials_set SRP: %s", gnutls_strerror(ret));
  } else {
    gnutls_priority_set_direct(*session, "NORMAL", NULL);
  }

  gnutls_server_name_set(*session, GNUTLS_NAME_DNS,
                         ppsession->target_host,
                         strlen(ppsession->target_host));

  ret = gnutls_handshake(*session);
  if (ret < 0) {
    fprintf(stderr, "Proxy-target TLS handshake failed: %s\n",
            gnutls_strerror(ret));
    return ret;
  }

  fprintf(stderr, "- Connected to %s:%d\n",
          ppsession->target_host, ppsession->target_port);
  
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
  int tmpret;
  int sd_client;
  int sd_target;
  int client_closed = 0, target_closed = 0;
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
      err(1, "select()");
    }
      
    /* SEND FROM CLIENT TO TARGET */
    memset(buffer, 0, sizeof(buffer));
    if (!client_closed && FD_ISSET(sd_client, &rfds)) {
      ret = gnutls_record_recv(session_client, buffer, RECORD_BUFFER_SIZE);
      if (ret == 0) {
        client_closed = 1;
        printf("- Client has closed the GnuTLS connection\n");
        break;
      } else if (ret < 0) {
        client_closed = 1;
        fprintf(stderr, "- Client sent corrupted data: %s\n", gnutls_strerror(ret));
        break;
      } else if (ret > 0) {
        tmpret = ret;
        ret = gnutls_record_send(session_target, buffer, tmpret);
        if (ret < 0) {
          fprintf(stderr, "- !!! Error sending to target: %s\n",
                  gnutls_strerror(ret));
        }
      }
    }

    /* SEND FROM TARGET TO CLIENT */
    memset(buffer, 0, sizeof(buffer));
    if (!target_closed && FD_ISSET(sd_target, &rfds)) {
      ret = gnutls_record_recv(session_target, buffer, RECORD_BUFFER_SIZE);
      if (ret == 0) {
        target_closed = 1;
        printf("- Target has closed the GnuTLS connection\n");
        break;
      } else if (ret < 0) {
        target_closed = 1;
        fprintf(stderr, "- Target sent corrupted data: %s\n", gnutls_strerror(ret));
        break;
      } else if (ret > 0) {
        tmpret = ret;
        ret = gnutls_record_send(session_client, buffer, tmpret);
        if (ret < 0) {
          fprintf(stderr, "- !!! Error sending to client: %s\n",
                  gnutls_strerror(ret));
        }
      }
    }      
  }

  if (!client_closed) {
    ret = gnutls_bye(session_client, GNUTLS_SHUT_WR);
    if (ret != GNUTLS_E_SUCCESS)
      fprintf(stderr, "- !!! Error in gnutls_bye to client: %s\n",
              gnutls_strerror(ret));
    ret = close(sd_client);
    if (ret == -1)
      warn("- !!! Error closing client sd");
  }

  if (!target_closed) {
    ret = gnutls_bye(session_target, GNUTLS_SHUT_WR);
    if (ret != GNUTLS_E_SUCCESS)
      fprintf(stderr, "- !!! Error in gnutls_bye to target: %s\n",
              gnutls_strerror(ret));
    ret = close(sd_target);
    if (ret == -1)
      warn("- !!! Error closing target sd");
  }

  return GNUTLS_E_SUCCESS;
}

static int do_passthru(gnutls_session_t session_client) {
  int ret;
  int sd_client;
  int sd_target;
  pp_session_t* ppsession;
  int client_closed = 0, target_closed = 0;
  fd_set rfds;
  int nfds;
  char buffer[RECORD_BUFFER_SIZE+1];

  sd_client = (int)(long)gnutls_transport_get_ptr(session_client);

  ppsession = gnutls_session_get_ptr(session_client);
  sd_target = tcp_connect(ppsession->target_host, ppsession->target_port);

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
      err(1, "select()");
    }

    /* SEND FROM CLIENT TO TARGET */
    memset(buffer, 0, sizeof(buffer));
    if (FD_ISSET(sd_client, &rfds)) {
      ret = recv(sd_client, buffer, RECORD_BUFFER_SIZE, 0);
      if (ret == 0) {
        client_closed = 1;
        fprintf(stderr, "- Client has closed the passthru connection\n");
        break;
      } else if (ret == -1) {
        err(1, "passthru read from client");
      } else if (ret > 0) {
        ret = send(sd_target, buffer, ret, 0);
        if (ret == -1)
          err(1, "passthru send to target");
      }
    }

    /* SEND FROM TARGET TO CLIENT */
    memset(buffer, 0, sizeof(buffer));
    if (FD_ISSET(sd_target, &rfds)) {
      ret = recv(sd_target, buffer, RECORD_BUFFER_SIZE, 0);
      if (ret == 0) {
        target_closed = 1;
        fprintf(stderr, "- Target has closed the passthru connection\n");
        break;
      } else if (ret == -1) {
        err(1, "passthru read from target");
      } else if (ret > 0) {
        ret = send(sd_client, buffer, ret, 0);
        if (ret == -1)
          err(1, "passthru send to client");
      }
    }
  }

  if (!client_closed) {
    ret = close(sd_client);
    if (ret == -1)
      warn("- !!! Error closing client sd");
  }

  if (!target_closed) {
    ret = close(sd_target);
    if (ret == -1)
      warn("- !!! Error closing target sd");
  }

  return GNUTLS_E_SUCCESS;

}
