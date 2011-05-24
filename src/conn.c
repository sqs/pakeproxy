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
#define HTTP_PROXY_AUTH_BUFFER_SIZE MAX_BUFFER_SIZE

static const char *HTTP_200_MSG =
    "HTTP/1.1 200 OK\r\n\r\n";

static const char *HTTP_407_MSG =
    "HTTP/1.1 407 Proxy Authentication Required\r\n"
    "Server: PAKEProxy\r\n"
    "Content-Length: 4\r\n"
    "Content-Type: text/plain\r\n"
    "Proxy-Authenticate: Basic realm=\"PAKEProxy\"\r\n"
    "Connection: close\r\n"
    "\r\n"
    "auth";

static const char *HTTP_502_MSG =
    "HTTP/1.1 502 Bad Gateway\r\n"
    "Server: PAKEProxy\r\n"
    "Content-Length: 15\r\n"
    "Content-Type: text/plain\r\n"
    "Connection: close\r\n"
    "\r\n"
    "502 Bad Gateway";

static int read_http_connect(int sd, pp_session_t* ppsession);
static int send_http_msg(int sd, const char *msg);
static int handle_target_handshake_error(gnutls_session_t session,
                                         int gnutls_error, int sd_client);
static int parse_proxy_authorization_header(char* buf, char** user, char** passwd);
static int do_connect_target(gnutls_session_t* session_target,
                               pp_session_t* ppsession_target);
static int srp_cred_callback(gnutls_session_t session,
                             char** username,
                             char** password);
static int tcp_connect(char* host, int port);
static int do_tunnel(gnutls_session_t session_client,
                     gnutls_session_t session_target);
static int do_passthru(gnutls_session_t session_client);

int do_proxy(gnutls_session_t session_client) {
  int ret;
  int sd_client = 0;
  gnutls_session_t session_target = 0;
  pp_session_t *ppsession;

  sd_client = (int)(long)gnutls_transport_get_ptr(session_client);
  ppsession = gnutls_session_get_ptr(session_client);

  ret = read_http_connect(sd_client, ppsession);
  if (ret == -1) {
    fprintf(stderr, "- Read HTTP connect failed\n");
    goto err;
  }

  if ((ppsession->srp_user && ppsession->srp_passwd) ||
      !ppsession->cfg->enable_passthru) {
    ret = do_connect_target(&session_target, ppsession);
    if (ret != GNUTLS_E_SUCCESS) {
      fprintf(stderr, "Connect to target failed: %s\n", gnutls_strerror(ret));
      handle_target_handshake_error(session_target, ret, sd_client);
      goto err;
    }

    send_http_msg(sd_client, HTTP_200_MSG);
    ret = gnutls_handshake(session_client);
    if (ret != GNUTLS_E_SUCCESS) {
      fprintf(stderr, "Client handshake failed: %s\n", gnutls_strerror(ret));
      goto err;
    }

    ret = do_tunnel(session_client, session_target);
    if (ret != GNUTLS_E_SUCCESS) {
      fprintf(stderr, "Tunneling failed: %s\n", gnutls_strerror(ret));
      goto err;
    }
  } else {
    send_http_msg(sd_client, HTTP_200_MSG);
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

/* Returns 0 on success (= continue with tunnel or passthru), and -1 on error
 * (= proxy auth challenge) */
static int read_http_connect(int sd, pp_session_t* ppsession) {
  char buf[HTTP_CONNECT_BUFFER_SIZE+1];
  char *cur = buf;
  ssize_t len;
  ssize_t total_len = 0;
  char* host;
  int ret;

  for (;;) {
    len = recv(sd, cur, sizeof(buf) - (cur - buf), 0);
    if (len == -1)
      break;
    cur += len;
    total_len += len;
    if (strncmp(cur - 4, "\r\n\r\n", 4) == 0)
      break;
  }
  buf[HTTP_CONNECT_BUFFER_SIZE] = '\0';

  ret = parse_proxy_authorization_header(buf, &ppsession->srp_user,
                                         &ppsession->srp_passwd);

  buf[sizeof(buf)-1] = '\0';
  // printf("recv %u bytes: <<<%s>>>\n", total_len, buf);
  
  if (strncmp(buf, "CONNECT ", strlen("CONNECT ")) == 0) {
    host = buf + strlen("CONNECT ");
    parse_hostport(host, &host, &ppsession->target_port);
    ppsession->target_host = strdup(host);
    fprintf(stderr, "- Client requested HTTP CONNECT %s:%d\n",
            ppsession->target_host, ppsession->target_port);

    /* try to get TLS login info from proxy-authorization or cmdline flags/file */
    if (ppsession->srp_user && ppsession->srp_passwd) {
      fprintf(stderr, "-   Auth: Proxy-Authz '%s'/'%s'\n",
              ppsession->srp_user, ppsession->srp_passwd);
      ret = 0;
    } else {
      ret = account_lookup(ppsession);
    }

    /* passthru? */
    if (ret != 0 && ppsession->cfg->enable_passthru)
      ret = 0;

    if (ret != 0) {
      send_http_msg(sd, HTTP_407_MSG);
      return -1;
    }
  }

  return 0;
}

static int send_http_msg(int sd, const char *msg) {
  ssize_t len;
  len = send(sd, msg, strlen(msg), 0);
  if (len != strlen(msg))
    err(1, "send_http_msg");
  return 0;
}

static int handle_target_handshake_error(gnutls_session_t session,
                                         int gnutls_error, int sd_client) {
  if (gnutls_error != GNUTLS_E_WARNING_ALERT_RECEIVED &&
      gnutls_error != GNUTLS_E_FATAL_ALERT_RECEIVED) {
    fprintf(stderr, "- Unexpected target handshake error: %s\n",
            gnutls_strerror(gnutls_error));
    return -1;
  }

  gnutls_alert_description_t alert = gnutls_alert_get(session);

  fprintf(stderr, "- Got TLS alert %s\n", gnutls_alert_get_name(alert));

  switch (alert) {
    case GNUTLS_A_UNKNOWN_PSK_IDENTITY:
    case GNUTLS_A_BAD_RECORD_MAC:
      send_http_msg(sd_client, HTTP_407_MSG);
      break;
    default:
      send_http_msg(sd_client, HTTP_502_MSG);
      break;
  }

  return 0;
}

static int parse_proxy_authorization_header(char* buf, char** user, char** passwd) {
  char *auth_hdr;
  char *b64val;
  char *b64val_end;
  char *val;
  int ret;
  const char *search_string = "\r\nProxy-Authorization: Basic ";

  /* TODO(sqs): this header name should be case insensitive */
  auth_hdr = strstr(buf, search_string);
  if (auth_hdr == NULL)
    return GNUTLS_E_INTERNAL_ERROR;

  b64val = auth_hdr + strlen(search_string);
  b64val_end = strstr(b64val, "\r\n");
  *b64val_end = '\0';

  val = malloc(HTTP_PROXY_AUTH_BUFFER_SIZE+1);
  if (val == NULL)
    err(1, "malloc val");

  ret = base64_decode(b64val, (unsigned char **)&val); /* TODO(sqs): free */

  /* TODO(sqs): check to ensure there is indeed a ':' in here */
  *user = val;
  *passwd = strchr(val, ':') + 1;
  (*passwd)[-1] = '\0';

  *user = strdup(*user);
  *passwd = strdup(*passwd);

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
  gnutls_session_set_ptr(*session, ppsession);

  gnutls_certificate_allocate_credentials(&cert_cred);
  gnutls_certificate_set_x509_trust_file(cert_cred, ppsession->cfg->ca_cert_file,
                                         GNUTLS_X509_FMT_PEM);
  ret = gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, cert_cred);
  if (ret != GNUTLS_E_SUCCESS)
    errx(1, "gnutls_credentials_set CRT: %s", gnutls_strerror(ret));

  gnutls_priority_set_direct(*session, "NONE:+AES-256-CBC:+AES-128-CBC:+SRP:+SHA1:+COMP-NULL:+VERS-TLS1.1:+VERS-TLS1.0", NULL);
  gnutls_srp_allocate_client_credentials(&srp_cred);
  gnutls_srp_set_client_credentials_function(srp_cred, srp_cred_callback);
  ret = gnutls_credentials_set(*session, GNUTLS_CRD_SRP, srp_cred);
  if (ret != GNUTLS_E_SUCCESS)
    errx(1, "gnutls_credentials_set SRP: %s", gnutls_strerror(ret));

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
  int ret;
  pp_session_t* ppsession;

  ppsession = gnutls_session_get_ptr(session);
  if (ppsession == NULL)
    return -1;

  ret = 0;
  if (!ppsession->srp_user || !ppsession->srp_passwd) {
    ret = account_lookup(ppsession);
  }
  
  if (ret == 0) {
    *username = strdup(ppsession->srp_user);
    *password = strdup(ppsession->srp_passwd);
    return 0;
  } else {
    *username = NULL;
    *password = NULL;
    return -1; /* error */
  }
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
