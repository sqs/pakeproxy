#include "pakeproxy.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <pthread.h>

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include "conn.h"
#include "misc.h"
#include "daemon.h"
#include "gnutls_support.h"
#include "cert.h"
#include "site.h"

#define DEFAULT_CA_CERT_FILE "data/ca-cert.pem"
#define DEFAULT_CA_KEY_FILE "data/ca-key.pem"
#define DEFAULT_CERT_CACHE_PATH "data/tmp/"
#define DEFAULT_CLIENT_PRIORITY "NORMAL"

#define DH_BITS 1024
#define SERVER_NAME_BUFFER_SIZE 1024

pp_config_t cfg;
pp_ca_t global_ca;

static void print_usage(char *argv0);

int main(int argc, char **argv) {
  int listen_sd;
  int sd;
  int c;
  pthread_t thread_id;

  cfg.listen_host = "127.0.0.1";
  cfg.listen_port = 8443;
  cfg.ca_cert_file = DEFAULT_CA_CERT_FILE;
  cfg.ca_key_file = DEFAULT_CA_KEY_FILE;
  cfg.cert_cache_path = DEFAULT_CERT_CACHE_PATH;
  cfg.client_priority = DEFAULT_CLIENT_PRIORITY;
  cfg.accounts_inline = NULL;
  
  int detect_only = 0;
  char *detect_host = NULL;

  while ((c = getopt(argc, argv, "a:C:D:K:m:l:p:h")) != -1) {
    switch (c) {
      case 'a':
        cfg.accounts_inline = optarg;
        break;
      case 'l':
        cfg.listen_host = optarg;
        break;
      case 'p':
        cfg.listen_port = atoi(optarg);
        break;
      case 'C':
        cfg.ca_cert_file = optarg;
        break;
      case 'K':
        cfg.ca_key_file = optarg;
        break;
      case 'm':
        cfg.cert_cache_path = optarg;
        break;
      case 'D':
        detect_only = 1;
        detect_host = optarg;
        break;
      case '?':
        if (isprint(optopt))
          fprintf(stderr, "Unknown option `-%c'.\n", optopt);
        else
          fprintf(stderr,
                   "Unknown option character `\\x%x'.\n",
                   optopt);
      case 'h':
      default:
        print_usage(argv[0]);
        return 1;
    }
  }

  init_gnutls(&cfg);
  load_ca_cert_and_key(&global_ca, cfg.ca_cert_file, cfg.ca_key_file);
  srand(time(NULL));

  if (detect_only) {
    fprintf(stderr, "Detecting whether %s:443 supports TLS-SRP...\n", detect_host);
    return site_uses_tls_srp(detect_host, 443) != 1; /* returncode 0 is success */
  }

  listen_sd = open_listen_socket(cfg.listen_host, cfg.listen_port);
  if (listen_sd == -1)
    exit(1);

  for (;;) {
    sd = do_accept(listen_sd);
    pthread_create(&thread_id, NULL, connection_thread, (void*)(long)sd);
  }

  close(listen_sd);
  global_deinit();

  return 0;
}

static void print_opt(char *opt, char *desc, char *more) {
  static const char *pad = "  ";
  printf("  %s\t%s\n", opt, desc);
  if (more)
    printf("  %*s\t%s\n", (int)strlen(opt), pad, more);
  printf("\n");
}

static void print_usage(char *argv0) {
  printf("Usage: %s [options]\n\n", argv0);
  printf("Proxies HTTPS connections to TLS-SRP sites\n");
  printf("More info: http://trustedhttp.org or email <sqs@cs.stanford.edu>\n\n");
  printf("Options:\n");
  print_opt("-a <accounts>", "Set accounts on command-line",
            "(format: \"host1,user1,pwd1|host2,user2,pwd2\")");
  print_opt("-l <host/ip>", "Listen address/host", "(default: 127.0.0.1)");
  print_opt("-p <port>", "Listen port", "(default: 8443)");
  print_opt("-D <host>", "Detect whether a host supports TLS-SRP; then exit", NULL);
  print_opt("-h      ", "Show this help message", NULL);
}
