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

#define DEFAULT_CA_CERT_FILE "/home/sqs/src/pakeproxy/data/ca-cert.pem"
#define DEFAULT_CA_KEY_FILE "/home/sqs/src/pakeproxy/data/ca-key.pem"
#define DEFAULT_ACCOUNTS_PATH "~/.pakeproxy/"
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
  cfg.client_priority = DEFAULT_CLIENT_PRIORITY;
  cfg.session_cache = 0;
  cfg.accounts_path = DEFAULT_ACCOUNTS_PATH;
  cfg.accounts_inline = NULL;
  cfg.enable_passthru = 1;
  cfg.enable_proxy_basic_auth = 1;

  while ((c = getopt(argc, argv, "A:a:BsLl:p:h")) != -1) {
    switch (c) {
      case 'A':
        cfg.accounts_path = optarg;
        break;
      case 'a':
        cfg.accounts_inline = optarg;
        break;
      case 'B':
        cfg.enable_proxy_basic_auth = 0;
        break;
      case 's':
        cfg.session_cache = 1;
        break;
      case 'L':
        cfg.enable_passthru = 0;
        break;
      case 'l':
        cfg.listen_host = optarg;
        break;
      case 'p':
        cfg.listen_port = atoi(optarg);
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
  print_opt("-A <dir>", "Set directory where account files are stored",
            "(default: ~/.pakeproxy/)");
  print_opt("-a <accounts>", "Set accounts on command-line",
            "(format: \"host1,user1,pwd1|host2,user2,pwd2\")");
  print_opt("-B      ", "Disable proxy HTTP Basic auth", "(default: enable)");
  print_opt("-s      ", "Use TLS session cache", "(default: off)");
  print_opt("-L      ", "Disable passthru of non-SRP TLS connections",
            "(default: enable)");
  print_opt("-l <host/ip>", "Listen address/host", "(default: 127.0.0.1)");
  print_opt("-p <port>", "Listen port", "(default: 8443)");
  print_opt("-h      ", "Show this help message", NULL);
}
