#ifndef DAEMON_H
#define DAEMON_H

#include <gnutls/gnutls.h>

int open_listen_socket(const char *host, int port);
int do_accept(int listen_sd);
void* connection_thread(void* arg);

int retrieve_server_cert(gnutls_session_t session,
                         const gnutls_datum_t* req_ca_dn,
                         int nreqs,
                         const gnutls_pk_algorithm_t* pk_algos,
                         int pk_algos_length,
                         gnutls_retr2_st* st);

#endif // DAEMON_H
