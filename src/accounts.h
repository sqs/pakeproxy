#ifndef ACCOUNTS_H
#define ACCOUNTS_H

#include "pakeproxy.h"

int site_uses_tls_login(char* host);
int account_lookup(pp_session_t* ppsession);

#endif // ACCOUNTS_H
