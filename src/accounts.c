#include "accounts.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ACCOUNT_FILENAME_BUFFER_SIZE 1024
#define ACCOUNT_BUFFER_SIZE 1024

static int account_inline_lookup(pp_session_t* ppsession);

int account_lookup(pp_session_t* ppsession) {
  int ret;

  ret = account_inline_lookup(ppsession);
  if (ret == 0)
    return 0;

  fprintf(stderr, "- Couldn't find account for %s:%d\n",
          ppsession->target_host, ppsession->target_port);
  return -1;
}

/* ppsession->account_inline is in form "host,user,password|"* */
static int account_inline_lookup(pp_session_t* ppsession) {
  char* accts = ppsession->cfg->accounts_inline;
  char* tmp;
  char* acct;
  char* host = ppsession->target_host;
  char* token;
  char* subtoken;
  char* accts_delim = "|";
  char* acct_delim = ",";
  char* saveptr1;
  char* saveptr2;
  int ret = -1;
  int j;

  accts = ppsession->cfg->accounts_inline;
  if (accts == NULL)
    return -1;

  accts = strdup(accts);
  tmp = accts;

  for (; ; accts = NULL) {
    token = strtok_r(accts, accts_delim, &saveptr1);
    if (token == NULL)
      break;

    for (j=1, acct = token; ; j++, acct = NULL) {
      subtoken = strtok_r(acct, acct_delim, &saveptr2);
      if (subtoken == NULL)
        break;
      if (j == 1 && strcmp(subtoken, host) != 0)
        break;
      if (j == 2)
        ppsession->srp_user = strdup(subtoken);
      if (j == 3) {
        ppsession->srp_passwd = strdup(subtoken);
        ret = 0;
        fprintf(stderr, "-   Auth: flag '%s'/'%s'\n",
                ppsession->srp_user, ppsession->srp_passwd);
        goto done;
      }
    }
  }

done:
  free(tmp);
  return ret;
}
