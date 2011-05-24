#include "accounts.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ACCOUNT_FILENAME_BUFFER_SIZE 1024
#define ACCOUNT_BUFFER_SIZE 1024

static int account_inline_lookup(pp_session_t* ppsession);
static int account_file_lookup(pp_session_t* ppsession);

int site_uses_tls_login(char* host) {
  return (strcmp(host, "tls-srp.test.trustedhttp.org") == 0);
}

int account_lookup(pp_session_t* ppsession) {
  int ret;

  ret = account_inline_lookup(ppsession);
  if (ret == 0)
    return 0;

  ret = account_file_lookup(ppsession);
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
        goto done;
      }
    }
  }

done:
  free(tmp);
  return ret;
}

static int account_file_lookup(pp_session_t* pps) {
  pp_config_t *cfg = pps->cfg;
  char fname[ACCOUNT_FILENAME_BUFFER_SIZE];
  char buf[ACCOUNT_BUFFER_SIZE+1];
  char *tmp;
  size_t len;
  FILE *f;

  snprintf(fname, ACCOUNT_FILENAME_BUFFER_SIZE, "%s/%s",
           cfg->accounts_path, pps->target_host);

  if (fname[0] == '~') {
    char* home = getenv("HOME");
    int n = strlen(fname) + strlen(home);
    char *fnametmp = (char*)malloc(n*sizeof(char));
    sprintf(fnametmp, "%s%s", home, fname+1);
    f = fopen(fnametmp, "r");
    free(fnametmp);
  } else {
    f = fopen(fname, "r");
  }
  
  if (f == NULL)
    return -1;

  len = fread(buf, 1, ACCOUNT_BUFFER_SIZE, f);
  fclose(f);
  buf[len] = '\0';

  tmp = strchr(buf, ',');
  if (tmp == NULL)
    return -1;

  *tmp = '\0';
  pps->srp_user = strdup(buf);
  pps->srp_passwd = strdup((char*)tmp + 1);

  /* if last passwd char is newline, assume user accidentally left whitespace */
  if (pps->srp_passwd[strlen(pps->srp_passwd)-1] == '\n')
    pps->srp_passwd[strlen(pps->srp_passwd)-1] = '\0';
  
  fprintf(stderr, "- File: found '%s'/'%s'\n", pps->srp_user, pps->srp_passwd);
  return 0;
}
