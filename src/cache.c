#include "cache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#define TLS_SESSION_CACHE_SIZE 50
#define MAX_SESSION_ID_SIZE 64
#define MAX_SESSION_DATA_SIZE 1024

typedef struct {
  char session_id[MAX_SESSION_ID_SIZE];
  int session_id_size;

  char session_data[MAX_SESSION_DATA_SIZE];
  int session_data_size;
} CACHE;

static CACHE *cache_db;
static int cache_db_ptr = 0;
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

static int cache_db_store(void *dbf, gnutls_datum_t key, gnutls_datum_t data);
static gnutls_datum_t cache_db_fetch(void *dbf, gnutls_datum_t key);
static int cache_db_remove(void *dbf, gnutls_datum_t key);

int global_init_cache() {
  cache_db = calloc(1, TLS_SESSION_CACHE_SIZE*sizeof(CACHE));
  if (cache_db != NULL) {
    return GNUTLS_E_SUCCESS;
  } else {
    return GNUTLS_E_INTERNAL_ERROR;
  }
}

void global_deinit_cache() {
  if (cache_db)
    free(cache_db);
  cache_db = NULL;
}

int session_init_cache(gnutls_session_t session) {
  gnutls_db_set_retrieve_function(session, cache_db_fetch);
  gnutls_db_set_remove_function(session, cache_db_remove);
  gnutls_db_set_store_function(session, cache_db_store);
  gnutls_db_set_ptr(session, NULL);
  return GNUTLS_E_SUCCESS;
}

static int cache_db_store (void *dbf, gnutls_datum_t key, gnutls_datum_t data) {
  printf("cache_db_store data=(%x,%u)\n", data.data[data.size-1], data.size);

  if (cache_db == NULL)
    return -1;

  if (key.size > MAX_SESSION_ID_SIZE)
    return -1;
  if (data.size > MAX_SESSION_DATA_SIZE)
    return -1;

  pthread_mutex_lock(&cache_mutex);

  memcpy(cache_db[cache_db_ptr].session_id, key.data, key.size);
  cache_db[cache_db_ptr].session_id_size = key.size;

  memcpy(cache_db[cache_db_ptr].session_data, data.data, data.size);
  cache_db[cache_db_ptr].session_data_size = data.size;

  cache_db_ptr++;
  cache_db_ptr %= TLS_SESSION_CACHE_SIZE;

  pthread_mutex_unlock(&cache_mutex);

  return 0;
}

static gnutls_datum_t cache_db_fetch(void *dbf, gnutls_datum_t key) {
  gnutls_datum_t res = { NULL, 0 };
  int i;

  printf("cache_db_fetch\n");

  if (cache_db == NULL)
    return res;

  pthread_mutex_lock(&cache_mutex);
  
  for (i = 0; i < TLS_SESSION_CACHE_SIZE; i++) {
    if (key.size == cache_db[i].session_id_size &&
        memcmp (key.data, cache_db[i].session_id, key.size) == 0) {      
      res.size = cache_db[i].session_data_size;
      res.data = gnutls_malloc(res.size);
      if (res.data != NULL) {
        memcpy(res.data, cache_db[i].session_data, res.size);
        printf("  - HIT, data=(%x,%u)\n", res.data[res.size-1], res.size);
      }
      break;
    }
  }
  pthread_mutex_unlock(&cache_mutex);
  return res;
}

static int cache_db_remove(void *dbf, gnutls_datum_t key) {
  int i;

  if (cache_db == NULL)
    return -1;

  pthread_mutex_lock(&cache_mutex);
  
  for (i = 0; i < TLS_SESSION_CACHE_SIZE; i++) {
    if (key.size == cache_db[i].session_id_size &&
        memcmp(key.data, cache_db[i].session_id, key.size) == 0) {
      cache_db[i].session_id_size = 0;
      cache_db[i].session_data_size = 0;
      pthread_mutex_unlock(&cache_mutex);
      return 0;
    }
  }

  pthread_mutex_unlock(&cache_mutex);
  return -1;

}
