/*

  silchash.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"

#include "md5.h"
#include "sha1.h"

/* List of all hash functions in SILC. You can dynamically add new hash
   functions into the list. At the initialization of SILC this list is 
   filled with the configured hash functions. */
struct SilcHashListStruct {
  SilcHashObject *hash;
  struct SilcHashListStruct *next;
};

/* List of dynamically registered hash functions. */
struct SilcHashListStruct *silc_hash_list = NULL;

/* Statically declared list of hash functions. */
SilcHashObject silc_hash_builtin_list[] = 
{
  { "sha1", 20, 64, silc_sha1_init, silc_sha1_update, silc_sha1_final,
    silc_sha1_transform, silc_sha1_context_len },
  { "md5", 16, 64, silc_md5_init, silc_md5_update, silc_md5_final,
    silc_md5_transform, silc_md5_context_len },

  { NULL, 0, 0, NULL, NULL, NULL, NULL, NULL }
};

/* Registers a new hash function into the SILC. This function is used at
   the initialization of the SILC. */

int silc_hash_register(SilcHashObject *hash)
{
  struct SilcHashListStruct *new, *h;

  SILC_LOG_DEBUG(("Registering new hash function `%s'", hash->name));

  new = silc_calloc(1, sizeof(*new));
  new->hash = silc_calloc(1, sizeof(*new->hash));

  /* Set the pointers */
  new->hash->name = strdup(hash->name);
  new->hash->hash_len = hash->hash_len;
  new->hash->block_len = hash->block_len;
  new->hash->init = hash->init;
  new->hash->update = hash->update;
  new->hash->final = hash->final;
  new->hash->context_len = hash->context_len;
  new->next = NULL;

  /* Add the new hash function to the list */
  if (!silc_hash_list) {
    silc_hash_list = new;
    return TRUE;
  }

  h = silc_hash_list;
  while (h) {
    if (!h->next) {
      h->next = new;
      break;
    }
    h = h->next;
  }

  return TRUE;
}

/* Unregister a hash function from the SILC. */

int silc_hash_unregister(SilcHashObject *hash)
{
  struct SilcHashListStruct *h, *tmp;

  SILC_LOG_DEBUG(("Unregistering hash function"));

  h = silc_hash_list;

  /* Unregister all hash functions */
  if (hash == SILC_ALL_HASH_FUNCTIONS) {
    /* Unregister all ciphers */
    while (h) {
      tmp = h->next;
      silc_free(h->hash->name);
      silc_free(h);
      h = tmp;
    }

    return TRUE;
  }

  /* Unregister the hash function */
  if (h->hash == hash) {
    tmp = h->next;
    silc_free(h->hash->name);
    silc_free(h);
    silc_hash_list = tmp;

    return TRUE;
  }

  while (h) {
    if (h->next->hash == hash) {
      tmp = h->next->next;
      silc_free(h->hash->name);
      silc_free(h);
      h->next = tmp;
      return TRUE;
    }

    h = h->next;
  }

  return FALSE;
}

/* Allocates a new SilcHash object. New object is returned into new_hash
   argument. */

int silc_hash_alloc(const unsigned char *name, SilcHash *new_hash)
{
  struct SilcHashListStruct *h;
  int i;
  
  SILC_LOG_DEBUG(("Allocating new hash object"));

  /* Allocate the new object */
  *new_hash = silc_calloc(1, sizeof(**new_hash));

  if (silc_hash_list) {
    h = silc_hash_list;
    while (h) {
      if (!strcmp(h->hash->name, name))
	break;
      h = h->next;
    }

    if (!h || !h->hash->context_len)
      goto check_builtin;

    /* Set the pointers */
    (*new_hash)->hash = h->hash;
    (*new_hash)->context = silc_calloc(1, h->hash->context_len());
    (*new_hash)->make_hash = silc_hash_make;

    return TRUE;
  }

 check_builtin:
  for (i = 0; silc_hash_builtin_list[i].name; i++)
    if (!strcmp(silc_hash_builtin_list[i].name, name))
      break;

  if (silc_hash_builtin_list[i].name == NULL) {
    silc_free(*new_hash);
    *new_hash = NULL;
    return FALSE;
  }
  
  /* Set the pointers */
  (*new_hash)->hash = &silc_hash_builtin_list[i];
  (*new_hash)->context = silc_calloc(1, (*new_hash)->hash->context_len());
  (*new_hash)->make_hash = silc_hash_make;
  
  return TRUE;
}

/* Free's the SilcHash object */

void silc_hash_free(SilcHash hash)
{
  if (hash) {
    silc_free(hash->context);
    silc_free(hash);
  }
}

/* Returns the length of the hash digest. */

unsigned int silc_hash_len(SilcHash hash)
{
  return hash->hash->hash_len;
}

/* Returns TRUE if hash algorithm `name' is supported. */

int silc_hash_is_supported(const unsigned char *name)
{
  struct SilcHashListStruct *h;
  int i;

  if (!name)
    return FALSE;
  
  if (silc_hash_list) {
    h = silc_hash_list;

    while (h) {
      if (!strcmp(h->hash->name, name))
	return TRUE;
      h = h->next;
    }
  }

  for (i = 0; silc_hash_builtin_list[i].name; i++)
    if (!strcmp(silc_hash_builtin_list[i].name, name))
      return TRUE;

  return FALSE;
}

/* Returns comma separated list of supported hash functions. */

char *silc_hash_get_supported()
{
  char *list = NULL;
  int i, len;
  struct SilcHashListStruct *h;

  len = 0;
  if (silc_hash_list) {
    h = silc_hash_list;

    while (h) {
      len += strlen(h->hash->name);
      list = silc_realloc(list, len + 1);
      
      memcpy(list + (len - strlen(h->hash->name)), 
	     h->hash->name, strlen(h->hash->name));
      memcpy(list + len, ",", 1);
      len++;
      
      h = h->next;
    }
  }

  for (i = 0; silc_hash_builtin_list[i].name; i++) {
    len += strlen(silc_hash_builtin_list[i].name);
    list = silc_realloc(list, len + 1);
    
    memcpy(list + (len - strlen(silc_hash_builtin_list[i].name)), 
	   silc_hash_builtin_list[i].name, 
	   strlen(silc_hash_builtin_list[i].name));
    memcpy(list + len, ",", 1);
    len++;
  }

  list[len - 1] = 0;

  return list;
}

/* Creates the hash value and returns it to the return_hash argument. */

void silc_hash_make(SilcHash hash, const unsigned char *data, 
		    unsigned int len, unsigned char *return_hash)
{
  hash->hash->init(hash->context);
  hash->hash->update(hash->context, (unsigned char *)data, len);
  hash->hash->final(hash->context, return_hash);
}

/* Creates fingerprint of the data. If `hash' is NULL SHA1 is used as
   default hash function. The returned fingerprint must be free's by the
   caller. */

char *silc_hash_fingerprint(SilcHash hash, const unsigned char *data,
			    unsigned int data_len)
{
  char fingerprint[64], *cp;
  unsigned char h[32];
  int i;

  if (!hash)
    silc_hash_alloc("sha1", &hash);

  silc_hash_make(hash, data, data_len, h);
  
  memset(fingerprint, 0, sizeof(fingerprint));
  cp = fingerprint;
  for (i = 0; i < hash->hash->hash_len; i++) {
    snprintf(cp, sizeof(fingerprint), "%02X", h[i]);
    cp += 2;
    
    if ((i + 1) % 2 == 0)
      snprintf(cp++, sizeof(fingerprint), " ");

    if ((i + 1) % 10 == 0)
      snprintf(cp++, sizeof(fingerprint), " ");
  }
  
  return strdup(fingerprint);
}
