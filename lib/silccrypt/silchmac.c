/*

  silchmac.c

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

/* List of dynamically registered HMACs. */
SilcDList silc_hmac_list = NULL;

/* Registers a new HMAC into the SILC. This function is used at the
   initialization of the SILC. */

int silc_hmac_register(SilcHmacObject *hmac)
{
  SilcHmacObject *new;

  SILC_LOG_DEBUG(("Registering new HMAC `%s'", hmac->name));

  new = silc_calloc(1, sizeof(*new));
  new->name = strdup(hmac->name);
  new->len = hmac->len;

  /* Add to list */
  if (silc_hmac_list == NULL)
    silc_hmac_list = silc_dlist_init();
  silc_dlist_add(silc_hmac_list, new);

  return TRUE;
}

/* Unregister a HMAC from the SILC. */

int silc_hmac_unregister(SilcHmacObject *hmac)
{
  SilcHmacObject *entry;

  SILC_LOG_DEBUG(("Unregistering HMAC"));

  if (!silc_hmac_list)
    return FALSE;

  silc_dlist_start(silc_hmac_list);
  while ((entry = silc_dlist_get(silc_hmac_list)) != SILC_LIST_END) {
    if (entry == hmac) {
      silc_dlist_del(silc_hmac_list, entry);

      if (silc_dlist_count(silc_hmac_list) == 0) {
	silc_dlist_uninit(silc_hmac_list);
	silc_hmac_list = NULL;
      }

      return TRUE;
    }
  }

  return FALSE;
}

/* Allocates a new SilcHmac object of name of `name'.  The `hash' may
   be provided as argument.  If provided it is used as the hash function
   of the HMAC.  If it is NULL then the hash function is allocated and
   the name of the hash algorithm is derived from the `name'. */

int silc_hmac_alloc(char *name, SilcHash hash, SilcHmac *new_hmac)
{
  SilcHmacObject *entry;

  SILC_LOG_DEBUG(("Allocating new HMAC"));

  /* Allocate the new object */
  *new_hmac = silc_calloc(1, sizeof(**new_hmac));

  if (!hash) {
    char *tmp = strdup(name), *hname;

    hname = tmp;
    if (strchr(hname, '-'))
      hname = strchr(hname, '-') + 1;
    if (strchr(hname, '-'))
      *strchr(hname, '-') = '\0';

    if (!silc_hash_alloc(hname, &hash)) {
      silc_free(tmp);
      return FALSE;
    }

    (*new_hmac)->allocated_hash = TRUE;
    silc_free(tmp);
  }

  (*new_hmac)->hash = hash;

  if (silc_hmac_list) {
    silc_dlist_start(silc_hmac_list);
    while ((entry = silc_dlist_get(silc_hmac_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, name)) {
	(*new_hmac)->hmac = entry; 
	return TRUE;
      }
    }
  }

  return FALSE;
}

/* Free's the SilcHmac object. */

void silc_hmac_free(SilcHmac hmac)
{
  if (hmac) {
    if (hmac->allocated_hash)
      silc_hash_free(hmac->hash);
    silc_free(hmac);
  }
}

/* Returns the length of the MAC that the HMAC will produce. */

uint32 silc_hmac_len(SilcHmac hmac)
{
  return hmac->hmac->len;
}

/* Returns TRUE if HMAC `name' is supported. */

int silc_hmac_is_supported(const char *name)
{
  SilcHmacObject *entry;

  if (!name)
    return FALSE;
  
  if (silc_hmac_list) {
    silc_dlist_start(silc_hmac_list);
    while ((entry = silc_dlist_get(silc_hmac_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, name))
	return TRUE;
    }
  }

  return FALSE;
}

/* Returns comma separated list of supported HMACs. */

char *silc_hmac_get_supported()
{
  SilcHmacObject *entry;
  char *list = NULL;
  int len;

  len = 0;
  if (silc_hmac_list) {
    silc_dlist_start(silc_hmac_list);
    while ((entry = silc_dlist_get(silc_hmac_list)) != SILC_LIST_END) {
      len += strlen(entry->name);
      list = silc_realloc(list, len + 1);
      
      memcpy(list + (len - strlen(entry->name)), 
	     entry->name, strlen(entry->name));
      memcpy(list + len, ",", 1);
      len++;
    }
  }

  list[len - 1] = 0;

  return list;
}

/* Sets the HMAC key used in the HMAC creation */

void silc_hmac_set_key(SilcHmac hmac, const unsigned char *key,
		       uint32 key_len)
{
  if (hmac->key) {
    memset(hmac->key, 0, hmac->key_len);
    silc_free(hmac->key);
  }
  hmac->key = silc_calloc(key_len, sizeof(unsigned char));
  hmac->key_len = key_len;
  memcpy(hmac->key, key, key_len);
}

/* Creates the HMAC. The created keyed hash value is returned to 
   return_hash argument. */

void silc_hmac_make_internal(SilcHmac hmac, unsigned char *data,
			     uint32 data_len, unsigned char *key,
			     uint32 key_len, unsigned char *return_hash)
{
  SilcHash hash = hmac->hash;
  unsigned char inner_pad[hash->hash->block_len + 1];
  unsigned char outer_pad[hash->hash->block_len + 1];
  unsigned char hvalue[hash->hash->hash_len];
  unsigned char mac[128];
  void *hash_context;
  int i;

  SILC_LOG_DEBUG(("Making HMAC for message"));

  hash_context = silc_calloc(1, hash->hash->context_len());

  memset(inner_pad, 0, sizeof(inner_pad));
  memset(outer_pad, 0, sizeof(outer_pad));

  /* If the key length is more than block size of the hash function, the
     key is hashed. */
  if (key_len > hash->hash->block_len) {
    silc_hash_make(hash, key, key_len, hvalue);
    key = hvalue;
    key_len = hash->hash->hash_len;
  }

  /* Copy the key into the pads */
  memcpy(inner_pad, key, key_len);
  memcpy(outer_pad, key, key_len);

  /* XOR the key with pads */
  for (i = 0; i < hash->hash->block_len; i++) {
    inner_pad[i] ^= 0x36;
    outer_pad[i] ^= 0x5c;
  }

  /* Do the HMAC transform (too bad I can't do make_hash directly, sigh) */
  hash->hash->init(hash_context);
  hash->hash->update(hash_context, inner_pad, hash->hash->block_len);
  hash->hash->update(hash_context, data, data_len);
  hash->hash->final(hash_context, mac);
  hash->hash->init(hash_context);
  hash->hash->update(hash_context, outer_pad, hash->hash->block_len);
  hash->hash->update(hash_context, mac, hash->hash->hash_len);
  hash->hash->final(hash_context, mac);
  memcpy(return_hash, mac, hmac->hmac->len);
  memset(mac, 0, sizeof(mac));
  silc_free(hash_context);
}

/* Create the HMAC. This is thee make_hmac function pointer.  This
   uses the internal key set with silc_hmac_set_key. */

void silc_hmac_make(SilcHmac hmac, unsigned char *data,
		    uint32 data_len, unsigned char *return_hash,
		    uint32 *return_len)
{
  silc_hmac_make_internal(hmac, data, data_len, hmac->key, 
			  hmac->key_len, return_hash);
  if (return_len)
    *return_len = hmac->hmac->len;
}

/* Creates HMAC just as above except that this doesn't use the internal
   key. The key is sent as argument to the function. */

void silc_hmac_make_with_key(SilcHmac hmac, unsigned char *data,
			     uint32 data_len, 
			     unsigned char *key, uint32 key_len,
			     unsigned char *return_hash,
			     uint32 *return_len)
{
  silc_hmac_make_internal(hmac, data, data_len, key, key_len, return_hash);
  if (return_len)
    *return_len = hmac->hmac->len;
}

/* Creates the HMAC just as above except that the hash value is truncated
   to the truncated_len sent as argument. NOTE: One should not truncate to
   less than half of the length of original hash value. However, this 
   routine allows these dangerous truncations. */

void silc_hmac_make_truncated(SilcHmac hmac, unsigned char *data,
			      uint32 data_len,
			      uint32 truncated_len,
			      unsigned char *return_hash)
{
  unsigned char hvalue[hmac->hash->hash->hash_len];

  silc_hmac_make_internal(hmac, data, data_len, 
			  hmac->key, hmac->key_len, hvalue);
  memcpy(return_hash, hvalue, truncated_len);
  memset(hvalue, 0, sizeof(hvalue));
}
