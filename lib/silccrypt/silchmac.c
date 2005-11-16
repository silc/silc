/*

  silchmac.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1999 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"

/* HMAC context */
struct SilcHmacStruct {
  SilcHmacObject *hmac;
  SilcHash hash;
  unsigned char inner_pad[64];
  unsigned char outer_pad[64];
  unsigned char *key;
  unsigned int key_len        : 31;
  unsigned int allocated_hash : 1;   /* TRUE if the hash was allocated */
};

#ifndef SILC_EPOC
/* List of dynamically registered HMACs. */
SilcDList silc_hmac_list = NULL;
#endif /* SILC_EPOC */

/* Default hmacs for silc_hmac_register_default(). */
const SilcHmacObject silc_default_hmacs[] =
{
  { "hmac-sha256-96", 12 },
  { "hmac-sha1-96", 12 },
  { "hmac-md5-96", 12 },
  { "hmac-sha256", 32 },
  { "hmac-sha1", 20 },
  { "hmac-md5", 16 },

  { NULL, 0 }
};

static void silc_hmac_init_internal(SilcHmac hmac, unsigned char *key,
				    SilcUInt32 key_len)
{
  SilcHash hash = hmac->hash;
  SilcUInt32 block_len;
  unsigned char hvalue[20];
  int i;

  memset(hmac->inner_pad, 0, sizeof(hmac->inner_pad));
  memset(hmac->outer_pad, 0, sizeof(hmac->outer_pad));

  block_len = silc_hash_block_len(hash);

  /* If the key length is more than block size of the hash function, the
     key is hashed. */
  if (key_len > block_len) {
    silc_hash_make(hash, key, key_len, hvalue);
    key = hvalue;
    key_len = silc_hash_len(hash);
  }

  /* Copy the key into the pads */
  memcpy(hmac->inner_pad, key, key_len);
  memcpy(hmac->outer_pad, key, key_len);

  /* XOR the key with pads */
  for (i = 0; i < block_len; i++) {
    hmac->inner_pad[i] ^= 0x36;
    hmac->outer_pad[i] ^= 0x5c;
  }
}

/* Registers a new HMAC into the SILC. This function is used at the
   initialization of the SILC. */

bool silc_hmac_register(const SilcHmacObject *hmac)
{
#ifndef SILC_EPOC
  SilcHmacObject *new;

  SILC_LOG_DEBUG(("Registering new HMAC `%s'", hmac->name));

  /* Check for existing */
  if (silc_hmac_list) {
    SilcHmacObject *entry;
    silc_dlist_start(silc_hmac_list);
    while ((entry = silc_dlist_get(silc_hmac_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, hmac->name))
	return FALSE;
    }
  }

  new = silc_calloc(1, sizeof(*new));
  new->name = strdup(hmac->name);
  new->len = hmac->len;

  /* Add to list */
  if (silc_hmac_list == NULL)
    silc_hmac_list = silc_dlist_init();
  silc_dlist_add(silc_hmac_list, new);

#endif /* SILC_EPOC */
  return TRUE;
}

/* Unregister a HMAC from the SILC. */

bool silc_hmac_unregister(SilcHmacObject *hmac)
{
#ifndef SILC_EPOC
  SilcHmacObject *entry;

  SILC_LOG_DEBUG(("Unregistering HMAC"));

  if (!silc_hmac_list)
    return FALSE;

  silc_dlist_start(silc_hmac_list);
  while ((entry = silc_dlist_get(silc_hmac_list)) != SILC_LIST_END) {
    if (hmac == SILC_ALL_HMACS || entry == hmac) {
      silc_dlist_del(silc_hmac_list, entry);
      silc_free(entry->name);
      silc_free(entry);

      if (silc_dlist_count(silc_hmac_list) == 0) {
	silc_dlist_uninit(silc_hmac_list);
	silc_hmac_list = NULL;
      }

      return TRUE;
    }
  }

#endif /* SILC_EPOC */
  return FALSE;
}

/* Function that registers all the default hmacs (all builtin ones).
   The application may use this to register the default hmacs if
   specific hmacs in any specific order is not wanted. */

bool silc_hmac_register_default(void)
{
#ifndef SILC_EPOC
  int i;

  for (i = 0; silc_default_hmacs[i].name; i++)
    silc_hmac_register(&(silc_default_hmacs[i]));

#endif /* SILC_EPOC */
  return TRUE;
}

bool silc_hmac_unregister_all(void)
{
#ifndef SILC_EPOC
  SilcHmacObject *entry;

  if (!silc_hmac_list)
    return FALSE;

  silc_dlist_start(silc_hmac_list);
  while ((entry = silc_dlist_get(silc_hmac_list)) != SILC_LIST_END) {
    silc_hmac_unregister(entry);
    if (!silc_hmac_list)
      break;
  }
#endif /* SILC_EPOC */
  return TRUE;
}

/* Allocates a new SilcHmac object of name of `name'.  The `hash' may
   be provided as argument.  If provided it is used as the hash function
   of the HMAC.  If it is NULL then the hash function is allocated and
   the name of the hash algorithm is derived from the `name'. */

bool silc_hmac_alloc(const char *name, SilcHash hash, SilcHmac *new_hmac)
{
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
      silc_free(*new_hmac);
      *new_hmac = NULL;
      return FALSE;
    }

    (*new_hmac)->allocated_hash = TRUE;
    silc_free(tmp);
  }

  (*new_hmac)->hash = hash;

#ifndef SILC_EPOC
  if (silc_hmac_list) {
    SilcHmacObject *entry;
    silc_dlist_start(silc_hmac_list);
    while ((entry = silc_dlist_get(silc_hmac_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, name)) {
	(*new_hmac)->hmac = entry;
	return TRUE;
      }
    }
  }
#else
  {
    /* On EPOC which don't have globals we check our constant hash list. */
    int i;
    for (i = 0; silc_default_hmacs[i].name; i++) {
      if (!strcmp(silc_default_hmacs[i].name, name)) {
	(*new_hmac)->hmac = (SilcHmacObject *)&(silc_default_hmacs[i]);
	return TRUE;
      }
    }
  }
#endif /* SILC_EPOC */

  silc_free(*new_hmac);
  *new_hmac = NULL;
  return FALSE;
}

/* Free's the SilcHmac object. */

void silc_hmac_free(SilcHmac hmac)
{
  if (hmac) {
    if (hmac->allocated_hash)
      silc_hash_free(hmac->hash);

    if (hmac->key) {
      memset(hmac->key, 0, hmac->key_len);
      silc_free(hmac->key);
    }

    silc_free(hmac);
  }
}

/* Returns the length of the MAC that the HMAC will produce. */

SilcUInt32 silc_hmac_len(SilcHmac hmac)
{
  return hmac->hmac->len;
}

/* Get hash context */

SilcHash silc_hmac_get_hash(SilcHmac hmac)
{
  return hmac->hash;
}

/* Return name of hmac */

const char *silc_hmac_get_name(SilcHmac hmac)
{
  return hmac->hmac->name;
}

/* Returns TRUE if HMAC `name' is supported. */

bool silc_hmac_is_supported(const char *name)
{
#ifndef SILC_EPOC
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
#else
  {
    int i;
    for (i = 0; silc_default_hmacs[i].name; i++)
      if (!strcmp(silc_default_hmacs[i].name, name))
	return TRUE;
  }
#endif /* SILC_EPOC */
  return FALSE;
}

/* Returns comma separated list of supported HMACs. */

char *silc_hmac_get_supported()
{
  SilcHmacObject *entry;
  char *list = NULL;
  int len = 0;

#ifndef SILC_EPOC
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
#else
  {
    int i;
    for (i = 0; silc_default_hmacs[i].name; i++) {
      entry = (SilcHmacObject *)&(silc_default_hmacs[i]);
      len += strlen(entry->name);
      list = silc_realloc(list, len + 1);

      memcpy(list + (len - strlen(entry->name)),
	     entry->name, strlen(entry->name));
      memcpy(list + len, ",", 1);
      len++;
    }
  }
#endif /* SILC_EPOC */

  list[len - 1] = 0;

  return list;
}

/* Sets the HMAC key used in the HMAC creation */

void silc_hmac_set_key(SilcHmac hmac, const unsigned char *key,
		       SilcUInt32 key_len)
{
  if (hmac->key) {
    memset(hmac->key, 0, hmac->key_len);
    silc_free(hmac->key);
  }
  hmac->key = silc_calloc(key_len, sizeof(unsigned char));
  hmac->key_len = key_len;
  memcpy(hmac->key, key, key_len);
}

/* Create the HMAC. This is thee make_hmac function pointer.  This
   uses the internal key set with silc_hmac_set_key. */

void silc_hmac_make(SilcHmac hmac, unsigned char *data,
		    SilcUInt32 data_len, unsigned char *return_hash,
		    SilcUInt32 *return_len)
{
  SILC_LOG_DEBUG(("Making HMAC for message"));

  silc_hmac_init(hmac);
  silc_hmac_update(hmac, data, data_len);
  silc_hmac_final(hmac, return_hash, return_len);
}

/* Creates HMAC just as above except that this doesn't use the internal
   key. The key is sent as argument to the function. */

void silc_hmac_make_with_key(SilcHmac hmac, unsigned char *data,
			     SilcUInt32 data_len,
			     unsigned char *key, SilcUInt32 key_len,
			     unsigned char *return_hash,
			     SilcUInt32 *return_len)
{
  SILC_LOG_DEBUG(("Making HMAC for message"));

  silc_hmac_init_with_key(hmac, key, key_len);
  silc_hmac_update(hmac, data, data_len);
  silc_hmac_final(hmac, return_hash, return_len);
}

/* Creates the HMAC just as above except that the hash value is truncated
   to the truncated_len sent as argument. NOTE: One should not truncate to
   less than half of the length of original hash value. However, this
   routine allows these dangerous truncations. */

void silc_hmac_make_truncated(SilcHmac hmac, unsigned char *data,
			      SilcUInt32 data_len,
			      SilcUInt32 truncated_len,
			      unsigned char *return_hash)
{
  unsigned char hvalue[20];

  SILC_LOG_DEBUG(("Making HMAC for message"));

  silc_hmac_init(hmac);
  silc_hmac_update(hmac, data, data_len);
  silc_hmac_final(hmac, return_hash, NULL);
  memcpy(return_hash, hvalue, truncated_len);
  memset(hvalue, 0, sizeof(hvalue));
}

/* Init HMAC for silc_hmac_update and silc_hmac_final. */

void silc_hmac_init(SilcHmac hmac)
{
  silc_hmac_init_with_key(hmac, hmac->key, hmac->key_len);
}

/* Same as above but with specific key */

void silc_hmac_init_with_key(SilcHmac hmac, const unsigned char *key,
			     SilcUInt32 key_len)
{
  SilcHash hash = hmac->hash;
  silc_hmac_init_internal(hmac, (unsigned char *)key, key_len);
  silc_hash_init(hash);
  silc_hash_update(hash, hmac->inner_pad, silc_hash_block_len(hash));
}

/* Add data to be used in the MAC computation. */

void silc_hmac_update(SilcHmac hmac, const unsigned char *data,
		      SilcUInt32 data_len)
{
  SilcHash hash = hmac->hash;
  silc_hash_update(hash, data, data_len);
}

/* Compute the final MAC. */

void silc_hmac_final(SilcHmac hmac, unsigned char *return_hash,
		     SilcUInt32 *return_len)
{
  SilcHash hash = hmac->hash;
  unsigned char mac[20];

  silc_hash_final(hash, mac);
  silc_hash_init(hash);
  silc_hash_update(hash, hmac->outer_pad, silc_hash_block_len(hash));
  silc_hash_update(hash, mac, silc_hash_len(hash));
  silc_hash_final(hash, mac);
  memcpy(return_hash, mac, hmac->hmac->len);
  memset(mac, 0, sizeof(mac));

  if (return_len)
    *return_len = hmac->hmac->len;
}
