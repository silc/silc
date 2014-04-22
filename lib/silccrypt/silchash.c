/*

  silchash.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silc.h"

#include "md5.h"
#include "sha1.h"
#include "sha256.h"

/* The main SILC hash structure. */
struct SilcHashStruct {
  SilcHashObject *hash;
  void *context;
};

#ifndef SILC_SYMBIAN
/* List of dynamically registered hash functions. */
SilcDList silc_hash_list = NULL;
#endif /* SILC_SYMBIAN */

/* Default hash functions for silc_hash_register_default(). */
const SilcHashObject silc_default_hash[] =
{
  { "sha256", "2.16.840.1.101.3.4.2.1",
    32, 64, silc_sha256_init, silc_sha256_update, silc_sha256_final,
    silc_sha256_transform, silc_sha256_context_len },
  { "sha1", "1.3.14.3.2.26",
    20, 64, silc_sha1_init, silc_sha1_update, silc_sha1_final,
    silc_sha1_transform, silc_sha1_context_len },
  { "md5", "1.2.840.113549.2.5",
    16, 64, silc_md5_init, silc_md5_update, silc_md5_final,
    silc_md5_transform, silc_md5_context_len },

  { NULL, NULL, 0, 0, NULL, NULL, NULL, NULL, NULL }
};

/* Registers a new hash function into the SILC. This function is used at
   the initialization of the SILC. */

SilcBool silc_hash_register(const SilcHashObject *hash)
{
#ifndef SILC_SYMBIAN
  SilcHashObject *new;

  SILC_LOG_DEBUG(("Registering new hash function `%s'", hash->name));

  /* Check for existing */
  if (silc_hash_list) {
    SilcHashObject *entry;
    silc_dlist_start(silc_hash_list);
    while ((entry = silc_dlist_get(silc_hash_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, hash->name))
	return FALSE;
    }
  }

  new = silc_calloc(1, sizeof(*new));
  if (!new)
    return FALSE;
  new->name = strdup(hash->name);
  if (!new->name) {
    silc_free(new);
    return FALSE;
  }
  new->oid = strdup(hash->oid);
  if (!new->oid) {
    silc_free(new);
    return FALSE;
  }
  new->hash_len = hash->hash_len;
  new->block_len = hash->block_len;
  new->init = hash->init;
  new->update = hash->update;
  new->final = hash->final;
  new->transform = hash->transform;
  new->context_len = hash->context_len;

  /* Add to list */
  if (silc_hash_list == NULL)
    silc_hash_list = silc_dlist_init();
  silc_dlist_add(silc_hash_list, new);

#endif /* SILC_SYMBIAN */
  return TRUE;
}

/* Unregister a hash function from the SILC. */

SilcBool silc_hash_unregister(SilcHashObject *hash)
{
#ifndef SILC_SYMBIAN
  SilcHashObject *entry;

  SILC_LOG_DEBUG(("Unregistering hash function"));

  if (!silc_hash_list)
    return FALSE;

  silc_dlist_start(silc_hash_list);
  while ((entry = silc_dlist_get(silc_hash_list)) != SILC_LIST_END) {
    if (hash == SILC_ALL_HASH_FUNCTIONS || entry == hash) {
      silc_dlist_del(silc_hash_list, entry);
      silc_free(entry->name);
      silc_free(entry->oid);
      silc_free(entry);

      if (silc_dlist_count(silc_hash_list) == 0) {
	silc_dlist_uninit(silc_hash_list);
	silc_hash_list = NULL;
      }

      return TRUE;
    }
  }

#endif /* SILC_SYMBIAN */
  return FALSE;
}

/* Function that registers all the default hash funcs (all builtin ones).
   The application may use this to register the default hash funcs if
   specific hash funcs in any specific order is not wanted. */

SilcBool silc_hash_register_default(void)
{
#ifndef SILC_SYMBIAN
  int i;

  for (i = 0; silc_default_hash[i].name; i++)
    silc_hash_register(&(silc_default_hash[i]));

#endif /* SILC_SYMBIAN */
  return TRUE;
}

SilcBool silc_hash_unregister_all(void)
{
#ifndef SILC_SYMBIAN
  SilcHashObject *entry;

  if (!silc_hash_list)
    return FALSE;

  silc_dlist_start(silc_hash_list);
  while ((entry = silc_dlist_get(silc_hash_list)) != SILC_LIST_END) {
    silc_hash_unregister(entry);
    if (!silc_hash_list)
      break;
  }
#endif /* SILC_SYMBIAN */
  return TRUE;
}

/* Allocates a new SilcHash object. New object is returned into new_hash
   argument. */

SilcBool silc_hash_alloc(const unsigned char *name, SilcHash *new_hash)
{
  SilcHashObject *entry = NULL;

  SILC_LOG_DEBUG(("Allocating new hash %s", name));

#ifndef SILC_SYMBIAN
  if (silc_hash_list) {
    silc_dlist_start(silc_hash_list);
    while ((entry = silc_dlist_get(silc_hash_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, name))
	break;
    }
  }
#else
  {
    /* On EPOC which don't have globals we check our constant hash list. */
    int i;
    for (i = 0; silc_default_hash[i].name; i++) {
      if (!strcmp(silc_default_hash[i].name, name)) {
	entry = (SilcHashObject *)&(silc_default_hash[i]);
	break;
      }
    }
  }
#endif /* SILC_SYMBIAN */

  if (entry) {
    *new_hash = silc_calloc(1, sizeof(**new_hash));
    if (!(*new_hash))
      return FALSE;
    (*new_hash)->hash = entry;
    (*new_hash)->context = silc_calloc(1, entry->context_len());
    if (!(*new_hash)->context) {
      silc_free(*new_hash);
      return FALSE;
    }
    return TRUE;
  }

  return FALSE;
}

/* Allocate hash by OID string */

SilcBool silc_hash_alloc_by_oid(const char *oid, SilcHash *new_hash)
{
  SilcHashObject *entry = NULL;

  SILC_LOG_DEBUG(("Allocating new hash %s", oid));

#ifndef SILC_SYMBIAN
  if (silc_hash_list) {
    silc_dlist_start(silc_hash_list);
    while ((entry = silc_dlist_get(silc_hash_list)) != SILC_LIST_END) {
      if (!strcmp(entry->oid, oid))
	break;
    }
  }
#else
  {
    /* On EPOC which don't have globals we check our constant hash list. */
    int i;
    for (i = 0; silc_default_hash[i].oid; i++) {
      if (!strcmp(silc_default_hash[i].oid, oid)) {
	entry = (SilcHashObject *)&(silc_default_hash[i]);
	break;
      }
    }
  }
#endif /* SILC_SYMBIAN */

  if (entry) {
    *new_hash = silc_calloc(1, sizeof(**new_hash));
    if (!(*new_hash))
      return FALSE;
    (*new_hash)->hash = entry;
    (*new_hash)->context = silc_calloc(1, entry->context_len());
    if (!(*new_hash)->context) {
      silc_free(*new_hash);
      return FALSE;
    }
    return TRUE;
  }

  return FALSE;
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

SilcUInt32 silc_hash_len(SilcHash hash)
{
  return hash->hash->hash_len;
}

/* Returns the block lenght of the hash. */

SilcUInt32 silc_hash_block_len(SilcHash hash)
{
  return hash->hash->block_len;
}

/* Returns the name of the hash function */

const char *silc_hash_get_name(SilcHash hash)
{
  return hash->hash->name;
}

/* Returns hash OID string */

const char *silc_hash_get_oid(SilcHash hash)
{
  return hash->hash->oid;
}

/* Returns TRUE if hash algorithm `name' is supported. */

SilcBool silc_hash_is_supported(const unsigned char *name)
{
#ifndef SILC_SYMBIAN
  SilcHashObject *entry;

  if (silc_hash_list) {
    silc_dlist_start(silc_hash_list);
    while ((entry = silc_dlist_get(silc_hash_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, name))
	return TRUE;
    }
  }
#else
  {
    int i;
    for (i = 0; silc_default_hash[i].name; i++)
      if (!strcmp(silc_default_hash[i].name, name))
	return TRUE;
  }
#endif /* SILC_SYMBIAN */
  return FALSE;
}

/* Returns comma separated list of supported hash functions. */

char *silc_hash_get_supported(void)
{
  SilcHashObject *entry;
  char *list = NULL;
  int len = 0;

#ifndef SILC_SYMBIAN
  if (silc_hash_list) {
    silc_dlist_start(silc_hash_list);
    while ((entry = silc_dlist_get(silc_hash_list)) != SILC_LIST_END) {
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
    for (i = 0; silc_default_hash[i].name; i++) {
      entry = (SilcHashObject *)&(silc_default_hash[i]);
      len += strlen(entry->name);
      list = silc_realloc(list, len + 1);

      memcpy(list + (len - strlen(entry->name)),
	     entry->name, strlen(entry->name));
      memcpy(list + len, ",", 1);
      len++;
    }
  }
#endif /* SILC_SYMBIAN */

  if (list)
    list[len - 1] = 0;

  return list;
}

/* Creates the hash value and returns it to the return_hash argument. */

void silc_hash_make(SilcHash hash, const unsigned char *data,
		    SilcUInt32 len, unsigned char *return_hash)
{
  silc_hash_init(hash);
  silc_hash_update(hash, data, len);
  silc_hash_final(hash, return_hash);
}

void silc_hash_init(SilcHash hash)
{
  hash->hash->init(hash->context);
}

void silc_hash_update(SilcHash hash, const unsigned char *data,
		      SilcUInt32 data_len)
{
  hash->hash->update(hash->context, (unsigned char *)data, data_len);
}

void silc_hash_final(SilcHash hash, unsigned char *return_hash)
{
  hash->hash->final(hash->context, return_hash);
}

void silc_hash_transform(SilcHash hash, SilcUInt32 *state,
			 const unsigned char *data)
{
  hash->hash->transform(state, data);
}

/* Creates fingerprint of the data. If `hash' is NULL SHA1 is used as
   default hash function. The returned fingerprint must be freed by the
   caller. */

char *silc_hash_fingerprint(SilcHash hash, const unsigned char *data,
			    SilcUInt32 data_len)
{
  SilcHash new_hash = NULL;
  unsigned char h[32];
  char *ret;

  if (!hash) {
    if (!silc_hash_alloc("sha1", &new_hash))
      return NULL;
    hash = new_hash;
  }

  silc_hash_make(hash, data, data_len, h);
  ret = silc_fingerprint(h, hash->hash->hash_len);

  if (new_hash != NULL)
    silc_hash_free(new_hash);
  return ret;
}

static const char vo[]= "aeiouy";
static const char co[]= "bcdfghklmnprstvzx";

/* Creates a babbleprint (Bubble Babble Encoding, developed by Antti
   Huima (draft-huima-babble-01.txt)), by first computing real fingerprint
   using `hash' or if NULL, then using SHA1, and then encoding the
   fingerprint to the babbleprint. */

char *silc_hash_babbleprint(SilcHash hash, const unsigned char *data,
			    SilcUInt32 data_len)
{
  SilcHash new_hash = NULL;
  char *babbleprint;
  unsigned char hval[32];
  unsigned int a, b, c, d, e, check;
  int i, k, out_len;

  if (!hash) {
    if (!silc_hash_alloc("sha1", &new_hash))
      return NULL;
    hash = new_hash;
  }

  /* Take fingerprint */
  silc_hash_make(hash, data, data_len, hval);

  /* Encode babbleprint */
  out_len = (((hash->hash->hash_len + 1) / 2) + 1) * 6;
  babbleprint = silc_calloc(out_len, sizeof(*babbleprint));
  if (!babbleprint) {
    silc_hash_free(new_hash);
    return NULL;
  }
  babbleprint[0] = co[16];

  check = 1;
  for (i = 0, k = 1; i < hash->hash->hash_len - 1; i += 2, k += 6) {
    a = (((hval[i] >> 6) & 3) + check) % 6;
    b = (hval[i] >> 2) & 15;
    c = ((hval[i] & 3) + (check / 6)) % 6;
    d = (hval[i + 1] >> 4) & 15;
    e = hval[i + 1] & 15;

    check = ((check * 5) + (hval[i] * 7) + hval[i + 1]) % 36;

    babbleprint[k + 0] = vo[a];
    babbleprint[k + 1] = co[b];
    babbleprint[k + 2] = vo[c];
    babbleprint[k + 3] = co[d];
    babbleprint[k + 4] = '-';
    babbleprint[k + 5] = co[e];
  }

  if ((hash->hash->hash_len % 2) != 0) {
    a = (((hval[i] >> 6) & 3) + check) % 6;
    b = (hval[i] >> 2) & 15;
    c = ((hval[i] & 3) + (check / 6)) % 6;
    babbleprint[k + 0] = vo[a];
    babbleprint[k + 1] = co[b];
    babbleprint[k + 2] = vo[c];
  } else {
    a = check % 6;
    b = 16;
    c = check / 6;
    babbleprint[k + 0] = vo[a];
    babbleprint[k + 1] = co[b];
    babbleprint[k + 2] = vo[c];
  }
  babbleprint[k + 3] = co[16];

  if (new_hash != NULL)
    silc_hash_free(new_hash);
  return babbleprint;
}
