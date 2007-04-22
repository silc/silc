/*

  silcskr.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"
#include "silcskr.h"

/* XXX Locking, when removing keys */

/************************** Types and definitions ***************************/

/* Search constraints */
typedef enum {
  SILC_SKR_FIND_PKCS_TYPE,
  SILC_SKR_FIND_USERNAME,
  SILC_SKR_FIND_HOST,
  SILC_SKR_FIND_REALNAME,
  SILC_SKR_FIND_EMAIL,
  SILC_SKR_FIND_ORG,
  SILC_SKR_FIND_COUNTRY,
  SILC_SKR_FIND_PUBLIC_KEY,
  SILC_SKR_FIND_CONTEXT,
  SILC_SKR_FIND_USAGE,		/* Never added as key specific */
} SilcSKRFindType;

/* Hash table key context */
typedef struct {
  SilcSKRFindType type;		/* Type of key */
  void *data;			/* Hash table key */
} *SilcSKREntry, SilcSKREntryStruct;

/* Foreach user context when finding entries from hash table */
typedef struct {
  SilcDList list;
  void *key_context;
  SilcSKRKeyUsage usage;
} SilcSKRFindForeach;

#if defined(SILC_DEBUG)
static const char *find_name[] = {
  "PKCS TYPE",
  "USERNAME",
  "HOST",
  "REALNAME",
  "EMAIL",
  "ORG",
  "COUNTRY",
  "PUBLIC KEY",
  "CONTEXT",
  "USAGE",
  NULL
};
#endif /* SILC_DEBUG */

/************************ Static utility functions **************************/

#if defined(SILC_DEBUG)

/* Returns search constraint string */

static void silc_skr_type_string(SilcSKRFindType type, void *data,
				 char *retbuf, SilcUInt32 retbuf_size)
{
  switch (type) {
  case SILC_SKR_FIND_PKCS_TYPE:
  case SILC_SKR_FIND_USAGE:
    silc_snprintf(retbuf, retbuf_size, "[%s] [%d]", find_name[type],
	     (int)SILC_PTR_TO_32(data));
    break;

  case SILC_SKR_FIND_PUBLIC_KEY:
    silc_snprintf(retbuf, retbuf_size, "[%s] [%p]", find_name[type], data);
    break;

  default:
    silc_snprintf(retbuf, retbuf_size, "[%s] [%s]", find_name[type],
	     (char *)data);
  }
}

#endif /* SILC_DEBUG */

/* Hash table destructor for search constraints */

static void silc_skr_find_destructor(void *key, void *context,
				     void *user_context)
{
  SilcSKRFindType type = SILC_PTR_TO_32(key);

  switch (type) {
  case SILC_SKR_FIND_PKCS_TYPE:
  case SILC_SKR_FIND_USAGE:
  case SILC_SKR_FIND_CONTEXT:
    break;

  case SILC_SKR_FIND_PUBLIC_KEY:
    silc_pkcs_public_key_free(context);
    break;

  default:
    silc_free(context);
  }
}

/* Hash table destructor for key entries */

static void silc_skr_destructor(void *key, void *context, void *user_context)
{
  SilcSKREntry type = key;
  SilcSKRKeyInternal entry = context;

  /* Destroy search data, except for SILC_SKR_FIND_PUBLIC_KEY because it
     shares same context with the key entry. */
  if (SILC_PTR_TO_32(type->type) != SILC_SKR_FIND_PUBLIC_KEY)
    silc_skr_find_destructor(SILC_32_TO_PTR(type->type), type->data, NULL);
  silc_free(type);

  /* Destroy key */
  entry->refcnt--;
  if (entry->refcnt > 0)
    return;

  silc_pkcs_public_key_free(entry->key.key);
  silc_free(entry);
}

/* Hash table hash function for key entries */

static SilcUInt32 silc_skr_hash(void *key, void *user_context)
{
  SilcSKREntry type = key;

  switch (type->type) {
  case SILC_SKR_FIND_PKCS_TYPE:
  case SILC_SKR_FIND_CONTEXT:
    return type->type + (type->type ^ SILC_PTR_TO_32(type->data));
    break;

  case SILC_SKR_FIND_PUBLIC_KEY:
    return type->type + silc_hash_public_key(type->data, user_context);
    break;

  default:
    break;
  }

  return type->type + silc_hash_string(type->data, user_context);
}

/* Hash table comparison function for key entries */

static SilcBool silc_skr_compare(void *key1, void *key2, void *user_context)
{
  SilcSKREntry type1 = key1;
  SilcSKREntry type2 = key2;

  if (type1->type != type2->type)
    return FALSE;

  switch (type1->type) {
  case SILC_SKR_FIND_PKCS_TYPE:
  case SILC_SKR_FIND_CONTEXT:
    return type1->data == type2->data;
    break;

  case SILC_SKR_FIND_PUBLIC_KEY:
    return silc_hash_public_key_compare(type1->data, type2->data,
					user_context);
    break;

  default:
    break;
  }

  return silc_utf8_strcasecmp((const char *)type1->data,
			      (const char *)type2->data);
}

/* Foreach function for finding entries in the repository */

static void silc_skr_find_foreach(void *key, void *context,
				  void *user_context)
{
  SilcSKRFindForeach *f = user_context;
  SilcSKRKeyInternal k = context;

  if (k) {
    /* If key context is present, it must match the context in the key.
       This is used only internally when adding keys, to check if the key
       is added with same context. */
    if (f->key_context && f->key_context != k->key.key_context)
      return;

    /* Check for usage bits.  At least one usage bit must be set. */
    if (f->usage && k->key.usage && (f->usage & k->key.usage) == 0)
      return;

    silc_dlist_add(f->list, k);
  }
}

/* Finds entry from repository by search constraint type and data */

static SilcBool silc_skr_find_entry(SilcSKR skr,
				    SilcSKRStatus *status,
				    SilcSKRFindType type,
				    void *type_data,
				    SilcDList *results,
				    void *key_context,
				    SilcSKRKeyUsage usage)
{
  SilcSKREntryStruct find;
  SilcSKRFindForeach f;

  f.list = silc_dlist_init();
  if (!f.list) {
    *status |= SILC_SKR_NO_MEMORY;
    return FALSE;
  }
  f.key_context = key_context;
  f.usage = usage;

  find.type = type;
  find.data = type_data;

  silc_hash_table_find_foreach(skr->keys, (void *)&find,
			       silc_skr_find_foreach, &f);

  if (!silc_dlist_count(f.list)) {
    *status |= SILC_SKR_NOT_FOUND;
    silc_dlist_uninit(f.list);
    return FALSE;
  }

  if (results)
    *results = f.list;
  else
    silc_dlist_uninit(f.list);

  return TRUE;
}

/* Add a key by search constraint type to repository */

static SilcBool silc_skr_add_entry(SilcSKR skr, SilcSKRFindType type,
				   void *type_data, SilcSKRKeyInternal key)
{
  SilcSKREntry entry;

  entry = silc_calloc(1, sizeof(*entry));
  if (!entry)
    return FALSE;

  entry->type = type;
  entry->data = type_data;

  return silc_hash_table_add(skr->keys, entry, key);
}

/* Add SILC style public key to repository */

static SilcSKRStatus silc_skr_add_silc(SilcSKR skr,
				       SilcPublicKey public_key,
				       SilcSKRKeyUsage usage,
				       void *key_context)
{
  SilcSKRKeyInternal key;
  SilcSKRStatus status = SILC_SKR_ERROR;
  SilcPublicKeyIdentifier ident;
  SilcSILCPublicKey silc_pubkey;

  /* Get the SILC public key */
  silc_pubkey = silc_pkcs_get_context(SILC_PKCS_SILC, public_key);
  ident = &silc_pubkey->identifier;

  SILC_LOG_DEBUG(("Adding SILC public key [%s]", ident->username));

  silc_mutex_lock(skr->lock);

  /* Check that this key hasn't been added already */
  if (silc_skr_find_entry(skr, &status, SILC_SKR_FIND_PUBLIC_KEY,
			  public_key, NULL, key_context, 0)) {
    silc_mutex_unlock(skr->lock);
    SILC_LOG_DEBUG(("Key already added"));
    return status | SILC_SKR_ALREADY_EXIST;
  }

  /* Allocate key entry */
  key = silc_calloc(1, sizeof(*key));
  if (!key) {
    silc_mutex_unlock(skr->lock);
    return status | SILC_SKR_NO_MEMORY;
  }

  key->key.usage = usage;
  key->key.key = public_key;
  key->key.key_context = key_context;

  /* Add key specifics */

  if (!silc_skr_add_entry(skr, SILC_SKR_FIND_PUBLIC_KEY,
			  public_key, key))
    goto err;
  key->refcnt++;

  if (!silc_skr_add_entry(skr, SILC_SKR_FIND_PKCS_TYPE,
			  SILC_32_TO_PTR(SILC_PKCS_SILC), key))
    goto err;
  key->refcnt++;

  if (ident->username) {
    if (!silc_skr_add_entry(skr, SILC_SKR_FIND_USERNAME,
			    ident->username, key))
      goto err;
    key->refcnt++;
  }

  if (ident->host) {
    if (!silc_skr_add_entry(skr, SILC_SKR_FIND_HOST,
			    ident->host, key))
      goto err;
    key->refcnt++;
  }

  if (ident->realname) {
    if (!silc_skr_add_entry(skr, SILC_SKR_FIND_REALNAME,
			    ident->realname, key))
      goto err;
    key->refcnt++;
  }

  if (ident->email) {
    if (!silc_skr_add_entry(skr, SILC_SKR_FIND_EMAIL,
			    ident->email, key))
      goto err;
    key->refcnt++;
  }

  if (ident->org) {
    if (!silc_skr_add_entry(skr, SILC_SKR_FIND_ORG,
			    ident->org, key))
      goto err;
    key->refcnt++;
  }

  if (ident->country) {
    if (!silc_skr_add_entry(skr, SILC_SKR_FIND_COUNTRY,
			    ident->country, key))
      goto err;
    key->refcnt++;
  }

  if (key_context) {
    if (!silc_skr_add_entry(skr, SILC_SKR_FIND_CONTEXT,
			    key_context, key))
      goto err;
    key->refcnt++;
  }

  silc_mutex_unlock(skr->lock);

  return SILC_SKR_OK;

 err:
  silc_mutex_unlock(skr->lock);
  return status;
}

/* Add SILC style public key to repository, and only the public key, not
   other details from the key. */

static SilcSKRStatus silc_skr_add_silc_simple(SilcSKR skr,
					      SilcPublicKey public_key,
					      SilcSKRKeyUsage usage,
					      void *key_context)
{
  SilcSKRKeyInternal key;
  SilcSKRStatus status = SILC_SKR_ERROR;

  SILC_LOG_DEBUG(("Adding SILC public key"));

  silc_mutex_lock(skr->lock);

  /* Check that this key hasn't been added already */
  if (silc_skr_find_entry(skr, &status, SILC_SKR_FIND_PUBLIC_KEY,
			  public_key, NULL, key_context, 0)) {
    silc_mutex_unlock(skr->lock);
    SILC_LOG_DEBUG(("Key already added"));
    return status | SILC_SKR_ALREADY_EXIST;
  }

  /* Allocate key entry */
  key = silc_calloc(1, sizeof(*key));
  if (!key) {
    silc_mutex_unlock(skr->lock);
    return status | SILC_SKR_NO_MEMORY;
  }

  key->key.usage = usage;
  key->key.key = public_key;
  key->key.key_context = key_context;

  /* Add key specifics */

  if (!silc_skr_add_entry(skr, SILC_SKR_FIND_PUBLIC_KEY,
			  public_key, key))
    goto err;
  key->refcnt++;

  if (key_context) {
    if (!silc_skr_add_entry(skr, SILC_SKR_FIND_CONTEXT,
			    key_context, key))
      goto err;
    key->refcnt++;
  }

  silc_mutex_unlock(skr->lock);

  return SILC_SKR_OK;

 err:
  silc_mutex_unlock(skr->lock);
  return status;
}

/* This performs AND operation.  Any entry already in `results' that is not
   in `list' will be removed from `results'. */

static SilcBool silc_skr_results_and(SilcDList list, SilcSKRStatus *status,
				     SilcDList *results)
{
  SilcSKRKeyInternal entry, r;

  if (*results == NULL) {
    *results = silc_dlist_init();
    if (*results == NULL) {
      *status |= SILC_SKR_NO_MEMORY;
      return FALSE;
    }
  }

  /* If results is empty, just add all entries from list to results */
  if (!silc_dlist_count(*results)) {
    silc_dlist_start(list);
    while ((entry = silc_dlist_get(list)) != SILC_LIST_END)
      silc_dlist_add(*results, entry);

    return TRUE;
  }

  silc_dlist_start(*results);
  while ((entry = silc_dlist_get(*results)) != SILC_LIST_END) {

    /* Check if this entry is in list  */
    silc_dlist_start(list);
    while ((r = silc_dlist_get(list)) != SILC_LIST_END) {
      if (r == entry)
	break;
    }
    if (r != SILC_LIST_END)
      continue;

    /* Remove from results */
    silc_dlist_del(*results, entry);
  }

  /* If results became empty, we did not find any key */
  if (!silc_dlist_count(*results)) {
    SILC_LOG_DEBUG(("Not all search constraints found"));
    *status |= SILC_SKR_NOT_FOUND;
    return FALSE;
  }

  return TRUE;
}


/**************************** Key Repository API ****************************/

/* Allocate key repository */

SilcSKR silc_skr_alloc(void)
{
  SilcSKR skr;

  skr = silc_calloc(1, sizeof(*skr));
  if (!skr)
    return NULL;

  if (!silc_skr_init(skr)) {
    silc_skr_free(skr);
    return NULL;
  }

  return skr;
}

/* Free key repository */

void silc_skr_free(SilcSKR skr)
{
  silc_skr_uninit(skr);
  silc_free(skr);
}

/* Initializes key repository */

SilcBool silc_skr_init(SilcSKR skr)
{
  if (!silc_mutex_alloc(&skr->lock))
    return FALSE;

  skr->keys = silc_hash_table_alloc(0, silc_skr_hash, NULL,
				    silc_skr_compare, NULL,
				    silc_skr_destructor, NULL, TRUE);
  if (!skr->keys)
    return FALSE;

  return TRUE;
}

/* Uninitializes key repository */

void silc_skr_uninit(SilcSKR skr)
{
  if (skr->keys)
    silc_hash_table_free(skr->keys);
  silc_mutex_free(skr->lock);
}

/* Adds public key to key repository */

SilcSKRStatus silc_skr_add_public_key(SilcSKR skr,
				      SilcPublicKey public_key,
				      SilcSKRKeyUsage usage,
				      void *key_context)
{
  SilcPKCSType type;

  if (!public_key)
    return SILC_SKR_ERROR;

  type = silc_pkcs_get_type(public_key);

  SILC_LOG_DEBUG(("Adding public key to repository"));

  switch (type) {

  case SILC_PKCS_SILC:
    return silc_skr_add_silc(skr, public_key, usage, key_context);
    break;

  default:
    break;
  }

  return SILC_SKR_ERROR;
}

/* Adds public key to repository. */

SilcSKRStatus silc_skr_add_public_key_simple(SilcSKR skr,
					     SilcPublicKey public_key,
					     SilcSKRKeyUsage usage,
					     void *key_context)
{
  SilcPKCSType type;

  if (!public_key)
    return SILC_SKR_ERROR;

  type = silc_pkcs_get_type(public_key);

  SILC_LOG_DEBUG(("Adding public key to repository"));

  switch (type) {

  case SILC_PKCS_SILC:
    return silc_skr_add_silc_simple(skr, public_key, usage, key_context);
    break;

  default:
    break;
  }

  return SILC_SKR_ERROR;
}


/************************** Search Constraints API **************************/

/* Allocate search constraints */

SilcSKRFind silc_skr_find_alloc(void)
{
  SilcSKRFind find;

  find = silc_calloc(1, sizeof(*find));
  if (!find)
    return NULL;

  find->constr = silc_hash_table_alloc(0, silc_hash_uint, NULL, NULL, NULL,
				       silc_skr_find_destructor, NULL, TRUE);
  if (!find->constr) {
    silc_skr_find_free(find);
    return NULL;
  }

  return find;
}

/* Free search constraints */

void silc_skr_find_free(SilcSKRFind find)
{
  if (find->constr)
    silc_hash_table_free(find->constr);
  silc_free(find);
}

SilcBool silc_skr_find_set_pkcs_type(SilcSKRFind find, SilcPKCSType type)
{
  return silc_hash_table_add(find->constr,
			     SILC_32_TO_PTR(SILC_SKR_FIND_PKCS_TYPE),
			     SILC_32_TO_PTR(type));
}

SilcBool silc_skr_find_set_username(SilcSKRFind find, const char *username)
{
  void *c = silc_memdup(username, strlen(username));
  if (!c)
    return FALSE;
  return silc_hash_table_add(find->constr,
			     SILC_32_TO_PTR(SILC_SKR_FIND_USERNAME), c);
}

SilcBool silc_skr_find_set_host(SilcSKRFind find, const char *host)
{
  void *c = silc_memdup(host, strlen(host));
  if (!c)
    return FALSE;
  return silc_hash_table_add(find->constr,
			     SILC_32_TO_PTR(SILC_SKR_FIND_HOST), c);
}

SilcBool silc_skr_find_set_realname(SilcSKRFind find, const char *realname)
{
  void *c = silc_memdup(realname, strlen(realname));
  if (!c)
    return FALSE;
  return silc_hash_table_add(find->constr,
			     SILC_32_TO_PTR(SILC_SKR_FIND_REALNAME), c);
}

SilcBool silc_skr_find_set_email(SilcSKRFind find, const char *email)
{
  void *c = silc_memdup(email, strlen(email));
  if (!c)
    return FALSE;
  return silc_hash_table_add(find->constr,
			     SILC_32_TO_PTR(SILC_SKR_FIND_EMAIL), c);
}

SilcBool silc_skr_find_set_org(SilcSKRFind find, const char *org)
{
  void *c = silc_memdup(org, strlen(org));
  if (!c)
    return FALSE;
  return silc_hash_table_add(find->constr,
			     SILC_32_TO_PTR(SILC_SKR_FIND_ORG), c);
}

SilcBool silc_skr_find_set_country(SilcSKRFind find, const char *country)
{
  void *c = silc_memdup(country, strlen(country));
  if (!c)
    return FALSE;
  return silc_hash_table_add(find->constr,
			     SILC_32_TO_PTR(SILC_SKR_FIND_COUNTRY), c);
}

SilcBool silc_skr_find_set_public_key(SilcSKRFind find,
				      SilcPublicKey public_key)
{
  SilcPublicKey pk = silc_pkcs_public_key_copy(public_key);
  if (!pk)
    return FALSE;
  return silc_hash_table_add(find->constr,
			     SILC_32_TO_PTR(SILC_SKR_FIND_PUBLIC_KEY), pk);
}

SilcBool silc_skr_find_set_context(SilcSKRFind find, void *context)
{
  return silc_hash_table_add(find->constr,
			     SILC_32_TO_PTR(SILC_SKR_FIND_CONTEXT), context);
}

SilcBool silc_skr_find_set_usage(SilcSKRFind find, SilcSKRKeyUsage usage)
{
  if (!usage)
    return TRUE;
  return silc_hash_table_add(find->constr,
			     SILC_32_TO_PTR(SILC_SKR_FIND_USAGE),
			     SILC_32_TO_PTR(usage));
}

/******************************** Search API ********************************/

/* Finds key(s) by the set search constraints.  The callback will be called
   once keys has been found. */
/* This is now synchronous function but may later change async */

SilcAsyncOperation silc_skr_find(SilcSKR skr, SilcSchedule schedule,
				 SilcSKRFind find,
				 SilcSKRFindCallback callback,
				 void *callback_context)
{
  SilcSKRStatus status = SILC_SKR_ERROR;
  SilcHashTableList htl;
  SilcDList list, results = NULL;
  void *type, *ctx, *usage = NULL;

  SILC_LOG_DEBUG(("Finding key from repository"));

  if (!find || !callback)
    return NULL;

  silc_mutex_lock(skr->lock);

  /* Get usage bits, if searching by them */
  silc_hash_table_find(find->constr, SILC_32_TO_PTR(SILC_SKR_FIND_USAGE),
		       NULL, &usage);

  silc_hash_table_list(find->constr, &htl);
  while (silc_hash_table_get(&htl, &type, &ctx)) {

#if defined(SILC_DEBUG)
    char tmp[256];
    memset(tmp, 0, sizeof(tmp));
    silc_skr_type_string((SilcSKRFindType)SILC_32_TO_PTR(type),
			 ctx, tmp, sizeof(tmp) - 1);
    SILC_LOG_DEBUG(("Finding key by %s", tmp));
#endif /* SILC_DEBUG */

    /* SILC_SKR_FIND_USAGE is handled separately while searching the keys. */
    if ((SilcSKRFindType)SILC_32_TO_PTR(type) == SILC_SKR_FIND_USAGE)
      continue;

    /* Find entries by this search constraint */
    if (!silc_skr_find_entry(skr, &status,
			     (SilcSKRFindType)SILC_32_TO_PTR(type),
			     ctx, &list, NULL, SILC_PTR_TO_32(usage))) {
      SILC_LOG_DEBUG(("Not found"));
      if (results) {
	silc_dlist_uninit(results);
	results = NULL;
      }
      break;
    }

    /* For now, our logic rule is AND.  All constraints must be found
       to find the key.  Later OR might be added also. */
    if (!silc_skr_results_and(list, &status, &results)) {
      SILC_LOG_DEBUG(("Not found"));
      if (results) {
	silc_dlist_uninit(results);
	results = NULL;
      }
      silc_dlist_uninit(list);
      break;
    }

    silc_dlist_uninit(list);
  }
  silc_hash_table_list_reset(&htl);

  silc_mutex_unlock(skr->lock);

  /* Return results */
  if (!results) {
    callback(skr, find, status, NULL, callback_context);
  } else {
    silc_dlist_start(results);
    callback(skr, find, SILC_SKR_OK, results, callback_context);
  }

  return NULL;
}
