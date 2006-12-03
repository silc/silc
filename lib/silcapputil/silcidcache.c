/*

  silcidcache.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2000 - 2006 Pekka Riikonen

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
#include "silcidcache.h"

/************************** Types and definitions ***************************/

/* ID Cache context */
struct SilcIDCacheStruct {
  SilcHashTable id_table;	     /* ID hash table */
  SilcHashTable name_table;	     /* Name hash table */
  SilcHashTable context_table;	     /* Context hash table */
  SilcIDCacheDestructor destructor;  /* Entry destructor */
  void *context;		     /* Destructor context */
  SilcIdType id_type;		     /* Type of ID cache */
};


/************************ Static utility functions **************************/

/* Callback that is called by the hash table routine when traversing
   entries in the hash table. */

static void silc_idcache_get_all_foreach(void *key, void *context,
					 void *user_context)
{
  SilcList *list = user_context;
  if (!context)
    return;
  silc_list_add(*list, context);
}

/* Cache entry destructor */

static void silc_idcache_destructor(SilcIDCache cache,
				    SilcIDCacheEntry entry,
				    void *app_context)
{
  if (cache->destructor)
    cache->destructor(cache, entry, cache->destructor, app_context);

  memset(entry, 'F', sizeof(*entry));
  silc_free(entry);
}


/****************************** Public API **********************************/

/* Allocates new ID cache object. */

SilcIDCache silc_idcache_alloc(SilcUInt32 count, SilcIdType id_type,
			       SilcIDCacheDestructor destructor,
			       void *destructor_context)
{
  SilcIDCache cache;

  SILC_LOG_DEBUG(("Allocating new cache"));

  cache = silc_calloc(1, sizeof(*cache));
  if (!cache)
    return NULL;

  cache->id_table = silc_hash_table_alloc(count, silc_hash_id,
					  SILC_32_TO_PTR(id_type),
					  silc_hash_id_compare,
					  SILC_32_TO_PTR(id_type),
					  NULL, NULL, TRUE);
  cache->name_table = silc_hash_table_alloc(count, silc_hash_utf8_string, NULL,
					    silc_hash_utf8_compare, NULL,
					    NULL, NULL, TRUE);
  cache->context_table = silc_hash_table_alloc(count, silc_hash_ptr, NULL,
					       NULL, NULL, NULL, NULL, TRUE);
  cache->destructor = destructor;
  cache->context = destructor_context;
  cache->id_type = id_type;

  if (!cache->id_table || !cache->name_table || !cache->context_table) {
    if (cache->id_table)
      silc_hash_table_free(cache->id_table);
    if (cache->name_table)
      silc_hash_table_free(cache->name_table);
    if (cache->context_table)
      silc_hash_table_free(cache->context_table);
    silc_free(cache);
    return NULL;
  }

  return cache;
}

/* Frees ID cache object and cache entries */

void silc_idcache_free(SilcIDCache cache)
{
  silc_hash_table_free(cache->id_table);
  silc_hash_table_free(cache->name_table);
  silc_hash_table_free(cache->context_table);
  silc_free(cache);
}

/* Add new entry to cache */

SilcIDCacheEntry
silc_idcache_add(SilcIDCache cache, char *name, void *id, void *context)
{
  SilcIDCacheEntry c;

  if (!id)
    return NULL;

  /* Allocate new cache entry */
  c = silc_calloc(1, sizeof(*c));
  if (!c)
    return NULL;

  c->id = id;
  c->name = name;
  c->context = context;

  SILC_LOG_DEBUG(("Adding cache entry %p", c));

  /* Add the new entry to the hash tables */

  if (id) {
    if (silc_idcache_find_by_id_one(cache, id, NULL)) {
      SILC_LOG_ERROR(("Attempted to add same ID twice to ID Cache"));
      goto err;
    }
    if (!silc_hash_table_add(cache->id_table, id, c))
      goto err;
  }
  if (name)
    if (!silc_hash_table_add(cache->name_table, name, c))
      goto err;
  if (context)
    if (!silc_hash_table_add(cache->context_table, context, c))
      goto err;

  return c;

 err:
  if (c->name)
    silc_hash_table_del_by_context(cache->name_table, c->name, c);
  if (c->context)
    silc_hash_table_del_by_context(cache->context_table, c->context, c);
  if (c->id)
    silc_hash_table_del_by_context(cache->id_table, c->id, c);
  silc_free(c);

  return NULL;
}

/* Delete cache entry from cache. */

SilcBool silc_idcache_del(SilcIDCache cache, SilcIDCacheEntry entry,
			  void *app_context)
{
  SilcBool ret = FALSE;

  SILC_LOG_DEBUG(("Deleting cache entry %p", entry));

  if (entry->name)
    ret = silc_hash_table_del_by_context(cache->name_table, entry->name,
					 entry);
  if (entry->context)
    ret = silc_hash_table_del_by_context(cache->context_table, entry->context,
					 entry);
  if (entry->id)
    ret = silc_hash_table_del_by_context(cache->id_table, entry->id,
					 entry);

  if (ret)
    silc_idcache_destructor(cache, entry, app_context);

  return ret;
}

/* Deletes ID cache entry by ID. */

SilcBool silc_idcache_del_by_id(SilcIDCache cache, void *id,
				void *app_context)
{
  SilcIDCacheEntry c;

  if (!silc_hash_table_find(cache->id_table, id, NULL, (void **)&c))
    return FALSE;

  return silc_idcache_del(cache, c, app_context);
}

/* Deletes ID cache entry by context. */

SilcBool silc_idcache_del_by_context(SilcIDCache cache, void *context,
				     void *app_context)
{
  SilcIDCacheEntry c;

  if (!silc_hash_table_find(cache->context_table, context, NULL, (void **)&c))
    return FALSE;

  return silc_idcache_del(cache, c, app_context);
}

/* Update entry */

SilcBool silc_idcache_update(SilcIDCache cache, SilcIDCacheEntry entry,
			     void *new_id, char *new_name,
			     SilcBool free_old_name)
{
  if (new_id) {
    if (!silc_hash_table_del_by_context(cache->id_table, entry->id, entry))
      return FALSE;

    if (cache->id_type == SILC_ID_CLIENT)
      *(SilcClientID *)entry->id = *(SilcClientID *)new_id;
    if (cache->id_type == SILC_ID_SERVER)
      *(SilcServerID *)entry->id = *(SilcServerID *)new_id;
    if (cache->id_type == SILC_ID_CHANNEL)
      *(SilcChannelID *)entry->id = *(SilcChannelID *)new_id;

    if (!silc_hash_table_add(cache->id_table, entry->id, entry))
      return FALSE;
  }

  if (new_name) {
    if (!silc_hash_table_del_by_context(cache->name_table, entry->name, entry))
      return FALSE;

    if (free_old_name)
      silc_free(entry->name);
    entry->name = new_name;

    if (!silc_hash_table_add(cache->name_table, entry->name, entry))
      return FALSE;
  }

  return TRUE;
}

/* Update entry by context */

SilcBool silc_idcache_update_by_context(SilcIDCache cache, void *context,
					void *new_id, char *new_name,
					SilcBool free_old_name)
{
  SilcIDCacheEntry c;

  if (!silc_hash_table_find(cache->context_table, context, NULL, (void **)&c))
    return FALSE;

  return silc_idcache_update(cache, c, new_id, new_name, free_old_name);
}

/* Returns all cache entrys from the ID cache to the `ret' ID Cache List. */

SilcBool silc_idcache_get_all(SilcIDCache cache, SilcList *ret_list)
{
  if (!ret_list)
    return FALSE;

  if (!silc_hash_table_count(cache->id_table))
    return FALSE;

  silc_hash_table_foreach(cache->id_table, silc_idcache_get_all_foreach,
			  ret_list);

  if (!silc_list_count(*ret_list))
    return FALSE;

  return TRUE;
}

/* Find ID Cache entry by ID. May return multiple entries. */

SilcBool silc_idcache_find_by_id(SilcIDCache cache, void *id,
				 SilcList *ret_list)
{
  if (!ret_list)
    return FALSE;

  if (!silc_hash_table_count(cache->id_table))
    return FALSE;

  silc_hash_table_find_foreach(cache->id_table, id,
			       silc_idcache_get_all_foreach, ret_list);

  if (!silc_list_count(*ret_list))
    return FALSE;

  return TRUE;
}

/* Find one specific ID entry.  Compare full IDs */

SilcBool silc_idcache_find_by_id_one(SilcIDCache cache, void *id,
				     SilcIDCacheEntry *ret)
{
  return silc_hash_table_find_ext(cache->id_table, id, NULL, (void *)ret,
				  NULL, NULL,
				  silc_hash_id_compare_full,
				  SILC_32_TO_PTR(cache->id_type));
}

/* Finds cache entry by context. */

SilcBool silc_idcache_find_by_context(SilcIDCache cache, void *context,
				      SilcIDCacheEntry *ret)
{
  return silc_hash_table_find(cache->context_table, context, NULL,
			      (void *)ret);
}

/* Find ID Cache entry by name. Returns list of cache entries. */

SilcBool silc_idcache_find_by_name(SilcIDCache cache, char *name,
				   SilcList *ret_list)
{
  if (!ret_list)
    return FALSE;

  if (!silc_hash_table_count(cache->name_table))
    return FALSE;

  silc_hash_table_find_foreach(cache->name_table, name,
			       silc_idcache_get_all_foreach, ret_list);

  if (!silc_list_count(*ret_list))
    return FALSE;

  return TRUE;
}

/* Find ID Cache entry by name. Returns one cache entry. */

SilcBool silc_idcache_find_by_name_one(SilcIDCache cache, char *name,
				       SilcIDCacheEntry *ret)
{
  return silc_hash_table_find(cache->name_table, name, NULL, (void *)ret);
}
