/*

  silcidcache.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2000 - 2001 Pekka Riikonen

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
#include "silcidcache.h"

/* Static prototypes */
static void silc_idcache_destructor(void *key, void *context,
				    void *user_context);
static SilcIDCacheList silc_idcache_list_alloc();
static void silc_idcache_list_add(SilcIDCacheList list, 
				  SilcIDCacheEntry cache);

/*
   SILC ID Cache object.

   This is context for the ID cache system. This includes all the cache
   entries and other internal data. This is read-only object and not
   visible outside this cache system.

   Fields are as follows:

   SilcHashTable id_table

       Hash table using the ID as the key.

   SilcHashTable name_table

       Hash table using the name as the key.

   SilcHashTable context_table

       Hash table using the context as the key.

   SilcIDCacheDestructor destructor

       Destructor callback that is called when an cache entry expires or is
       purged from the ID cache. The application must not free cache entry
       because the library will do it automatically. The appliation, however,
       is responsible of freeing any data in the entry.

   SilcIdType id_type

       Indicates the type of the ID's this cache holds.

*/
struct SilcIDCacheStruct {
  SilcHashTable id_table;
  SilcHashTable name_table;
  SilcHashTable context_table;
  SilcIDCacheDestructor destructor;
  SilcIdType type;
};

/* 
   ID Cache list.
   
   This is returned when searching the cache. Enumeration functions are
   provided to traverse the list; actually this is used as table not as
   list. :)

   By default the found cache entries are saved into the static cache
   table to provide access without reallocation. However, if the static
   table is full, rest of the cache entries are dynamically allocated
   into `cache_dyn' table. Traversing functions automatically handles
   these situations.

*/
struct SilcIDCacheListStruct {
  SilcIDCacheEntry cache[64];
  SilcIDCacheEntry *cache_dyn;
  uint32 cache_dyn_count;
  uint32 cache_count;
  uint32 pos;
  bool dyn;
};

/* Allocates new ID cache object. The initial amount of allocated entries
   can be sent as argument. If `count' is 0 the system uses default values. 
   The `id_type' defines the types of the ID's that will be saved to the
   cache. */

SilcIDCache silc_idcache_alloc(uint32 count, SilcIdType id_type,
			       SilcIDCacheDestructor destructor)
{
  SilcIDCache cache;

  SILC_LOG_DEBUG(("Allocating new cache"));

  cache = silc_calloc(1, sizeof(*cache));
  cache->id_table = silc_hash_table_alloc(count, silc_hash_id, 
					  (void *)(uint32)id_type,
					  silc_hash_id_compare, 
					  (void *)(uint32)id_type, 
					  silc_idcache_destructor, NULL, 
					  FALSE);
  cache->name_table = silc_hash_table_alloc(count, silc_hash_string, NULL,
					    silc_hash_string_compare, NULL, 
					    NULL, NULL, FALSE);
  cache->context_table = silc_hash_table_alloc(count, silc_hash_ptr, NULL,
					       NULL, NULL, NULL, NULL, FALSE);
  cache->destructor = destructor;
  cache->type = id_type;

  return cache;
}

/* Frees ID cache object and cache entries */

void silc_idcache_free(SilcIDCache cache)
{
  if (cache) {
    silc_hash_table_free(cache->id_table);
    silc_hash_table_free(cache->name_table);
    silc_hash_table_free(cache->context_table);
    silc_free(cache);
  }
}

/* Add new entry to the cache. Returns TRUE if the entry was added and
   FALSE if it could not be added. The `name' is the name associated with
   the ID, the `id' the actual ID and the `context' a used specific context.
   If the `expire' is TRUE the entry expires in default time and if FALSE
   the entry never expires from the cache. */

bool silc_idcache_add(SilcIDCache cache, char *name, void *id, 
		      void *context, int expire)
{
  SilcIDCacheEntry c;
  uint32 curtime = time(NULL);

  SILC_LOG_DEBUG(("Adding cache entry"));

  /* Allocate new cache entry */
  c = silc_calloc(1, sizeof(*c));
  c->id = id;
  c->name = name;
  c->expire = (expire ? (curtime + SILC_ID_CACHE_EXPIRE) : 0);
  c->context = context;

  /* Add the new entry to the hash tables */

  if (id)
    silc_hash_table_add(cache->id_table, id, c);
  if (name)
    silc_hash_table_add(cache->name_table, name, c);
  if (context)
    silc_hash_table_add(cache->context_table, context, c);

  /* See whether we have time to rehash the tables */
  if ((silc_hash_table_count(cache->id_table) / 2) >
      silc_hash_table_size(cache->id_table)) {
    silc_hash_table_rehash(cache->id_table, 0);
    silc_hash_table_rehash(cache->name_table, 0);
    silc_hash_table_rehash(cache->context_table, 0);
  }

  return TRUE;
}

/* Destructor for the ID Cache entry */

static void silc_idcache_destructor(void *key, void *context,
				    void *user_context)
{
  silc_free(context);
}

/* Delete cache entry from cache. */

bool silc_idcache_del(SilcIDCache cache, SilcIDCacheEntry old)
{
  bool ret = FALSE;

  SILC_LOG_DEBUG(("Deleting cache entry"));

  if (old->name)
    ret = silc_hash_table_del_by_context(cache->name_table, old->name, old);
  if (old->context)
    ret = silc_hash_table_del(cache->context_table, old->context);
  if (old->id)
    ret = silc_hash_table_del(cache->id_table, old->id);

  return ret;
}

/* Deletes ID cache entry by ID. */

bool silc_idcache_del_by_id(SilcIDCache cache, void *id)
{
  SilcIDCacheEntry c;

  if (!silc_hash_table_find(cache->id_table, id, NULL, (void *)&c))
    return FALSE;

  return silc_idcache_del(cache, c);
}

/* Same as above but with specific hash and comparison functions. If the
   functions are NULL then default values are used. */

bool silc_idcache_del_by_id_ext(SilcIDCache cache, void *id,
				SilcHashFunction hash, 
				void *hash_context,
				SilcHashCompare compare, 
				void *compare_context)
{
  SilcIDCacheEntry c;
  bool ret = FALSE;

  SILC_LOG_DEBUG(("Deleting cache entry"));

  if (!silc_hash_table_find_ext(cache->id_table, id, NULL, (void *)&c,
				hash, hash_context, compare, 
				compare_context))
    return FALSE;

  if (c->name)
    ret = silc_hash_table_del_by_context(cache->name_table, c->name, c);
  if (c->context)
    ret = silc_hash_table_del(cache->context_table, c->context);
  if (c->id)
    ret = silc_hash_table_del_ext(cache->id_table, c->id, hash,
				  hash_context, compare, compare_context,
				  NULL, NULL);

  return ret;
}

/* Deletes ID cache entry by context. */

bool silc_idcache_del_by_context(SilcIDCache cache, void *context)
{
  SilcIDCacheEntry c;
  bool ret = FALSE;

  SILC_LOG_DEBUG(("Deleting cache entry"));

  if (!silc_hash_table_find(cache->context_table, context, NULL, (void *)&c))
    return FALSE;

  if (c->name)
    ret = silc_hash_table_del_by_context(cache->name_table, c->name, c);
  if (c->context)
    ret = silc_hash_table_del(cache->context_table, c->context);
  if (c->id)
    ret = silc_hash_table_del_by_context(cache->id_table, c->id, c);

  return ret;
}

/* Deletes all ID entries from cache. Free's memory as well. */

bool silc_idcache_del_all(SilcIDCache cache)
{
  silc_hash_table_free(cache->id_table);
  silc_hash_table_free(cache->name_table);
  silc_hash_table_free(cache->context_table);

  return TRUE;
}

static void silc_idcache_destructor_dummy(void *key, void *context,
					  void *user_context)
{
  /* Dummy - nothing */
}

/* Foreach callback fro silc_idcache_purge. */

static void silc_idcache_purge_foreach(void *key, void *context,
				       void *user_context)
{
  SilcIDCache cache = (SilcIDCache)user_context;
  uint32 curtime = time(NULL);
  SilcIDCacheEntry c = (SilcIDCacheEntry)context;

  if (c->expire && c->expire < curtime) {
    /* Remove the entry from the hash tables */
    if (c->name)
      silc_hash_table_del_by_context(cache->name_table, c->name, c);
    if (c->context)
      silc_hash_table_del(cache->context_table, c->context);
    if (c->id)
      silc_hash_table_del_by_context_ext(cache->id_table, c->id, c,
					 NULL, NULL, NULL, NULL, 
					 silc_idcache_destructor_dummy, NULL);

    /* Call the destructor */
    if (cache->destructor)
      cache->destructor(cache, c);

    /* Free the entry, it has been deleted from the hash tables */
    silc_free(c);
  }
}

/* Purges the cache by removing expired cache entires. Note that this
   may be very slow operation. */

bool silc_idcache_purge(SilcIDCache cache)
{
  silc_hash_table_foreach(cache->id_table, silc_idcache_purge_foreach, cache);
  return TRUE;
}

/* Purges the specific entry by context. */

bool silc_idcache_purge_by_context(SilcIDCache cache, void *context)
{
  SilcIDCacheEntry c;
  bool ret = FALSE;

  if (!silc_hash_table_find(cache->context_table, context, NULL, 
			    (void *)&c))
    return FALSE;

    /* Remove the entry from the hash tables */
  if (c->name)
    ret = silc_hash_table_del_by_context(cache->name_table, c->name, c);
  if (c->context)
    ret = silc_hash_table_del(cache->context_table, c->context);
  if (c->id)
    ret =
      silc_hash_table_del_by_context_ext(cache->id_table, c->id, c,
					 NULL, NULL, NULL, NULL, 
					 silc_idcache_destructor_dummy, NULL);
  
  /* Call the destructor */
  if (cache->destructor)
    cache->destructor(cache, c);

  /* Free the entry, it has been deleted from the hash tables */
  silc_free(c);

  return ret;
}

/* Callback that is called by the hash table routine when traversing
   entrys in the hash table. */

static void silc_idcache_get_all_foreach(void *key, void *context,
					 void *user_context)
{
  SilcIDCacheList list = (SilcIDCacheList)user_context;
  silc_idcache_list_add(list, (SilcIDCacheEntry)context);
}

/* Returns all cache entrys from the ID cache to the `ret' ID Cache List. */

bool silc_idcache_get_all(SilcIDCache cache, SilcIDCacheList *ret)
{
  SilcIDCacheList list;

  if (!ret)
    return TRUE;

  list = silc_idcache_list_alloc();
  silc_hash_table_foreach(cache->id_table, silc_idcache_get_all_foreach, list);

  if (silc_idcache_list_count(list) == 0) {
    silc_idcache_list_free(list);
    return FALSE;
  }

  *ret = list;

  return TRUE;
}

/* Find ID Cache entry by ID. May return multiple entries. */

bool silc_idcache_find_by_id(SilcIDCache cache, void *id, 
			     SilcIDCacheList *ret)
{
  SilcIDCacheList list;

  list = silc_idcache_list_alloc();

  if (!ret)
    return TRUE;

  silc_hash_table_find_foreach(cache->id_table, id,
			       silc_idcache_get_all_foreach, list);

  if (silc_idcache_list_count(list) == 0) {
    silc_idcache_list_free(list);
    return FALSE;
  }

  *ret = list;

  return TRUE;
}

/* Find specific ID with specific hash function and comparison functions.
   If `hash' is NULL then the default hash funtion is used and if `compare'
   is NULL default comparison function is used. */

bool silc_idcache_find_by_id_one_ext(SilcIDCache cache, void *id, 
				     SilcHashFunction hash, 
				     void *hash_context,
				     SilcHashCompare compare, 
				     void *compare_context,
				     SilcIDCacheEntry *ret)
{
  return silc_hash_table_find_ext(cache->id_table, id, NULL, (void *)ret,
				  hash, hash_context, compare, 
				  compare_context);
}

/* Find one specific ID entry. */

bool silc_idcache_find_by_id_one(SilcIDCache cache, void *id, 
				 SilcIDCacheEntry *ret)
{
  return silc_hash_table_find(cache->id_table, id, NULL, (void *)ret);
}

/* Finds cache entry by context. */

bool silc_idcache_find_by_context(SilcIDCache cache, void *context, 
				  SilcIDCacheEntry *ret)
{
  return silc_hash_table_find(cache->context_table, context, NULL, 
			      (void *)ret);
}

/* Find ID Cache entry by name. Returns list of cache entries. */

bool silc_idcache_find_by_name(SilcIDCache cache, char *name,
			       SilcIDCacheList *ret)
{
  SilcIDCacheList list;

  list = silc_idcache_list_alloc();

  if (!ret)
    return TRUE;

  silc_hash_table_find_foreach(cache->name_table, name, 
			       silc_idcache_get_all_foreach, list);

  if (silc_idcache_list_count(list) == 0) {
    silc_idcache_list_free(list);
    return FALSE;
  }

  *ret = list;

  return TRUE;
}

/* Find ID Cache entry by name. Returns one cache entry. */

bool silc_idcache_find_by_name_one(SilcIDCache cache, char *name,
				   SilcIDCacheEntry *ret)
{
  if (!silc_hash_table_find(cache->name_table, name, NULL, (void *)ret))
    return FALSE;

  return TRUE;
}

/* Allocates ID cache list. */

static SilcIDCacheList silc_idcache_list_alloc()
{
  SilcIDCacheList list;

  list = silc_calloc(1, sizeof(*list));

  return list;
}

/* Adds cache entry to the ID cache list. If needed reallocates memory
   for the list. */

static void silc_idcache_list_add(SilcIDCacheList list, SilcIDCacheEntry cache)
{
  int i;

  /* Try to add to static cache */
  if (!list->cache_dyn_count)
    for (i = 0; i < (sizeof(list->cache) / sizeof(list->cache[0])); i++) {
      if (!list->cache[i]) {
	list->cache[i] = cache;
	list->cache_count++;
	return;
      }
    }

  /* Static cache is full, allocate dynamic cache */
  for (i = 0; i < list->cache_dyn_count; i++) {
    if (!list->cache_dyn[i]) {
      list->cache_dyn[i] = cache;
      list->cache_count++;
      break;
    }
  }

  if (i >= list->cache_dyn_count) {
    int k;

    i = list->cache_dyn_count;
    list->cache_dyn = silc_realloc(list->cache_dyn, 
				   sizeof(*list->cache_dyn) * (i + 5));

    /* NULL the reallocated area */
    for (k = i; k < (i + 5); k++)
      list->cache_dyn[k] = NULL;

    list->cache_dyn[i] = cache;
    list->cache_count++;
    list->cache_dyn_count += 5;
  }
}

/* Returns number of cache entries in the ID cache list. */

int silc_idcache_list_count(SilcIDCacheList list)
{
  return list->cache_count;
}

/* Returns first entry from the ID cache list. */

bool silc_idcache_list_first(SilcIDCacheList list, SilcIDCacheEntry *ret)
{
  list->pos = 0;

  if (!list->cache[list->pos])
    return FALSE;
  
  if (ret)
    *ret = list->cache[list->pos];

  return TRUE;
}

/* Returns next entry from the ID cache list. */

bool silc_idcache_list_next(SilcIDCacheList list, SilcIDCacheEntry *ret)
{
  list->pos++;

  if (!list->dyn &&
      list->pos >= (sizeof(list->cache) / sizeof(list->cache[0]))) {
    list->pos = 0;
    list->dyn = TRUE;
  }

  if (list->dyn && list->pos >= list->cache_dyn_count)
    return FALSE;

  if (!list->dyn && !list->cache[list->pos])
    return FALSE;
  
  if (list->dyn && !list->cache_dyn[list->pos])
    return FALSE;
  
  if (ret) {
    if (!list->dyn)
      *ret = list->cache[list->pos];
    else
      *ret = list->cache_dyn[list->pos];
  }
  
  return TRUE;
}

/* Frees ID cache list. User must free the list object returned by
   any of the searching functions. */

void silc_idcache_list_free(SilcIDCacheList list)
{
  if (list) {
    if (list->cache_dyn)
      silc_free(list->cache_dyn);
    silc_free(list);
  }
}
