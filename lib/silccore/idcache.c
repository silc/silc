/*

  idcache.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/*
 * $Id$
 * $Log$
 * Revision 1.6  2000/07/26 07:03:20  priikone
 * 	Use ID check as well in silc_idcache_add.
 *
 * Revision 1.5  2000/07/18 06:51:48  priikone
 * 	Use length of data found from cache instead of length of searched
 * 	data in comparison.
 *
 * Revision 1.4  2000/07/17 11:46:36  priikone
 * 	Added debug logging
 *
 * Revision 1.3  2000/07/12 05:54:01  priikone
 * 	Major rewrite of whole ID Cache system.
 *
 * Revision 1.2  2000/07/05 06:06:35  priikone
 * 	Global cosmetic change.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:55  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "silcincludes.h"
#include "idcache.h"

/* Static prototypes */
static int silc_idcache_sorter(const void *a, const void *b);
static SilcIDCacheList silc_idcache_list_alloc();
static void silc_idcache_list_add(SilcIDCacheList list, 
				  SilcIDCacheEntry cache);

/*
   SILC ID Cache object.

   This is context for the ID cache system. This includes all the cache
   entries and other internal data. This is read-only object and not
   visible outside this cache system.

   Fields are as follows:

   SilcIDCacheEntry cache

       Table of the cache entries allocated by silc_idcache_add function.
       This table is reallocated when new entry is added into the cache.

   unsigned int cache_count

       Number of cache entries in the cache.

   int sorted

       Boolean value to indicate whether the cache is sorted or not. If
       cache is not sorted the fast access (described next) cannot be used.
       Sorting can be done by calling sorting function or when adding new
       entries to the cache.

   int fast_access[];

       Table to provide fast access into the cache by index. When searching
       by data this table is used to get the index to the first occurence
       of that data (or part of the data) in the cache. Purpose of this
       is to provide faster access to the cache when searching by data.
       This is updated by silc_idcache_add and sorting functions.

*/
struct SilcIDCacheStruct {
  SilcIDCacheEntry cache;
  unsigned int cache_count;
  int sorted;
  int fast_access[256];
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
  unsigned int cache_dyn_count;
  unsigned int cache_count;
  unsigned int pos;
};

/* Allocates new ID cache object. The initial amount of allocated entries
   can be sent as argument. If `count' is 0 the system uses default values. */

SilcIDCache silc_idcache_alloc(unsigned int count)
{
  SilcIDCache cache;

  SILC_LOG_DEBUG(("Allocating new cache"));

  cache = silc_calloc(1, sizeof(*cache));
  cache->cache = silc_calloc(count ? count : 5, sizeof(*cache->cache));
  cache->cache_count = count ? count : 5;
  memset(cache->fast_access, -1, sizeof(cache->fast_access));

  return cache;
}

/* Free's ID cache object and cache entries */

void silc_idcache_free(SilcIDCache cache)
{
  if (cache) {
    silc_free(cache->cache);
    silc_free(cache);
  }
}

/* qsort() sorter function. */

static int silc_idcache_sorter(const void *a, const void *b)
{
  SilcIDCacheEntry a1, b1;

  a1 = (SilcIDCacheEntry)a;
  b1 = (SilcIDCacheEntry)b;
  
  if (!a1->data && !b1->data)
    return 0;

  if (!a1->data)
    return -1;

  if (!b1->data)
    return 1;

  return a1->data[0] - b1->data[0];
}

/* Sorts given cache by data. After sorting this updates the fast access
   table that can be used to access the cache faster. */

void silc_idcache_sort_by_data(SilcIDCache cache)
{
  int i;

  qsort(cache->cache, cache->cache_count, 
	sizeof(*cache->cache), silc_idcache_sorter);

  memset(cache->fast_access, -1, sizeof(cache->fast_access));

  /* Update the fast access table (this of course takes its own time when
     the cache is very large). */
  for (i = 0; i < cache->cache_count; i++) {
    if (cache->cache[i].data &&
	cache->fast_access[(int)cache->cache[i].data[0]] == -1)
      cache->fast_access[(int)cache->cache[i].data[0]] = i;
  }

  cache->sorted = TRUE;
}

/* Find ID Cache entry by data. The data maybe anything that must
   match exactly. Returns list of cache entries. */

int silc_idcache_find_by_data(SilcIDCache cache, char *data, 
			      SilcIDCacheList *ret)
{
  int i;
  SilcIDCacheList list;

  if (!cache || !cache->cache || !data)
    return FALSE;

  list = silc_idcache_list_alloc();

  if (cache->sorted)
    i = cache->fast_access[(int)data[0]];
  else
    i = 0;

  for (i = i; i < cache->cache_count; i++) {
    if (cache->sorted && cache->cache[i].data &&
	cache->cache[i].data[0] != data[0])
      break;

    if (cache->cache[i].data && 
	!memcmp(cache->cache[i].data, data, strlen(cache->cache[i].data)))
      silc_idcache_list_add(list, &(cache->cache[i]));
  }

  if (!silc_idcache_list_count(list))
    return FALSE;

  if (ret)
    *ret = list;
  else
    silc_idcache_list_free(list);

  return TRUE;
}

/* Find ID Cache entry by data. The data maybe anything that must
   match exactly. Returns one cache entry. */

int silc_idcache_find_by_data_one(SilcIDCache cache, char *data,
				  SilcIDCacheEntry *ret)
{
  int i;

  if (!cache || !cache->cache || !data)
    return FALSE;

  if (cache->sorted)
    i = cache->fast_access[(int)data[0]];
  else
    i = 0;

  for (i = i; i < cache->cache_count; i++)
    if (cache->cache[i].data && 
	!memcmp(cache->cache[i].data, data, strlen(cache->cache[i].data))) {
      if (ret)
	*ret = &(cache->cache[i]);
      return TRUE;
    }

  return FALSE;
}

/* Find ID Cache entry by data, loosely. The data don't have to be 100%
   match. This ignores data case-sensitivity when searching with this
   function. Returns list of cache entries. */

int silc_idcache_find_by_data_loose(SilcIDCache cache, char *data, 
				    SilcIDCacheList *ret)
{
  int i, c;
  SilcIDCacheList list;

  if (!cache || !cache->cache || !data)
    return FALSE;

  list = silc_idcache_list_alloc();

  c = tolower((int)data[0]);

  if (cache->sorted)
    i = cache->fast_access[c];
  else
    i = 0;

  for (i = i; i < cache->cache_count; i++) {
    if (cache->sorted && cache->cache[i].data &&
	cache->cache[i].data[0] != (char)c)
      break;
    
    if (cache->cache[i].data && 
	!strcasecmp(cache->cache[i].data, data))
      silc_idcache_list_add(list, &(cache->cache[i]));
  }

  if (cache->sorted) {
    c = toupper((int)data[0]);
    i = cache->fast_access[c];

    for (i = i; i < cache->cache_count; i++) {
      if (cache->sorted && cache->cache[i].data &&
	  cache->cache[i].data[0] != (char)c)
	break;

      if (cache->cache[i].data && 
	  !strcasecmp(cache->cache[i].data, data))
	silc_idcache_list_add(list, &(cache->cache[i]));
    }
  }
    
  if (!silc_idcache_list_count(list))
    return FALSE;

  if (ret)
    *ret = list;
  else
    silc_idcache_list_free(list);

  return TRUE;
}

/* Find ID Cache entry by ID. Returns list of cache entries. If `id' is
   SILC_ID_CACHE_ANY this returns all ID's of type `type'. */

int silc_idcache_find_by_id(SilcIDCache cache, void *id, SilcIdType type,
			    SilcIDCacheList *ret)
{
  int i, id_len;
  SilcIDCacheList list;

  if (!cache || !cache->cache || !id)
    return FALSE;

  id_len = silc_id_get_len(type);

  list = silc_idcache_list_alloc();

  if (id != SILC_ID_CACHE_ANY) {
    for (i = 0; i < cache->cache_count; i++)
      if (cache->cache[i].id && !memcmp(cache->cache[i].id, id, id_len))
	silc_idcache_list_add(list, &(cache->cache[i]));
  } else {
    for (i = 0; i < cache->cache_count; i++)
      if (cache->cache[i].id && cache->cache[i].type == type)
	silc_idcache_list_add(list, &(cache->cache[i]));
  }

  if (!silc_idcache_list_count(list))
    return FALSE;

  if (ret)
    *ret = list;
  else
    silc_idcache_list_free(list);

  return TRUE;
}

/* Find ID Cache entry by ID. Returns one cache entry. */

int silc_idcache_find_by_id_one(SilcIDCache cache, void *id, SilcIdType type, 
				SilcIDCacheEntry *ret)
{
  int i, id_len;

  if (!cache || !cache->cache || !id)
    return FALSE;

  id_len = silc_id_get_len(type);

  for (i = 0; i < cache->cache_count; i++)
    if (cache->cache[i].id && !memcmp(cache->cache[i].id, id, id_len)) {
      if (ret)
	*ret = &(cache->cache[i]);
      return TRUE;
    }

  return FALSE;
}

/* Finds cache entry by context. */

int silc_idcache_find_by_context(SilcIDCache cache, void *context, 
				 SilcIDCacheEntry *ret)
{
  int i;

  if (!cache || !cache->cache || !context)
    return FALSE;

  for (i = 0; i < cache->cache_count; i++)
    if (cache->cache[i].context && cache->cache[i].context == context) {
      if (ret)
	*ret = &(cache->cache[i]);
      return TRUE;
    }

  return FALSE;
}

/* Add new entry to the cache. Returns TRUE or FALSE. If `sort' is TRUE
   then the cache is sorted after the new entry has been added. The
   cache must be sorted in order for the fast access feature to work,
   however, it is not mandatory. */

int silc_idcache_add(SilcIDCache cache, char *data, SilcIdType id_type,
		     void *id, void *context, int sort)
{
  int i;
  unsigned int count;
  unsigned long curtime = time(NULL);
  SilcIDCacheEntry c;

  if (!cache || !cache->cache)
    return FALSE;

  SILC_LOG_DEBUG(("Adding cache entry"));

  c = cache->cache;
  count = cache->cache_count;

  if (c == NULL) {
    c = silc_calloc(5, sizeof(*c));
    count = 5;
  }

  /* See if it exists already */
  /* XXX this slows down this function. */
  if (silc_idcache_find_by_id(cache, id, id_type, NULL))
    return FALSE;

  for (i = 0; i < count; i++) {
    if (c[i].data == NULL && c[i].id == NULL) {
      c[i].data = data;
      c[i].type = id_type;
      c[i].id = id;
      c[i].expire = curtime + SILC_ID_CACHE_EXPIRE;
      c[i].context = context;
      break;
    }
  }

  if (i == count) {
    c = silc_realloc(c, sizeof(*c) * (count + 5));
    for (i = count; i < count + 5; i++) {
      c[i].data = NULL;
      c[i].id = NULL;
    }
    c[count].data = data;
    c[count].type = id_type;
    c[count].id = id;
    c[count].expire = curtime + SILC_ID_CACHE_EXPIRE;
    c[count].context = context;
    count += 5;
  }

  cache->cache = c;
  cache->cache_count = count;
  cache->sorted = sort;

  if (sort)
    silc_idcache_sort_by_data(cache);

  return TRUE;
}

/* Delete cache entry from cache. */
/* XXX */

int silc_idcache_del(SilcIDCache cache, SilcIDCacheEntry old)
{

  return TRUE;
}

/* XXX */

int silc_idcache_del_by_data(SilcIDCache cache, char *data)
{

  return TRUE;
}

/* Deletes ID cache entry by ID. */

int silc_idcache_del_by_id(SilcIDCache cache, SilcIdType type, void *id)
{
  int i, id_len;

  if (!cache || !cache->cache || !id)
    return FALSE;

  id_len = silc_id_get_len(type);

  for (i = 0; i < cache->cache_count; i++)
    if (cache->cache[i].id && !memcmp(cache->cache[i].id, id, id_len)) {
      cache->cache[i].id = NULL;
      cache->cache[i].data = NULL;
      cache->cache[i].type = 0;
      cache->cache[i].context = NULL;
      return TRUE;
    }

  return FALSE;
}

/* Deletes all ID entries from cache. Free's memory as well. */

int silc_idcache_del_all(SilcIDCache cache)
{
  if (!cache || !cache->cache)
    return FALSE;

  silc_free(cache->cache);
  cache->cache = NULL;
  cache->cache_count = 0;

  return TRUE;
}

/* Purges the cache by removing expired cache entires. This does not
   free any memory though. */

int silc_idcache_purge(SilcIDCache cache)
{
  SilcIDCacheEntry c;
  unsigned long curtime = time(NULL);
  int i;

  if (!cache || !cache->cache)
    return FALSE;

  c = cache->cache;

  for (i = 0; i < cache->cache_count; i++) {
    if (c[i].data && 
	(c[i].expire == 0 || c[i].expire < curtime)) {
      c[i].id = NULL;
      c[i].data = NULL;
      c[i].type = 0;
      c[i].expire = 0;
      c[i].context = NULL;
    }
  }

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
    for (i = 0; i < sizeof(list->cache); i++) {
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

    i += 5;
    list->cache_dyn = silc_realloc(list->cache_dyn, 
				   sizeof(*list->cache) * (i));

    /* NULL the reallocated area */
    for (k = list->cache_dyn_count; k < i; k++)
      list->cache_dyn[k] = NULL;

    list->cache_dyn[list->cache_dyn_count] = cache;
    list->cache_dyn_count = i;
    list->cache_count++;
  }
}

/* Returns number of cache entries in the ID cache list. */

int silc_idcache_list_count(SilcIDCacheList list)
{
  return list->cache_count;
}

/* Returns first entry from the ID cache list. */

int silc_idcache_list_first(SilcIDCacheList list, SilcIDCacheEntry *ret)
{
  list->pos = 0;

  if (!list->cache[list->pos])
    return FALSE;
  
  if (ret)
    *ret = list->cache[list->pos];

  return TRUE;
}

/* Returns next entry from the ID cache list. */

int silc_idcache_list_next(SilcIDCacheList list, SilcIDCacheEntry *ret)
{
  int dyn = FALSE;
  list->pos++;

  if (list->pos >= sizeof(list->cache)) {
    list->pos = 0;
    dyn = TRUE;
  }

  if (dyn && list->pos >= list->cache_dyn_count)
    return FALSE;

  if (!dyn && !list->cache[list->pos])
    return FALSE;
  
  if (dyn && !list->cache_dyn[list->pos])
    return FALSE;
  
  if (ret) {
    if (!dyn)
      *ret = list->cache[list->pos];
    else
      *ret = list->cache_dyn[list->pos];
  }
  
  return TRUE;
}

/* Free's ID cache list. User must free the list object returned by
   any of the searching functions. */

void silc_idcache_list_free(SilcIDCacheList list)
{
  if (list) {
    if (list->cache_dyn)
      silc_free(list->cache_dyn);
    silc_free(list);
  }
}
