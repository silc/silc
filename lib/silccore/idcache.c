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
/* XXX: This ID cache system sucks and must be rewritten! */
/*
 * $Id$
 * $Log$
 * Revision 1.1  2000/06/27 11:36:55  priikone
 * Initial revision
 *
 *
 */

#include "silcincludes.h"

/* qsort() sorter function. */

static int silc_idcache_sorter(const void *a, const void *b)
{
  SilcIDCache *a1, *b1;
  
  a1 = (SilcIDCache *)a;
  b1 = (SilcIDCache *)b;
  
  return a1->data[0] - b1->data[0];
}

/* Sorts given cache by data */

void silc_idcache_sort_by_data(SilcIDCache *cache, unsigned int count)
{
  qsort(cache, count, sizeof(*cache), silc_idcache_sorter);
}

/* Find ID Cache entry by data. The data maybe anything that must
   match exactly. */

int silc_idcache_find_by_data(SilcIDCache *cache, unsigned int cache_count,
			      char *data, SilcIDCache **ret)
{
  int i;

  if (cache == NULL)
    return FALSE;

  if (data == NULL)
    return FALSE;

  for (i = 0; i < cache_count; i++)
    if (cache[i].data && !memcmp(cache[i].data, data, strlen(data))) {
      if (ret)
	*ret = &(cache[i]);
      return TRUE;
    }

  return FALSE;
}

/* Find ID Cache entry by ID. */

int silc_idcache_find_by_id(SilcIDCache *cache, unsigned int cache_count, 
			    void *id, SilcIdType type, SilcIDCache **ret)
{
  int i, id_len;

  if (cache == NULL)
    return FALSE;

  if (id == NULL)
    return FALSE;

  id_len = silc_id_get_len(type);

  for (i = 0; i < cache_count; i++)
    if (cache[i].id && !memcmp(cache[i].id, id, id_len)) {
      if (ret)
	*ret = &(cache[i]);
      return TRUE;
    }

  return FALSE;
}

/* Add new entry to the cache. Returns number of allocated cache
   entries in the cache. */

int silc_idcache_add(SilcIDCache **cache, unsigned int cache_count,
		     char *data, SilcIdType id_type, void *id, 
		     void *context)
{
  SilcIDCache *c;
  int i;
  unsigned long curtime = time(NULL);

  SILC_LOG_DEBUG(("Adding cache entry"));

  c = *cache;

  if (c == NULL) {
    c = silc_calloc(5, sizeof(*c));
    if (!c)
      return 0;
    cache_count = 5;
  }

  /* See if it exists already */
  if (silc_idcache_find_by_id(c, cache_count, id, id_type, NULL) == TRUE)
    return cache_count;

  for (i = 0; i < cache_count; i++) {
    if (c[i].data == NULL) {
      c[i].data = data;
      c[i].type = id_type;
      c[i].id = id;
      c[i].expire = curtime + SILC_ID_CACHE_EXPIRE;
      c[i].context = context;
      break;
    }
  }

  if (i == cache_count) {
    c = silc_realloc(c, sizeof(*c) * (cache_count + 5));
    if (!c)
      return cache_count;
    for (i = cache_count; i < cache_count + 5; i++) {
      c[i].data = NULL;
      c[i].id = NULL;
    }
    c[cache_count].data = data;
    c[cache_count].type = id_type;
    c[cache_count].id = id;
    c[cache_count].expire = curtime + SILC_ID_CACHE_EXPIRE;
    c[cache_count].context = context;
    cache_count += 5;
  }

  *cache = c;

  return cache_count;
}

/* Delete cache entry from cache. */
/* XXX */

int silc_idcache_del(SilcIDCache *cache, SilcIDCache *old)
{

  return TRUE;
}

/* XXX */

int silc_idcache_del_by_data(SilcIDCache *cache, unsigned int cache_count,
			     char *data)
{

  return TRUE;
}

/* Deletes ID cache entry by ID. */

int silc_idcache_del_by_id(SilcIDCache *cache, unsigned int cache_count,
			   SilcIdType type, void *id)
{
  int i, id_len;

  if (cache == NULL)
    return FALSE;

  if (id == NULL)
    return FALSE;

  id_len = silc_id_get_len(type);

  for (i = 0; i < cache_count; i++)
    if (cache[i].id && !memcmp(cache[i].id, id, id_len)) {
      cache[i].id = NULL;
      cache[i].data = NULL;
      cache[i].type = 0;
      cache[i].context = NULL;
      return TRUE;
    }

  return FALSE;
}

/* Deletes all ID entries from cache. Free's memory as well. */

int silc_idcache_del_all(SilcIDCache **cache, unsigned int cache_count)
{
  SilcIDCache *c = *cache;
  int i;

  if (c == NULL)
    return FALSE;

  for (i = 0; i < cache_count; i++) {
    c[i].id = NULL;
    c[i].data = NULL;
    c[i].type = 0;
    c[i].expire = 0;
    c[i].context = NULL;
  }

  silc_free(*cache);
  *cache = NULL;

  return TRUE;
}

/* Purges the cache by removing expired cache entires. This does not
   free any memory though. */

int silc_idcache_purge(SilcIDCache *cache, unsigned int cache_count)
{
  unsigned long curtime = time(NULL);
  int i;

  if (cache == NULL)
    return FALSE;

  for (i = 0; i < cache_count; i++) {
    if (cache[i].data && 
	(cache[i].expire == 0 || cache[i].expire < curtime)) {
      cache[i].id = NULL;
      cache[i].data = NULL;
      cache[i].type = 0;
      cache[i].expire = 0;
      cache[i].context = NULL;
    }
  }

  return TRUE;
}
