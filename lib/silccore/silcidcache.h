/*

  silcidcache.h

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

#ifndef IDCACHE_H
#define IDCACHE_H

/* 
   Silc ID Cache Entry object.

   This is one entry in the SILC ID Cache system. Contents of this is
   allocated outside the ID cache system, however, all the fields are 
   filled with ID cache utility functions. The ID cache system does not
   allocate any of these fields nor free them.

   void *id

      The actual ID.

   char name

      A name associated with the ID.

   uint32 expire

      Time when this cache entry expires.  This is normal time() value
      plus the validity.  Cache entry has expired if current time is
      more than value in this field.  If this value is zero (0) the
      entry never expires.

   void *context

      Any caller specified context.

*/
typedef struct {
  void *id;
  char *name;
  uint32 expire;
  void *context;
} *SilcIDCacheEntry;

/* Forward declaration for SILC ID Cache object. */
typedef struct SilcIDCacheStruct *SilcIDCache;

/* Forward declaration for ID Cache List */
typedef struct SilcIDCacheListStruct *SilcIDCacheList;

/* Destructor callback that is called when an cache entry expires or is
   purged from the ID cache. The application must not free cache entry
   because the library will do it automatically. The appliation, however,
   is responsible of freeing any data in the entry. */
typedef void (*SilcIDCacheDestructor)(SilcIDCache cache,
				      SilcIDCacheEntry entry);

#define SILC_ID_CACHE_ANY ((void *)1)

#define SILC_ID_CACHE_EXPIRE 3600
#define SILC_ID_CACHE_EXPIRE_DEF (time(NULL) + SILC_ID_CACHE_EXPIRE)

/* Prototypes */
SilcIDCache silc_idcache_alloc(uint32 count, SilcIdType id_type,
			       SilcIDCacheDestructor destructor);
void silc_idcache_free(SilcIDCache cache);
bool silc_idcache_add(SilcIDCache cache, char *name, void *id, 
		      void *context, int expire);
bool silc_idcache_del(SilcIDCache cache, SilcIDCacheEntry old);
bool silc_idcache_del_by_id(SilcIDCache cache, void *id);
bool silc_idcache_del_by_id_ext(SilcIDCache cache, void *id,
				SilcHashFunction hash, 
				void *hash_context,
				SilcHashCompare compare, 
				void *compare_context);
bool silc_idcache_del_by_context(SilcIDCache cache, void *context);
bool silc_idcache_del_all(SilcIDCache cache);
bool silc_idcache_purge(SilcIDCache cache);
bool silc_idcache_purge_by_context(SilcIDCache cache, void *context);
bool silc_idcache_get_all(SilcIDCache cache, SilcIDCacheList *ret);
bool silc_idcache_find_by_id(SilcIDCache cache, void *id, 
			     SilcIDCacheList *ret);
bool silc_idcache_find_by_id_one(SilcIDCache cache, void *id, 
				 SilcIDCacheEntry *ret);
bool silc_idcache_find_by_id_one_ext(SilcIDCache cache, void *id, 
				     SilcHashFunction hash, 
				     void *hash_context,
				     SilcHashCompare compare, 
				     void *compare_context,
				     SilcIDCacheEntry *ret);
bool silc_idcache_find_by_context(SilcIDCache cache, void *context, 
				  SilcIDCacheEntry *ret);
bool silc_idcache_find_by_name(SilcIDCache cache, char *name, 
			       SilcIDCacheList *ret);
bool silc_idcache_find_by_name_one(SilcIDCache cache, char *name,
				   SilcIDCacheEntry *ret);
int silc_idcache_list_count(SilcIDCacheList list);
bool silc_idcache_list_first(SilcIDCacheList list, SilcIDCacheEntry *ret);
bool silc_idcache_list_next(SilcIDCacheList list, SilcIDCacheEntry *ret);
void silc_idcache_list_free(SilcIDCacheList list);

#endif
