/*

  silcidcache.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2000 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silccore/SILC ID Cache Interface
 *
 * DESCRIPTION
 *
 * SILC ID Cache is an cache for all kinds of ID's used in the SILC
 * protocol.  Application can save here the ID's it uses and the interface
 * provides fast retrieval of the ID's from the cache.
 *
 ***/

#ifndef SILCIDCACHE_H
#define SILCIDCACHE_H

/****s* silccore/SilcIDCacheAPI/SilcIDCacheEntry
 *
 * NAME
 *
 *    typedef struct { ... } SilcIDCacheEntry;
 *
 * DESCRIPTION
 *
 *    This is one entry in the SILC ID Cache system. Contents of this is
 *    allocated outside the ID cache system, however, all the fields are
 *    filled with ID cache utility functions. The ID cache system does not
 *    allocate any of these fields nor free them.
 *
 *    void *id
 *
 *      The actual ID.
 *
 *    char name
 *
 *      A name associated with the ID.
 *
 *    SilcUInt32 expire
 *
 *      Time when this cache entry expires.  This is normal time() value
 *      plus the validity.  Cache entry has expired if current time is
 *      more than value in this field.  If this value is zero (0) the
 *      entry never expires.
 *
 *    void *context
 *
 *      Any caller specified context.
 *
 * SOURCE
 */
typedef struct {
  void *id;
  char *name;
  SilcUInt32 expire;
  void *context;
} *SilcIDCacheEntry;
/***/

/****s* silccore/SilcIDCacheAPI/SilcIDCache
 *
 * NAME
 *
 *    typedef struct SilcIDCacheStruct *SilcIDCache;
 *
 * DESCRIPTION
 *
 *    This context is the actual ID Cache and is allocated by
 *    silc_idcache_alloc and given as argument usually to all
 *    silc_idcache_* functions.  It is freed by the
 *    silc_idcache_free function.
 *
 ***/
typedef struct SilcIDCacheStruct *SilcIDCache;

/****s* silccore/SilcIDCacheAPI/SilcIDCacheList
 *
 * NAME
 *
 *    typedef struct SilcIDCacheListStruct *SilcIDCacheList;
 *
 * DESCRIPTION
 *
 *    This context is the ID Cache List and is allocated by
 *    some of the silc_idcache_* functions. Functions that may return
 *    multiple entries from the cache allocate the entries in to the
 *    SilcIDCacheList. The context is freed by silc_idcache_list_free
 *    function.
 *
 ***/
typedef struct SilcIDCacheListStruct *SilcIDCacheList;

/****f* silccore/SilcIDCacheAPI/SilcIDCacheDestructor
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcIDCacheDestructor)(SilcIDCache cache,
 *                                          SilcIDCacheEntry entry,
 *                                          void *context);
 *
 * DESCRIPTION
 *
 *    Destructor callback that is called when an cache entry expires or is
 *    purged from the ID cache. The application must not free cache entry
 *    because the library will do it automatically. The appliation, however,
 *    is responsible of freeing any data in the entry.
 *
 ***/
typedef void (*SilcIDCacheDestructor)(SilcIDCache cache,
				      SilcIDCacheEntry entry,
				      void *context);

#define SILC_ID_CACHE_EXPIRE 3600
#define SILC_ID_CACHE_EXPIRE_DEF (time(NULL) + SILC_ID_CACHE_EXPIRE)

/* Prototypes */

/****f* silccore/SilcIDCacheAPI/silc_idcache_alloc
 *
 * SYNOPSIS
 *
 *    SilcIDCache silc_idcache_alloc(SilcUInt32 count, SilcIdType id_type,
 *                                   SilcIDCacheDestructor destructor,
 *                                   void *destructor_context,
 *                                   bool delete_id, bool delete_name);
 *
 * DESCRIPTION
 *
 *    Allocates new ID cache object. The initial amount of allocated entries
 *    can be sent as argument. If `count' is 0 the system uses default values.
 *    The `id_type' defines the types of the ID's that will be saved to the
 *    cache.
 *
 *    If 'delete_id' is TRUE then library will free the ID when a
 *    cache entry is deleted.  If 'delete_name' is TRUE then library
 *    will delete the associated name when a cache entry is deleted.
 *
 ***/
SilcIDCache silc_idcache_alloc(SilcUInt32 count, SilcIdType id_type,
			       SilcIDCacheDestructor destructor,
			       void *destructor_context,
			       bool delete_id, bool delete_name);

/****f* silccore/SilcIDCacheAPI/silc_idcache_free
 *
 * SYNOPSIS
 *
 *    void silc_idcache_free(SilcIDCache cache);
 *
 * DESCRIPTION
 *
 *    Frees ID cache object and all cache entries.
 *
 ***/
void silc_idcache_free(SilcIDCache cache);

/****f* silccore/SilcIDCacheAPI/silc_idcache_add
 *
 * SYNOPSIS
 *
 *    bool silc_idcache_add(SilcIDCache cache, char *name, void *id,
 *                          void *context, int expire, SilcIDCacheEntry *ret);
 *
 * DESCRIPTION
 *
 *    Add new entry to the cache. Returns TRUE if the entry was added and
 *    FALSE if it could not be added. The `name' is the name associated with
 *    the ID, the `id' the actual ID and the `context' a user specific context.
 *    If the `expire' is non-zero the entry expires in that specified time.
 *    If zero the entry never expires from the cache.
 *
 *    The `name', `id' and `context' pointers will be saved in the cache,
 *    and if the caller frees these pointers the caller is also responsible
 *    of deleting the cache entry.  Otherwise the cache will have the freed
 *    pointers stored.
 *
 *    If the `ret' is non-NULL the created ID Cache entry is returned to
 *    that pointer.
 *
 ***/
bool silc_idcache_add(SilcIDCache cache, char *name, void *id,
		      void *context, int expire, SilcIDCacheEntry *ret);

/****f* silccore/SilcIDCacheAPI/silc_idcache_del
 *
 * SYNOPSIS
 *
 *    bool silc_idcache_del(SilcIDCache cache, SilcIDCacheEntry old);
 *
 * DESCRIPTION
 *
 *    Delete cache entry from cache. Returns TRUE if the entry was deleted.
 *    The destructor function is not called.
 *
 ***/
bool silc_idcache_del(SilcIDCache cache, SilcIDCacheEntry old);

/****f* silccore/SilcIDCacheAPI/silc_idcache_del_by_id
 *
 * SYNOPSIS
 *
 *    bool silc_idcache_del_by_id(SilcIDCache cache, void *id);
 *
 * DESCRIPTION
 *
 *    Delete cache entry by ID. Returns TRUE if the entry was deleted.
 *    The destructor function is not called.
 *
 ***/
bool silc_idcache_del_by_id(SilcIDCache cache, void *id);

/****f* silccore/SilcIDCacheAPI/silc_idcache_del_by_id_ext
 *
 * SYNOPSIS
 *
 *    bool silc_idcache_del_by_id_ext(SilcIDCache cache, void *id,
 *                                    SilcHashFunction hash,
 *                                    void *hash_context,
 *                                    SilcHashCompare compare,
 *                                    void *compare_context);
 *
 * DESCRIPTION
 *
 *    Same as silc_idcache_del_by_id but with specific hash and comparison
 *    functions. If the functions are NULL then default values are used.
 *    Returns TRUE if the entry was deleted. The destructor function is
 *    called.
 *
 ***/
bool silc_idcache_del_by_id_ext(SilcIDCache cache, void *id,
				SilcHashFunction hash,
				void *hash_context,
				SilcHashCompare compare,
				void *compare_context);

/****f* silccore/SilcIDCacheAPI/silc_idcache_del_by_context
 *
 * SYNOPSIS
 *
 *    bool silc_idcache_del_by_context(SilcIDCache cache, void *context);
 *
 * DESCRIPTION
 *
 *    Deletes cachen entry by the user specified context. Returns TRUE
 *    if the entry was deleted. The destructor function is not called.
 *
 ***/
bool silc_idcache_del_by_context(SilcIDCache cache, void *context);

/****f* silccore/SilcIDCacheAPI/silc_idcache_del_all
 *
 * SYNOPSIS
 *
 *    bool silc_idcache_del_all(SilcIDCache cache);
 *
 * DESCRIPTION
 *
 *    Deletes all cache entries from the cache and frees all memory.
 *    The destructor function is not called.
 *
 ***/
bool silc_idcache_del_all(SilcIDCache cache);

/****f* silccore/SilcIDCacheAPI/silc_idcache_purge
 *
 * SYNOPSIS
 *
 *    bool silc_idcache_purge(SilcIDCache cache);
 *
 * DESCRIPTION
 *
 *    Purges the cache by removing expired cache entires. Note that this
 *    may be very slow operation. Returns TRUE if the purging was successful.
 *    The destructor function is called for each purged cache entry.
 *
 ***/
bool silc_idcache_purge(SilcIDCache cache);

/****f* silccore/SilcIDCacheAPI/silc_idcache_by_context
 *
 * SYNOPSIS
 *
 *    bool silc_idcache_purge_by_context(SilcIDCache cache, void *context);
 *
 * DESCRIPTION
 *
 *    Purges the cache by context and removes expired cache entires.
 *    Returns TRUE if the puring was successful. The destructor function
 *    is called for the purged cache entry.
 *
 ***/
bool silc_idcache_purge_by_context(SilcIDCache cache, void *context);

/****f* silccore/SilcIDCacheAPI/silc_idcache_get_all
 *
 * SYNOPSIS
 *
 *    bool silc_idcache_get_all(SilcIDCache cache, SilcIDCacheList *ret);
 *
 * DESCRIPTION
 *
 *    Returns all cache entries from the ID cache to the `ret' SilcIDCacheList.
 *    Returns TRUE if the retrieval was successful. The caller must free
 *    the returned SilcIDCacheList.
 *
 ***/
bool silc_idcache_get_all(SilcIDCache cache, SilcIDCacheList *ret);

/****f* silccore/SilcIDCacheAPI/silc_idcache_find_by_id
 *
 * SYNOPSIS
 *
 *    bool silc_idcache_find_by_id(SilcIDCache cache, void *id,
 *                                 SilcIDCacheList *ret);
 *
 * DESCRIPTION
 *
 *    Find ID Cache entry by ID. This may return multiple entry and the
 *    `ret' SilcIDCacheList is allocated. Returns TRUE if the entry was
 *    found. The caller must free the returned SilcIDCacheList.
 *
 ***/
bool silc_idcache_find_by_id(SilcIDCache cache, void *id,
			     SilcIDCacheList *ret);

/****f* silccore/SilcIDCacheAPI/silc_idcache_find_by_id_one
 *
 * SYNOPSIS
 *
 *     bool silc_idcache_find_by_id_one(SilcIDCache cache, void *id,
 *                                      SilcIDCacheEntry *ret);
 *
 * DESCRIPTION
 *
 *    Find ID Cache entry by ID. Returns only one entry from the cache
 *    and the found entry is considered to be exact match. Returns TRUE
 *    if the entry was found.
 *
 ***/
bool silc_idcache_find_by_id_one(SilcIDCache cache, void *id,
				 SilcIDCacheEntry *ret);

/****f* silccore/SilcIDCacheAPI/silc_idcache_find_by_id_one_ext
 *
 * SYNOPSIS
 *
 *    bool silc_idcache_find_by_id_one_ext(SilcIDCache cache, void *id,
 *                                         SilcHashFunction hash,
 *                                         void *hash_context,
 *                                         SilcHashCompare compare,
 *                                         void *compare_context,
 *                                         SilcIDCacheEntry *ret);
 *
 * DESCRIPTION
 *
 *    Same as silc_idcache_find_by_id_one but with specific hash and
 *    comparison functions. If `hash' is NULL then the default hash
 *    funtion is used and if `compare' is NULL default comparison function
 *    is used. Returns TRUE if the entry was found.
 *
 ***/
bool silc_idcache_find_by_id_one_ext(SilcIDCache cache, void *id,
				     SilcHashFunction hash,
				     void *hash_context,
				     SilcHashCompare compare,
				     void *compare_context,
				     SilcIDCacheEntry *ret);

/****f* silccore/SilcIDCacheAPI/silc_idcache_find_by_context
 *
 * SYNOPSIS
 *
 *    bool silc_idcache_find_by_context(SilcIDCache cache, void *context,
 *                                      SilcIDCacheEntry *ret);
 *
 * DESCRIPTION
 *
 *    Find cache entry by user specified context. Returns TRUE if the
 *    entry was found.
 *
 ***/
bool silc_idcache_find_by_context(SilcIDCache cache, void *context,
				  SilcIDCacheEntry *ret);

/****f* silccore/SilcIDCacheAPI/silc_idcache_find_by_name
 *
 * SYNOPSIS
 *
 *    bool silc_idcache_find_by_name(SilcIDCache cache, char *name,
 *                                   SilcIDCacheList *ret);
 *
 * DESCRIPTION
 *
 *    Find cache entries by the name associated with the ID. This may
 *    return muliptle entries allocated to the SilcIDCacheList. Returns
 *    TRUE if the entry was found. The caller must free the SIlcIDCacheList.
 *
 ***/
bool silc_idcache_find_by_name(SilcIDCache cache, char *name,
			       SilcIDCacheList *ret);

/****f* silccore/SilcIDCacheAPI/silc_idcache_find_by_name_one
 *
 * SYNOPSIS
 *
 *    bool silc_idcache_find_by_name_one(SilcIDCache cache, char *name,
 *                                       SilcIDCacheEntry *ret);
 *
 * DESCRIPTION
 *
 *    Find cache entry by the name associated with the ID. This returns
 *    one entry and the found entry is considered to be exact match.
 *    return muliptle entries allocated to the SilcIDCacheList. Returns
 *    TRUE if the entry was found.
 *
 ***/
bool silc_idcache_find_by_name_one(SilcIDCache cache, char *name,
				   SilcIDCacheEntry *ret);

/****f* silccore/SilcIDCacheAPI/silc_idcache_list_count
 *
 * SYNOPSIS
 *
 *    int silc_idcache_list_count(SilcIDCacheList list);
 *
 * DESCRIPTION
 *
 *    Returns the number of cache entries in the ID cache list.
 *
 ***/
int silc_idcache_list_count(SilcIDCacheList list);

/****f* silccore/SilcIDCacheAPI/silc_idcache_list_first
 *
 * SYNOPSIS
 *
 *    bool silc_idcache_list_first(SilcIDCacheList list,
 *                                 SilcIDCacheEntry *ret);
 *
 * DESCRIPTION
 *
 *    Returns the first cache entry from the ID cache list. Returns FALSE
 *    If the entry could not be retrieved.
 *
 ***/
bool silc_idcache_list_first(SilcIDCacheList list, SilcIDCacheEntry *ret);

/****f* silccore/SilcIDCacheAPI/silc_idcache_list_next
 *
 * SYNOPSIS
 *
 *    bool silc_idcache_list_next(SilcIDCacheList list, SilcIDCacheEntry *ret);
 *
 * DESCRIPTION
 *
 *    Returns the next cache entry from the ID Cache list. Returns FALSE
 *    when there are not anymore entries in the list.
 *
 ***/
bool silc_idcache_list_next(SilcIDCacheList list, SilcIDCacheEntry *ret);

/****f* silccore/SilcIDCacheAPI/silc_idcache_list_free
 *
 * SYNOPSIS
 *
 *    void silc_idcache_list_free(SilcIDCacheList list);
 *
 * DESCRIPTION
 *
 *     Frees ID cache list. User must free the list context returned by
 *     any of the searching functions.
 *
 ***/
void silc_idcache_list_free(SilcIDCacheList list);

#endif
