/*

  silcidcache.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2000 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcapputil/SILC ID Cache Interface
 *
 * DESCRIPTION
 *
 * SILC ID Cache is an cache for all kinds of ID's used in the SILC
 * protocol.  Application can save here the ID's it uses and the interface
 * provides fast retrieval of the ID's from the cache.
 *
 * SILC ID Cache is not thread-safe.  If the same cache context must be
 * used in multithreaded environment concurrency control must be employed.
 *
 ***/

#ifndef SILCIDCACHE_H
#define SILCIDCACHE_H

/****s* silcapputil/SilcIDCacheAPI/SilcIDCacheEntry
 *
 * NAME
 *
 *    typedef struct SilcIDCacheEntryStruct { ... } SilcIDCacheEntry;
 *
 * DESCRIPTION
 *
 *    This is an entry in the SILC ID Cache system.  This context is
 *    allocated by adding new entry to ID cache by calling silc_idcache_add.
 *    Each of the fields in the structure are allocated by the caller.
 *
 * SOURCE
 */
typedef struct SilcIDCacheEntryStruct {
  struct SilcIDCacheEntryStruct *next;
  void *id;			       /* Associated ID */
  char *name;			       /* Associated entry name */
  void *context;		       /* Associated context */
} *SilcIDCacheEntry;
/***/

/****s* silcapputil/SilcIDCacheAPI/SilcIDCache
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

/****f* silcapputil/SilcIDCacheAPI/SilcIDCacheDestructor
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcIDCacheDestructor)(SilcIDCache cache,
 *                                          const SilcIDCacheEntry entry,
 *                                          void *destructor_context,
 *                                          void *app_context);
 *
 * DESCRIPTION
 *
 *    Destructor callback given as argument to silc_idcache_alloc.  This
 *    is called when an entry is deleted from the cache.  Application
 *    must free the contents of the `entry'.
 *
 ***/
typedef void (*SilcIDCacheDestructor)(SilcIDCache cache,
				      const SilcIDCacheEntry entry,
				      void *destructor_context,
				      void *app_context);

/* Prototypes */

/****f* silcapputil/SilcIDCacheAPI/silc_idcache_alloc
 *
 * SYNOPSIS
 *
 *    SilcIDCache silc_idcache_alloc(SilcUInt32 count, SilcIdType id_type,
 *                                   SilcIDCacheDestructor destructor,
 *                                   void *destructor_context,
 *                                   SilcBool delete_id, SilcBool delete_name);
 *
 * DESCRIPTION
 *
 *    Allocates new ID cache object. The initial amount of allocated entries
 *    can be sent as argument. If `count' is 0 the system uses default values.
 *    The `id_type' defines the types of the ID's that will be saved to the
 *    cache.
 *
 ***/
SilcIDCache silc_idcache_alloc(SilcUInt32 count, SilcIdType id_type,
			       SilcIDCacheDestructor destructor,
			       void *destructor_context);

/****f* silcapputil/SilcIDCacheAPI/silc_idcache_free
 *
 * SYNOPSIS
 *
 *    void silc_idcache_free(SilcIDCache cache);
 *
 * DESCRIPTION
 *
 *    Frees ID cache context and all cache entries.
 *
 ***/
void silc_idcache_free(SilcIDCache cache);

/****f* silcapputil/SilcIDCacheAPI/silc_idcache_add
 *
 * SYNOPSIS
 *
 *    SilcIDCacheEntry
 *    silc_idcache_add(SilcIDCache cache, char *name, void *id, void *context);
 *
 * DESCRIPTION
 *
 *    Add new entry to the cache.  Returns the allocated cache entry if the
 *    entry was added successfully, or NULL if error occurred.  The `name' is
 *    the name associated with the ID, the `id' the actual ID and the
 *    `context' a caller specific context.  The caller is responsible of
 *    freeing the `name' and `id' when the entry is deleted.
 *
 ***/
SilcIDCacheEntry
silc_idcache_add(SilcIDCache cache, char *name, void *id, void *context);

/****f* silcapputil/SilcIDCacheAPI/silc_idcache_del
 *
 * SYNOPSIS
 *
 *    SilcBool silc_idcache_del(SilcIDCache cache, SilcIDCacheEntry entry,
 *                              void *app_context);
 *
 * DESCRIPTION
 *
 *    Delete cache entry from cache.  Returns TRUE if the entry was deleted.
 *    The destructor will be called for the entry.  The `app_context' is
 *    delivered to the destructor.
 *
 ***/
SilcBool silc_idcache_del(SilcIDCache cache, SilcIDCacheEntry entry,
			  void *app_context);

/****f* silcapputil/SilcIDCacheAPI/silc_idcache_del_by_id
 *
 * SYNOPSIS
 *
 *    SilcBool silc_idcache_del_by_id(SilcIDCache cache, void *id,
 *                                    void *app_context);
 *
 * DESCRIPTION
 *
 *    Delete cache entry by ID.  Returns TRUE if the entry was deleted.
 *    The destructor will be called for the entry.  The `app_context' is
 *    delivered to the destructor.
 *
 ***/
SilcBool silc_idcache_del_by_id(SilcIDCache cache, void *id,
				void *app_context);

/****f* silcapputil/SilcIDCacheAPI/silc_idcache_del_by_context
 *
 * SYNOPSIS
 *
 *    SilcBool silc_idcache_del_by_context(SilcIDCache cache, void *context);
 *
 * DESCRIPTION
 *
 *    Deletes cachen entry by the user specified context.  Returns TRUE
 *    if the entry was deleted.  The destructor will be called for the
 *    entry.  The `app_context' is delivered to the destructor.
 *
 ***/
SilcBool silc_idcache_del_by_context(SilcIDCache cache, void *context,
				     void *app_context);

/****f* silcapputil/SilcIDCacheAPI/silc_idcache_update
 *
 * SYNOPSIS
 *
 *    SilcBool silc_idcache_update(SilcIDCache cache, SilcIDCacheEntry entry,
 *                                 void *new_id, char *new_name,
 *                                 SilcBool free_old_name);
 *
 * DESCRIPTION
 *
 *    Updates cache `entry' with new values.  If the `new_id' is non-NULL
 *    then the new value will be copied over the old value in the `entry'
 *    unless the ID doesn't exist, when the `new_id' will be stored in `entry'.
 *    If the `new_name' is non-NULL then the `entry' will be updated with
 *    `new_name'.  The caller is responsible of freeing the old name if it
 *    was updated with new one.  The old ID value does not need to be freed
 *    as the new value is copied over the old value.  If the `free_old_name'
 *    is TRUE the library will free the old name from the entry.
 *
 ***/
SilcBool silc_idcache_update(SilcIDCache cache, SilcIDCacheEntry entry,
			     void *new_id, char *new_name,
			     SilcBool free_old_name);

/****f* silcapputil/SilcIDCacheAPI/silc_idcache_update_by_context
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_idcache_update_by_context(SilcIDCache cache, void *context,
 *                                   void *new_id, char *new_name,
 *                                   SilcBool free_old_name);
 *
 * DESCRIPTION
 *
 *    Same as silc_idcache_update but finds the corrent ID cache entry by
 *    the `context' added to the ID cache.
 *
 ***/
SilcBool silc_idcache_update_by_context(SilcIDCache cache, void *context,
					void *new_id, char *new_name,
					SilcBool free_old_name);

/****f* silcapputil/SilcIDCacheAPI/silc_idcache_get_all
 *
 * SYNOPSIS
 *
 *    SilcBool silc_idcache_get_all(SilcIDCache cache, SilcList *ret_list);
 *
 * DESCRIPTION
 *
 *    Returns all cache entries into the SilcList `ret_list' pointer.  Each
 *    entry in the list is SilcIDCacheEntry.  Returns FALSE if the cache
 *    is empty.
 *
 ***/
SilcBool silc_idcache_get_all(SilcIDCache cache, SilcList *ret_list);

/****f* silcapputil/SilcIDCacheAPI/silc_idcache_find_by_id
 *
 * SYNOPSIS
 *
 *    SilcBool silc_idcache_find_by_id(SilcIDCache cache, void *id,
 *                                     SilcList *ret_list);
 *
 * DESCRIPTION
 *
 *    Find ID Cache entry by ID.  This may return multiple entries.
 *    The entires are returned into the `ret_list' SilcList context.
 *    Returns TRUE if entry was found.
 *
 * NOTES
 *
 *    If this function is used to find Client ID (SilcClientID), only the
 *    hash portion of the Client ID is compared.  Use the function
 *    silc_idcache_find_by_id_one to find exact match for Client ID (full
 *    ID is compared and not only the hash).
 *
 *    Comparing only the hash portion of Client ID allows searching of
 *    Client ID's by nickname, because the hash is based on the nickname.
 *    As nicknames are not unique, multiple entries may be found.
 *
 ***/
SilcBool silc_idcache_find_by_id(SilcIDCache cache, void *id,
				 SilcList *ret_list);

/****f* silcapputil/SilcIDCacheAPI/silc_idcache_find_by_id_one
 *
 * SYNOPSIS
 *
 *     SilcBool silc_idcache_find_by_id_one(SilcIDCache cache, void *id,
 *                                          SilcIDCacheEntry *ret);
 *
 * DESCRIPTION
 *
 *    Find ID Cache entry by ID.  Returns only one entry from the cache
 *    and the found entry is considered to be exact match.  Returns TRUE
 *    if the entry was found.
 *
 ***/
SilcBool silc_idcache_find_by_id_one(SilcIDCache cache, void *id,
				     SilcIDCacheEntry *ret);

/****f* silcapputil/SilcIDCacheAPI/silc_idcache_find_by_context
 *
 * SYNOPSIS
 *
 *    SilcBool silc_idcache_find_by_context(SilcIDCache cache, void *context,
 *                                      SilcIDCacheEntry *ret);
 *
 * DESCRIPTION
 *
 *    Find cache entry by user specified context. Returns TRUE if the
 *    entry was found.
 *
 ***/
SilcBool silc_idcache_find_by_context(SilcIDCache cache, void *context,
				      SilcIDCacheEntry *ret);

/****f* silcapputil/SilcIDCacheAPI/silc_idcache_find_by_name
 *
 * SYNOPSIS
 *
 *    SilcBool silc_idcache_find_by_name(SilcIDCache cache, char *name,
 *                                       SilcList *ret_list);
 *
 * DESCRIPTION
 *
 *    Find cache entries by the name associated with the ID.  This may
 *    return multiple entries to the `ret_list' SilcList context.  Returns
 *    TRUE if the entry was found.
 *
 ***/
SilcBool silc_idcache_find_by_name(SilcIDCache cache, char *name,
				   SilcList *ret_list);

/****f* silcapputil/SilcIDCacheAPI/silc_idcache_find_by_name_one
 *
 * SYNOPSIS
 *
 *    SilcBool silc_idcache_find_by_name_one(SilcIDCache cache, char *name,
 *                                       SilcIDCacheEntry *ret);
 *
 * DESCRIPTION
 *
 *    Find cache entry by the name associated with the ID.  This returns
 *    one entry and the found entry is considered to be exact match.
 *    Returns TRUE if the entry was found.
 *
 ***/
SilcBool silc_idcache_find_by_name_one(SilcIDCache cache, char *name,
				       SilcIDCacheEntry *ret);

#endif /* SILCIDCACHE_H */
