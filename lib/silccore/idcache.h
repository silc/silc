/*

  idcache.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

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
   SilcIDCache structure.

   char *data

      The data that is usually used to find the data from the cache.
      For example for Client ID's this is nickname.

   SilcIdType type

      Type of the ID.

   void *id

      The actual ID.

   unsigned long expire

      Time when this cache entry expires.  This is normal time() value
      plus the validity.  Cache entry has expired if current time is
      more than value in this field, or if this field has been set to
      zero (0) value.

   void *context

      Any caller specified context.

*/
typedef struct {
  char *data;
  SilcIdType type;
  void *id;
  unsigned long expire;
  void *context;
} SilcIDCache;

#define SILC_ID_CACHE_EXPIRE 3600

/* Prototypes */
void silc_idcache_sort_by_data(SilcIDCache *cache, unsigned int count);
int silc_idcache_find_by_data(SilcIDCache *cache, unsigned int cache_count,
			      char *data, SilcIDCache **ret);
int silc_idcache_find_by_id(SilcIDCache *cache, unsigned int cache_count, 
			    void *id, SilcIdType type, SilcIDCache **ret);
int silc_idcache_add(SilcIDCache **cache, unsigned int cache_count,
		     char *data, SilcIdType id_type, void *id, 
		     void *context);
int silc_idcache_del(SilcIDCache *cache, SilcIDCache *old);
int silc_idcache_del_by_data(SilcIDCache *cache, unsigned int cache_count,
			     char *data);
int silc_idcache_del_by_id(SilcIDCache *cache, unsigned int cache_count,
			   SilcIdType type, void *id);
int silc_idcache_del_all(SilcIDCache **cache, unsigned int cache_count);
int silc_idcache_purge(SilcIDCache *cache, unsigned int cache_count);

#endif
