/*

  silchashtable.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCHASHTABLE_H
#define SILCHASHTABLE_H

/* Forward declarations */
typedef struct SilcHashTableStruct *SilcHashTable;

/* A type for the hash function. This function is used to hash the
   provided key value `key' and return the index for the hash table. */
typedef uint32 (*SilcHashFunction)(void *key);

/* A comparison funtion that is called to compare the two keys `key1' and
   `key2'. If they are equal this must return TRUE or FALSE otherwise.
   The application provides this function when allocating a new hash table. */
typedef bool (*SilcHashCompare)(void *key1, void *key2);

/* A destructor callback that the library will call to destroy the 
   `key' and `context'.  The appliation provides the function when
   allocating a new hash table. */
typedef void (*SilcHashDestructor)(void *key, void *context);

/* Prototypes */
SilcHashTable silc_hash_table_alloc(uint32 table_size, 
				    SilcHashFunction hash,
				    SilcHashCompare compare,
				    SilcHashDestructor destructor);
void silc_hash_table_free(SilcHashTable ht);
uint32 silc_hash_table_size(SilcHashTable ht);
void silc_hash_table_add(SilcHashTable ht, void *key, void *context);
void silc_hash_table_replace(SilcHashTable ht, void *key, void *context);
bool silc_hash_table_del(SilcHashTable ht, void *key);
bool silc_hash_table_find(SilcHashTable ht, void *key,
			  void **ret_key, void **ret_context);
void silc_hash_table_rehash(SilcHashTable ht, uint32 new_size);

#endif
