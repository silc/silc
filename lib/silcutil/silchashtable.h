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
typedef struct SilcHashTableListStruct SilcHashTableList;

/* List structure to traverse the hash table. */
struct SilcHashTableListStruct {
  SilcHashTable ht;
  void *entry;
  uint32 index;
};

/* A type for the hash function. This function is used to hash the
   provided key value `key' and return the index for the hash table. */
typedef uint32 (*SilcHashFunction)(void *key, void *user_context);

/* A comparison funtion that is called to compare the two keys `key1' and
   `key2'. If they are equal this must return TRUE or FALSE otherwise.
   The application provides this function when allocating a new hash table. */
typedef bool (*SilcHashCompare)(void *key1, void *key2, void *user_context);

/* A destructor callback that the library will call to destroy the 
   `key' and `context'.  The appliation provides the function when
   allocating a new hash table. */
typedef void (*SilcHashDestructor)(void *key, void *context, 
				   void *user_context);

/* Foreach function. This is called when traversing the entrys in the
   hash table using silc_hash_table_foreach. */
typedef void (*SilcHashForeach)(void *key, void *context, void *user_context);

/* Simple hash table interface */

SilcHashTable silc_hash_table_alloc(uint32 table_size, 
				    SilcHashFunction hash,
				    void *hash_user_context,
				    SilcHashCompare compare,
				    void *compare_user_context,
				    SilcHashDestructor destructor,
				    void *destructor_user_context,
				    bool auto_rehash);
void silc_hash_table_free(SilcHashTable ht);
uint32 silc_hash_table_size(SilcHashTable ht);
uint32 silc_hash_table_count(SilcHashTable ht);
void silc_hash_table_add(SilcHashTable ht, void *key, void *context);
void silc_hash_table_replace(SilcHashTable ht, void *key, void *context);
bool silc_hash_table_del(SilcHashTable ht, void *key);
bool silc_hash_table_del_by_context(SilcHashTable ht, void *key, 
				    void *context);
bool silc_hash_table_find(SilcHashTable ht, void *key,
			  void **ret_key, void **ret_context);
void silc_hash_table_find_foreach(SilcHashTable ht, void *key,
				  SilcHashForeach foreach, void *user_context);
void silc_hash_table_foreach(SilcHashTable ht, SilcHashForeach foreach,
			     void *user_context);
void silc_hash_table_rehash(SilcHashTable ht, uint32 new_size);
void silc_hash_table_list(SilcHashTable ht, SilcHashTableList *htl);
bool silc_hash_table_get(SilcHashTableList *htl, void **key, void **context);


/* Extended hash table interface (same as above but with specific
   hash and comparison functions). */

void silc_hash_table_add_ext(SilcHashTable ht, void *key, void *context,
			     SilcHashFunction hash, void *hash_user_context);
void silc_hash_table_replace_ext(SilcHashTable ht, void *key, void *context,
				 SilcHashFunction hash, 
				 void *hash_user_context);
bool silc_hash_table_del_ext(SilcHashTable ht, void *key,
			     SilcHashFunction hash, 
			     void *hash_user_context,
			     SilcHashCompare compare, 
			     void *compare_user_context);
bool silc_hash_table_del_by_context_ext(SilcHashTable ht, void *key, 
					void *context,
					SilcHashFunction hash, 
					void *hash_user_context,
					SilcHashCompare compare, 
					void *compare_user_context);
bool silc_hash_table_find_ext(SilcHashTable ht, void *key,
			      void **ret_key, void **ret_context,
			      SilcHashFunction hash, 
			      void *hash_user_context,
			      SilcHashCompare compare, 
			      void *compare_user_context);
void silc_hash_table_find_foreach_ext(SilcHashTable ht, void *key,
				      SilcHashFunction hash, 
				      void *hash_user_context,
				      SilcHashCompare compare, 
				      void *compare_user_context,
				      SilcHashForeach foreach, 
				      void *foreach_user_context);
void silc_hash_table_rehash_ext(SilcHashTable ht, uint32 new_size,
				SilcHashFunction hash, 
				void *hash_user_context);

#endif
