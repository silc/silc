/*

  silchashtable.c

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
/* Implementation of collision resistant hash table. */
/* $Id$ */

#include "silcincludes.h"
#include "silchashtable.h"

/* Default size of the hash table (index to prime table) */
#define SILC_HASH_TABLE_SIZE 3

/* Produce the index by hashing the key */
#define SILC_HASH_TABLE_HASH (ht->hash(key) % primesize[ht->table_size])

/* One entry in the hash table. Includes the key and the associated
   context. The `next' pointer is non-NULL if two (or more) different
   keys hashed to same value.  The pointer is the pointer to the next
   entry. */
typedef struct SilcHashTableEntryStruct {
  void *key;
  void *context;
  struct SilcHashTableEntryStruct *next;
} *SilcHashTableEntry;

/* Hash table. */
struct SilcHashTableStruct {
  SilcHashTableEntry *table;
  uint32 table_size;
  SilcHashFunction hash;
  SilcHashCompare compare;
  SilcHashDestructor destructor;
};

/* Prime sizes for the hash table. The size of the table will always
   be one of these. */
const uint32 primesize[42] = 
{
  1, 3, 5, 11, 17, 37, 67, 109, 131, 163, 257, 367, 521, 823, 1031, 
  1237, 2053, 2777, 4099, 6247, 8209, 14057, 16411, 21089, 32771, 47431,
  65537, 106721, 131101, 262147, 360163, 524309, 810343, 1048583, 2097169,
  4194319, 6153409, 8388617, 13845163, 16777259, 33554467, 67108879
};

/* Find appropriate size for the hash table. The size will be a prime. */

static uint32 silc_hash_table_primesize(uint32 size, uint32 *index)
{
  int i;

  for (i = 0; i < sizeof(primesize); i++)
    if (primesize[i] >= size) {
      *index = i;
      return primesize[i];
    }

  *index = i - 1;
  return primesize[i - 1];
}

/* Internal routine to find entry in the hash table by `key'. */

static inline SilcHashTableEntry *
silc_hash_table_find_internal(SilcHashTable ht, void *key,
			      SilcHashTableEntry *prev_entry)
{
  SilcHashTableEntry *entry, prev = NULL;

  entry = &ht->table[SILC_HASH_TABLE_HASH];
  if (ht->compare) {
    while (*entry && ht->compare((*entry)->key, key) == FALSE) {
      prev = *entry;
      entry = &(*entry)->next;
    }
  } else {
    while (*entry && (*entry)->key != key) {
      prev = *entry;
      entry = &(*entry)->next;
    }
  }

  *prev_entry = prev;
  return entry;
}

/* Allocates new hash table and returns it.  If the `table_size' is not
   zero then the hash table size is the size provided. If zero then the
   default size will be used. Note that if the `table_size' is provided
   it should be a prime. The `hash', `compare' and `destructor' are
   the hash function, the key comparison function and key and context
   destructor function, respectively. The `hash' is mandatory, the others
   are optional. */

SilcHashTable silc_hash_table_alloc(uint32 table_size, 
				    SilcHashFunction hash,
				    SilcHashCompare compare,
				    SilcHashDestructor destructor)
{
  SilcHashTable ht;
  uint32 size_index = SILC_HASH_TABLE_SIZE;

  if (!hash)
    return NULL;

  ht = silc_calloc(1, sizeof(*ht));
  ht->table = silc_calloc(table_size ? silc_hash_table_primesize(table_size,
								 &size_index) :
			  primesize[SILC_HASH_TABLE_SIZE],
			  sizeof(*ht->table));
  ht->table_size = size_index;
  ht->hash = hash;
  ht->compare = compare;
  ht->destructor = destructor;

  return ht;
}

/* Frees the hash table. The destructor function provided in the
   silc_hash_table_alloc will be called for all keys in the hash table. */

void silc_hash_table_free(SilcHashTable ht)
{
  int i;

  for (i = 0; i < primesize[ht->table_size]; i++)
    if (ht->table[i]) {
      if (ht->destructor)
	ht->destructor(ht->table[i]->key, ht->table[i]->context);
      silc_free(ht->table[i]);
    }

  silc_free(ht->table);
  silc_free(ht);
}

/* Returns the size of the hash table */

uint32 silc_hash_table_size(SilcHashTable ht)
{
  return primesize[ht->table_size];
}

/* Adds new entry to the hash table. The `key' is hashed using the
   hash function and the both `key' and `context' will be saved to the
   hash table. This function quarantees that the entry is always added
   to the hash table reliably (it is collision resistant). */

void silc_hash_table_add(SilcHashTable ht, void *key, void *context)
{
  SilcHashTableEntry *entry;
  uint32 index = SILC_HASH_TABLE_HASH;

  entry = &ht->table[index];
  if (*entry) {
    /* The entry exists already. We have a collision, add it to the
       list to avoid collision. */
    SilcHashTableEntry e, tmp;

    e = *entry;
    tmp = e->next;
    while (tmp) {
      e = tmp;
      tmp = tmp->next;
    }

    e->next = silc_calloc(1, sizeof(*e->next));
    e->next->key = key;
    e->next->context = context;
  } else {
    /* New key */
    *entry = silc_calloc(1, sizeof(**entry));
    (*entry)->key = key;
    (*entry)->context = context;
  }
}

/* Same as above but if the `key' already exists in the hash table
   the old key and the old context will be replace with the `key' and
   the `context. The destructor function will be called for the
   replaced key and context. */

void silc_hash_table_replace(SilcHashTable ht, void *key, void *context)
{
  SilcHashTableEntry *entry;
  uint32 index = SILC_HASH_TABLE_HASH;

  entry = &ht->table[index];
  if (*entry) {
    /* The entry exists already. We have a collision, replace the old
       key and context. */
    if (ht->destructor)
      ht->destructor((*entry)->key, (*entry)->context);
  } else {
    /* New key */
    *entry = silc_calloc(1, sizeof(**entry));
  }

  (*entry)->key = key;
  (*entry)->context = context;
}

/* Removes the entry from the hash table by the provided `key'. This will
   call the destructor funtion for the found entry. Return TRUE if the
   entry was removed successfully and FALSE otherwise. */

bool silc_hash_table_del(SilcHashTable ht, void *key)
{
  SilcHashTableEntry *entry, prev, e;

  entry = silc_hash_table_find_internal(ht, key, &prev);
  if (*entry == NULL)
    return FALSE;

  e = *entry;

  if (!prev && e->next)
    *entry = e->next;
  if (!prev && e->next == NULL)
    *entry = NULL;
  if (prev)
    prev->next = NULL;
  if (prev && e->next)
    prev->next = e->next;

  if (ht->destructor)
    ht->destructor(e->key, e->context);
  silc_free(e);

  return TRUE;
}

/* Finds the entry in the hash table by the provided `key' as fast as
   possible. Return TRUE if the entry was found and FALSE otherwise. 
   The found entry is returned to the `ret_key' and `ret_context',
   respectively. If the `ret_key and `ret_context' are NULL then this
   maybe used only to check whether given key exists in the table. */

bool silc_hash_table_find(SilcHashTable ht, void *key,
			  void **ret_key, void **ret_context)
{
  SilcHashTableEntry *entry, prev;

  entry = silc_hash_table_find_internal(ht, key, &prev);
  if (*entry == NULL)
    return FALSE;

  if (ret_key)
    *ret_key = (*entry)->key;
  if (ret_context)
    *ret_context = (*entry)->context;

  return TRUE;
}

/* Rehashs the hash table. The size of the new hash table is provided
   as `new_size'. If the `new_size' is zero then this routine will make
   the new table of a suitable size. Note that this operation may be
   very slow. */

void silc_hash_table_rehash(SilcHashTable ht, uint32 new_size)
{

}
