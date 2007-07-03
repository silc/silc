/*

  silchashtable.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Hash Table Interface
 *
 * DESCRIPTION
 *
 * Implementation of collision resistant hash table. This is a hash table
 * that provides a reliable (what you add there stays there, and duplicate
 * keys are allowed) with as fast reference to the key as possible. If
 * there are a lot of duplicate keys in the hash table the lookup slows down.
 * However, this is reliable and no data is lost at any point. If you know
 * that you never have duplicate keys then this is as fast as any simple hash
 * table.
 *
 * The interface provides many ways to search the hash table including
 * an extended interface where caller can specify its own hash and comparison
 * functions.  The interface also supports SilcStack and all memory allocated
 * by the hash table can be allocated from SilcStack.
 *
 * There are two ways to traverse the entire hash table if this feature
 * is needed. There exists a foreach function that calls a foreach
 * callback for each entry in the hash table. Other way is to use
 * SilcHashTableList structure and traverse the hash table inside while()
 * using the list structure. Both are equally fast.
 *
 * The hash table is not thread safe.  If same SilcHashtable context is used
 * in multi thread environment concurrency control must be employed.
 *
 ***/

#ifndef SILCHASHTABLE_H
#define SILCHASHTABLE_H

/****s* silcutil/SilcHashTableAPI/SilcHashTable
 *
 * NAME
 *
 *    typedef struct SilcHashTableStruct *SilcHashTable;
 *
 * DESCRIPTION
 *
 *    This context is the actual hash table and is allocated
 *    by silc_hash_table_alloc and given as argument usually to
 *    all silc_hash_table_* functions.  It is freed by the
 *    silc_hash_table_free function.
 *
 ***/
typedef struct SilcHashTableStruct *SilcHashTable;

/****s* silcutil/SilcHashTableAPI/SilcHashTableList
 *
 * NAME
 *
 *    typedef struct SilcHashTableListStruct SilcHashTableList;
 *
 * DESCRIPTION
 *
 *    This structure is used to tarverse the hash table. This structure
 *    is given as argument to the silc_hash_table_list function to
 *    initialize it and then used to traverse the hash table with the
 *    silc_hash_table_get function. It needs not be allocated or freed.
 *
 * EXAMPLE
 *
 *    SilcHashTableList htl;
 *    silc_hash_table_list(hash_table, &htl);
 *    while (silc_hash_table_get(&htl, (void *)&key, (void *)&context))
 *      ...
 *    silc_hash_table_list_reset(&htl);
 *
 * SOURCE
 */
typedef struct SilcHashTableListStruct SilcHashTableList;

/* List structure to traverse the hash table. */
struct SilcHashTableListStruct {
  SilcHashTable ht;
  void *entry;
  unsigned int index        : 31;
  unsigned int auto_rehash  : 1;
};
/***/

/****f* silcutil/SilcHashTableAPI/SilcHashFunction
 *
 * SYNOPSIS
 *
 *    typedef SilcUInt32 (*SilcHashFunction)(void *key, void *user_context);
 *
 * DESCRIPTION
 *
 *    A type for the hash function. This function is used to hash the
 *    provided key value `key' and return the index for the hash table.
 *    The `user_context' is application specific context and is delivered
 *    to the callback.
 *
 ***/
typedef SilcUInt32 (*SilcHashFunction)(void *key, void *user_context);

/****f* silcutil/SilcHashTableAPI/SilcHashCompare
 *
 * SYNOPSIS
 *
 *    typedef SilcBool (*SilcHashCompare)(void *key1, void *key2,
 *                                        void *user_context);
 *
 * DESCRIPTION
 *
 *    A comparison funtion that is called to compare the two keys `key1' and
 *    `key2'. If they are equal this must return TRUE or FALSE otherwise.
 *    The application provides this function when allocating a new hash table.
 *    The `user_context' is application specific context and is delivered
 *    to the callback.
 *
 ***/
typedef SilcBool (*SilcHashCompare)(void *key1, void *key2,
				    void *user_context);

/****f* silcutil/SilcHashTableAPI/SilcHashDestructor
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcHashDestructor)(void *key, void *context,
 *                                       void *user_context);
 *
 * DESCRIPTION
 *
 *    A destructor callback that the library will call to destroy the
 *    `key' and `context'.  The application provides the function when
 *    allocating a new hash table. The `user_context' is application
 *    specific context and is delivered to the callback.
 *
 ***/
typedef void (*SilcHashDestructor)(void *key, void *context,
				   void *user_context);

/****f* silcutil/SilcHashTableAPI/SilcHashForeach
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcHashForeach)(void *key, void *context,
 *                                    void *user_context);
 *
 * DESCRIPTION
 *
 *    Foreach function. This is called when traversing the entrys in the
 *    hash table using silc_hash_table_foreach. The `user_context' is
 *    application specific context and is delivered to the callback.
 *
 ***/
typedef void (*SilcHashForeach)(void *key, void *context, void *user_context);

/* Simple hash table interface */

/****f* silcutil/SilcHashTableAPI/silc_hash_table_alloc
 *
 * SYNOPSIS
 *
 *    SilcHashTable silc_hash_table_alloc(SilcStack stack,
 *                                        SilcUInt32 table_size,
 *                                        SilcHashFunction hash,
 *                                        void *hash_user_context,
 *                                        SilcHashCompare compare,
 *                                        void *compare_user_context,
 *                                        SilcHashDestructor destructor,
 *                                        void *destructor_user_context,
 *                                        SilcBool auto_rehash);
 *
 * DESCRIPTION
 *
 *    Allocates new hash table and returns it.  If the `stack' is non-NULL
 *    the hash table is allocated from `stack'.  If the `table_size' is not
 *    zero then the hash table size is the size provided. If zero then the
 *    default size will be used. Note that if the `table_size' is provided
 *    it should be a prime. The `hash', `compare' and `destructor' are
 *    the hash function, the key comparison function and key and context
 *    destructor function, respectively. The `hash' is mandatory, the others
 *    are optional.
 *
 ***/
SilcHashTable silc_hash_table_alloc(SilcStack stack,
				    SilcUInt32 table_size,
				    SilcHashFunction hash,
				    void *hash_user_context,
				    SilcHashCompare compare,
				    void *compare_user_context,
				    SilcHashDestructor destructor,
				    void *destructor_user_context,
				    SilcBool auto_rehash);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_free
 *
 * SYNOPSIS
 *
 *    void silc_hash_table_free(SilcHashTable ht);
 *
 * DESCRIPTION
 *
 *    Frees the hash table. The destructor function provided in the
 *    silc_hash_table_alloc will be called for all keys in the hash table.
 *
 *    If the SilcStack was given to silc_hash_table_alloc this call will
 *    release all memory allocated during the life time of the `ht' back
 *    to the SilcStack.
 *
 ***/
void silc_hash_table_free(SilcHashTable ht);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_size
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_hash_table_size(SilcHashTable ht);
 *
 * DESCRIPTION
 *
 *    Returns the size of the hash table. This is the true size of the
 *    hash table.
 *
 ***/
SilcUInt32 silc_hash_table_size(SilcHashTable ht);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_count
 *
 * SYNOPSIS
 *
 *    SilcUInt32 silc_hash_table_count(SilcHashTable ht);
 *
 * DESCRIPTION
 *
 *    Returns the number of the entires in the hash table. If there is more
 *    entries in the table thatn the size of the hash table calling the
 *    silc_hash_table_rehash is recommended.
 *
 ***/
SilcUInt32 silc_hash_table_count(SilcHashTable ht);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_add
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_table_add(SilcHashTable ht, void *key, void *context);
 *
 * DESCRIPTION
 *
 *    Adds new entry to the hash table. The `key' is hashed using the
 *    hash function and the both `key' and `context' will be saved to the
 *    hash table. This function quarantees that the entry is always added
 *    to the hash table reliably (it is collision resistant).
 *
 ***/
SilcBool silc_hash_table_add(SilcHashTable ht, void *key, void *context);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_set
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_table_set(SilcHashTable ht, void *key,
 *                                 void *context);
 *
 * DESCRIPTION
 *
 *    Same as silc_hash_table_add but if the `key' already exists in the
 *    hash table the old key and the old context will be replaced with the
 *    `key' and the `context. The destructor function will be called for the
 *    replaced key and context.
 *
 ***/
SilcBool silc_hash_table_set(SilcHashTable ht, void *key, void *context);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_del
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_table_del(SilcHashTable ht, void *key);
 *
 * DESCRIPTION
 *
 *    Removes the entry from the hash table by the provided `key'. This will
 *    call the destructor funtion for the found entry. Return TRUE if the
 *    entry was removed successfully and FALSE otherwise.
 *
 ***/
SilcBool silc_hash_table_del(SilcHashTable ht, void *key);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_del_by_context
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_table_del_by_context(SilcHashTable ht, void *key,
 *                                            void *context);
 *
 * DESCRIPTION
 *
 *    Same as silc_hash_table_del but verifies that the context associated
 *    with the `key' matches the `context'. This is handy to use with hash
 *    tables that may have duplicate keys. In that case the `context' may
 *    be used to check whether the correct entry is being deleted.
 *
 ***/
SilcBool silc_hash_table_del_by_context(SilcHashTable ht, void *key,
					void *context);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_find
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_table_find(SilcHashTable ht, void *key,
 *                                  void **ret_key, void **ret_context);
 *
 * DESCRIPTION
 *
 *    Finds the entry in the hash table by the provided `key' as fast as
 *    possible. Return TRUE if the entry was found and FALSE otherwise.
 *    The found entry is returned to the `ret_key' and `ret_context',
 *    respectively. If the `ret_key and `ret_context' are NULL then this
 *    maybe used only to check whether given key exists in the table.
 *
 ***/
SilcBool silc_hash_table_find(SilcHashTable ht, void *key,
			      void **ret_key, void **ret_context);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_find_by_context
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_table_find_by_context(SilcHashTable ht, void *key,
 *                                             void *context, void **ret_key);
 *
 * DESCRIPTION
 *
 *    Finds the entry in the hash table by the provided `key' and
 *    `context' as fast as possible.  This is handy function when there
 *    can be multiple same keys in the hash table.  By using this function
 *    the specific key with specific context can be found.  Return
 *    TRUE if the entry with the key and context was found and FALSE
 *    otherwise.  The function returns only the key to `ret_key' since
 *    the caller already knows the context.
 *
 ***/
SilcBool silc_hash_table_find_by_context(SilcHashTable ht, void *key,
					 void *context, void **ret_key);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_find_foreach
 *
 * SYNOPSIS
 *
 *    void silc_hash_table_find_foreach(SilcHashTable ht, void *key,
 *                                      SilcHashForeach foreach,
 *                                      void *user_context);
 *
 * DESCRIPTION
 *
 *    As the hash table is collision resistant it is possible to save duplicate
 *    keys to the hash table. This function can be used to find all keys
 *    and contexts from the hash table that are found using the `key'. The
 *    `foreach' is called for every found key. If no entries can be found
 *    the `foreach' will be called once with the context set NULL and
 *    `key' and `user_context' sent to the function.
 *
 * NOTES
 *
 *    The hash table will not be rehashed during the traversing of the table,
 *    even if the table was marked as auto rehashable.  The caller also must
 *    not call silc_hash_table_rehash while traversing the table.
 *
 ***/
void silc_hash_table_find_foreach(SilcHashTable ht, void *key,
				  SilcHashForeach foreach, void *user_context);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_foreach
 *
 * SYNOPSIS
 *
 *    void silc_hash_table_foreach(SilcHashTable ht, SilcHashForeach foreach,
 *                                 void *user_context);
 *
 * DESCRIPTION
 *
 *    Traverse all entrys in the hash table and call the `foreach' for
 *    every entry with the `user_context' context.
 *
 * NOTES
 *
 *    The hash table will not be rehashed during the traversing of the table,
 *    even if the table was marked as auto rehashable.  The caller also must
 *    not call silc_hash_table_rehash while traversing the table.
 *
 ***/
void silc_hash_table_foreach(SilcHashTable ht, SilcHashForeach foreach,
			     void *user_context);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_rehash
 *
 * SYNOPSIS
 *
 *    void silc_hash_table_rehash(SilcHashTable ht, SilcUInt32 new_size);
 *
 * DESCRIPTION
 *
 *    Rehashs the hash table. The size of the new hash table is provided
 *    as `new_size'. If the `new_size' is zero then this routine will make
 *    the new table of a suitable size. Note that this operation may be
 *    very slow.
 *
 ***/
void silc_hash_table_rehash(SilcHashTable ht, SilcUInt32 new_size);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_list
 *
 * SYNOPSIS
 *
 *    void silc_hash_table_list(SilcHashTable ht, SilcHashTableList *htl);
 *
 * DESCRIPTION
 *
 *    Prepares the `htl' SilcHashTableList sent as argument to be used in the
 *    hash table traversing with the silc_hash_table_get.  After the hash
 *    table traversing is completed the silc_hash_table_list_reset must be
 *    called.
 *
 * NOTES
 *
 *    The hash table will not be rehashed during the traversing of the list,
 *    even if the table was marked as auto rehashable.  The caller also must
 *    not call silc_hash_table_rehash while traversing the list.
 *
 ***/
void silc_hash_table_list(SilcHashTable ht, SilcHashTableList *htl);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_list_reset
 *
 * SYNOPSIS
 *
 *    void silc_hash_table_list_reset(SilcHashTableList *htl);
 *
 * DESCRIPTION
 *
 *    Resets the `htl' SilcHashTableList.  This must be called after the
 *    hash table traversing is completed.
 *
 ***/
void silc_hash_table_list_reset(SilcHashTableList *htl);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_get
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_table_get(SilcHashTableList *htl, void **key,
 *                                 void **context);
 *
 * DESCRIPTION
 *
 *    Returns always the next entry in the hash table into the `key' and
 *    `context' and TRUE.  If this returns FALSE then there are no more
 *    entries.
 *
 * EXAMPLE
 *
 *    SilcHashTableList htl;
 *    silc_hash_table_list(hash_table, &htl);
 *    while (silc_hash_table_get(&htl, (void *)&key, (void *)&context))
 *      ...
 *    silc_hash_table_list_reset(&htl);
 *
 ***/
SilcBool silc_hash_table_get(SilcHashTableList *htl,
			     void **key, void **context);


/* Extended hash table interface (same as above but with specific
   hash and comparison functions). */

/****f* silcutil/SilcHashTableAPI/silc_hash_table_add_ext
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_table_add_ext(SilcHashTable ht, void *key,
 *                                     void *context,
 *                                     SilcHashFunction hash,
 *                                     void *hash_user_context);
 *
 * DESCRIPTION
 *
 *    Adds new entry to the hash table. The `key' is hashed using the
 *    hash function and the both `key' and `context' will be saved to the
 *    hash table. This function quarantees that the entry is always added
 *    to the hash table reliably (it is collision resistant).
 *
 *    The `hash' and `hash_user_context' are application specified hash
 *    function. If not provided the hash table's default is used.
 *
 ***/
SilcBool silc_hash_table_add_ext(SilcHashTable ht,
				 void *key, void *context,
				 SilcHashFunction hash,
				 void *hash_user_context);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_set_ext
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_table_set_ext(SilcHashTable ht, void *key,
 *                                     void *context,
 *                                     SilcHashFunction hash,
 *                                     void *hash_user_context);
 *
 * DESCRIPTION
 *
 *    Same as silc_hash_table_add_ext but if the `key' already exists in the
 *    hash table the old key and the old context will be replaced with the
 *    `key' and the `context. The destructor function will be called for the
 *    replaced key and context.
 *
 *    The `hash' and `hash_user_context' are application specified hash
 *    function. If not provided the hash table's default is used.
 *
 ***/
SilcBool silc_hash_table_set_ext(SilcHashTable ht,
				 void *key, void *context,
				 SilcHashFunction hash,
				 void *hash_user_context);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_del_ext
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_table_del_ext(SilcHashTable ht, void *key,
 *                                     SilcHashFunction hash,
 *                                     void *hash_user_context,
 *                                     SilcHashCompare compare,
 *                                     void *compare_user_context,
 *                                     SilcHashDestructor destructor,
 *                                     void *destructor_user_context);
 *
 * DESCRIPTION
 *
 *    Removes the entry from the hash table by the provided `key'. This will
 *    call the destructor funtion for the found entry. Return TRUE if the
 *    entry was removed successfully and FALSE otherwise.
 *
 *    The `hash' and `hash_user_context' are application specified hash
 *    function. If not provided the hash table's default is used.
 *    The `compare' and `compare_user_context' are application specified
 *    comparing function. If not provided the hash table's default is used.
 *    The `destructor' and `destructor_user_context' are application
 *    specific destructor function.
 *
 ***/
SilcBool silc_hash_table_del_ext(SilcHashTable ht, void *key,
				 SilcHashFunction hash,
				 void *hash_user_context,
				 SilcHashCompare compare,
				 void *compare_user_context,
				 SilcHashDestructor destructor,
				 void *destructor_user_context);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_del_by_context_ext
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_hash_table_del_by_context_ext(SilcHashTable ht, void *key,
 *                                       void *context,
 *                                       SilcHashFunction hash,
 *                                       void *hash_user_context,
 *                                       SilcHashCompare compare,
 *                                       void *compare_user_context,
 *                                       SilcHashDestructor destructor,
 *                                       void *destructor_user_context);
 *
 * DESCRIPTION
 *
 *    Same as silc_hash_table_del but verifies that the context associated
 *    with the `key' matches the `context'. This is handy to use with hash
 *    tables that may have duplicate keys. In that case the `context' may
 *    be used to check whether the correct entry is being deleted.
 *
 *    The `hash' and `hash_user_context' are application specified hash
 *    function. If not provided the hash table's default is used.
 *    The `compare' and `compare_user_context' are application specified
 *    comparing function. If not provided the hash table's default is used.
 *    The `destructor' and `destructor_user_context' are application
 *    specific destructor function.
 *
 ***/
SilcBool silc_hash_table_del_by_context_ext(SilcHashTable ht, void *key,
					    void *context,
					    SilcHashFunction hash,
					    void *hash_user_context,
					    SilcHashCompare compare,
					    void *compare_user_context,
					    SilcHashDestructor destructor,
					    void *destructor_user_context);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_find_ext
 *
 * SYNOPSIS
 *
 *    SilcBool silc_hash_table_find_ext(SilcHashTable ht, void *key,
 *                                      void **ret_key, void **ret_context,
 *                                      SilcHashFunction hash,
 *                                      void *hash_user_context,
 *                                      SilcHashCompare compare,
 *                                      void *compare_user_context);
 *
 * DESCRIPTION
 *
 *    Finds the entry in the hash table by the provided `key' as fast as
 *    possible. Return TRUE if the entry was found and FALSE otherwise.
 *    The found entry is returned to the `ret_key' and `ret_context',
 *    respectively. If the `ret_key and `ret_context' are NULL then this
 *    maybe used only to check whether given key exists in the table.
 *
 *    The `hash' and `hash_user_context' are application specified hash
 *    function. If not provided the hash table's default is used.
 *    The `compare' and `compare_user_context' are application specified
 *    comparing function. If not provided the hash table's default is used.
 *
 ***/
SilcBool silc_hash_table_find_ext(SilcHashTable ht, void *key,
				  void **ret_key, void **ret_context,
				  SilcHashFunction hash,
				  void *hash_user_context,
				  SilcHashCompare compare,
				  void *compare_user_context);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_find_by_context_ext
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_hash_table_find_by_context_ext(SilcHashTable ht, void *key,
 *                                        void *context, void **ret_key,
 *                                        SilcHashFunction hash,
 *                                        void *hash_user_context,
 *                                        SilcHashCompare compare,
 *                                        void *compare_user_context);
 *
 * DESCRIPTION
 *
 *    Finds the entry in the hash table by the provided `key' and
 *    `context' as fast as possible.  This is handy function when there
 *    can be multiple same keys in the hash table.  By using this function
 *    the specific key with specific context can be found.  Return
 *    TRUE if the entry with the key and context was found and FALSE
 *    otherwise.  The function returns only the key to `ret_key' since
 *    the caller already knows the context.
 *
 *    The `hash' and `hash_user_context' are application specified hash
 *    function. If not provided the hash table's default is used.
 *    The `compare' and `compare_user_context' are application specified
 *    comparing function. If not provided the hash table's default is used.
 *
 ***/
SilcBool silc_hash_table_find_by_context_ext(SilcHashTable ht, void *key,
					     void *context, void **ret_key,
					     SilcHashFunction hash,
					     void *hash_user_context,
					     SilcHashCompare compare,
					     void *compare_user_context);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_find_foreach_ext
 *
 * SYNOPSIS
 *
 *    void silc_hash_table_find_foreach_ext(SilcHashTable ht, void *key,
 *                                          SilcHashFunction hash,
 *                                          void *hash_user_context,
 *                                          SilcHashCompare compare,
 *                                          void *compare_user_context,
 *                                          SilcHashForeach foreach,
 *                                          void *foreach_user_context);
 *
 * DESCRIPTION
 *
 *    As the hash table is collision resistant it is possible to save duplicate
 *    keys to the hash table. This function can be used to find all keys
 *    and contexts from the hash table that are found using the `key'. The
 *    `foreach' is called for every found key. If no entries can be found
 *    the `foreach' will be called once with the context set NULL and
 *    `key' and `user_context' sent to the function.
 *
 *    The `hash' and `hash_user_context' are application specified hash
 *    function. If not provided the hash table's default is used.
 *    The `compare' and `compare_user_context' are application specified
 *    comparing function. If not provided the hash table's default is used.
 *
 * NOTES
 *
 *    The hash table will not be rehashed during the traversing of the table,
 *    even if the table was marked as auto rehashable.  The caller also must
 *    not call silc_hash_table_rehash while traversing the table.
 *
 ***/
void silc_hash_table_find_foreach_ext(SilcHashTable ht, void *key,
				      SilcHashFunction hash,
				      void *hash_user_context,
				      SilcHashCompare compare,
				      void *compare_user_context,
				      SilcHashForeach foreach,
				      void *foreach_user_context);

/****f* silcutil/SilcHashTableAPI/silc_hash_table_rehash_ext
 *
 * SYNOPSIS
 *
 *    void silc_hash_table_rehash_ext(SilcHashTable ht, SilcUInt32 new_size,
 *                                    SilcHashFunction hash,
 *                                    void *hash_user_context);
 *
 * DESCRIPTION
 *
 *    Rehashs the hash table. The size of the new hash table is provided
 *    as `new_size'. If the `new_size' is zero then this routine will make
 *    the new table of a suitable size. Note that this operation may be
 *    very slow.
 *
 *    The `hash' and `hash_user_context' are application specified hash
 *    function. If not provided the hash table's default is used.
 *
 ***/
void silc_hash_table_rehash_ext(SilcHashTable ht, SilcUInt32 new_size,
				SilcHashFunction hash,
				void *hash_user_context);

#endif
