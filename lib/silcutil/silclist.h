/*

  silclist.h

  Author: Timo Sirainen <tss@iki.fi>

  Copyright (C) 2002 Timo Sirainen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC List Interface
 *
 * DESCRIPTION
 *
 * Implementation of the SilcList interface.  This interface provides
 * simple linked list.
 *
 ***/

#ifndef SILCLIST_H
#define SILCLIST_H

/****s* silcutil/SilcList/SilcList
 *
 * NAME
 * 
 *    typedef struct { ... } SilcList;
 *
 * DESCRIPTION
 *
 *    This is the SilcList context, and is initialized by calling the
 *    function silc_list_init.
 *
 * EXAMPLE
 *
 *     SilcList list;
 *     silc_list_init(list, struct SilcInternalEntryStruct, next);
 *
 ***/
typedef struct {
  void *head, *tail;
  void *current;
  int offset;
} SilcList;

/****d* silcutil/SilcList/SILC_LIST_END
 *
 * NAME
 * 
 *    #define SILC_LIST_END ...
 *
 * DESCRIPTION
 *
 *    Functions return this when the list is invalid or when traversing
 *    the list there is no more entires in the list.
 *
 * SOURCE
 */
#define SILC_LIST_END NULL
/***/

/* Initializes SilcList object. Example:

   SilcList list;

   silc_list_init(list, struct SilcInternalEntryStruct, next);

   Where `list' is the defined list, and second argument is the structure
   of the entries in the list and last argument is the pointer in the entry
   structure that is used as list member. SilcInternalEntry might be as 
   follows:

   struct SilcInternalEntryStruct {
     char *dummy;
     struct SilcInternalEntryStruct *next; // The list member pointer
   };

   The `next' pointer in the structure (or some other pointer for that matter)
   is given for the silc_list_init as the last argument. This pointer is used
   by the list routines to link the entries together in the list. Your code
   should not touch the member pointer manually.
*/

/****f* silcutil/SilcList/silc_list_init
 *
 * SYNOPSIS
 *
 *    #define silc_list_init(list, type, field) ...
 *
 * DESCRIPTION
 *
 *    This macro initializes the SilcList list.  The `list' is the defined
 *    list, second argument is the structure of the entries in the list,
 *    and last argument is the pointer in the entry structure that is used
 *    as list member.  When using SilcList, you should not touch the
 *    structure member pointer (the `next' for example) manually.
 *
 * EXAMPLE
 *
 *    struct SilcInternalEntryStruct {
 *      char *dummy;
 *      struct SilcInternalEntryStruct *next; // The list member pointer
 *    };
 *
 *    SilcList list;
 *    silc_list_init(list, struct SilcInternalEntryStruct, next);
 *
 ***/
#define silc_list_init(list, type, field) \
  __silc_list_init(&(list), offsetof(type, field))

static inline void __silc_list_init(SilcList *list, int offset)
{
  list->head = list->tail = list->current = SILC_LIST_END;
  list->offset = offset;
}

#define list_next(list, pos) ((void **) ((char *) (pos) + (list)->offset))

/****f* silcutil/SilcList/silc_list_count
 *
 * SYNOPSIS
 *
 *    #define silc_list_count(list) ...
 *
 * DESCRIPTION
 *
 *    Returns the number of entries in the list indicated by `list'.
 *
 ***/
#define silc_list_count(list) __silc_list_count(&(list))
static inline int __silc_list_count(SilcList *list)
{
  int count = 0;
  void *pos;

  for (pos = list->head; pos != NULL; pos = *list_next(list, pos))
    count++;

  return count;
}

/****f* silcutil/SilcList/silc_list_start
 *
 * SYNOPSIS
 *
 *    #define silc_list_start(list) ...
 *
 * DESCRIPTION
 *
 *    Sets the start of the list.  This prepares the list for traversing
 *    the entries from the start of the list.
 *
 ***/
#define silc_list_start(list) (list).current = (list).head;

/****f* silcutil/SilcList/silc_list_add
 *
 * SYNOPSIS
 *
 *    #define silc_list_add(list, entry) ...
 *
 * DESCRIPTION
 *
 *    Adds new entry indicated by `entry' to the end of the list indicated 
 *    by `list'.
 *
 ***/
#define silc_list_add(list, entry) __silc_list_add(&(list), entry)
static inline void __silc_list_add(SilcList *list, void *data)
{
  if (list->head == NULL)
    list->head = data;
  else
    *list_next(list, list->tail) = data;

  list->tail = data;
  *list_next(list, data) = NULL;
}

/****f* silcutil/SilcList/silc_list_del
 *
 * SYNOPSIS
 *
 *    #define silc_list_del(list, entry) ...
 *
 * DESCRIPTION
 *
 *    Remove entry indicated by `entry' from the list indicated by `list'.
 *
 ***/
#define silc_list_del(list, data) __silc_list_del(&(list), data)
static inline void __silc_list_del(SilcList *list, void *data)
{
  void **pos, *prev;

  prev = NULL;
  for (pos = &list->head; *pos != NULL; pos = list_next(list, *pos)) {
    if (*pos == data) {
      *pos = *list_next(list, data);
      if (list->current == data)
        list->current = *pos;
      break;
    }

    prev = *pos;
  }

  if (data == list->tail)
    list->tail = prev;
}

/****f* silcutil/SilcList/silc_list_get
 *
 * SYNOPSIS
 *
 *    #define silc_list_get(list, entry) ...
 *
 * DESCRIPTION
 *
 *    Returns the current entry from the list indicated by `list' and
 *    moves the list pointer forward so that calling this next time will
 *    return the next entry from the list.  This can be used to traverse
 *    the list.  Returns SILC_LIST_END when the entire list has been
 *    tarversed and no additional entries exist in the list. Later,
 *    silc_list_start must be called again when re-starting the list
 *    tarversing.
 *
 * EXAMPLE
 *
 *    // Traverse the list from the beginning to the end 
 *    silc_list_start(list)
 *    while ((entry = silc_list_get(list)) != SILC_LIST_END) {
 *      ...
 *    }
 *
 ***/
#define silc_list_get(x) __silc_list_get(&(x))

static inline
void *__silc_list_get(SilcList *list)
{
  void *pos;

  pos = list->current;
  if (pos != NULL)
    list->current = *list_next(list, pos);
  return pos;
}

#endif
