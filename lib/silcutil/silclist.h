/*

  silclist.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

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
 * SILC List is not thread-safe.  If the same list context must be used
 * in multithreaded environment concurrency control must be employed.
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
 ***/
typedef struct {
  void *head;			     /* Start of the list */
  void *tail;			     /* End of the list */
  void *current;		     /* Current pointer in list */
  SilcUInt16 next_offset;	     /* Offset to 'next' pointer */
  SilcUInt16 prev_offset;	     /* Offset to 'prev' pointer */
  unsigned int prev_set    : 1;	     /* Set if 'prev' exists */
  unsigned int end_set     : 1;	     /* Set if silc_list_end was called */
  unsigned int count       : 30;     /* Number of entries in the list */
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

/****f* silcutil/SilcList/silc_list_init
 *
 * SYNOPSIS
 *
 *    #define silc_list_init(list, type, nextfield) ...
 *
 * DESCRIPTION
 *
 *    This macro initializes the SilcList list.  The `list' is the defined
 *    list, second argument is the structure of the entries in the list,
 *    and last argument is the pointer in the structure that is used
 *    as next list members.  When using SilcList you must not touch the
 *    structure member pointers manually.  If your list has also a prev
 *    pointer should use silc_list_init_prev instead of this call if
 *    you need to be able traverse the list backwards as well.
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
#define silc_list_init(list, type, nextfield)		\
do {							\
  (list).count = 0;					\
  (list).next_offset = silc_offsetof(type, nextfield);	\
  (list).prev_set = 0;					\
  (list).prev_offset = 0;				\
  (list).head = (list).tail = (list).current = NULL;	\
} while(0)

/****f* silcutil/SilcList/silc_list_init_prev
 *
 * SYNOPSIS
 *
 *    #define silc_list_init_prev(list, type, nextfield, prevfield) ...
 *
 * DESCRIPTION
 *
 *    This macro initializes the SilcList list.  The `list' is the defined
 *    list, second argument is the structure of the entries in the list,
 *    and last two arguments are the pointers in the structure that is used
 *    as next and prev list members.  When using SilcList you must not
 *    touch the structure member pointers manually.
 *
 *    Having both next and prev pointers makes it possible to traverse
 *    list from both ends of the list (from start to end, and from end
 *    to start).
 *
 * EXAMPLE
 *
 *    struct SilcInternalEntryStruct {
 *      char *dummy;
 *      struct SilcInternalEntryStruct *next; // The list member pointer
 *      struct SilcInternalEntryStruct *prev; // The list member pointer
 *    };
 *
 *    SilcList list;
 *    silc_list_init_prev(list, struct SilcInternalEntryStruct, next, prev);
 *
 ***/
#define silc_list_init_prev(list, type, nextfield, prevfield)	\
do {								\
  (list).count = 0;						\
  (list).next_offset = silc_offsetof(type, nextfield);		\
  (list).prev_offset = silc_offsetof(type, prevfield);		\
  (list).prev_set = 1;						\
  (list).head = (list).tail = (list).current = NULL;		\
} while(0)

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
#define silc_list_count(list) (list).count

/****f* silcutil/SilcList/silc_list_start
 *
 * SYNOPSIS
 *
 *    #define silc_list_start(list) ...
 *
 * DESCRIPTION
 *
 *    Sets the start of the list.  This prepares the list for traversing
 *    the entries from the start of the list towards end of the list.
 *
 ***/
#define silc_list_start(list)				\
  ((list).current = (list).head, (list).end_set = 0)

/****f* silcutil/SilcList/silc_list_end
 *
 * SYNOPSIS
 *
 *    #define silc_list_end(list) ...
 *
 * DESCRIPTION
 *
 *    Sets the end of the list.  This prepares the list for traversing
 *    the entries from the end of the list towards start of the list.
 *
 * NOTES
 *
 *    You can use this call only if you initialized the list with
 *    silc_list_init_prev.
 *
 ***/
#define silc_list_end(list)				\
  ((list).current = (list).tail, (list).end_set = 1)

/* Macros to get position to next and prev list pointers */
#define __silc_list_next(list, pos)				\
  ((void **)((unsigned char *)(pos) + (list).next_offset))
#define __silc_list_prev(list, pos)				\
  ((void **)((unsigned char *)(pos) + (list).prev_offset))

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
#define silc_list_add(list, entry)			\
do {							\
  if (!(list).head)					\
    (list).head = (entry);				\
  else							\
    *__silc_list_next(list, (list).tail) = (entry);	\
  if ((list).prev_set)					\
    *__silc_list_prev(list, entry) = (list).tail;	\
  (list).tail = (entry);				\
  *__silc_list_next(list, entry) = NULL;		\
  (list).count++;					\
} while(0)

/****f* silcutil/SilcList/silc_list_insert
 *
 * SYNOPSIS
 *
 *    #define silc_list_insert(list, current, entry) ...
 *
 * DESCRIPTION
 *
 *    Insert new entry indicated by `entry' after the entry `current'
 *    to the list indicated by `list'.  If `current' is NULL, then the
 *    `entry' is added at the head of the list.  Use the silc_list_add
 *    to add at the end of the list.
 *
 ***/
#define silc_list_insert(list, current, entry)				 \
do {									 \
  if (!(current)) {							 \
    if ((list).head)							 \
      *__silc_list_next(list, entry) = (list).head;			 \
    else								 \
      *__silc_list_next(list, entry) = NULL;				 \
    if ((list).prev_set && (list).head)					 \
      *__silc_list_prev(list, (list).head) = entry;			 \
    if (!(list).tail)							 \
      (list).tail = (entry);						 \
    (list).head = (entry);						 \
    if ((list).prev_set)						 \
      *__silc_list_prev(list, entry) = NULL;				 \
  } else {								 \
    *__silc_list_next(list, entry) = *__silc_list_next(list, current);	 \
    *__silc_list_next(list, current) = entry;				 \
    if ((list).prev_set) {						 \
      *__silc_list_prev(list, entry) = current;				 \
      if (*__silc_list_next(list, entry))				 \
        *__silc_list_prev(list, *__silc_list_next(list, entry)) = entry; \
    }									 \
    if ((list).tail == (current))					 \
      (list).tail = (entry);						 \
  }									 \
  (list).count++;							 \
} while(0)

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
#define silc_list_del(list, entry)					\
do {									\
  void **p, *prev;							\
  prev = NULL;								\
  for (p = &(list).head; *p; p = __silc_list_next(list, *p)) {		\
    if (*p == (entry)) {						\
      *p = *__silc_list_next(list, entry);				\
      if (*p && (list).prev_set)					\
        *__silc_list_prev(list, *p) = *__silc_list_prev(list, entry);	\
      if ((list).current == (entry))					\
        (list).current = *p;						\
      (list).count--;							\
      break;								\
    }									\
    prev = *p;								\
  }									\
  if (entry == (list).tail)						\
    (list).tail = prev;							\
} while(0)

/****f* silcutil/SilcList/silc_list_get
 *
 * SYNOPSIS
 *
 *    #define silc_list_get(list) ...
 *
 * DESCRIPTION
 *
 *    Returns the current entry from the list indicated by `list' and
 *    moves the list pointer forward so that calling this next time will
 *    return the next entry from the list.  This can be used to traverse
 *    the list.  Returns SILC_LIST_END when the entire list has been
 *    tarversed and no additional entries exist in the list. Later,
 *    silc_list_start (or silc_list_end) must be called again when
 *    re-starting the list tarversing.
 *
 * EXAMPLE
 *
 *    // Traverse the list from the beginning to the end
 *    silc_list_start(list);
 *    while ((entry = silc_list_get(list)) != SILC_LIST_END) {
 *      ...
 *    }
 *
 *    // Traverse the list from the end to the beginning
 *    silc_list_end(list);
 *    while ((entry = silc_list_get(list)) != SILC_LIST_END) {
 *      ...
 *    }
 *
 ***/
#define silc_list_get(x) __silc_list_get(&(x))
static inline
void *__silc_list_get(SilcList *list)
{
  void *pos = list->current;
  if (pos)
    list->current = (list->end_set ? *__silc_list_prev(*list, pos) :
		     *__silc_list_next(*list, pos));
  return pos;
}

#endif
