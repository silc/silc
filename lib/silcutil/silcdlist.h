/*

  silcdlist.h

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

#ifndef SILDCLIST_H
#define SILDCLIST_H

#include "silclist.h"

/****h* silcutil/SILC Dynamic List Interface
 *
 * DESCRIPTION
 *
 * SILC Dynamic List API can be used to add opaque contexts to list that
 * will automatically allocate list entries.  The simpler SilcList cannot
 * be used for this purpose because in that case the context passed to the
 * list must be defined as list structure already.  This is not the case in
 * SilcDList.  But SilcDList is a bit slower than SilcList because it
 * requires memory allocation when adding new entries to the list.
 *
 * SILC Dynamic List is not thread-safe.  If the same list context must be
 * used in multithreaded environment concurrency control must be employed.
 *
 * EXAMPLE
 *
 * SilcDList list = silc_dlist_init();
 *
 * silc_dlist_add(list, entry1);
 * silc_dlist_add(list, entry2);
 *
 * // Traverse the list from the beginning to the end
 * silc_dlist_start(list)
 * while ((entry = silc_dlist_get(list)) != SILC_LIST_END) {
 *      ...
 * }
 *
 * silc_dlist_uninit(list);
 *
 ***/

/****s* silcutil/SilcDListAPI/SilcDList
 *
 * NAME
 *
 *    typedef struct { ... } *SilcDList;
 *
 * DESCRIPTION
 *
 *    This is the actual SilcDList object that is used by application.
 *    Application defines this object and adds contexts to this list with
 *    Dynamic List Interface functions.
 *
 ***/
typedef struct SilcDListStruct {
  SilcStack stack;
  SilcList list;
  void *current;
  void *prev;
} *SilcDList;

/* SilcDListEntry structure, one entry in the list. This MUST NOT be used
   directly by the application. */
typedef struct SilcDListEntryStruct {
  void *context;
  struct SilcDListEntryStruct *next;
  struct SilcDListEntryStruct *prev;
} *SilcDListEntry;

/****f* silcutil/SilcDListAPI/silc_dlist_init
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcDList silc_dlist_init(void);
 *
 * DESCRIPTION
 *
 *    Initializes SilcDList.  Returns the SilcDList context or NULL if system
 *    is out of memory.
 *
 ***/

static inline
SilcDList silc_dlist_init(void)
{
  SilcDList list;

  list = (SilcDList)silc_malloc(sizeof(*list));
  if (!list)
    return NULL;
  list->stack = list->current = list->prev = NULL;
  silc_list_init_prev(list->list, struct SilcDListEntryStruct, next, prev);

  return list;
}

/****f* silcutil/SilcDListAPI/silc_dlist_sinit
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcDList silc_dlist_sinit(SilcStack stack);
 *
 * DESCRIPTION
 *
 *    Initializes SilcDList.  Returns the SilcDList context or NULL on error.
 *    This is same as silc_dlist_init but allocates the memory from `stack'
 *    if `stack' is non-NULL.
 *
 ***/

static inline
SilcDList silc_dlist_sinit(SilcStack stack)
{
  SilcDList list;

  if (stack)
    stack = silc_stack_alloc(0, stack);
  list = (SilcDList)silc_smalloc(stack, sizeof(*list));
  if (!list) {
    silc_stack_free(stack);
    return NULL;
  }
  list->stack = stack;
  list->current = list->prev = NULL;
  silc_list_init_prev(list->list, struct SilcDListEntryStruct, next, prev);

  return list;
}

/****f* silcutil/SilcDListAPI/silc_dlist_uninit
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_dlist_uninit(SilcDList list);
 *
 * DESCRIPTION
 *
 *    Uninits and frees all memory. Must be called to free memory. Does NOT
 *    free the contexts saved by caller.  If the silc_dlist_sinit was used
 *    with SilcStack this will release all memory allocated by the SilcDList
 *    back to the SilcStack.
 *
 ***/

static inline
void silc_dlist_uninit(SilcDList list)
{
  if (list) {
    SilcDListEntry e;
    SilcStack stack = list->stack;
    silc_list_start(list->list);
    while ((e = (SilcDListEntry)silc_list_get(list->list)) != SILC_LIST_END) {
      silc_list_del(list->list, e);
      silc_sfree(stack, e);
    }
    silc_sfree(stack, list);
    silc_stack_free(stack);
  }
}

/****f* silcutil/SilcDListAPI/silc_dlist_count
 *
 * SYNOPSIS
 *
 *    static inline
 *    int silc_dlist_count(SilcDList list);
 *
 * DESCRIPTION
 *
 * Return the number of entries in the list.
 *
 ***/

static inline
int silc_dlist_count(SilcDList list)
{
  return silc_list_count(list->list);
}

/****f* silcutil/SilcDListAPI/silc_dlist_start
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_dlist_start(SilcDList list);
 *
 * DESCRIPTION
 *
 *    Set the start of the list. This prepares the list for traversing entries
 *    from the start of the list towards end of the list.
 *
 ***/

static inline
void silc_dlist_start(SilcDList list)
{
  silc_list_start(list->list);
  list->current = list->prev = NULL;
}

/****f* silcutil/SilcDListAPI/silc_dlist_end
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_dlist_end(SilcDList list);
 *
 * DESCRIPTION
 *
 *    Set the end of the list. This prepares the list for traversing entries
 *    from the end of the list towards start of the list.
 *
 ***/

static inline
void silc_dlist_end(SilcDList list)
{
  silc_list_end(list->list);
  list->current = list->prev = NULL;
}

/****f* silcutil/SilcDListAPI/silc_dlist_add
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBool silc_dlist_add(SilcDList list, void *context);
 *
 * DESCRIPTION
 *
 *    Adds new entry to the list. This is the default function to add new
 *    entries to the list.
 *
 ***/

static inline
SilcBool silc_dlist_add(SilcDList list, void *context)
{
  SilcDListEntry e = (SilcDListEntry)silc_smalloc(list->stack, sizeof(*e));
  if (silc_unlikely(!e))
    return FALSE;
  e->context = context;
  silc_list_add(list->list, e);
  return TRUE;
}

/****f* silcutil/SilcDList/silc_dlist_insert
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBool silc_dlist_insert(SilcDList list, void *context);
 *
 * DESCRIPTION
 *
 *    Insert new entry to the list between current and previous entry.
 *    If list is at the start this adds the entry at head of the list.
 *    Use silc_dlist_add to add at the end of the list.
 *
 ***/

static inline
SilcBool silc_dlist_insert(SilcDList list, void *context)
{
  SilcDListEntry e = (SilcDListEntry)silc_smalloc(list->stack, sizeof(*e));
  if (silc_unlikely(!e))
    return FALSE;
  e->context = context;
  silc_list_insert(list->list, list->prev, e);
  return TRUE;
}

/****f* silcutil/SilcDListAPI/silc_dlist_del
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_dlist_del(SilcDList list, void *entry);
 *
 * DESCRIPTION
 *
 *    Remove entry from the list.
 *
 ***/

static inline
void silc_dlist_del(SilcDList list, void *entry)
{
  SilcDListEntry e;

  silc_list_start(list->list);
  while ((e = (SilcDListEntry)silc_list_get(list->list)) != SILC_LIST_END) {
    if (e->context == entry) {
      silc_list_del(list->list, e);
#if defined(SILC_DEBUG)
      memset(e, 'F', sizeof(*e));
#endif
      if (list->current == e)
	list->current = NULL;
      if (list->prev == e)
	list->prev = NULL;
      silc_sfree(list->stack, e);
      break;
    }
  }
}

/****f* silcutil/SilcDListAPI/silc_dlist_get
 *
 * SYNOPSIS
 *
 *    static inline
 *    void *silc_dlist_get(SilcDList list);
 *
 * DESCRIPTION
 *
 *    Returns current entry from the list and moves the list pointer forward
 *    so that calling this next time returns the next entry from the list.
 *    This can be used to traverse the list. Return SILC_LIST_END when the
 *    entire list has been traversed. Later, silc_list_start (or
 *    silc_dlist_end) must be called again when re-starting list traversing.
 *
 * EXAMPLE
 *
 *    // Traverse the list from the beginning to the end
 *    silc_dlist_start(list)
 *    while ((entry = silc_dlist_get(list)) != SILC_LIST_END) {
 *      ...
 *    }
 *
 ***/

static inline
void *silc_dlist_get(SilcDList list)
{
  SilcDListEntry e;
  list->prev = list->current;
  list->current = e = (SilcDListEntry)silc_list_get(list->list);
  if (e != SILC_LIST_END)
    return e->context;
  return SILC_LIST_END;
}

#endif
