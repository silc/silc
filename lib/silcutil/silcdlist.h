/*

  silcdlist.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2000 - 2005 Pekka Riikonen

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
 * will automatically allocate list entries.  Normal SILC List API cannot
 * be used for this purpose because in that case the context passed to the
 * list must be defined as list structure already.  This is not the case in
 * SilcDList.
 *
 * This is slower than SilcList because this requires one extra memory
 * allocation when adding new entries to the list.  The context is probably
 * allocated already and the new list entry requires one additional memory
 * allocation.  The memory allocation and freeing is done automatically in
 * the API and does not show to the caller.
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
 * SOURCE
 */
typedef struct SilcDListStruct {
  SilcList list;
  void *current;
  void *prev;
} *SilcDList;
/***/

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
 *    Initializes SilcDList.
 *
 ***/

static inline
SilcDList silc_dlist_init(void)
{
  SilcDList list;

  list = (SilcDList)silc_malloc(sizeof(*list));
  if (!list)
    return NULL;
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
 *    free the contexts saved by caller.
 *
 ***/

static inline
void silc_dlist_uninit(SilcDList list)
{
  if (list) {
    SilcDListEntry e;
    silc_list_start(list->list);
    while ((e = (SilcDListEntry)silc_list_get(list->list)) != SILC_LIST_END) {
      silc_list_del(list->list, e);
      silc_free(e);
    }
    silc_free(list);
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
  SilcDListEntry e = (SilcDListEntry)silc_malloc(sizeof(*e));
  if (!e)
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
  SilcDListEntry e = (SilcDListEntry)silc_malloc(sizeof(*e));
  if (!e)
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
 *    void silc_dlist_del(SilcDList list, void *context);
 *
 * DESCRIPTION
 *
 *    Remove entry from the list. Returns < 0 on error, 0 otherwise.
 *
 ***/

static inline
void silc_dlist_del(SilcDList list, void *context)
{
  SilcDListEntry e;

  silc_list_start(list->list);
  while ((e = (SilcDListEntry)silc_list_get(list->list)) != SILC_LIST_END) {
    if (e->context == context) {
      silc_list_del(list->list, e);
#if defined(SILC_DEBUG)
      memset(e, 'F', sizeof(*e));
#endif
      if (list->current == e)
	list->current = NULL;
      if (list->prev == e)
	list->prev = NULL;
      silc_free(e);
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
