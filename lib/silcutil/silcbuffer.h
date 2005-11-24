/*

  silcbuffer.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1998 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

/****h* silcutil/SILC Buffer Interface
 *
 * DESCRIPTION
 *
 * SilcBuffer is very simple and easy to use, yet you can do to the
 * buffer almost anything you want with its method functions. The buffer
 * is constructed of four different data sections that in whole creates
 * the allocated data area.
 *
 ***/

#ifndef SILCBUFFER_H
#define SILCBUFFER_H

/****s* silcutil/SilcBufferAPI/SilcBuffer
 *
 * NAME
 *
 *    typedef struct { ... } *SilcBuffer, SilcBufferStruct;
 *
 * DESCRIPTION
 *
 *    SILC Buffer object. Following short description of the fields
 *    of the buffer.
 *
 * EXAMPLE
 *
 *    unsiged char *head;
 *
 *        Head of the allocated buffer. This is the start of the allocated
 *        data area and remains as same throughout the lifetime of the buffer.
 *        However, the end of the head area or the start of the currently valid
 *        data area is variable.
 *
 *        --------------------------------
 *        | head  | data         | tail  |
 *        --------------------------------
 *        ^       ^
 *
 *        Current head section in the buffer is sb->data - sb->head.
 *
 *    unsigned char *data;
 *
 *        Currently valid data area. This is the start of the currently valid
 *        main data area. The data area is variable in all directions.
 *
 *        --------------------------------
 *        | head  | data         | tail  |
 *        --------------------------------
 *                ^              ^
 *
 *        Current valid data area in the buffer is sb->tail - sb->data.
 *
 *     unsigned char *tail;
 *
 *        Tail of the buffer. This is the end of the currently valid data area
 *        or start of the tail area. The start of the tail area is variable.
 *
 *        --------------------------------
 *        | head  | data         | tail  |
 *        --------------------------------
 *                               ^       ^
 *
 *        Current tail section in the buffer is sb->end - sb->tail.
 *
 *    unsigned char *end;
 *
 *        End of the allocated buffer. This is the end of the allocated data
 *        area and remains as same throughout the lifetime of the buffer.
 *        Usually this field is not needed except when checking the size
 *        of the buffer.
 *
 *        --------------------------------
 *        | head  | data         | tail  |
 *        --------------------------------
 *                                       ^
 *
 *        Length of the entire buffer is (ie. truelen) sb->end - sb->head.
 *
 *     Currently valid data area is considered to be the main data area in
 *     the buffer. However, the entire buffer is of course valid data and can
 *     be used as such. Usually head section of the buffer includes different
 *     kind of headers or similar. Data section includes the main data of
 *     the buffer. Tail section can be seen as a reserve space of the data
 *     section. Tail section can be pulled towards end, and thus the data
 *     section becomes larger.
 *
 * SOURCE
 */
typedef struct {
  unsigned char *head;
  unsigned char *data;
  unsigned char *tail;
  unsigned char *end;
} *SilcBuffer, SilcBufferStruct;
/***/

/* Macros */

/****d* silcutil/SilcBufferAPI/silc_buffer_truelen
 *
 * NAME
 *
 *    #define silc_buffer_truelen(buffer)
 *
 * DESCRIPTION
 *
 *    Returns the true length of the buffer.
 *
 * SOURCE
 */
#define silc_buffer_truelen(x) (SilcUInt32)((x)->end - (x)->head)
/***/

/****d* silcutil/SilcBufferAPI/silc_buffer_len
 *
 * NAME
 *
 *    #define silc_buffer_len(buffer)
 *
 * DESCRIPTION
 *
 *    Returns the current length of the data area of the buffer.
 *
 * SOURCE
 */
#define silc_buffer_len(x) (SilcUInt32)((x)->tail - (x)->data)
/***/

/****d* silcutil/SilcBufferAPI/silc_buffer_headlen
 *
 * NAME
 *
 *    #define silc_buffer_headlen(buffer)
 *
 * DESCRIPTION
 *
 *    Returns the current length of the head data area of the buffer.
 *
 * SOURCE
 */
#define silc_buffer_headlen(x) (SilcUInt32)((x)->data - (x)->head)
/***/

/****d* silcutil/SilcBufferAPI/silc_buffer_taillen
 *
 * NAME
 *
 *    #define silc_buffer_taillen(buffer)
 *
 * DESCRIPTION
 *
 *    Returns the current length of the tail data area of the buffer.
 *
 * SOURCE
 */
#define silc_buffer_taillen(x) (SilcUInt32)((x)->end - (x)->tail)
/***/

/* Inline functions */

/****f* silcutil/SilcBufferAPI/silc_buffer_alloc
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBuffer silc_buffer_alloc(SilcUInt32 len);
 *
 * DESCRIPTION
 *
 *    Allocates new SilcBuffer and returns it.  Returns NULL on error.
 *
 ***/

static inline
SilcBuffer silc_buffer_alloc(SilcUInt32 len)
{
  SilcBuffer sb;

  /* Allocate new SilcBuffer */
  sb = (SilcBuffer)silc_calloc(1, sizeof(*sb));
  if (!sb)
    return NULL;

  /* Allocate the actual data area */
  sb->head = (unsigned char *)silc_calloc(len, sizeof(*sb->head));
  if (!sb->head)
    return NULL;

  /* Set pointers to the new buffer */
  sb->data = sb->head;
  sb->tail = sb->head;
  sb->end = sb->head + len;

  return sb;
}

/****f* silcutil/SilcBufferAPI/silc_buffer_free
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_buffer_free(SilcBuffer sb);
 *
 * DESCRIPTION
 *
 *    Frees SilcBuffer.
 *
 ***/

static inline
void silc_buffer_free(SilcBuffer sb)
{
  if (sb) {
#if defined(SILC_DEBUG)
    if (sb->head)
      memset(sb->head, 'F', silc_buffer_truelen(sb));
#endif
    silc_free(sb->head);
    silc_free(sb);
  }
}

/****f* silcutil/SilcBufferAPI/silc_buffer_steal
 *
 * SYNOPSIS
 *
 *    static inline
 *    unsigned char *silc_buffer_steal(SilcBuffer sb, SilcUInt32 *data_len);
 *
 * DESCRIPTION
 *
 *    Steals the data from the buffer `sb'.  This returns pointer to the
 *    start of the buffer and the true length of that buffer.  The `sb'
 *    cannot be used anymore after calling this function because the
 *    data buffer was stolen.  The `sb' must be freed with silc_buffer_free.
 *    The caller is responsible of freeing the stolen data buffer with
 *    silc_free.
 *
 ***/

static inline
unsigned char *silc_buffer_steal(SilcBuffer sb, SilcUInt32 *data_len)
{
  unsigned char *buf = sb->head;
  if (data_len)
    *data_len = silc_buffer_truelen(sb);
  sb->head = sb->data = sb->tail = sb->end = NULL;
  return buf;
}

/****f* silcutil/SilcBufferAPI/silc_buffer_set
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_buffer_set(SilcBuffer sb,
 *			   unsigned char *data,
 *                         SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Sets the `data' and `data_len' to the buffer pointer sent as argument.
 *    The data area is automatically set to the `data_len'. This function
 *    can be used to set the data to static buffer without needing any
 *    memory allocations. The `data' will not be copied to the buffer.
 *
 * EXAMPLE
 *
 *    SilcBufferStruct buf;
 *    silc_buffer_set(&buf, data, data_len);
 *
 ***/

static inline
void silc_buffer_set(SilcBuffer sb, unsigned char *data, SilcUInt32 data_len)
{
  sb->data = sb->head = data;
  sb->tail = sb->end = data + data_len;
}

/****f* silcutil/SilcBufferAPI/silc_buffer_pull
 *
 * SYNOPSIS
 *
 *    static inline
 *    unsigned char *silc_buffer_pull(SilcBuffer sb, SilcUInt32 len);
 *
 * DESCRIPTION
 *
 *    Pulls current data area towards end. The length of the currently
 *    valid data area is also decremented. Returns pointer to the data
 *    area before pulling. Returns NULL on error.
 *
 * EXAMPLE
 *
 *    ---------------------------------
 *    | head  | data       | tail     |
 *    ---------------------------------
 *            ^
 *            Pulls the start of the data area.
 *
 *    ---------------------------------
 *    | head     | data    | tail     |
 *    ---------------------------------
 *            ^
 *
 *    silc_buffer_pull(sb, 20);
 *
 ***/

static inline
unsigned char *silc_buffer_pull(SilcBuffer sb, SilcUInt32 len)
{
  unsigned char *old_data = sb->data;
#if defined(SILC_DEBUG)
  assert(len <= silc_buffer_len(sb));
#else
  if (len > silc_buffer_len(sb))
    return NULL;
#endif
  sb->data += len;
  return old_data;
}

/****f* silcutil/SilcBufferAPI/silc_buffer_push
 *
 * SYNOPSIS
 *
 *    static inline
 *    unsigned char *silc_buffer_push(SilcBuffer sb, SilcUInt32 len);
 *
 * DESCRIPTION
 *
 *    Pushes current data area towards beginning. Length of the currently
 *    valid data area is also incremented. Returns a pointer to the
 *    data area before pushing. Returns NULL on error.
 *
 * EXAMPLE
 *
 *    ---------------------------------
 *    | head     | data    | tail     |
 *    ---------------------------------
 *               ^
 *               Pushes the start of the data area.
 *
 *    ---------------------------------
 *    | head  | data       | tail     |
 *    ---------------------------------
 *               ^
 *
 *    silc_buffer_push(sb, 20);
 *
 ***/

static inline
unsigned char *silc_buffer_push(SilcBuffer sb, SilcUInt32 len)
{
  unsigned char *old_data = sb->data;
#if defined(SILC_DEBUG)
  assert((sb->data - len) >= sb->head);
#else
  if ((sb->data - len) < sb->head)
    return NULL;
#endif
  sb->data -= len;
  return old_data;
}

/****f* silcutil/SilcBufferAPI/silc_buffer_pull_tail
 *
 * SYNOPSIS
 *
 *    static inline
 *    unsigned char *silc_buffer_pull_tail(SilcBuffer sb, SilcUInt32 len);
 *
 * DESCRIPTION
 *
 *    Pulls current tail section towards end. Length of the current valid
 *    data area is also incremented. Returns a pointer to the data area
 *    before pulling. Returns NULL on error.
 *
 * EXAMPLE
 *
 *    ---------------------------------
 *    | head  | data       | tail     |
 *    ---------------------------------
 *                         ^
 *                         Pulls the start of the tail section.
 *
 *    ---------------------------------
 *    | head  | data           | tail |
 *    ---------------------------------
 *                         ^
 *
 *    silc_buffer_pull_tail(sb, 23);
 *
 ***/

static inline
unsigned char *silc_buffer_pull_tail(SilcBuffer sb, SilcUInt32 len)
{
  unsigned char *old_tail = sb->tail;
#if defined(SILC_DEBUG)
  assert(len <= silc_buffer_taillen(sb));
#else
  if (len > silc_buffer_taillen(sb))
    return NULL;
#endif
  sb->tail += len;
  return old_tail;
}

/****f* silcutil/SilcBufferAPI/silc_buffer_push_tail
 *
 * SYNOPSIS
 *
 *    static inline
 *    unsigned char *silc_buffer_push_tail(SilcBuffer sb, SilcUInt32 len);
 *
 * DESCRIPTION
 *
 *    Pushes current tail section towards beginning. Length of the current
 *    valid data area is also decremented. Returns a pointer to the
 *    tail section before pushing. Returns NULL on error.
 *
 * EXAMPLE
 *
 *    ---------------------------------
 *    | head  | data           | tail |
 *    ---------------------------------
 *                             ^
 *                             Pushes the start of the tail section.
 *
 *    ---------------------------------
 *    | head  | data       | tail     |
 *    ---------------------------------
 *                             ^
 *
 *    silc_buffer_push_tail(sb, 23);
 *
 ***/

static inline
unsigned char *silc_buffer_push_tail(SilcBuffer sb, SilcUInt32 len)
{
  unsigned char *old_tail = sb->tail;
#if defined(SILC_DEBUG)
  assert((sb->tail - len) >= sb->data);
#else
  if ((sb->tail - len) < sb->data)
    return NULL;
#endif
  sb->tail -= len;
  return old_tail;
}

/****f* silcutil/SilcBufferAPI/silc_buffer_put_head
 *
 * SYNOPSIS
 *
 *    static inline
 *    unsigned char *silc_buffer_put_head(SilcBuffer sb,
 *					  const unsigned char *data,
 *					  SilcUInt32 len);
 *
 * DESCRIPTION
 *
 *    Puts data at the head of the buffer. Returns pointer to the copied
 *    data area. Returns NULL on error.
 *
 * EXAMPLE
 *
 *    ---------------------------------
 *    | head  | data       | tail     |
 *    ---------------------------------
 *    ^
 *    Puts data to the head section.
 *
 *    silc_buffer_put_head(sb, data, data_len);
 *
 ***/

static inline
unsigned char *silc_buffer_put_head(SilcBuffer sb,
				    const unsigned char *data,
				    SilcUInt32 len)
{
#if defined(SILC_DEBUG)
  assert(len <= silc_buffer_headlen(sb));
#else
  if (len > silc_buffer_headlen(sb))
    return NULL;
#endif
  return (unsigned char *)memcpy(sb->head, data, len);
}

/****f* silcutil/SilcBufferAPI/silc_buffer_put
 *
 * SYNOPSIS
 *
 *    static inline
 *    unsigned char *silc_buffer_put(SilcBuffer sb,
 *				     const unsigned char *data,
 *				     SilcUInt32 len);
 *
 * DESCRIPTION
 *
 *    Puts data at the start of the valid data area. Returns a pointer
 *    to the copied data area.  Returns NULL on error.
 *
 * EXAMPLE
 *
 *    ---------------------------------
 *    | head  | data       | tail     |
 *    ---------------------------------
 *            ^
 *            Puts data to the data section.
 *
 *    silc_buffer_put(sb, data, data_len);
 *
 ***/

static inline
unsigned char *silc_buffer_put(SilcBuffer sb,
			       const unsigned char *data,
			       SilcUInt32 len)
{
#if defined(SILC_DEBUG)
  assert(len <= silc_buffer_len(sb));
#else
  if (len > silc_buffer_len(sb))
    return NULL;
#endif
  return (unsigned char *)memcpy(sb->data, data, len);
}

/****f* silcutil/SilcBufferAPI/silc_buffer_put_tail
 *
 * SYNOPSIS
 *
 *    static inline
 *    unsigned char *silc_buffer_put_tail(SilcBuffer sb,
 *					  const unsigned char *data,
 *					  SilcUInt32 len);
 *
 * DESCRIPTION
 *
 *    Puts data at the tail of the buffer. Returns pointer to the copied
 *    data area.  Returns NULL on error.
 *
 * EXAMPLE
 *
 *    ---------------------------------
 *    | head  | data           | tail |
 *    ---------------------------------
 *                             ^
 * 			       Puts data to the tail section.
 *
 *    silc_buffer_put_tail(sb, data, data_len);
 *
 ***/

static inline
unsigned char *silc_buffer_put_tail(SilcBuffer sb,
				    const unsigned char *data,
				    SilcUInt32 len)
{
#if defined(SILC_DEBUG)
  assert(len <= silc_buffer_taillen(sb));
#else
  if (len > silc_buffer_taillen(sb))
    return NULL;
#endif
  return (unsigned char *)memcpy(sb->tail, data, len);
}

/****f* silcutil/SilcBufferAPI/silc_buffer_alloc_size
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBuffer silc_buffer_alloc_size(SilcUInt32 len);
 *
 * DESCRIPTION
 *
 *    Allocates `len' bytes size buffer and moves the tail area automatically
 *    `len' bytes so that the buffer is ready to use without calling the
 *    silc_buffer_pull_tail.  Returns NULL on error.
 *
 ***/

static inline
SilcBuffer silc_buffer_alloc_size(SilcUInt32 len)
{
  SilcBuffer sb = silc_buffer_alloc(len);
  if (!sb)
    return NULL;
  silc_buffer_pull_tail(sb, len);
  return sb;
}

/****f* silcutil/SilcBufferAPI/silc_buffer_reset
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_buffer_reset(SilcBuffer sb);
 *
 * DESCRIPTION
 *
 *    Resets the buffer to the state as if it was just allocated by
 *    silc_buffer_alloc.  This does not clear the data area.  Use
 *    silc_buffer_clear if you also want to clear the data area.
 *
 ***/

static inline
void silc_buffer_reset(SilcBuffer sb)
{
  sb->data = sb->tail = sb->head;
}

/****f* silcutil/SilcBufferAPI/silc_buffer_clear
 *
 * SYNOPSIS
 *
 *    static inline
 *    void silc_buffer_clear(SilcBuffer sb);
 *
 * DESCRIPTION
 *
 *    Clears and initialiazes the buffer to the state as if it was just
 *    allocated by silc_buffer_alloc.
 *
 ***/

static inline
void silc_buffer_clear(SilcBuffer sb)
{
  memset(sb->head, 0, silc_buffer_truelen(sb));
  silc_buffer_reset(sb);
}

/****f* silcutil/SilcBufferAPI/silc_buffer_copy
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBuffer silc_buffer_copy(SilcBuffer sb);
 *
 * DESCRIPTION
 *
 *    Generates copy of a SilcBuffer. This copies everything inside the
 *    currently valid data area, nothing more. Use silc_buffer_clone to
 *    copy entire buffer.  Returns NULL on error.
 *
 ***/

static inline
SilcBuffer silc_buffer_copy(SilcBuffer sb)
{
  SilcBuffer sb_new;

  sb_new = silc_buffer_alloc_size(silc_buffer_len(sb));
  if (!sb_new)
    return NULL;
  silc_buffer_put(sb_new, sb->data, silc_buffer_len(sb));

  return sb_new;
}

/****f* silcutil/SilcBufferAPI/silc_buffer_clone
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBuffer silc_buffer_clone(SilcBuffer sb);
 *
 * DESCRIPTION
 *
 *    Clones SilcBuffer. This generates new SilcBuffer and copies
 *    everything from the source buffer. The result is exact clone of
 *    the original buffer.  Returns NULL on error.
 *
 ***/

static inline
SilcBuffer silc_buffer_clone(SilcBuffer sb)
{
  SilcBuffer sb_new;

  sb_new = silc_buffer_alloc_size(silc_buffer_truelen(sb));
  if (!sb_new)
    return NULL;
  silc_buffer_put(sb_new, sb->head, silc_buffer_truelen(sb));
  sb_new->data = sb_new->head + silc_buffer_headlen(sb);
  sb_new->tail = sb_new->data + silc_buffer_len(sb);

  return sb_new;
}

/****f* silcutil/SilcBufferAPI/silc_buffer_realloc
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBuffer silc_buffer_realloc(SilcBuffer sb, SilcUInt32 newsize);
 *
 * DESCRIPTION
 *
 *    Reallocates buffer. Old data is saved into the new buffer. The buffer
 *    is exact clone of the old one except that there is now more space
 *    at the end of buffer.  This always returns the same `sb' unless `sb'
 *    was NULL. Returns NULL on error.
 *
 ***/

static inline
SilcBuffer silc_buffer_realloc(SilcBuffer sb, SilcUInt32 newsize)
{
  SilcUInt32 hlen, dlen;
  unsigned char *h;

  if (!sb)
    return silc_buffer_alloc(newsize);

  if (newsize <= silc_buffer_truelen(sb))
    return sb;

  hlen = silc_buffer_headlen(sb);
  dlen = silc_buffer_len(sb);
  h = (unsigned char *)silc_realloc(sb->head, newsize);
  if (!h)
    return NULL;
  sb->head = h;
  sb->data = sb->head + hlen;
  sb->tail = sb->data + dlen;
  sb->end = sb->head + newsize;

  return sb;
}

/****f* silcutil/SilcBufferAPI/silc_buffer_realloc_size
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBuffer silc_buffer_realloc_size(SilcBuffer sb, SilcUInt32 newsize);
 *
 * DESCRIPTION
 *
 *    Same as silc_buffer_realloc but moves moves the tail area
 *    automatically so that the buffer is ready to use without calling the
 *    silc_buffer_pull_tail.  Returns NULL on error.
 *
 ***/

static inline
SilcBuffer silc_buffer_realloc_size(SilcBuffer sb, SilcUInt32 newsize)
{
  sb = silc_buffer_realloc(sb, newsize);
  if (!sb)
    return NULL;
  silc_buffer_pull_tail(sb, silc_buffer_taillen(sb));
  return sb;
}


/* SilcStack aware SilcBuffer routines */

/****f* silcutil/SilcBufferAPI/silc_buffer_salloc
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBuffer silc_buffer_salloc(SilcStack stack, SilcUInt32 len);
 *
 * DESCRIPTION
 *
 *    Allocates new SilcBuffer and returns it.
 *
 *    This routine use SilcStack are memory source.
 *
 ***/

static inline
SilcBuffer silc_buffer_salloc(SilcStack stack, SilcUInt32 len)
{
  SilcBuffer sb;

  /* Allocate new SilcBuffer */
  sb = (SilcBuffer)silc_scalloc(stack, 1, sizeof(*sb));
  if (!sb)
    return NULL;

  /* Allocate the actual data area */
  sb->head = (unsigned char *)silc_smalloc_ua(stack, len);
  if (!sb->head)
    return NULL;

  /* Set pointers to the new buffer */
  sb->data = sb->head;
  sb->tail = sb->head;
  sb->end = sb->head + len;

  return sb;
}

/****f* silcutil/SilcBufferAPI/silc_buffer_salloc_size
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBuffer silc_buffer_salloc_size(SilcStack stack, SilcUInt32 len);
 *
 * DESCRIPTION
 *
 *    Allocates `len' bytes size buffer and moves the tail area automatically
 *    `len' bytes so that the buffer is ready to use without calling the
 *    silc_buffer_pull_tail.
 *
 *    This routine use SilcStack are memory source.
 *
 ***/

static inline
SilcBuffer silc_buffer_salloc_size(SilcStack stack, SilcUInt32 len)
{
  SilcBuffer sb = silc_buffer_salloc(stack, len);
  if (!sb)
    return NULL;
  silc_buffer_pull_tail(sb, len);
  return sb;
}

/****f* silcutil/SilcBufferAPI/silc_buffer_srealloc
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBuffer silc_buffer_srealloc(SilcStack stack,
 *                                    SilcBuffer sb, SilcUInt32 newsize);
 *
 * DESCRIPTION
 *
 *    Reallocates buffer. Old data is saved into the new buffer. The buffer
 *    is exact clone of the old one except that there is now more space
 *    at the end of buffer.
 *
 *    This routine use SilcStack are memory source.
 *
 ***/

static inline
SilcBuffer silc_buffer_srealloc(SilcStack stack,
				SilcBuffer sb, SilcUInt32 newsize)
{
  SilcUInt32 hlen, dlen;
  unsigned char *h;

  if (!sb)
    return silc_buffer_salloc(stack, newsize);

  if (newsize <= silc_buffer_truelen(sb))
    return sb;

  hlen = silc_buffer_headlen(sb);
  dlen = silc_buffer_len(sb);
  h = (unsigned char *)silc_srealloc_ua(stack, silc_buffer_truelen(sb),
					sb->head, newsize);
  if (!h) {
    /* Do slow and stack wasting realloc.  The old sb->head is lost and
       is freed eventually. */
    h = silc_smalloc_ua(stack, newsize);
    if (!h)
      return NULL;
    memcpy(h, sb->head, silc_buffer_truelen(sb));
  }

  sb->head = h;
  sb->data = sb->head + hlen;
  sb->tail = sb->data + dlen;
  sb->end = sb->head + newsize;

  return sb;
}

/****f* silcutil/SilcBufferAPI/silc_buffer_srealloc_size
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBuffer silc_buffer_srealloc_size(SilcStack stack,
 *                                         SilcBuffer sb, SilcUInt32 newsize);
 *
 * DESCRIPTION
 *
 *    Same as silc_buffer_srealloc but moves moves the tail area
 *    automatically so that the buffer is ready to use without calling the
 *    silc_buffer_pull_tail.
 *
 *    This routine use SilcStack are memory source.
 *
 ***/

static inline
SilcBuffer silc_buffer_srealloc_size(SilcStack stack,
				     SilcBuffer sb, SilcUInt32 newsize)
{
  sb = silc_buffer_srealloc(stack, sb, newsize);
  if (!sb)
    return NULL;
  silc_buffer_pull_tail(sb, silc_buffer_taillen(sb));
  return sb;
}

/****f* silcutil/SilcBufferAPI/silc_buffer_scopy
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBuffer silc_buffer_scopy(SilcStack stack, SilcBuffer sb);
 *
 * DESCRIPTION
 *
 *    Generates copy of a SilcBuffer. This copies everything inside the
 *    currently valid data area, nothing more. Use silc_buffer_clone to
 *    copy entire buffer.
 *
 *    This routine use SilcStack are memory source.
 *
 ***/

static inline
SilcBuffer silc_buffer_scopy(SilcStack stack, SilcBuffer sb)
{
  SilcBuffer sb_new;

  sb_new = silc_buffer_salloc_size(stack, silc_buffer_len(sb));
  if (!sb_new)
    return NULL;
  silc_buffer_put(sb_new, sb->data, silc_buffer_len(sb));

  return sb_new;
}

/****f* silcutil/SilcBufferAPI/silc_buffer_sclone
 *
 * SYNOPSIS
 *
 *    static inline
 *    SilcBuffer silc_buffer_sclone(SilcStack stack, SilcBuffer sb);
 *
 * DESCRIPTION
 *
 *    Clones SilcBuffer. This generates new SilcBuffer and copies
 *    everything from the source buffer. The result is exact clone of
 *    the original buffer.
 *
 *    This routine use SilcStack are memory source.
 *
 ***/

static inline
SilcBuffer silc_buffer_sclone(SilcStack stack, SilcBuffer sb)
{
  SilcBuffer sb_new;

  sb_new = silc_buffer_salloc_size(stack, silc_buffer_truelen(sb));
  if (!sb_new)
    return NULL;
  silc_buffer_put(sb_new, sb->head, silc_buffer_truelen(sb));
  sb_new->data = sb_new->head + silc_buffer_headlen(sb);
  sb_new->tail = sb_new->data + silc_buffer_len(sb);

  return sb_new;
}

#endif /* SILCBUFFER_H */
