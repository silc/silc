/*

  silcbuffer.h 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1998 - 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */
/* Optimized buffer managing routines.  These are short inline functions. */

#ifndef SILCBUFFER_H
#define SILCBUFFER_H

/* 
   SILC Buffer object.

   SilcBuffer is very simple and easy to use, yet you can do to the
   buffer almost anything you want with its method functions. The buffer
   is constructed of four different data sections that in whole creates
   the allocated data area. Following short description of the fields
   of the buffer.

   uint32 truelen;

       True length of the buffer. This is set at the allocation of the
       buffer and it should not be touched after that. This field should
       be considered read-only.

   uint32 len;

       Length of the currently valid data area. Tells the length of the 
       data at the buffer. This is set to zero at the allocation of the
       buffer and should not be updated by hand. Method functions of the
       buffer automatically updates this field. However, it is not
       read-only field and can be updated manually if necessary.

   unsiged char *head;

       Head of the allocated buffer. This is the start of the allocated
       data area and remains as same throughout the lifetime of the buffer.
       However, the end of the head area or the start of the currently valid
       data area is variable.

       --------------------------------
       | head  | data         | tail  |
       --------------------------------
       ^       ^

       Current head section in the buffer is sb->data - sb->head.

   unsigned char *data;

       Currently valid data area. This is the start of the currently valid
       main data area. The data area is variable in all directions.

       --------------------------------
       | head  | data         | tail  |
       --------------------------------
               ^              ^
 
       Current valid data area in the buffer is sb->tail - sb->data.

    unsigned char *tail;

       Tail of the buffer. This is the end of the currently valid data area
       or start of the tail area. The start of the tail area is variable.

       --------------------------------
       | head  | data         | tail  |
       --------------------------------
                              ^       ^

       Current tail section in the buffer is sb->end - sb->tail.

   unsigned char *end;

       End of the allocated buffer. This is the end of the allocated data
       area and remains as same throughout the lifetime of the buffer.
       Usually this field is not needed except when checking the size
       of the buffer.

       --------------------------------
       | head  | data         | tail  |
       --------------------------------
                                      ^

       Length of the entire buffer is (ie. truelen) sb->end - sb->head.

    Currently valid data area is considered to be the main data area in
    the buffer. However, the entire buffer is of course valid data and can
    be used as such. Usually head section of the buffer includes different
    kind of headers or similar. Data section includes the main data of
    the buffer. Tail section can be seen as a reserve space of the data
    section. Tail section can be pulled towards end thus the data section
    becomes larger.

    This buffer scheme is based on Linux kernel's Socket Buffer, the 
    idea were taken directly from there and credits should go there.

*/

typedef struct {
  uint32 truelen;
  uint32 len;
  unsigned char *head;
  unsigned char *data;
  unsigned char *tail;
  unsigned char *end;
} *SilcBuffer, SilcBufferStruct;

/* Macros */

/* Returns the true length of the buffer. This is used to pull
   the buffer area to the end of the buffer. */
#define SILC_BUFFER_END(x) ((x)->end - (x)->head)

/* Inline functions */

static inline
SilcBuffer silc_buffer_alloc(uint32 len)
{
  SilcBuffer sb;

  /* Allocate new SilcBuffer */
  sb = (SilcBuffer)silc_calloc(1, sizeof(*sb));

  /* Allocate the actual data area */
  sb->head = (unsigned char *)silc_calloc(len, sizeof(*sb->head));

  /* Set pointers to the new buffer */
  sb->truelen = len;
  sb->data = sb->head;
  sb->tail = sb->head;
  sb->end = sb->head + sb->truelen;

  return sb;
}

/* Free's a SilcBuffer */

static inline
void silc_buffer_free(SilcBuffer sb)
{
  if (sb) {
    memset(sb->head, 'F', sb->truelen);
    silc_free(sb->head);
    silc_free(sb);
  }
}

/* Sets the `data' and `data_len' to the buffer pointer sent as argument.
   The data area is automatically set to the `data_len'. This function
   can be used to set the data to static buffer without needing any
   memory allocations. The `data' will not be copied to the buffer. */

static inline
void silc_buffer_set(SilcBuffer sb, unsigned char *data, uint32 data_len)
{
  sb->data = sb->head = data;
  sb->tail = sb->end = data + data_len;
  sb->len = sb->truelen = data_len;
}

/* Pulls current data area towards end. The length of the currently
   valid data area is also decremented. Returns pointer to the data
   area before pulling. 

   Example:
   ---------------------------------
   | head  | data       | tail     |
   ---------------------------------
           ^
           Pulls the start of the data area.

   ---------------------------------
   | head     | data    | tail     |
   ---------------------------------
           ^
*/

static inline 
unsigned char *silc_buffer_pull(SilcBuffer sb, uint32 len)
{
  unsigned char *old_data = sb->data;

#ifdef SILC_DEBUG
  assert(len <= (uint32)(sb->tail - sb->data));
#endif

  sb->data += len;
  sb->len -= len;

  return old_data;
}

/* Pushes current data area towards beginning. Length of the currently
   valid data area is also incremented. Returns a pointer to the 
   data area before pushing. 

   Example:
   ---------------------------------
   | head     | data    | tail     |
   ---------------------------------
              ^
              Pushes the start of the data area.

   ---------------------------------
   | head  | data       | tail     |
   ---------------------------------
              ^
*/

static inline 
unsigned char *silc_buffer_push(SilcBuffer sb, uint32 len)
{
  unsigned char *old_data = sb->data;

#ifdef SILC_DEBUG
  assert((sb->data - len) >= sb->head);
#endif

  sb->data -= len;
  sb->len += len;

  return old_data;
}

/* Pulls current tail section towards end. Length of the current valid
   data area is also incremented. Returns a pointer to the data area 
   before pulling.

   Example:
   ---------------------------------
   | head  | data       | tail     |
   ---------------------------------
                        ^
                        Pulls the start of the tail section.

   ---------------------------------
   | head  | data           | tail |
   ---------------------------------
                        ^
*/

static inline 
unsigned char *silc_buffer_pull_tail(SilcBuffer sb, uint32 len)
{
  unsigned char *old_tail = sb->tail;

#ifdef SILC_DEBUG
  assert((uint32)(sb->end - sb->tail) >= len);
#endif

  sb->tail += len;
  sb->len += len;

  return old_tail;
}

/* Pushes current tail section towards beginning. Length of the current
   valid data area is also decremented. Returns a pointer to the 
   tail section before pushing. 

   Example:
   ---------------------------------
   | head  | data           | tail |
   ---------------------------------
                            ^
                            Pushes the start of the tail section.

   ---------------------------------
   | head  | data       | tail     |
   ---------------------------------
                            ^
*/

static inline
unsigned char *silc_buffer_push_tail(SilcBuffer sb, uint32 len)
{
  unsigned char *old_tail = sb->tail;

#ifdef SILC_DEBUG
  assert((sb->tail - len) >= sb->data);
#endif

  sb->tail -= len;
  sb->len -= len;

  return old_tail;
}

/* Puts data at the head of the buffer. Returns pointer to the copied
   data area. 
   
   Example:
   ---------------------------------
   | head  | data       | tail     |
   ---------------------------------
   ^
   Puts data to the head section. 
*/

static inline
unsigned char *silc_buffer_put_head(SilcBuffer sb, 
				    const unsigned char *data,
				    uint32 len)
{
#ifdef SILC_DEBUG
  assert((uint32)(sb->data - sb->head) >= len);
#endif
  return (unsigned char *)memcpy(sb->head, data, len);
}

/* Puts data at the start of the valid data area. Returns a pointer 
   to the copied data area. 

   Example:
   ---------------------------------
   | head  | data       | tail     |
   ---------------------------------
           ^
           Puts data to the data section.
*/

static inline
unsigned char *silc_buffer_put(SilcBuffer sb, 
			       const unsigned char *data,
			       uint32 len)
{
#ifdef SILC_DEBUG
  assert((uint32)(sb->tail - sb->data) >= len);
#endif
  return (unsigned char *)memcpy(sb->data, data, len);
}

/* Puts data at the tail of the buffer. Returns pointer to the copied
   data area. 

   Example:
   ---------------------------------
   | head  | data           | tail |
   ---------------------------------
                            ^
			    Puts data to the tail section.
*/

static inline
unsigned char *silc_buffer_put_tail(SilcBuffer sb, 
				    const unsigned char *data,
				    uint32 len)
{
#ifdef SILC_DEBUG
  assert((uint32)(sb->end - sb->tail) >= len);
#endif
  return (unsigned char *)memcpy(sb->tail, data, len);
}

/* Clears and initialiazes the buffer to the state as if it was just
   allocated by silc_buffer_alloc. */

static inline
void silc_buffer_clear(SilcBuffer sb)
{
  memset(sb->head, 0, sb->truelen);
  sb->data = sb->head;
  sb->tail = sb->head;
  sb->len = 0;
}

/* Generates copy of a SilcBuffer. This copies everything inside the
   currently valid data area, nothing more. Use silc_buffer_clone to
   copy entire buffer. */

static inline
SilcBuffer silc_buffer_copy(SilcBuffer sb)
{
  SilcBuffer sb_new;

  sb_new = silc_buffer_alloc(sb->len);
  silc_buffer_pull_tail(sb_new, SILC_BUFFER_END(sb_new));
  silc_buffer_put(sb_new, sb->data, sb->len);

  return sb_new;
}

/* Clones SilcBuffer. This generates new SilcBuffer and copies
   everything from the source buffer. The result is exact clone of
   the original buffer. */

static inline
SilcBuffer silc_buffer_clone(SilcBuffer sb)
{
  SilcBuffer sb_new;

  sb_new = silc_buffer_alloc(sb->truelen);
  silc_buffer_pull_tail(sb_new, SILC_BUFFER_END(sb_new));
  silc_buffer_put(sb_new, sb->head, sb->truelen);
  sb_new->data = sb_new->head + (sb->data - sb->head);
  sb_new->tail = sb_new->data + sb->len;
  sb_new->len = sb->len;

  return sb_new;
}

/* Reallocates buffer. Old data is saved into the new buffer. Returns
   new SilcBuffer pointer. The buffer is exact clone of the old one
   except that there is now more space at the end of buffer. */

static inline
SilcBuffer silc_buffer_realloc(SilcBuffer sb, uint32 newsize)
{
  SilcBuffer sb_new;

  if (!sb)
    return silc_buffer_alloc(newsize);

  if (newsize <= sb->truelen)
    return sb;

  sb_new = silc_buffer_alloc(newsize);
  silc_buffer_pull_tail(sb_new, SILC_BUFFER_END(sb_new));
  silc_buffer_put(sb_new, sb->head, sb->truelen);
  sb_new->data = sb_new->head + (sb->data - sb->head);
  sb_new->tail = sb_new->data + sb->len;
  sb_new->len = sb->len;

  silc_buffer_free(sb);

  return sb_new;
}

#endif
