/*

  silcbuffer.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1998 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCBUFFER_H
#define SILCBUFFER_H

/* 
   SILC Buffer object.

   SilcBuffer is very simple and easy to use, yet you can do to the
   buffer almost anything you want with its method functions. The buffer
   is constructed of four different data sections that in whole creates
   the allocated data area. Following short description of the fields
   of the buffer.

   unsigned int truelen;

       True length of the buffer. This is set at the allocation of the
       buffer and it should not be touched after that. This field should
       be considered read-only.

   unsigned int len;

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
    kind of headers or similiar. Data section includes the main data of
    the buffer. Tail section can be seen as a reserve space of the data
    section. Tail section can be pulled towards end thus the data section
    becomes larger.

    This buffer scheme is based on Linux kernel's Socket Buffer, the 
    idea were taken directly from there and credits should go there.

*/

typedef struct SilcBufferStruct {
  unsigned int truelen;
  unsigned int len;
  unsigned char *head;
  unsigned char *data;
  unsigned char *tail;
  unsigned char *end;

  /* Method functions. */
  unsigned char *(*pull)(struct SilcBufferStruct *, unsigned int);
  unsigned char *(*push)(struct SilcBufferStruct *, unsigned int);
  unsigned char *(*pull_tail)(struct SilcBufferStruct *, unsigned int);
  unsigned char *(*push_tail)(struct SilcBufferStruct *, unsigned int);
  unsigned char *(*put)(struct SilcBufferStruct *, unsigned char *, 
			unsigned int);
  unsigned char *(*put_head)(struct SilcBufferStruct *, unsigned char *, 
			     unsigned int);
  unsigned char *(*put_tail)(struct SilcBufferStruct *, unsigned char *, 
			     unsigned int);
} SilcBufferObject;

typedef SilcBufferObject *SilcBuffer;

/* Macros */

/* Returns the true length of the buffer. This is used to pull
   the buffer area to the end of the buffer. */
#define SILC_BUFFER_END(x) ((x)->end - (x)->head)

#ifndef SILC_DEBUG		/* When we are not doing debugging we use
				   optimized inline buffer functions. */
/* 
 * Optimized buffer managing routines.  These are short inline
 * functions.
 */

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

extern inline 
unsigned char *silc_buffer_pull(SilcBuffer sb, unsigned int len)
{
  unsigned char *old_data = sb->data;

  assert(len <= (sb->tail - sb->data));

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

extern inline 
unsigned char *silc_buffer_push(SilcBuffer sb, unsigned int len)
{
  unsigned char *old_data = sb->data;

  assert((sb->data - len) >= sb->head);

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

extern inline 
unsigned char *silc_buffer_pull_tail(SilcBuffer sb, unsigned int len)
{
  unsigned char *old_tail = sb->tail;

  assert((sb->end - sb->tail) >= len);

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

extern inline
unsigned char *silc_buffer_push_tail(SilcBuffer sb, unsigned int len)
{
  unsigned char *old_tail = sb->tail;

  assert((sb->tail - len) >= sb->data);

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

extern inline
unsigned char *silc_buffer_put_head(SilcBuffer sb, 
				    unsigned char *data,
				    unsigned int len)
{
  assert((sb->data - sb->head) >= len);
  return memcpy(sb->head, data, len);
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

extern inline
unsigned char *silc_buffer_put(SilcBuffer sb, 
			       unsigned char *data,
			       unsigned int len)
{
  assert((sb->tail - sb->data) >= len);
  return memcpy(sb->data, data, len);
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

extern inline
unsigned char *silc_buffer_put_tail(SilcBuffer sb, 
				    unsigned char *data,
				    unsigned int len)
{
  assert((sb->end - sb->tail) >= len);
  return memcpy(sb->tail, data, len);
}

#endif /* !SILC_DEBUG */

/* Prototypes */
SilcBuffer silc_buffer_alloc(unsigned int len);
void silc_buffer_free(SilcBuffer sb);
#ifdef SILC_DEBUG
unsigned char *silc_buffer_pull(SilcBuffer sb, unsigned int len);
unsigned char *silc_buffer_push(SilcBuffer sb, unsigned int len);
unsigned char *silc_buffer_pull_tail(SilcBuffer sb, unsigned int len);
unsigned char *silc_buffer_push_tail(SilcBuffer sb, unsigned int len);
unsigned char *silc_buffer_put_head(SilcBuffer sb, 
				    unsigned char *data,
				    unsigned int len);
unsigned char *silc_buffer_put(SilcBuffer sb, 
			       unsigned char *data,
			       unsigned int len);
unsigned char *silc_buffer_put_tail(SilcBuffer sb, 
				    unsigned char *data,
				    unsigned int len);
#endif

#endif
