/*

  silcbuffer.c

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
/*
 * $Id$
 * $Log$
 * Revision 1.3  2000/11/01 21:43:44  priikone
 * 	removed memset not needed
 *
 * Revision 1.2  2000/10/31 19:48:32  priikone
 * 	A LOT updates. Cannot separate. :)
 *
 * Revision 1.1  2000/09/13 17:45:15  priikone
 * 	Splitted SILC core library. Core library includes now only
 * 	SILC protocol specific stuff. New utility library includes the
 * 	old stuff from core library that is more generic purpose stuff.
 *
 * Revision 1.2  2000/07/05 06:06:35  priikone
 * 	Global cosmetic change.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:55  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "silcincludes.h"
#include "silcbuffer.h"

#ifdef SILC_DEBUG		/* If we are doing debugging we won't
				   have the optimized inline buffer functions
				   available as optimization is not set
				   to compiler. These normal routines are
				   used in debugging mode. */

/* XXX These are currenly obsolete as SILC is compiled always with -O
   flag thus inline functions maybe used always. So, fix these. */

/* Allocates a new SilcBuffer and returns a pointer to it. The data
   area of the new buffer is set to the real beginning of the buffer. 

   Buffer after allocation:
   ---------------------------------
   |                               |
   ---------------------------------
   ^ head, data, tail              ^ end

*/

SilcBuffer silc_buffer_alloc(unsigned int len)
{
  SilcBuffer sb;
  unsigned char *data;

  /* Allocate new SilcBuffer */
  sb = silc_calloc(1, sizeof(*sb));

  /* Allocate the actual data area */
  data = silc_calloc(len, sizeof(*data));

  /* Set pointers to the new buffer */
  sb->truelen = len;
  sb->len = 0;
  sb->head = data;
  sb->data = data;
  sb->tail = data;
  sb->end = data + sb->truelen;

  return sb;
}

/* Free's a SilcBuffer */

void silc_buffer_free(SilcBuffer sb)
{
  if (sb) {
    memset(sb->head, 'F', sb->truelen);
    silc_free(sb->head);
    silc_free(sb);
  }
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

unsigned char *silc_buffer_put_tail(SilcBuffer sb, 
				    unsigned char *data,
				    unsigned int len)
{
  assert((sb->end - sb->tail) >= len);
  return memcpy(sb->tail, data, len);
}

#endif
