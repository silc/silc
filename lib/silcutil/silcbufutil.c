/*

  silcbufutil.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

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
 * Revision 1.1  2000/09/13 17:45:16  priikone
 * 	Splitted SILC core library. Core library includes now only
 * 	SILC protocol specific stuff. New utility library includes the
 * 	old stuff from core library that is more generic purpose stuff.
 *
 * Revision 1.3  2000/07/14 06:08:49  priikone
 * 	Added silc_buffer_realloc. Fixed silc_buffer_clone.
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

#ifdef SILC_DEBUG		/* If we are doing debugging we won't
				   have the optimized inline buffer functions
				   available as optimization is not set
				   to compiler. These normal routines are
				   used in debugging mode. */

/* Clears and initialiazes the buffer to the state as if it was just
   allocated by silc_buffer_alloc. */

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

SilcBuffer silc_buffer_realloc(SilcBuffer sb, unsigned int newsize)
{
  SilcBuffer sb_new;

  sb_new = silc_buffer_alloc(newsize);
  silc_buffer_pull_tail(sb_new, SILC_BUFFER_END(sb_new));
  silc_buffer_put(sb_new, sb->head, sb->truelen);
  sb_new->data = sb_new->head + (sb->data - sb->head);
  sb_new->tail = sb_new->data + sb->len;
  sb_new->len = sb->len;

  silc_buffer_free(sb);

  return sb_new;
}

#endif /* SILC_DEBUG */
