/*

  mpbin.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2000 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"

/* Encodes MP integer into binary data. Returns allocated data that
   must be free'd by the caller. If `len' is provided the destination
   buffer is allocated that large. If zero then the size is approximated. */

unsigned char *silc_mp_mp2bin(SilcInt *val, unsigned int len,
			      unsigned int *ret_len)
{
  int i;
  unsigned int size;
  unsigned char *ret;
  SilcInt tmp;

  size = (len ? len : ((silc_mp_sizeinbase(val, 2) + 7) / 8));
  ret = silc_calloc(size, sizeof(*ret));
  
  silc_mp_init_set(&tmp, val);

  for (i = size; i > 0; i--) {
    ret[i - 1] = (unsigned char)(silc_mp_get_ui(&tmp) & 0xff);
    silc_mp_fdiv_q_2exp(&tmp, &tmp, 8);
  }

  silc_mp_clear(&tmp);

  if (ret_len)
    *ret_len = size;

  return ret;
}

/* Samve as above but does not allocate any memory.  The encoded data is
   returned into `dst' and it's length to the `ret_len'. If `dst_len is
   non-zero then the destination buffer is assumbed to be that large. */

void silc_mp_mp2bin_noalloc(SilcInt *val, unsigned char *dst,
			    unsigned int dst_len)
{
  int i;
  unsigned int size = dst_len;
  SilcInt tmp;

  silc_mp_init_set(&tmp, val);

  for (i = size; i > 0; i--) {
    dst[i - 1] = (unsigned char)(silc_mp_get_ui(&tmp) & 0xff);
    silc_mp_fdiv_q_2exp(&tmp, &tmp, 8);
  }

  silc_mp_clear(&tmp);
}

/* Decodes binary data into MP integer. The integer sent as argument
   must be initialized. */

void silc_mp_bin2mp(unsigned char *data, unsigned int len, SilcInt *ret)
{
  int i;

  silc_mp_set_ui(ret, 0);

  for (i = 0; i < len; i++) {
    silc_mp_mul_2exp(ret, ret, 8);
    silc_mp_add_ui(ret, ret, data[i]);
  }
}
