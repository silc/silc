/*

  sha512_internal.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SHA512_INTERNAL_H
#define SHA512_INTERNAL_H

typedef struct {
    SilcUInt64 length;
    SilcUInt64 state[8];
    SilcUInt32 curlen;
    unsigned char buf[128];
} sha512_state;

int sha512_init(sha512_state * md);
int sha512_process(sha512_state * md, const unsigned char *in,
		   unsigned long inlen);
int sha512_done(sha512_state * md, unsigned char *hash);
void sha512_transform(SilcUInt64 *state, unsigned char *buf);

#endif /* SHA512_INTERNAL_H */
