/*

  blowfish_internal.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef BLOWFISH_INTERNAL_H
#define BLOWFISH_INTERNAL_H

#include "ciphers_def.h"

/* Cipher's context */
typedef struct blow_key
{
    u32 P[18];
    u32 S[1024];
} BlowfishContext;

/* Prototypes */
int blowfish_encrypt(BlowfishContext *ctx, 
		     u32 *in_blk, u32 *out_blk, int size);
int blowfish_decrypt(BlowfishContext *ctx, 
		     u32 *in_blk, u32 *out_blk, int size);
int blowfish_set_key(BlowfishContext *ctx,
		     unsigned char *key, int keybytes);

#endif
