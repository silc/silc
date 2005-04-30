/*

  twofish_internal.h

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

#ifndef TWOFISH_INTERNAL_H
#define TWOFISH_INTERNAL_H

#include "ciphers_def.h"

/* Cipher's context */
typedef struct {
  u4byte k_len;
  u4byte l_key[40];
  u4byte s_key[4];
} TwofishContext;

/* Prototypes */
u4byte *twofish_set_key(TwofishContext *ctx,
			const u4byte in_key[], const u4byte key_len);
void twofish_encrypt(TwofishContext *ctx,
		     const u4byte in_blk[4], u4byte out_blk[]);
void twofish_decrypt(TwofishContext *ctx,
		     const u4byte in_blk[4], u4byte out_blk[4]);

#endif
