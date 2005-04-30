/*

  rijndael_internal.h

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

#ifndef RIJNDAEL_INTERNAL_H
#define RIJNDAEL_INTERNAL_H

#include "ciphers_def.h"

/* Cipher's context */
typedef struct {
  u4byte e_key[60];
  u4byte d_key[60];
  u4byte k_len;
} RijndaelContext;

/* Prototypes */
u4byte *rijndael_set_key(RijndaelContext *ctx,
			 const u4byte in_key[], const u4byte key_len);
void rijndael_encrypt(RijndaelContext *ctx,
		      const u4byte in_blk[4], u4byte out_blk[4]);
void rijndael_decrypt(RijndaelContext *ctx,
		      const u4byte in_blk[4], u4byte out_blk[4]);

#endif
