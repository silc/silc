/*

  loki_internal.h

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

#ifndef LOKI_INTERNAL_H
#define LOKI_INTERNAL_H

/* Cipher's context */
typedef struct {
  u4byte l_key[96];
} LokiContext;

/* Prototypes */
u4byte *loki_set_key(LokiContext *ctx,
		     const u4byte in_key[], const u4byte key_len);
void loki_encrypt(LokiContext *ctx,
		  const u4byte in_blk[4], u4byte out_blk[4]);
void loki_decrypt(LokiContext *ctx,
		  const u4byte in_blk[4], u4byte out_blk[4]);

#endif
