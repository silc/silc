/*

  cast5_internal.h

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

#ifndef CAST5_INTERNAL_H
#define CAST5_INTERNAL_H

#include "ciphers_def.h"

typedef struct {
  SilcUInt32 K[32];
  SilcUInt16 keylen;
  SilcUInt16 padlen;
} cast5_key;

int cast5_setup(const unsigned char *key, int keylen, int num_rounds,
		cast5_key *skey);
int cast5_encrypt(cast5_key *skey, const SilcUInt32 pt[2],
		  SilcUInt32 ct[2]);
int cast5_decrypt(cast5_key *skey, const SilcUInt32 ct[2],
		  SilcUInt32 pt[2]);

#endif /* CAST5_INTERNAL_H */
