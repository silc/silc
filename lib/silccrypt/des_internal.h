/*

  des_internal.h

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

#ifndef DES_INTERNAL_H
#define DES_INTERNAL_H

#include "ciphers_def.h"

typedef struct {
  SilcUInt32 ek[32];
  SilcUInt32 dk[32];
  SilcUInt32 padlen;
} des_key;

typedef struct {
  SilcUInt32 ek[3][32];
  SilcUInt32 dk[3][32];
  SilcUInt32 padlen;
} des3_key;

int des_setup(const unsigned char *key, int keylen, int num_rounds,
	      des_key *skey);
int des_encrypt(des_key *skey, const SilcUInt32 pt[2],
		SilcUInt32 ct[2]);
int des_decrypt(des_key *skey, const SilcUInt32 ct[2],
		SilcUInt32 pt[2]);

int des3_setup(const unsigned char *key, int keylen, int num_rounds,
	       des3_key *skey);
int des3_encrypt(des3_key *skey, const SilcUInt32 pt[2],
		 SilcUInt32 ct[2]);
int des3_decrypt(des3_key *skey, const SilcUInt32 ct[2],
		 SilcUInt32 pt[2]);

#endif /* DES_INTERNAL_H */
