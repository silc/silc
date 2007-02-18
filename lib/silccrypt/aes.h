/*

  aes.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef AES_H
#define AES_H

/*
 * SILC Crypto API for AES
 */

SILC_CIPHER_API_SET_KEY(aes_cbc);
SILC_CIPHER_API_SET_IV(aes_cbc);
SILC_CIPHER_API_ENCRYPT(aes_cbc);
SILC_CIPHER_API_DECRYPT(aes_cbc);
SILC_CIPHER_API_CONTEXT_LEN(aes_cbc);
SILC_CIPHER_API_SET_KEY(aes_ctr);
SILC_CIPHER_API_SET_IV(aes_ctr);
SILC_CIPHER_API_ENCRYPT(aes_ctr);
SILC_CIPHER_API_DECRYPT(aes_ctr);
SILC_CIPHER_API_CONTEXT_LEN(aes_ctr);

#endif
