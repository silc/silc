/*

  des.h

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

#ifndef DES_H
#define DES_H

/*
 * SILC Crypto API for DES and 3DES
 */

SILC_CIPHER_API_SET_KEY(des);
SILC_CIPHER_API_SET_IV(des);
SILC_CIPHER_API_CONTEXT_LEN(des);
SILC_CIPHER_API_ENCRYPT(des);
SILC_CIPHER_API_DECRYPT(des);

SILC_CIPHER_API_SET_KEY(3des);
SILC_CIPHER_API_SET_IV(3des);
SILC_CIPHER_API_CONTEXT_LEN(3des);
SILC_CIPHER_API_ENCRYPT(3des);
SILC_CIPHER_API_DECRYPT(3des);

#endif /* DES_H */
