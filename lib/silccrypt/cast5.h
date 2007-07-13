/*

  cast5.h

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

#ifndef CAST5_H
#define CAST5_H

/*
 * SILC Crypto API for Cast-128
 */

SILC_CIPHER_API_SET_KEY(cast5);
SILC_CIPHER_API_SET_IV(cast5);
SILC_CIPHER_API_CONTEXT_LEN(cast5);
SILC_CIPHER_API_ENCRYPT(cast5);
SILC_CIPHER_API_DECRYPT(cast5);

#endif /* CAST5_H */
