/*

  cast.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1999 - 2000, 2006, 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef CAST_H
#define CAST_H

/*
 * SILC Crypto API for Cast-256
 */

SILC_CIPHER_API_SET_KEY(cast_cbc);
SILC_CIPHER_API_SET_IV(cast_cbc);
SILC_CIPHER_API_CONTEXT_LEN(cast_cbc);
SILC_CIPHER_API_ENCRYPT(cast_cbc);
SILC_CIPHER_API_DECRYPT(cast_cbc);

#endif
