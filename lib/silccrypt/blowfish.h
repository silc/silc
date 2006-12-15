/*

  blowfish.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef BLOWFISH_H
#define BLOWFISH_H

/*
 * SILC Crypto API for Blowfish
 */

SILC_CIPHER_API_SET_KEY(blowfish);
SILC_CIPHER_API_CONTEXT_LEN(blowfish);
SILC_CIPHER_API_ENCRYPT_CBC(blowfish);
SILC_CIPHER_API_DECRYPT_CBC(blowfish);

#endif
