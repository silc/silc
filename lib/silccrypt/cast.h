/*

  cast.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1999 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
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

SILC_CIPHER_API_SET_KEY(cast);
SILC_CIPHER_API_SET_KEY_WITH_STRING(cast);
SILC_CIPHER_API_CONTEXT_LEN(cast);
SILC_CIPHER_API_ENCRYPT_CBC(cast);
SILC_CIPHER_API_DECRYPT_CBC(cast);

#endif
