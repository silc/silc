/*

  sha256.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SHA256_H
#define SHA256_H

/* 
 * SILC Hash API for SHA256
 */

SILC_HASH_API_INIT(sha256);
SILC_HASH_API_UPDATE(sha256);
SILC_HASH_API_FINAL(sha256);
SILC_HASH_API_TRANSFORM(sha256);
SILC_HASH_API_CONTEXT_LEN(sha256);

#endif /* SHA256_H */
