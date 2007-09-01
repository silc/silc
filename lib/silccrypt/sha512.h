/*

  sha512.h

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

#ifndef SHA512_H
#define SHA512_H

/*
 * SILC Hash API for SHA512
 */

SILC_HASH_API_INIT(sha512);
SILC_HASH_API_UPDATE(sha512);
SILC_HASH_API_FINAL(sha512);
SILC_HASH_API_TRANSFORM(sha512);
SILC_HASH_API_CONTEXT_LEN(sha512);

#endif /* SHA512_H */
