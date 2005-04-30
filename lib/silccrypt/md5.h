/*

  md5.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef MD5_H
#define MD5_H

/* 
 * SILC Hash API for MD5
 */

SILC_HASH_API_INIT(md5);
SILC_HASH_API_UPDATE(md5);
SILC_HASH_API_FINAL(md5);
SILC_HASH_API_TRANSFORM(md5);
SILC_HASH_API_CONTEXT_LEN(md5);

#endif
