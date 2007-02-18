/*

  none.c

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

#include "silc.h"
#include "none.h"

/*
 * SILC Crypto API for None cipher (ie. no cipher) :)
 */

SILC_CIPHER_API_SET_KEY(none)
{
  return TRUE;
}

SILC_CIPHER_API_SET_IV(none)
{

}

SILC_CIPHER_API_CONTEXT_LEN(none)
{
  return 1;
}

SILC_CIPHER_API_ENCRYPT(none)
{
  memmove(dst, src, len);
  return TRUE;
}

SILC_CIPHER_API_DECRYPT(none)
{
  memmove(dst, src, len);
  return TRUE;
}
