/*

  twofish.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/*
 * $Id$
 * $Log$
 * Revision 1.1  2000/06/27 11:36:55  priikone
 * Initial revision
 *
 *
 */

#ifndef TWOFISH_H
#define TWOFISH_H

#include "twofish_internal.h"

/* 
 * SILC Crypto API for Twofish
 */

SILC_CIPHER_API_SET_KEY(twofish);
SILC_CIPHER_API_SET_KEY_WITH_STRING(twofish);
SILC_CIPHER_API_CONTEXT_LEN(twofish);
SILC_CIPHER_API_ENCRYPT_CBC(twofish);
SILC_CIPHER_API_DECRYPT_CBC(twofish);

#endif
