/*

  pkcs1.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
#ifndef PKCS1_H
#define PKCS1_H

/*
 * SILC PKCS API for PKCS #1
 *
 * Note all the other PKCS API functions are used from the rsa.c.
 * See the definitions in rsa.c and in silcpkcs.c.
 */

SILC_PKCS_API_ENCRYPT(pkcs1);
SILC_PKCS_API_DECRYPT(pkcs1);
SILC_PKCS_API_SIGN(pkcs1);
SILC_PKCS_API_VERIFY(pkcs1);

#endif
