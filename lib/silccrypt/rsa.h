/*

  rsa.h

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

#ifndef RSA_H
#define RSA_H

/*
 * SILC PKCS API for RSA
 */

SILC_PKCS_API_INIT(rsa);
SILC_PKCS_API_CLEAR_KEYS(rsa);
SILC_PKCS_API_GET_PUBLIC_KEY(rsa);
SILC_PKCS_API_GET_PRIVATE_KEY(rsa);
SILC_PKCS_API_SET_PUBLIC_KEY(rsa);
SILC_PKCS_API_SET_PRIVATE_KEY(rsa);
SILC_PKCS_API_CONTEXT_LEN(rsa);
SILC_PKCS_API_ENCRYPT(rsa);
SILC_PKCS_API_DECRYPT(rsa);
SILC_PKCS_API_SIGN(rsa);
SILC_PKCS_API_VERIFY(rsa);


#endif
