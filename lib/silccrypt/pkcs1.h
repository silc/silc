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
   PKCS #1 RSA wrapper.

   Heavily modified to work under SILC, code that is not needed in SILC has
   been removed for good, and some code was fixed and changed.

   For example, RSA_DecodeOneBlock was not used at all by Mozilla, however,
   I took this code in to use after doing some fixing.  Also, OAEP is removed
   totally for now.  I'm not sure whether OAEP could be used in the future
   with SILC but not for now.

   This file also implements partial SILC PKCS API for RSA with PKCS #1.
   It is partial because all the other functions but encrypt, decrypt,
   sign and verify are common.

   Note:

   The mandatory PKCS #1 implementation in SILC must be compliant to either
   PKCS #1 version 1.5 or PKCS #1 version 2 with the following notes:
   The signature encoding is always in same format as the encryption
   encoding regardles of the PKCS #1 version.  The signature with
   appendix (with hash algorithm OID in the data) must not be used
   in the SILC.  Rationale for this is that there is no binding between
   the PKCS #1 OIDs and the hash algorithms used in the SILC protocol.
   Hence, the encoding is always in PKCS #1 version 1.5 format.

   Any questions and comments regarding this modified version should be
   sent to priikone@poseidon.pspt.fi.

   References: ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-1v2.asc,
               ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-1.asc,
	       and RFC 2437.
*/

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
