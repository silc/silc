/*

  rsa_internal.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2003 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef RSA_INTERNAL_H
#define RSA_INTERNAL_H

/* RSA Keys, includes both Private and Public key */
typedef struct {
  int bits;			/* bits in key */
  SilcMPInt n;			/* modulus */
  SilcMPInt e;			/* public exponent */
  SilcMPInt d;			/* private exponent (no CRT) */
  SilcMPInt p;			/* p */
  SilcMPInt q;			/* q */
  SilcMPInt dP;			/* CRT, d mod p - 1 */
  SilcMPInt dQ;			/* CRT, d mod q - 1 */
  SilcMPInt pQ;			/* CRT, p * (p ^ -1 mod q) mod n */
  SilcMPInt qP;			/* CRT, q * (q ^ -1 mod p) mod n */
  unsigned int pub_set : 1;	/* TRUE if n and e is set */
  unsigned int prv_set : 1;	/* TRUE if d is set */
  unsigned int crt     : 1;	/* TRUE if CRT is used */
} RsaKey;

bool rsa_generate_keys(RsaKey *key, SilcUInt32 bits,
		       SilcMPInt *p, SilcMPInt *q);
bool rsa_clear_keys(RsaKey *key);
bool rsa_public_operation(RsaKey *key, SilcMPInt *src, SilcMPInt *dst);
bool rsa_private_operation(RsaKey *key, SilcMPInt *src, SilcMPInt *dst);

#endif
