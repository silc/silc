/*

  rsa.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef RSA_H
#define RSA_H

/* RSA Public Key */
typedef struct {
  int bits;			/* bits in key */
  SilcMPInt n;			/* modulus */
  SilcMPInt e;			/* public exponent */
} RsaPublicKey;

/* RSA Private Key */
typedef struct {
  int bits;			/* bits in key */
  SilcMPInt n;			/* modulus */
  SilcMPInt e;			/* public exponent */
  SilcMPInt d;			/* private exponent */
  SilcMPInt p;			/* CRT, p */
  SilcMPInt q;			/* CRT, q */
  SilcMPInt dP;			/* CRT, d mod p - 1 */
  SilcMPInt dQ;			/* CRT, d mod q - 1 */
  SilcMPInt qP;			/* CRT, q ^ -1 mod p */
} RsaPrivateKey;

SilcBool rsa_generate_keys(SilcUInt32 bits, SilcMPInt *p, SilcMPInt *q,
			   void **ret_public_key, void **ret_private_key);
SilcBool rsa_public_operation(RsaPublicKey *key, SilcMPInt *src,
			      SilcMPInt *dst);
SilcBool rsa_private_operation(RsaPrivateKey *key, SilcMPInt *src,
			       SilcMPInt *dst);

#endif /* RSA_H */
