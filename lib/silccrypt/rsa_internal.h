/*

  rsa_internal.h

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

#ifndef RSA_INTERNAL_H
#define RSA_INTERNAL_H

/* RSA Keys, includes both Private and Public key */
typedef struct {
  int bits;			/* bits in key */
  SilcInt p;			/* prime p */
  SilcInt q;			/* prime q */
  SilcInt n;			/* modulus */
  SilcInt e;			/* public exponent */
  SilcInt d;			/* private exponent */
} RsaKey;

void rsa_generate_keys(RsaKey *key, unsigned int bits, 
		       SilcInt *p, SilcInt *q);
void rsa_clear_keys(RsaKey *key);
void rsa_en_de_crypt(SilcInt *cm, SilcInt *mc, 
		     SilcInt *expo, SilcInt *modu);

#endif
