/*

  rsa.c 	RSA Public and Private key generation functions,
 	   	RSA encrypt and decrypt functions.

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  Created: Sat Mar  1 13:26:45 1997 pekka

  RSA public key cryptographic algorithm used in this distribution is:

  	Key generation:
  	p, q		primes
  	p != q
 	n = p * q	modulus

 	Public key exponent:
 	e   relatively prime to (p-1) * (q-1)
 	Private key exponent:
 	d = e ^ -1 mod lcm(((p-1) * (q-1)))

 	Encryption:
 	c = m ^ e mod n
 	Decryption:
 	m = c ^ d mod n

  Supports CRT (Chinese Remainder Theorem) for private key operations.

  The SSH's (Secure Shell), PGP's (Pretty Good Privacy) and RSAREF
  Toolkit were used as reference when coding this implementation. They
  all were a big help for me.

  I also suggest reading Bruce Schneier's; Applied Cryptography, Second
  Edition, John Wiley & Sons, Inc. 1996. This book deals about RSA and
  everything else too about cryptography.

*/
/* $Id$ */

/*
   ChangeLog

   o Mon Feb 12 11:20:32 EET 2001  Pekka

     Changed RSA private exponent generation to what PKCS #1 suggests.  We
     try to find the smallest possible d by doing modinv(e, lcm(phi)) instead
     of modinv(e, phi).  Note: this is not security fix but optimization.

   o Tue Feb 20 13:58:58 EET 2001  Pekka

     Set key->bits in rsa_generate_key.  It is the modulus length in bits.
     The `tmplen' in encrypt, decrypt, sign and verify PKCS API functions
     is now calculated by (key->bits + 7) / 8.  It is the length of one block.

   o Sat Mar 16 18:27:19 EET 2002  Pekka

     Use the SilcRng sent as argument to SILC_PKCS_API_INIT in prime
     generation.

   o Sat Sep 26 19:59:48 EEST 2002  Pekka

     Fixed double free in public key setting.  Use a bit larger e as
     starting point in key generation.
*/

#include "silc.h"
#include "rsa.h"

/* Generates RSA public and private keys. Primes p and q that are used
   to compute the modulus n has to be generated before calling this. They
   are then sent as argument for the function. */

SilcBool silc_rsa_generate_keys(SilcUInt32 bits, SilcMPInt *p, SilcMPInt *q,
				void **ret_public_key, void **ret_private_key)
{
  RsaPublicKey *pubkey;
  RsaPrivateKey *privkey;
  SilcMPInt phi, hlp;
  SilcMPInt div, lcm;
  SilcMPInt pm1, qm1;

  *ret_public_key = pubkey = silc_calloc(1, sizeof(*pubkey));
  if (!pubkey)
    return FALSE;

  *ret_private_key = privkey = silc_calloc(1, sizeof(*privkey));
  if (!privkey)
    return FALSE;

  /* Initialize variables */
  silc_mp_init(&privkey->n);
  silc_mp_init(&privkey->e);
  silc_mp_init(&privkey->d);
  silc_mp_init(&privkey->dP);
  silc_mp_init(&privkey->dQ);
  silc_mp_init(&privkey->qP);
  silc_mp_init(&phi);
  silc_mp_init(&hlp);
  silc_mp_init(&div);
  silc_mp_init(&lcm);
  silc_mp_init(&pm1);
  silc_mp_init(&qm1);

  /* Set modulus length */
  privkey->bits = bits;

  /* Compute modulus, n = p * q */
  silc_mp_mul(&privkey->n, p, q);

  /* phi = (p - 1) * (q - 1) */
  silc_mp_sub_ui(&pm1, p, 1);
  silc_mp_sub_ui(&qm1, q, 1);
  silc_mp_mul(&phi, &pm1, &qm1);

  /* Set e, the public exponent. We try to use same public exponent
     for all keys. Also, to make encryption faster we use small
     number. */
  silc_mp_set_ui(&privkey->e, 65533);
 retry_e:
  /* See if e is relatively prime to phi. gcd == greates common divisor,
     if gcd equals 1 they are relatively prime. */
  silc_mp_gcd(&hlp, &privkey->e, &phi);
  if ((silc_mp_cmp_ui(&hlp, 1)) > 0) {
    silc_mp_add_ui(&privkey->e, &privkey->e, 2);
    goto retry_e;
  }

  /* Find d, the private exponent, e ^ -1 mod lcm(phi). */
  silc_mp_gcd(&div, &pm1, &qm1);
  silc_mp_div(&lcm, &phi, &div);
  silc_mp_modinv(&privkey->d, &privkey->e, &lcm);

  /* Optimize d with CRT. */
  silc_mp_mod(&privkey->dP, &privkey->d, &pm1);
  silc_mp_mod(&privkey->dQ, &privkey->d, &qm1);
  silc_mp_modinv(&privkey->qP, q, p);
  silc_mp_set(&privkey->p, p);
  silc_mp_set(&privkey->q, q);

  silc_mp_uninit(&phi);
  silc_mp_uninit(&hlp);
  silc_mp_uninit(&div);
  silc_mp_uninit(&lcm);
  silc_mp_uninit(&pm1);
  silc_mp_uninit(&qm1);

  /* Set public key */
  silc_mp_init(&pubkey->n);
  silc_mp_init(&pubkey->e);
  pubkey->bits = privkey->bits;
  silc_mp_set(&pubkey->n, &privkey->n);
  silc_mp_set(&pubkey->e, &privkey->e);

  return TRUE;
}

/* RSA public key operation */

SilcBool silc_rsa_public_operation(RsaPublicKey *key, SilcMPInt *src,
				   SilcMPInt *dst)
{
  /* dst = src ^ e mod n */
  silc_mp_pow_mod(dst, src, &key->e, &key->n);
  return TRUE;
}

/* RSA private key operation */

SilcBool silc_rsa_private_operation(RsaPrivateKey *key, SilcMPInt *src,
				    SilcMPInt *dst)
{
  SilcMPInt tmp;

  silc_mp_init(&tmp);

  /* dst = (src ^ dP mod p) */
  silc_mp_pow_mod(dst, src, &key->dP, &key->p);

  /* tmp = (src ^ dQ mod q) */
  silc_mp_pow_mod(&tmp, src, &key->dQ, &key->q);

  /* dst = (dst - tmp) * qP mod p */
  silc_mp_sub(dst, dst, &tmp);
  silc_mp_mul(dst, dst, &key->qP);
  silc_mp_mod(dst, dst, &key->p);

  /* dst = (q * dst) + tmp */
  silc_mp_mul(dst, dst, &key->q);
  silc_mp_add(dst, dst, &tmp);

  silc_mp_uninit(&tmp);

  return TRUE;
}
