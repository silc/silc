/* 
 * rsa.c 	RSA Public and Private key generation functions,
 *	   	RSA encrypt and decrypt functions.
 *
 * Author: Pekka Riikonen <priikone@poseidon.pspt.fi>
 *
 * Copyright (C) 1997 - 2001 Pekka Riikonen
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Created: Sat Mar  1 13:26:45 1997 pekka
 *
 * RSA public key cryptographic algorithm used in this distribution is:
 *
 * 	Key generation:
 * 	p, q		primes
 * 	p != q
 *	n = p * q	modulus
 *
 *	Public key exponent:
 *	e   relatively prime to (p-1) * (q-1)
 *	Private key exponent:
 *	d = e ^ -1 mod lcm(((p-1) * (q-1)))
 *
 *	Encryption:
 *	c = m ^ e mod n
 *	Decryption:
 *	m = c ^ d mod n
 *
 * The SSH's (Secure Shell), PGP's (Pretty Good Privacy) and RSAREF 
 * Toolkit were used as reference when coding this implementation. They 
 * all were a big help for me.
 *
 * I also suggest reading Bruce Schneier's; Applied Cryptography, Second 
 * Edition, John Wiley & Sons, Inc. 1996. This book deals about RSA and 
 * everything else too about cryptography.
 *
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

*/

#include "silcincludes.h"
#include "rsa_internal.h"
#include "rsa.h"

/*
 * SILC PKCS API for RSA
 */

/* Generates RSA key pair. */

SILC_PKCS_API_INIT(rsa)
{
  SilcUInt32 prime_bits = keylen / 2;
  SilcMPInt p, q;
  bool found = FALSE;

  printf("Generating RSA Public and Private keys, might take a while...\n");

  silc_mp_init(&p);
  silc_mp_init(&q);

  /* Find p and q */
  while (!found) {
    printf("Finding p: ");
    silc_math_gen_prime(&p, prime_bits, TRUE);
    
    printf("\nFinding q: ");
    silc_math_gen_prime(&q, prime_bits, TRUE);

    if ((silc_mp_cmp(&p, &q)) == 0)
      printf("\nFound equal primes, not good, retrying...\n");
    else
      found = TRUE;
  }

  /* If p is smaller than q, switch them */
  if ((silc_mp_cmp(&p, &q)) > 0) {
    SilcMPInt hlp;
    silc_mp_init(&hlp);

    silc_mp_set(&hlp, &p);
    silc_mp_set(&p, &q);
    silc_mp_set(&q, &hlp);

    silc_mp_uninit(&hlp);
  }

  /* Generate the actual keys */
  rsa_generate_keys((RsaKey *)context, keylen, &p, &q);

  silc_mp_uninit(&p);
  silc_mp_uninit(&q);
  
  printf("\nKeys generated succesfully.\n");

  return TRUE;
}

SILC_PKCS_API_CLEAR_KEYS(rsa)
{
  rsa_clear_keys((RsaKey *)context);
}

/* Returns SILC style encoded RSA public key. */

SILC_PKCS_API_GET_PUBLIC_KEY(rsa)
{
  RsaKey *key = (RsaKey *)context;
  unsigned char *e, *n, *ret;
  SilcUInt32 e_len, n_len;
  unsigned char tmp[4];

  e = silc_mp_mp2bin(&key->e, 0, &e_len);
  n = silc_mp_mp2bin(&key->n, key->bits / 8, &n_len);

  *ret_len = e_len + 4 + n_len + 4;
  ret = silc_calloc(*ret_len, sizeof(unsigned char));

  /* Put the length of the e. */
  SILC_PUT32_MSB(e_len, tmp);
  memcpy(ret, tmp, 4);

  /* Put the e. */
  memcpy(ret + 4, e, e_len);

  /* Put the length of the n. */
  SILC_PUT32_MSB(n_len, tmp);
  memcpy(ret + 4 + e_len, tmp, 4);

  /* Put the n. */
  memcpy(ret + 4 + e_len + 4, n, n_len);

  memset(e, 0, e_len);
  memset(n, 0, n_len);
  silc_free(e);
  silc_free(n);

  return ret;
}

/* Returns SILC style encoded RSA private key. Public key is always
   returned in private key as well. Public keys are often derived
   directly from private key. */

SILC_PKCS_API_GET_PRIVATE_KEY(rsa)
{
  RsaKey *key = (RsaKey *)context;
  unsigned char *e, *n, *d, *ret;
  SilcUInt32 e_len, n_len, d_len;
  unsigned char tmp[4];

  e = silc_mp_mp2bin(&key->e, 0, &e_len);
  n = silc_mp_mp2bin(&key->n, key->bits / 8, &n_len);
  d = silc_mp_mp2bin(&key->d, 0, &d_len);

  *ret_len = e_len + 4 + n_len + 4 + d_len + 4;
  ret = silc_calloc(*ret_len, sizeof(unsigned char));

  /* Put the length of the e. */
  SILC_PUT32_MSB(e_len, tmp);
  memcpy(ret, tmp, 4);

  /* Put the e. */
  memcpy(ret + 4, e, e_len);

  /* Put the length of the n. */
  SILC_PUT32_MSB(n_len, tmp);
  memcpy(ret + 4 + e_len, tmp, 4);

  /* Put the n. */
  memcpy(ret + 4 + e_len + 4, n, n_len);

  /* Put the length of the d. */
  SILC_PUT32_MSB(d_len, tmp);
  memcpy(ret + 4 + e_len + 4 + n_len, tmp, 4);

  /* Put the n. */
  memcpy(ret + 4 + e_len + 4 + n_len + 4, d, d_len);

  memset(e, 0, e_len);
  memset(n, 0, n_len);
  memset(d, 0, d_len);
  silc_free(e);
  silc_free(n);
  silc_free(d);

  return ret;
}

/* Set public key */

SILC_PKCS_API_SET_PUBLIC_KEY(rsa)
{
  RsaKey *key = (RsaKey *)context;
  unsigned char tmp[4];
  SilcUInt32 e_len, n_len;

  if (key->pub_set) {
    silc_mp_uninit(&key->e);
    silc_mp_uninit(&key->e);
    key->pub_set = FALSE;
  }

  silc_mp_init(&key->e);
  silc_mp_init(&key->n);

  memcpy(tmp, key_data, 4);
  SILC_GET32_MSB(e_len, tmp);
  if (e_len > key_len) {
    silc_mp_uninit(&key->e);
    silc_mp_uninit(&key->n);
    return 0;
  }

  silc_mp_bin2mp(key_data + 4, e_len, &key->e);
  
  memcpy(tmp, key_data + 4 + e_len, 4);
  SILC_GET32_MSB(n_len, tmp);
  if (e_len + n_len > key_len) {
    silc_mp_uninit(&key->e);
    silc_mp_uninit(&key->n);
    return 0;
  }

  silc_mp_bin2mp(key_data + 4 + e_len + 4, n_len, &key->n);

  key->bits = n_len * 8;
  key->pub_set = TRUE;

  return key->bits;
}

/* Set private key. This derives the public key from the private
   key and sets the public key as well. Public key should not be set
   already and should not be set after setting private key. */

SILC_PKCS_API_SET_PRIVATE_KEY(rsa)
{
  RsaKey *key = (RsaKey *)context;
  unsigned char tmp[4];
  SilcUInt32 e_len, n_len, d_len;

  if (key->prv_set) {
    silc_mp_uninit(&key->d);
    key->prv_set = FALSE;
  }

  if (key->pub_set) {
    silc_mp_uninit(&key->e);
    silc_mp_uninit(&key->n);
    key->pub_set = FALSE;
  }

  silc_mp_init(&key->e);
  silc_mp_init(&key->n);
  silc_mp_init(&key->d);

  memcpy(tmp, key_data, 4);
  SILC_GET32_MSB(e_len, tmp);
  if (e_len > key_len) {
    silc_mp_uninit(&key->e);
    silc_mp_uninit(&key->n);
    silc_mp_uninit(&key->d);
    return FALSE;
  }

  silc_mp_bin2mp(key_data + 4, e_len, &key->e);
  
  memcpy(tmp, key_data + 4 + e_len, 4);
  SILC_GET32_MSB(n_len, tmp);
  if (e_len + n_len > key_len) {
    silc_mp_uninit(&key->e);
    silc_mp_uninit(&key->n);
    silc_mp_uninit(&key->d);
    return FALSE;
  }

  silc_mp_bin2mp(key_data + 4 + e_len + 4, n_len, &key->n);

  memcpy(tmp, key_data + 4 + e_len + 4 + n_len, 4);
  SILC_GET32_MSB(d_len, tmp);
  if (e_len + n_len + d_len > key_len) {
    silc_mp_uninit(&key->e);
    silc_mp_uninit(&key->n);
    silc_mp_uninit(&key->d);
    return FALSE;
  }

  silc_mp_bin2mp(key_data + 4 + e_len + 4 + n_len + 4, d_len, &key->d);

  key->bits = n_len * 8;
  key->prv_set = TRUE;
  key->pub_set = TRUE;

  return TRUE;
}

SILC_PKCS_API_CONTEXT_LEN(rsa)
{
  return sizeof(RsaKey);
}

SILC_PKCS_API_ENCRYPT(rsa)
{
  RsaKey *key = (RsaKey *)context;
  int i, tmplen;
  SilcMPInt mp_tmp;
  SilcMPInt mp_dst;

  silc_mp_init(&mp_tmp);
  silc_mp_init(&mp_dst);
  silc_mp_set_ui(&mp_tmp, 0);
  silc_mp_set_ui(&mp_dst, 0);

  /* Format the data into MP int */
  for (i = 0; i < src_len; i++) {
    silc_mp_mul_2exp(&mp_tmp, &mp_tmp, 8);
    silc_mp_add_ui(&mp_tmp, &mp_tmp, src[i]);
  }

  /* Encrypt */
  rsa_en_de_crypt(&mp_dst, &mp_tmp, &key->e, &key->n);
  
  tmplen = (key->bits + 7) / 8;

  /* Format the MP int back into data */
  for (i = tmplen; i > 0; i--) {
    dst[i - 1] = (unsigned char)(silc_mp_get_ui(&mp_dst) & 0xff);
    silc_mp_div_2exp(&mp_dst, &mp_dst, 8);
  }
  *dst_len = tmplen;

  silc_mp_uninit(&mp_tmp);
  silc_mp_uninit(&mp_dst);

  return TRUE;
}

SILC_PKCS_API_DECRYPT(rsa)
{
  RsaKey *key = (RsaKey *)context;
  int i, tmplen;
  SilcMPInt mp_tmp;
  SilcMPInt mp_dst;

  silc_mp_init(&mp_tmp);
  silc_mp_init(&mp_dst);
  silc_mp_set_ui(&mp_tmp, 0);
  silc_mp_set_ui(&mp_dst, 0);

  /* Format the data into MP int */
  for (i = 0; i < src_len; i++) {
    silc_mp_mul_2exp(&mp_tmp, &mp_tmp, 8);
    silc_mp_add_ui(&mp_tmp, &mp_tmp, src[i]);
  }

  /* Decrypt */
  rsa_en_de_crypt(&mp_dst, &mp_tmp, &key->d, &key->n);

  tmplen = (key->bits + 7) / 8;

  /* Format the MP int back into data */
  for (i = tmplen; i > 0; i--) {
    dst[i - 1] = (unsigned char)(silc_mp_get_ui(&mp_dst) & 0xff);
    silc_mp_div_2exp(&mp_dst, &mp_dst, 8);
  }
  *dst_len = tmplen;

  silc_mp_uninit(&mp_tmp);
  silc_mp_uninit(&mp_dst);

  return TRUE;
}

SILC_PKCS_API_SIGN(rsa)
{
  RsaKey *key = (RsaKey *)context;
  int i, tmplen;
  SilcMPInt mp_tmp;
  SilcMPInt mp_dst;

  silc_mp_init(&mp_tmp);
  silc_mp_init(&mp_dst);
  silc_mp_set_ui(&mp_tmp, 0);
  silc_mp_set_ui(&mp_dst, 0);

  /* Format the data into MP int */
  for (i = 0; i < src_len; i++) {
    silc_mp_mul_2exp(&mp_tmp, &mp_tmp, 8);
    silc_mp_add_ui(&mp_tmp, &mp_tmp, src[i]);
  }

  /* Sign */
  rsa_en_de_crypt(&mp_dst, &mp_tmp, &key->d, &key->n);

  tmplen = (key->bits + 7) / 8;

  /* Format the MP int back into data */
  for (i = tmplen; i > 0; i--) {
    dst[i - 1] = (unsigned char)(silc_mp_get_ui(&mp_dst) & 0xff);
    silc_mp_div_2exp(&mp_dst, &mp_dst, 8);
  }
  *dst_len = tmplen;

  silc_mp_uninit(&mp_tmp);
  silc_mp_uninit(&mp_dst);

  return TRUE;
}

SILC_PKCS_API_VERIFY(rsa)
{
  RsaKey *key = (RsaKey *)context;
  int i, ret;
  SilcMPInt mp_tmp, mp_tmp2;
  SilcMPInt mp_dst;

  silc_mp_init(&mp_tmp);
  silc_mp_init(&mp_tmp2);
  silc_mp_init(&mp_dst);
  silc_mp_set_ui(&mp_tmp, 0);
  silc_mp_set_ui(&mp_tmp2, 0);
  silc_mp_set_ui(&mp_dst, 0);

  /* Format the signature into MP int */
  for (i = 0; i < signature_len; i++) {
    silc_mp_mul_2exp(&mp_tmp2, &mp_tmp2, 8);
    silc_mp_add_ui(&mp_tmp2, &mp_tmp2, signature[i]);
  }

  /* Verify */
  rsa_en_de_crypt(&mp_dst, &mp_tmp2, &key->e, &key->n);

  /* Format the data into MP int */
  for (i = 0; i < data_len; i++) {
    silc_mp_mul_2exp(&mp_tmp, &mp_tmp, 8);
    silc_mp_add_ui(&mp_tmp, &mp_tmp, data[i]);
  }

  ret = TRUE;

  /* Compare */
  if ((silc_mp_cmp(&mp_tmp, &mp_dst)) != 0)
    ret = FALSE;

  silc_mp_uninit(&mp_tmp);
  silc_mp_uninit(&mp_tmp2);
  silc_mp_uninit(&mp_dst);

  return ret;
}

/* Generates RSA public and private keys. Primes p and q that are used
   to compute the modulus n has to be generated before calling this. They
   are then sent as argument for the function. */

void rsa_generate_keys(RsaKey *key, SilcUInt32 bits, 
		       SilcMPInt *p, SilcMPInt *q)
{
  SilcMPInt phi, hlp;
  SilcMPInt div, lcm;
  SilcMPInt pm1, qm1;
  
  /* Initialize variables */
  silc_mp_init(&key->n);
  silc_mp_init(&key->e);
  silc_mp_init(&key->d);
  silc_mp_init(&phi);
  silc_mp_init(&hlp);
  silc_mp_init(&div);
  silc_mp_init(&lcm);
  silc_mp_init(&pm1);
  silc_mp_init(&qm1);

  /* Set modulus length */
  key->bits = bits;

  /* Compute modulus, n = p * q */
  silc_mp_mul(&key->n, p, q);
  
  /* phi = (p - 1) * (q - 1) */
  silc_mp_sub_ui(&pm1, p, 1);
  silc_mp_sub_ui(&qm1, q, 1);
  silc_mp_mul(&phi, &pm1, &qm1);
  
  /* Set e, the public exponent. We try to use same public exponent
     for all keys. Also, to make encryption faster we use small 
     number. */
  silc_mp_set_ui(&key->e, 127);
 retry_e:
  /* See if e is relatively prime to phi. gcd == greates common divisor,
     if gcd equals 1 they are relatively prime. */
  silc_mp_gcd(&hlp, &key->e, &phi);
  if((silc_mp_cmp_ui(&hlp, 1)) > 0) {
    silc_mp_add_ui(&key->e, &key->e, 2);
    goto retry_e;
  }
  
  /* Find d, the private exponent. */
  silc_mp_gcd(&div, &pm1, &qm1);
  silc_mp_div(&lcm, &phi, &div);
  silc_mp_modinv(&key->d, &key->e, &lcm);
  
  silc_mp_uninit(&phi);
  silc_mp_uninit(&hlp);
  silc_mp_uninit(&div);
  silc_mp_uninit(&lcm);
  silc_mp_uninit(&pm1);
  silc_mp_uninit(&qm1);
}

/* Clears whole key structure. */

void rsa_clear_keys(RsaKey *key)
{
  key->bits = 0;
  if (key->pub_set) {
    silc_mp_uninit(&key->n);
    silc_mp_uninit(&key->e);
  }
  if (key->prv_set)
    silc_mp_uninit(&key->d);
}

/* RSA encrypt/decrypt function. cm = ciphertext or plaintext,
   mc = plaintext or ciphertext, expo = public or private exponent,
   and modu = modulus. 

   Encrypt: c = m ^ e mod n,
   Decrypt: m = c ^ d mod n 
*/

void rsa_en_de_crypt(SilcMPInt *cm, SilcMPInt *mc, 
		     SilcMPInt *expo, SilcMPInt *modu)
{
  silc_mp_pow_mod(cm, mc, expo, modu);
}
