/* 
 * rsa.c 	RSA Public and Private key generation functions,
 *	   	RSA encrypt and decrypt functions.
 *
 * Author: Pekka Riikonen <priikone@poseidon.pspt.fi>
 *
 * Copyright (C) 1997 - 2000 Pekka Riikonen
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
 *	d = e ^ -1 mod ((p-1) * (q-1))
 *
 *	Encryption:
 *	c = m ^ e mod n
 *	Decryption:
 *	m = c ^ d mod n
 *
 * This code is based on SSH's (Secure Shell), PGP's (Pretty Good Privacy) 
 * and RSAREF Toolkit's RSA source codes. They all were a big help for me.
 *
 * I also suggest reading Bruce Schneier's; Applied Cryptography, Second 
 * Edition, John Wiley & Sons, Inc. 1996. This book deals about RSA and 
 * everything else too about cryptography.
 *
 */

#include "silcincludes.h"
#include "rsa.h"

/*
 * SILC PKCS API for RSA
 */

/* Generates RSA key pair. */

SILC_PKCS_API_INIT(rsa)
{
  unsigned int prime_bits = keylen / 2;
  SilcInt p, q;

  printf("Generating RSA Public and Private keys, might take a while...\n");

  silc_mp_init(&p);
  silc_mp_init(&q);

  /* Find p and q */
 retry_primes:
  printf("Finding p: ");
  silc_math_gen_prime(&p, prime_bits, TRUE);
  
  printf("\nFinding q: ");
  silc_math_gen_prime(&q, prime_bits, TRUE);
  
  if ((silc_mp_cmp(&p, &q)) == 0) {
    printf("\nFound equal primes, not good, retrying...\n");
    goto retry_primes;
  }

  /* If p is smaller than q, switch them */
  if ((silc_mp_cmp(&p, &q)) > 0) {
    SilcInt hlp;
    silc_mp_init(&hlp);

    silc_mp_set(&hlp, &p);
    silc_mp_set(&p, &q);
    silc_mp_set(&q, &hlp);

    silc_mp_clear(&hlp);
  }

  /* Generate the actual keys */
  rsa_generate_keys((RsaKey *)context, keylen, &p, &q);

  silc_mp_clear(&p);
  silc_mp_clear(&q);
  
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
  unsigned short e_len, n_len;
  unsigned char tmp[2];

  e_len = silc_mp_sizeinbase(&key->e, 16);
  n_len = silc_mp_sizeinbase(&key->n, 16);
  e = silc_calloc(e_len + 1, sizeof(unsigned char));
  n = silc_calloc(n_len + 1, sizeof(unsigned char));
  silc_mp_get_str(e, 16, &key->e);
  silc_mp_get_str(n, 16, &key->n);

  *ret_len = e_len + 2 + n_len + 2;
  ret = silc_calloc(*ret_len, sizeof(unsigned char));

  /* Put the length of the e. */
  tmp[0] = e_len >> 8;
  tmp[1] = e_len;
  memcpy(ret, tmp, 2);

  /* Put the e. */
  memcpy(ret + 2, e, e_len);

  /* Put the length of the n. */
  tmp[0] = n_len >> 8;
  tmp[1] = n_len;
  memcpy(ret + 2 + e_len, tmp, 2);

  /* Put the n. */
  memcpy(ret + 2 + e_len + 2, n, n_len);

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
  unsigned short e_len, n_len, d_len;
  unsigned char tmp[2];

  e_len = silc_mp_sizeinbase(&key->e, 16);
  n_len = silc_mp_sizeinbase(&key->n, 16);
  d_len = silc_mp_sizeinbase(&key->d, 16);
  e = silc_calloc(e_len + 1, sizeof(unsigned char));
  n = silc_calloc(n_len + 1, sizeof(unsigned char));
  d = silc_calloc(d_len + 1, sizeof(unsigned char));
  silc_mp_get_str(e, 16, &key->e);
  silc_mp_get_str(n, 16, &key->n);
  silc_mp_get_str(d, 16, &key->d);

  *ret_len = e_len + 2 + n_len + 2 + d_len + 2;
  ret = silc_calloc(*ret_len, sizeof(unsigned char));

  /* Put the length of the e. */
  tmp[0] = e_len >> 8;
  tmp[1] = e_len;
  memcpy(ret, tmp, 2);

  /* Put the e. */
  memcpy(ret + 2, e, e_len);

  /* Put the length of the n. */
  tmp[0] = n_len >> 8;
  tmp[1] = n_len;
  memcpy(ret + 2 + e_len, tmp, 2);

  /* Put the n. */
  memcpy(ret + 2 + e_len + 2, n, n_len);

  /* Put the length of the d. */
  tmp[0] = d_len >> 8;
  tmp[1] = d_len;
  memcpy(ret + 2 + e_len + 2 + n_len, tmp, 2);

  /* Put the n. */
  memcpy(ret + 2 + e_len + 2 + n_len + 2, d, d_len);

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
  unsigned char *e, *n, tmp[2];
  unsigned short e_len, n_len;

  silc_mp_init(&key->e);
  silc_mp_init(&key->n);

  memcpy(tmp, key_data, 2);
  e_len = ((unsigned int)tmp[0] << 8) | ((unsigned int)tmp[1]);
  if (e_len > key_len) {
    silc_mp_clear(&key->e);
    silc_mp_clear(&key->n);
    return FALSE;
  }

  e = silc_calloc(e_len + 1, sizeof(unsigned char));
  memcpy(e, key_data + 2, e_len);
  silc_mp_set_str(&key->e, e, 16);
  
  memcpy(tmp, key_data + 2 + e_len, 2);
  n_len = ((unsigned int)tmp[0] << 8) | ((unsigned int)tmp[1]);
  if (e_len + n_len > key_len) {
    memset(e, 0, e_len);
    silc_free(e);
    silc_mp_clear(&key->e);
    silc_mp_clear(&key->n);
    return FALSE;
  }

  n = silc_calloc(n_len + 1, sizeof(unsigned char));
  memcpy(n, key_data + 2 + e_len + 2, n_len);
  silc_mp_set_str(&key->n, n, 16);

  memset(e, 0, e_len);
  memset(n, 0, n_len);
  silc_free(e);
  silc_free(n);

  return TRUE;
}

/* Set private key. This derives the public key from the private
   key and sets the public key as well. Public key should not be set
   already and should not be set after setting private key. */

SILC_PKCS_API_SET_PRIVATE_KEY(rsa)
{
  RsaKey *key = (RsaKey *)context;
  unsigned char *e, *n, *d, tmp[2];
  unsigned short e_len, n_len, d_len;

  silc_mp_init(&key->e);
  silc_mp_init(&key->n);
  silc_mp_init(&key->d);

  memcpy(tmp, key_data, 2);
  e_len = ((unsigned int)tmp[0] << 8) | ((unsigned int)tmp[1]);
  if (e_len > key_len) {
    silc_mp_clear(&key->e);
    silc_mp_clear(&key->n);
    return FALSE;
  }

  e = silc_calloc(e_len + 1, sizeof(unsigned char));
  memcpy(e, key_data + 2, e_len);
  silc_mp_set_str(&key->e, e, 16);
  
  memcpy(tmp, key_data + 2 + e_len, 2);
  n_len = ((unsigned int)tmp[0] << 8) | ((unsigned int)tmp[1]);
  if (e_len + n_len > key_len) {
    memset(e, 0, e_len);
    silc_free(e);
    silc_mp_clear(&key->e);
    silc_mp_clear(&key->n);
    return FALSE;
  }

  n = silc_calloc(n_len + 1, sizeof(unsigned char));
  memcpy(n, key_data + 2 + e_len + 2, n_len);
  silc_mp_set_str(&key->n, n, 16);

  memcpy(tmp, key_data + 2 + e_len + 2 + n_len, 2);
  d_len = ((unsigned int)tmp[0] << 8) | ((unsigned int)tmp[1]);
  if (e_len + n_len + d_len > key_len) {
    memset(n, 0, n_len);
    silc_free(n);
    memset(e, 0, e_len);
    silc_free(e);
    silc_mp_clear(&key->e);
    silc_mp_clear(&key->n);
    return FALSE;
  }

  d = silc_calloc(d_len + 1, sizeof(unsigned char));
  memcpy(d, key_data + 2 + e_len + 2 + n_len + 2, d_len);
  silc_mp_set_str(&key->d, d, 16);

  memset(e, 0, e_len);
  memset(n, 0, n_len);
  memset(d, 0, d_len);
  silc_free(e);
  silc_free(n);
  silc_free(d);

  return TRUE;
}

SILC_PKCS_API_CONTEXT_LEN(rsa)
{
  return sizeof(RsaKey);
}

SILC_PKCS_API_DATA_CONTEXT_LEN(rsa)
{
  return sizeof(RsaDataContext);
}

SILC_PKCS_API_SET_ARG(rsa)
{
  RsaDataContext *data_ctx = (RsaDataContext *)data_context;

  switch(argnum) {
  case 1:
    data_ctx->src = val;
    return TRUE;
    break;
  case 2:
    data_ctx->dst = val;
    return TRUE;
    break;
  case 3:
    data_ctx->exp = val;
    return TRUE;
    break;
  case 4:
    data_ctx->mod = val;
    return TRUE;
    break;
  default:
    return FALSE;
    break;
  }

  return FALSE;
}

SILC_PKCS_API_ENCRYPT(rsa)
{
  RsaKey *key = (RsaKey *)context;
  int i, tmplen;
  SilcInt mp_tmp;
  SilcInt mp_dst;

  silc_mp_init_set_ui(&mp_tmp, 0);
  silc_mp_init_set_ui(&mp_dst, 0);

  /* Format the data into MP int */
  for (i = 0; i < src_len; i++) {
    silc_mp_mul_2exp(&mp_tmp, &mp_tmp, 8);
    silc_mp_add_ui(&mp_tmp, &mp_tmp, src[i]);
  }

  silc_mp_out_str(stderr, 16, &mp_tmp);

  /* Encrypt */
  rsa_en_de_crypt(&mp_dst, &mp_tmp, &key->e, &key->n);
  
  fprintf(stderr, "\n");
  silc_mp_out_str(stderr, 16, &mp_dst);

  tmplen = (1024 + 7) / 8;

  /* Format the MP int back into data */
  for (i = tmplen; i > 0; i--) {
    dst[i - 1] = (unsigned char)(silc_mp_get_ui(&mp_dst) & 0xff);
    silc_mp_fdiv_q_2exp(&mp_dst, &mp_dst, 8);
  }
  *dst_len = tmplen;

  silc_mp_clear(&mp_tmp);
  silc_mp_clear(&mp_dst);

  return TRUE;
}

SILC_PKCS_API_DECRYPT(rsa)
{
  RsaKey *key = (RsaKey *)context;
  int i, tmplen;
  SilcInt mp_tmp;
  SilcInt mp_dst;

  silc_mp_init_set_ui(&mp_tmp, 0);
  silc_mp_init_set_ui(&mp_dst, 0);

  /* Format the data into MP int */
  for (i = 0; i < src_len; i++) {
    silc_mp_mul_2exp(&mp_tmp, &mp_tmp, 8);
    silc_mp_add_ui(&mp_tmp, &mp_tmp, src[i]);
  }

  silc_mp_out_str(stderr, 16, &mp_tmp);

  /* Decrypt */
  rsa_en_de_crypt(&mp_dst, &mp_tmp, &key->d, &key->n);

  fprintf(stderr, "\n");
  silc_mp_out_str(stderr, 16, &mp_dst);

  tmplen = (1024 + 7) / 8;

  /* Format the MP int back into data */
  for (i = tmplen; i > 0; i--) {
    dst[i - 1] = (unsigned char)(silc_mp_get_ui(&mp_dst) & 0xff);
    silc_mp_fdiv_q_2exp(&mp_dst, &mp_dst, 8);
  }
  *dst_len = tmplen;

  silc_mp_clear(&mp_tmp);
  silc_mp_clear(&mp_dst);

  return TRUE;
}

SILC_PKCS_API_SIGN(rsa)
{
  RsaKey *key = (RsaKey *)context;
  int i, tmplen;
  SilcInt mp_tmp;
  SilcInt mp_dst;

  silc_mp_init_set_ui(&mp_tmp, 0);
  silc_mp_init_set_ui(&mp_dst, 0);

  /* Format the data into MP int */
  for (i = 0; i < src_len; i++) {
    silc_mp_mul_2exp(&mp_tmp, &mp_tmp, 8);
    silc_mp_add_ui(&mp_tmp, &mp_tmp, src[i]);
  }

  /* Sign */
  rsa_en_de_crypt(&mp_dst, &mp_tmp, &key->d, &key->n);

  tmplen = (1024 + 7) / 8;

  /* Format the MP int back into data */
  for (i = tmplen; i > 0; i--) {
    dst[i - 1] = (unsigned char)(silc_mp_get_ui(&mp_dst) & 0xff);
    silc_mp_fdiv_q_2exp(&mp_dst, &mp_dst, 8);
  }
  *dst_len = tmplen;

  silc_mp_clear(&mp_tmp);
  silc_mp_clear(&mp_dst);

  return TRUE;
}

SILC_PKCS_API_VERIFY(rsa)
{
  RsaKey *key = (RsaKey *)context;
  int i, ret;
  SilcInt mp_tmp, mp_tmp2;
  SilcInt mp_dst;

  silc_mp_init_set_ui(&mp_tmp, 0);
  silc_mp_init_set_ui(&mp_tmp2, 0);
  silc_mp_init_set_ui(&mp_dst, 0);

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

  silc_mp_clear(&mp_tmp);
  silc_mp_clear(&mp_tmp2);
  silc_mp_clear(&mp_dst);

  return ret;
}

/* Generates RSA public and private keys. Primes p and q that are used
   to compute the modulus n has to be generated before calling this. They
   are then sent as argument for the function. */

void rsa_generate_keys(RsaKey *key, unsigned int bits, 
		       SilcInt *p, SilcInt *q)
{
  SilcInt phi, hlp;
  SilcInt dq;
  SilcInt pm1, qm1;
  
  /* Initialize variables */
  silc_mp_init(&key->p);
  silc_mp_init(&key->q);
  silc_mp_init(&key->n);
  silc_mp_init(&key->e);
  silc_mp_init(&key->d);
  silc_mp_init(&phi);
  silc_mp_init(&hlp);
  silc_mp_init(&dq);
  silc_mp_init(&pm1);
  silc_mp_init(&qm1);

  /* Set the primes */
  silc_mp_set(&key->p, p);
  silc_mp_set(&key->q, q);
  
  /* Compute modulus, n = p * q */
  silc_mp_mul(&key->n, &key->p, &key->q);
  
  /* phi = (p - 1) * (q - 1) */
  silc_mp_sub_ui(&pm1, &key->p, 1);
  silc_mp_sub_ui(&qm1, &key->q, 1);
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
  
  /* Find d, the private exponent. First we do phi / 2, to get it a 
     bit smaller */
  silc_mp_div_ui(&dq, &phi, 2);
  silc_mp_modinv(&key->d, &key->e, &dq);
  
  silc_mp_clear(&phi);
  silc_mp_clear(&hlp);
  silc_mp_clear(&dq);
  silc_mp_clear(&pm1);
  silc_mp_clear(&qm1);
}

/* Clears whole key structure. */

void rsa_clear_keys(RsaKey *key)
{
  key->bits = 0;
  silc_mp_clear(&key->p);
  silc_mp_clear(&key->q);
  silc_mp_clear(&key->n);
  silc_mp_clear(&key->e);
  silc_mp_clear(&key->d);
}

/* RSA encrypt/decrypt function. cm = ciphertext or plaintext,
   mc = plaintext or ciphertext, expo = public or private exponent,
   and modu = modulus. 

   Encrypt: c = m ^ e mod n,
   Decrypt: m = c ^ d mod n 
*/

void rsa_en_de_crypt(SilcInt *cm, SilcInt *mc, 
		     SilcInt *expo, SilcInt *modu)
{
  silc_mp_powm(cm, mc, expo, modu);
}
