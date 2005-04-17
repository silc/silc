/*
 * rsa.c 	RSA Public and Private key generation functions,
 *	   	RSA encrypt and decrypt functions.
 *
 * Author: Pekka Riikonen <priikone@silcnet.org>
 *
 * Copyright (C) 1997 - 2003 Pekka Riikonen
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
 * Supports CRT (Chinese Remainder Theorem) for private key operations.
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

   o Sat Mar 16 18:27:19 EET 2002  Pekka

     Use the SilcRng sent as argument to SILC_PKCS_API_INIT in prime
     generation.

   o Sat Sep 26 19:59:48 EEST 2002  Pekka

     Fixed double free in public key setting.  Use a bit larger e as
     starting point in key generation.

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

  if (keylen < 768 || keylen > 16384)
    return FALSE;

  printf("Generating RSA Public and Private keys, might take a while...\n");

  silc_mp_init(&p);
  silc_mp_init(&q);

  /* Find p and q */
  while (!found) {
    printf("Finding p: ");
    silc_math_gen_prime(&p, prime_bits, TRUE, rng);

    printf("\nFinding q: ");
    silc_math_gen_prime(&q, prime_bits, TRUE, rng);

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

  printf("\nKeys generated successfully.\n");

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
  n = silc_mp_mp2bin(&key->n, (key->bits + 7) / 8, &n_len);

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
  SilcBuffer buf;
  unsigned char *e, *n, *d, *ret, *dp = NULL, *dq = NULL;
  unsigned char *pq = NULL, *qp = NULL, *p = NULL, *q = NULL;
  SilcUInt32 e_len, n_len, d_len, dp_len, dq_len, pq_len, qp_len, p_len, q_len;
  SilcUInt32 len = 0;

  e = silc_mp_mp2bin(&key->e, 0, &e_len);
  n = silc_mp_mp2bin(&key->n, (key->bits + 7) / 8, &n_len);
  d = silc_mp_mp2bin(&key->d, 0, &d_len);
  if (key->crt) {
    dp = silc_mp_mp2bin(&key->dP, 0, &dp_len);
    dq = silc_mp_mp2bin(&key->dQ, 0, &dq_len);
    pq = silc_mp_mp2bin(&key->pQ, 0, &pq_len);
    qp = silc_mp_mp2bin(&key->qP, 0, &qp_len);
    p = silc_mp_mp2bin(&key->p, 0, &p_len);
    q = silc_mp_mp2bin(&key->q, 0, &q_len);
    len = dp_len + 4 + dq_len + 4 + pq_len + 4 + qp_len + 4 + p_len + 4 +
      q_len + 4;
  }

  buf = silc_buffer_alloc_size(e_len + 4 + n_len + 4 + d_len + 4 + len);
  len = silc_buffer_format(buf,
			   SILC_STR_UI_INT(e_len),
			   SILC_STR_UI_XNSTRING(e, e_len),
			   SILC_STR_UI_INT(n_len),
			   SILC_STR_UI_XNSTRING(n, n_len),
			   SILC_STR_UI_INT(d_len),
			   SILC_STR_UI_XNSTRING(d, d_len),
			   SILC_STR_END);

  if (key->crt) {
    silc_buffer_pull(buf, len);
    silc_buffer_format(buf,
		       SILC_STR_UI_INT(dp_len),
		       SILC_STR_UI_XNSTRING(dp, dp_len),
		       SILC_STR_UI_INT(dq_len),
		       SILC_STR_UI_XNSTRING(dq, dq_len),
		       SILC_STR_UI_INT(pq_len),
		       SILC_STR_UI_XNSTRING(pq, pq_len),
		       SILC_STR_UI_INT(qp_len),
		       SILC_STR_UI_XNSTRING(qp, qp_len),
		       SILC_STR_UI_INT(p_len),
		       SILC_STR_UI_XNSTRING(p, p_len),
		       SILC_STR_UI_INT(q_len),
		       SILC_STR_UI_XNSTRING(q, q_len),
		       SILC_STR_END);
    silc_buffer_push(buf, len);

    memset(dp, 0, dp_len);
    memset(dq, 0, dq_len);
    memset(pq, 0, pq_len);
    memset(qp, 0, qp_len);
    memset(p, 0, p_len);
    memset(q, 0, q_len);
    silc_free(dp);
    silc_free(dq);
    silc_free(pq);
    silc_free(qp);
    silc_free(p);
    silc_free(q);
  }

  memset(d, 0, d_len);
  silc_free(e);
  silc_free(n);
  silc_free(d);

  ret = silc_buffer_steal(buf, ret_len);
  silc_buffer_free(buf);
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
    silc_mp_uninit(&key->n);
    key->pub_set = FALSE;
  }

  if (key_len < 4)
    return 0;

  silc_mp_init(&key->e);
  silc_mp_init(&key->n);

  memcpy(tmp, key_data, 4);
  SILC_GET32_MSB(e_len, tmp);
  if (!e_len || e_len + 4 > key_len) {
    silc_mp_uninit(&key->e);
    silc_mp_uninit(&key->n);
    return 0;
  }

  silc_mp_bin2mp(key_data + 4, e_len, &key->e);

  if (key_len < 4 + e_len + 4) {
    silc_mp_uninit(&key->e);
    silc_mp_uninit(&key->n);
    return 0;
  }

  memcpy(tmp, key_data + 4 + e_len, 4);
  SILC_GET32_MSB(n_len, tmp);
  if (!n_len || e_len + 4 + n_len + 4 > key_len) {
    silc_mp_uninit(&key->e);
    silc_mp_uninit(&key->n);
    return 0;
  }

  silc_mp_bin2mp(key_data + 4 + e_len + 4, n_len, &key->n);

  key->bits = silc_mp_sizeinbase(&key->n, 2);
  key->pub_set = TRUE;

  return key->bits;
}

/* Set private key. This derives the public key from the private
   key and sets the public key as well. Public key should not be set
   already and should not be set after setting private key. */

SILC_PKCS_API_SET_PRIVATE_KEY(rsa)
{
  RsaKey *key = (RsaKey *)context;
  SilcBufferStruct k;
  unsigned char *tmp;
  SilcUInt32 len;

  if (key->prv_set) {
    silc_mp_uninit(&key->d);
    key->prv_set = FALSE;
  }

  if (key->pub_set) {
    silc_mp_uninit(&key->e);
    silc_mp_uninit(&key->n);
    key->pub_set = FALSE;
  }

  if (key_len < 4)
    return FALSE;

  silc_buffer_set(&k, key_data, key_len);

  silc_mp_init(&key->e);
  silc_mp_init(&key->n);
  silc_mp_init(&key->d);
  key->prv_set = TRUE;
  key->pub_set = TRUE;

  /* Get e */
  if (silc_buffer_unformat(&k,
			   SILC_STR_UI_INT(&len),
			   SILC_STR_END) < 0)
    goto err;
  silc_buffer_pull(&k, 4);
  if (silc_buffer_unformat(&k,
			   SILC_STR_UI_XNSTRING(&tmp, len),
			   SILC_STR_END) < 0)
    goto err;
  silc_mp_bin2mp(tmp, len, &key->e);
  silc_buffer_pull(&k, len);

  /* Get n */
  if (silc_buffer_unformat(&k,
			   SILC_STR_UI_INT(&len),
			   SILC_STR_END) < 0)
    goto err;
  silc_buffer_pull(&k, 4);
  if (silc_buffer_unformat(&k,
			   SILC_STR_UI_XNSTRING(&tmp, len),
			   SILC_STR_END) < 0)
    goto err;
  silc_mp_bin2mp(tmp, len, &key->n);
  silc_buffer_pull(&k, len);

  /* Get d */
  if (silc_buffer_unformat(&k,
			   SILC_STR_UI_INT(&len),
			   SILC_STR_END) < 0)
    goto err;
  silc_buffer_pull(&k, 4);
  if (silc_buffer_unformat(&k,
			   SILC_STR_UI_XNSTRING(&tmp, len),
			   SILC_STR_END) < 0)
    goto err;
  silc_mp_bin2mp(tmp, len, &key->d);
  silc_buffer_pull(&k, len);

  /* Get optimized d for CRT, if present. */
  if (k.len > 4) {
    key->crt = TRUE;
    silc_mp_init(&key->dP);
    silc_mp_init(&key->dQ);
    silc_mp_init(&key->pQ);
    silc_mp_init(&key->qP);
    silc_mp_init(&key->p);
    silc_mp_init(&key->q);

    /* Get dP */
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_INT(&len),
			     SILC_STR_END) < 0)
      goto err;
    silc_buffer_pull(&k, 4);
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_XNSTRING(&tmp, len),
			     SILC_STR_END) < 0)
      goto err;
    silc_mp_bin2mp(tmp, len, &key->dP);
    silc_buffer_pull(&k, len);

    /* Get dQ */
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_INT(&len),
			     SILC_STR_END) < 0)
      goto err;
    silc_buffer_pull(&k, 4);
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_XNSTRING(&tmp, len),
			     SILC_STR_END) < 0)
      goto err;
    silc_mp_bin2mp(tmp, len, &key->dQ);
    silc_buffer_pull(&k, len);

    /* Get pQ */
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_INT(&len),
			     SILC_STR_END) < 0)
      goto err;
    silc_buffer_pull(&k, 4);
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_XNSTRING(&tmp, len),
			     SILC_STR_END) < 0)
      goto err;
    silc_mp_bin2mp(tmp, len, &key->pQ);
    silc_buffer_pull(&k, len);

    /* Get qP */
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_INT(&len),
			     SILC_STR_END) < 0)
      goto err;
    silc_buffer_pull(&k, 4);
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_XNSTRING(&tmp, len),
			     SILC_STR_END) < 0)
      goto err;
    silc_mp_bin2mp(tmp, len, &key->qP);
    silc_buffer_pull(&k, len);

    /* Get p */
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_INT(&len),
			     SILC_STR_END) < 0)
      goto err;
    silc_buffer_pull(&k, 4);
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_XNSTRING(&tmp, len),
			     SILC_STR_END) < 0)
      goto err;
    silc_mp_bin2mp(tmp, len, &key->p);
    silc_buffer_pull(&k, len);

    /* Get q */
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_INT(&len),
			     SILC_STR_END) < 0)
      goto err;
    silc_buffer_pull(&k, 4);
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_XNSTRING(&tmp, len),
			     SILC_STR_END) < 0)
      goto err;
    silc_mp_bin2mp(tmp, len, &key->q);
    silc_buffer_pull(&k, len);
  }

  key->bits = silc_mp_sizeinbase(&key->n, 2);
  return key->bits;

 err:
  rsa_clear_keys(key);
  return FALSE;
}

SILC_PKCS_API_CONTEXT_LEN(rsa)
{
  return sizeof(RsaKey);
}

/* Raw RSA routines */

SILC_PKCS_API_ENCRYPT(rsa)
{
  RsaKey *key = (RsaKey *)context;
  int tmplen;
  SilcMPInt mp_tmp;
  SilcMPInt mp_dst;

  silc_mp_init(&mp_tmp);
  silc_mp_init(&mp_dst);

  /* Format the data into MP int */
  silc_mp_bin2mp(src, src_len, &mp_tmp);

  /* Encrypt */
  rsa_public_operation(key, &mp_tmp, &mp_dst);

  tmplen = (key->bits + 7) / 8;

  /* Format the MP int back into data */
  silc_mp_mp2bin_noalloc(&mp_dst, dst, tmplen);
  *dst_len = tmplen;

  silc_mp_uninit(&mp_tmp);
  silc_mp_uninit(&mp_dst);

  return TRUE;
}

SILC_PKCS_API_DECRYPT(rsa)
{
  RsaKey *key = (RsaKey *)context;
  int tmplen;
  SilcMPInt mp_tmp;
  SilcMPInt mp_dst;

  silc_mp_init(&mp_tmp);
  silc_mp_init(&mp_dst);

  /* Format the data into MP int */
  silc_mp_bin2mp(src, src_len, &mp_tmp);

  /* Decrypt */
  rsa_private_operation(key, &mp_tmp, &mp_dst);

  tmplen = (key->bits + 7) / 8;

  /* Format the MP int back into data */
  silc_mp_mp2bin_noalloc(&mp_dst, dst, tmplen);
  *dst_len = tmplen;

  silc_mp_uninit(&mp_tmp);
  silc_mp_uninit(&mp_dst);

  return TRUE;
}

SILC_PKCS_API_SIGN(rsa)
{
  RsaKey *key = (RsaKey *)context;
  int tmplen;
  SilcMPInt mp_tmp;
  SilcMPInt mp_dst;

  silc_mp_init(&mp_tmp);
  silc_mp_init(&mp_dst);

  /* Format the data into MP int */
  silc_mp_bin2mp(src, src_len, &mp_tmp);

  /* Sign */
  rsa_private_operation(key, &mp_tmp, &mp_dst);

  tmplen = (key->bits + 7) / 8;

  /* Format the MP int back into data */
  silc_mp_mp2bin_noalloc(&mp_dst, dst, tmplen);
  *dst_len = tmplen;

  silc_mp_uninit(&mp_tmp);
  silc_mp_uninit(&mp_dst);

  return TRUE;
}

SILC_PKCS_API_VERIFY(rsa)
{
  RsaKey *key = (RsaKey *)context;
  int ret;
  SilcMPInt mp_tmp, mp_tmp2;
  SilcMPInt mp_dst;

  silc_mp_init(&mp_tmp);
  silc_mp_init(&mp_tmp2);
  silc_mp_init(&mp_dst);

  /* Format the signature into MP int */
  silc_mp_bin2mp(signature, signature_len, &mp_tmp2);

  /* Verify */
  rsa_public_operation(key, &mp_tmp2, &mp_dst);

  /* Format the data into MP int */
  silc_mp_bin2mp(data, data_len, &mp_tmp);

  ret = TRUE;

  /* Compare */
  if ((silc_mp_cmp(&mp_tmp, &mp_dst)) != 0)
    ret = FALSE;

  silc_mp_uninit(&mp_tmp);
  silc_mp_uninit(&mp_tmp2);
  silc_mp_uninit(&mp_dst);

  return ret;
}


/* PKCS#1 RSA routines */

SILC_PKCS_API_ENCRYPT(pkcs1)
{
  RsaKey *key = (RsaKey *)context;
  SilcMPInt mp_tmp;
  SilcMPInt mp_dst;
  unsigned char padded[2048 + 1];
  SilcUInt32 len = (key->bits + 7) / 8;

  if (sizeof(padded) < len)
    return FALSE;

  /* Pad data */
  if (!silc_pkcs1_encode(SILC_PKCS1_BT_PUB, src, src_len,
			 padded, len, NULL))
    return FALSE;

  silc_mp_init(&mp_tmp);
  silc_mp_init(&mp_dst);

  /* Data to MP */
  silc_mp_bin2mp(padded, len, &mp_tmp);

  /* Encrypt */
  rsa_public_operation(key, &mp_tmp, &mp_dst);

  /* MP to data */
  silc_mp_mp2bin_noalloc(&mp_dst, dst, len);
  *dst_len = len;

  memset(padded, 0, sizeof(padded));
  silc_mp_uninit(&mp_tmp);
  silc_mp_uninit(&mp_dst);

  return TRUE;
}

SILC_PKCS_API_DECRYPT(pkcs1)
{
  RsaKey *key = (RsaKey *)context;
  SilcMPInt mp_tmp;
  SilcMPInt mp_dst;
  unsigned char *padded, unpadded[2048 + 1];
  SilcUInt32 padded_len;

  silc_mp_init(&mp_tmp);
  silc_mp_init(&mp_dst);

  /* Data to MP */
  silc_mp_bin2mp(src, src_len, &mp_tmp);

  /* Decrypt */
  rsa_private_operation(key, &mp_tmp, &mp_dst);

  /* MP to data */
  padded = silc_mp_mp2bin(&mp_dst, (key->bits + 7) / 8, &padded_len);

  /* Unpad data */
  if (!silc_pkcs1_decode(SILC_PKCS1_BT_PUB, padded, padded_len,
			 unpadded, sizeof(unpadded), dst_len)) {
    memset(padded, 0, padded_len);
    silc_free(padded);
    silc_mp_uninit(&mp_tmp);
    silc_mp_uninit(&mp_dst);
    return FALSE;
  }

  /* Copy to destination */
  memcpy(dst, unpadded, *dst_len);

  memset(padded, 0, padded_len);
  memset(unpadded, 0, sizeof(unpadded));
  silc_free(padded);
  silc_mp_uninit(&mp_tmp);
  silc_mp_uninit(&mp_dst);

  return TRUE;
}

SILC_PKCS_API_SIGN(pkcs1)
{
  RsaKey *key = (RsaKey *)context;
  SilcMPInt mp_tmp;
  SilcMPInt mp_dst;
  unsigned char padded[2048 + 1];
  SilcUInt32 len = (key->bits + 7) / 8;

  if (sizeof(padded) < len)
    return FALSE;

  /* Pad data */
  if (!silc_pkcs1_encode(SILC_PKCS1_BT_PRV1, src, src_len,
			 padded, len, NULL))
    return FALSE;

  silc_mp_init(&mp_tmp);
  silc_mp_init(&mp_dst);

  /* Data to MP */
  silc_mp_bin2mp(padded, len, &mp_tmp);

  /* Sign */
  rsa_private_operation(key, &mp_tmp, &mp_dst);

  /* MP to data */
  silc_mp_mp2bin_noalloc(&mp_dst, dst, len);
  *dst_len = len;

  memset(padded, 0, sizeof(padded));
  silc_mp_uninit(&mp_tmp);
  silc_mp_uninit(&mp_dst);

  return TRUE;
}

SILC_PKCS_API_VERIFY(pkcs1)
{
  RsaKey *key = (RsaKey *)context;
  int ret = TRUE;
  SilcMPInt mp_tmp2;
  SilcMPInt mp_dst;
  unsigned char *verify, unpadded[2048 + 1];
  SilcUInt32 verify_len, len = (key->bits + 7) / 8;

  silc_mp_init(&mp_tmp2);
  silc_mp_init(&mp_dst);

  /* Format the signature into MP int */
  silc_mp_bin2mp(signature, signature_len, &mp_tmp2);

  /* Verify */
  rsa_public_operation(key, &mp_tmp2, &mp_dst);

  /* MP to data */
  verify = silc_mp_mp2bin(&mp_dst, len, &verify_len);

  /* Unpad data */
  if (!silc_pkcs1_decode(SILC_PKCS1_BT_PRV1, verify, verify_len,
			 unpadded, sizeof(unpadded), &len)) {
    memset(verify, 0, verify_len);
    silc_free(verify);
    silc_mp_uninit(&mp_tmp2);
    silc_mp_uninit(&mp_dst);
    return FALSE;
  }

  /* Compare */
  if (memcmp(data, unpadded, len))
    ret = FALSE;

  memset(verify, 0, verify_len);
  memset(unpadded, 0, sizeof(unpadded));
  silc_free(verify);
  silc_mp_uninit(&mp_tmp2);
  silc_mp_uninit(&mp_dst);

  return ret;
}

/* Generates RSA public and private keys. Primes p and q that are used
   to compute the modulus n has to be generated before calling this. They
   are then sent as argument for the function. */

bool rsa_generate_keys(RsaKey *key, SilcUInt32 bits,
		       SilcMPInt *p, SilcMPInt *q)
{
  SilcMPInt phi, hlp;
  SilcMPInt div, lcm;
  SilcMPInt pm1, qm1;

  /* Initialize variables */
  silc_mp_init(&key->n);
  silc_mp_init(&key->e);
  silc_mp_init(&key->d);
  silc_mp_init(&key->dP);
  silc_mp_init(&key->dQ);
  silc_mp_init(&key->pQ);
  silc_mp_init(&key->qP);
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
  silc_mp_set_ui(&key->e, 65533);
 retry_e:
  /* See if e is relatively prime to phi. gcd == greates common divisor,
     if gcd equals 1 they are relatively prime. */
  silc_mp_gcd(&hlp, &key->e, &phi);
  if ((silc_mp_cmp_ui(&hlp, 1)) > 0) {
    silc_mp_add_ui(&key->e, &key->e, 2);
    goto retry_e;
  }

  /* Find d, the private exponent, e ^ -1 mod lcm(phi). */
  silc_mp_gcd(&div, &pm1, &qm1);
  silc_mp_div(&lcm, &phi, &div);
  silc_mp_modinv(&key->d, &key->e, &lcm);

  /* Optimize d with CRT.  We precompute as much as possible. */
  silc_mp_mod(&key->dP, &key->d, &pm1);
  silc_mp_mod(&key->dQ, &key->d, &qm1);
  silc_mp_modinv(&key->pQ, p, q);
  silc_mp_mul(&key->pQ, p, &key->pQ);
  silc_mp_mod(&key->pQ, &key->pQ, &key->n);
  silc_mp_modinv(&key->qP, q, p);
  silc_mp_mul(&key->qP, q, &key->qP);
  silc_mp_mod(&key->qP, &key->qP, &key->n);
  silc_mp_set(&key->p, p);
  silc_mp_set(&key->q, q);
  key->crt = TRUE;

  silc_mp_uninit(&phi);
  silc_mp_uninit(&hlp);
  silc_mp_uninit(&div);
  silc_mp_uninit(&lcm);
  silc_mp_uninit(&pm1);
  silc_mp_uninit(&qm1);

  return TRUE;
}

/* Clears whole key structure. */

bool rsa_clear_keys(RsaKey *key)
{
  key->bits = 0;
  if (key->pub_set) {
    silc_mp_uninit(&key->n);
    silc_mp_uninit(&key->e);
  }
  if (key->prv_set)
    silc_mp_uninit(&key->d);
  if (key->prv_set && key->crt) {
    silc_mp_uninit(&key->dP);
    silc_mp_uninit(&key->dQ);
    silc_mp_uninit(&key->pQ);
    silc_mp_uninit(&key->qP);
    silc_mp_uninit(&key->p);
    silc_mp_uninit(&key->q);
  }
  return TRUE;
}

/* RSA public key operation */

bool rsa_public_operation(RsaKey *key, SilcMPInt *src, SilcMPInt *dst)
{
  /* dst = src ^ e mod n */
  silc_mp_pow_mod(dst, src, &key->e, &key->n);
  return TRUE;
}

/* RSA private key operation */

bool rsa_private_operation(RsaKey *key, SilcMPInt *src, SilcMPInt *dst)
{
  if (!key->crt) {
    /* dst = src ^ d mod n */
    silc_mp_pow_mod(dst, src, &key->d, &key->n);
  } else {
    /* CRT */
    SilcMPInt tmp;

    silc_mp_init(&tmp);

    /* dst = ((src ^ dP mod p) * qP) + ((src ^ dQ mod q) * pQ) mod n */
    silc_mp_pow_mod(dst, src, &key->dP, &key->p);
    silc_mp_mul(dst, dst, &key->qP);
    silc_mp_pow_mod(&tmp, src, &key->dQ, &key->q);
    silc_mp_mul(&tmp, &tmp, &key->pQ);
    silc_mp_add(dst, dst, &tmp);
    silc_mp_mod(dst, dst, &key->n);

    silc_mp_uninit(&tmp);
  }

  return TRUE;
}
