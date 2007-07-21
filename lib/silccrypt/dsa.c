/*

  dsa.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"
#include "dsa.h"

/************************** DSA PKCS Algorithm API **************************/

/* Notes about key formats:

   For DSA private key format the PKCS#8 (defined in PKCS#11) can be used but
   would be an overkill for this low level API.  Thus, we use our own DSA
   private key format that is equivalent to GnuTLS and OpenSSL DSA private
   key format:

   key ::= SEQUENCE {
     ver   INTEGER,
     p     INTEGER,
     q     INTEGER,
     g     INTEGER,
     y     INTEGER,
     x     INTEGER }

   For DSA public keys we also use our own format since the standard formats
   require the public key ASN.1 data to be in two parts (algorithm params and
   the key itself).  We don't require such format for this low level API and
   expect that if that format is used it is trivial to convert it to this
   internal format (which is just concatenation of the params and the key):

   key ::= SEQUENCE {
     p     INTEGER,
     q     INTEGER,
     g     INTEGER },
     y     INTEGER

   Notes about signature format:

   The encoded signature format is compliant with PKIX (X.509):

   sig ::= SEQUENCE {
     r     INTEGER,
     s     INTEGER }

*/

/* Generates DSA key pair.  For now this uses group size of 160 bits. */

SILC_PKCS_ALG_GENERATE_KEY(silc_dsa_generate_key)
{
  DsaPublicKey *pubkey;
  DsaPrivateKey *privkey;
  SilcMPInt tmp, tmp2;
  unsigned char rnd[4096];
  int i, len = (keylen + 7) / 8, q_len = 160 / 8;

  if (keylen < 768 || keylen > 16384)
    return FALSE;

  pubkey = silc_calloc(1, sizeof(*pubkey));
  if (!pubkey)
    return FALSE;

  privkey = silc_calloc(1, sizeof(*privkey));
  if (!privkey) {
    silc_free(pubkey);
    return FALSE;
  }

  silc_mp_init(&tmp);
  silc_mp_init(&tmp2);
  silc_mp_init(&privkey->p);
  silc_mp_init(&privkey->q);
  silc_mp_init(&privkey->g);
  silc_mp_init(&privkey->y);
  silc_mp_init(&privkey->x);
  silc_mp_init(&pubkey->p);
  silc_mp_init(&pubkey->q);
  silc_mp_init(&pubkey->g);
  silc_mp_init(&pubkey->y);

  /* Generate primes q and p.  The p will satisfy (q * rnd) + 1 == p */

  /* Generate prime q */
  silc_math_gen_prime(&privkey->q, q_len * 8, FALSE, rng);
  silc_mp_add(&tmp, &privkey->q, &privkey->q);

  do {
    /* Create p.  Take random data, this returns non-zero bytes.  Make the
       number even. */
    silc_rng_get_rn_data(rng, len - q_len, rnd, sizeof(rnd));
    rnd[(len - q_len) - 1] &= ~1;
    silc_mp_bin2mp(rnd, len - q_len, &tmp2);
    silc_mp_mul(&privkey->p, &privkey->q, &tmp2);
    silc_mp_add_ui(&privkey->p, &privkey->p, 1);

    /* Make p prime.  If it doesn't seem to happen, try again from the
       beginning. */
    for (i = 0; i < q_len * 2; i++) {
      if (silc_math_prime_test(&privkey->p))
	break;
      silc_mp_add(&privkey->p, &tmp, &privkey->p);
      silc_mp_add_ui(&tmp2, &tmp2, 2);
    }
  } while (i >= q_len * 2);

  /* Find generator */
  silc_mp_set_ui(&privkey->g, 1);
  do {
    silc_mp_add_ui(&privkey->g, &privkey->g, 1);
    silc_mp_pow_mod(&tmp, &privkey->g, &tmp2, &privkey->p);
  } while (silc_mp_cmp_ui(&tmp, 1) == 0);
  silc_mp_set(&privkey->g, &tmp);

  /* Generate private key */
  silc_rng_get_rn_data(rng, q_len, rnd, sizeof(rnd));
  silc_mp_bin2mp(rnd, q_len, &privkey->x);

  /* Generate public key */
  silc_mp_pow_mod(&privkey->y, &privkey->g, &privkey->x, &privkey->p);

  /* Now set the integers to public key too */
  silc_mp_set(&pubkey->p, &privkey->p);
  silc_mp_set(&pubkey->q, &privkey->q);
  silc_mp_set(&pubkey->g, &privkey->g);
  silc_mp_set(&pubkey->y, &privkey->y);

  privkey->group_order = q_len;
  privkey->bits = keylen;
  pubkey->group_order = q_len;
  pubkey->bits = keylen;

  silc_mp_uninit(&tmp);
  silc_mp_uninit(&tmp2);

  if (ret_public_key)
    *ret_public_key = pubkey;
  if (ret_private_key)
    *ret_private_key = privkey;

  return TRUE;
}

/* Import DSA public key */

SILC_PKCS_ALG_IMPORT_PUBLIC_KEY(silc_dsa_import_public_key)
{
  SilcAsn1 asn1;
  SilcBufferStruct alg_key;
  DsaPublicKey *pubkey;

  SILC_LOG_DEBUG(("Import public key"));

  if (!ret_public_key)
    return 0;

  asn1 = silc_asn1_alloc(NULL);
  if (!asn1)
    return 0;

  /* Allocate DSA public key */
  *ret_public_key = pubkey = silc_calloc(1, sizeof(*pubkey));
  if (!pubkey)
    goto err;

  /* Parse */
  silc_buffer_set(&alg_key, key, key_len);
  if (!silc_asn1_decode(asn1, &alg_key,
			SILC_ASN1_OPTS(SILC_ASN1_ALLOC),
			SILC_ASN1_SEQUENCE,
			  SILC_ASN1_INT(&pubkey->p),
			  SILC_ASN1_INT(&pubkey->q),
			  SILC_ASN1_INT(&pubkey->g),
			SILC_ASN1_END,
			SILC_ASN1_INT(&pubkey->y),
			SILC_ASN1_END))
    goto err;

  /* Set key length */
  pubkey->bits = ((silc_mp_sizeinbase(&pubkey->p, 2) + 7) / 8) * 8;

  silc_asn1_free(asn1);

  return key_len;

 err:
  silc_free(pubkey);
  silc_asn1_free(asn1);
  return 0;
}

/* Export DSA public key */

SILC_PKCS_ALG_EXPORT_PUBLIC_KEY(silc_dsa_export_public_key)
{
  DsaPublicKey *key = public_key;
  SilcAsn1 asn1 = NULL;
  SilcBufferStruct alg_key;
  unsigned char *ret;

  SILC_LOG_DEBUG(("Export public key"));

  asn1 = silc_asn1_alloc(stack);
  if (!asn1)
    goto err;

  /* Encode public key */
  memset(&alg_key, 0, sizeof(alg_key));
  if (!silc_asn1_encode(asn1, &alg_key,
			SILC_ASN1_OPTS(SILC_ASN1_ALLOC),
			SILC_ASN1_SEQUENCE,
			  SILC_ASN1_INT(&key->p),
			  SILC_ASN1_INT(&key->q),
			  SILC_ASN1_INT(&key->g),
			SILC_ASN1_END,
			SILC_ASN1_INT(&key->y),
			SILC_ASN1_END))
    goto err;

  ret = silc_buffer_steal(&alg_key, ret_len);
  silc_asn1_free(asn1);

  return ret;

 err:
  if (asn1)
    silc_asn1_free(asn1);
  return NULL;
}

/* Return key length */

SILC_PKCS_ALG_PUBLIC_KEY_BITLEN(silc_dsa_public_key_bitlen)
{
  DsaPublicKey *key = public_key;
  return key->bits;
}

/* Copy public key */

SILC_PKCS_ALG_PUBLIC_KEY_COPY(silc_dsa_public_key_copy)
{
  DsaPublicKey *key = public_key, *new_key;

  new_key = silc_calloc(1, sizeof(*new_key));
  if (!new_key)
    return NULL;

  silc_mp_init(&new_key->p);
  silc_mp_init(&new_key->q);
  silc_mp_init(&new_key->g);
  silc_mp_init(&new_key->y);
  new_key->bits = key->bits;
  new_key->group_order = key->group_order;

  return new_key;
}

/* Compare public keys */

SILC_PKCS_ALG_PUBLIC_KEY_COMPARE(silc_dsa_public_key_compare)
{
  DsaPublicKey *k1 = key1, *k2 = key2;

  if (k1->bits != k2->bits)
    return FALSE;
  if (k1->group_order != k2->group_order)
    return FALSE;
  if (silc_mp_cmp(&k1->p, &k2->p) != 0)
    return FALSE;
  if (silc_mp_cmp(&k1->q, &k2->q) != 0)
    return FALSE;
  if (silc_mp_cmp(&k1->g, &k2->g) != 0)
    return FALSE;
  if (silc_mp_cmp(&k1->y, &k2->y) != 0)
    return FALSE;

  return TRUE;
}

/* Free public key */

SILC_PKCS_ALG_PUBLIC_KEY_FREE(silc_dsa_public_key_free)
{
  DsaPublicKey *key = public_key;

  silc_mp_uninit(&key->p);
  silc_mp_uninit(&key->q);
  silc_mp_uninit(&key->g);
  silc_mp_uninit(&key->y);
  silc_free(key);
}

/* Import DSA private key. */

SILC_PKCS_ALG_IMPORT_PRIVATE_KEY(silc_dsa_import_private_key)
{
  SilcAsn1 asn1;
  SilcBufferStruct alg_key;
  DsaPrivateKey *privkey;
  SilcUInt32 ver;

  SILC_LOG_DEBUG(("Import private key"));

  if (!ret_private_key)
    return 0;

  asn1 = silc_asn1_alloc(NULL);
  if (!asn1)
    return 0;

  /* Allocate DSA private key */
  *ret_private_key = privkey = silc_calloc(1, sizeof(*privkey));
  if (!privkey)
    goto err;

  /* Parse */
  silc_buffer_set(&alg_key, key, key_len);
  if (!silc_asn1_decode(asn1, &alg_key,
			SILC_ASN1_OPTS(SILC_ASN1_ALLOC),
			SILC_ASN1_SEQUENCE,
			  SILC_ASN1_SHORT_INT(&ver),
			  SILC_ASN1_INT(&privkey->p),
			  SILC_ASN1_INT(&privkey->q),
			  SILC_ASN1_INT(&privkey->g),
			  SILC_ASN1_INT(&privkey->y),
			  SILC_ASN1_INT(&privkey->x),
			SILC_ASN1_END, SILC_ASN1_END))
    goto err;

  /* Set key length */
  privkey->bits = ((silc_mp_sizeinbase(&privkey->p, 2) + 7) / 8) * 8;

  silc_asn1_free(asn1);

  return key_len;

 err:
  silc_free(privkey);
  silc_asn1_free(asn1);
  return 0;
}

/* Export DSA private key. */

SILC_PKCS_ALG_EXPORT_PRIVATE_KEY(silc_dsa_export_private_key)
{
  DsaPrivateKey *key = private_key;
  SilcAsn1 asn1;
  SilcBufferStruct alg_key;
  unsigned char *ret;

  SILC_LOG_DEBUG(("Export private key"));

  asn1 = silc_asn1_alloc(stack);
  if (!asn1)
    return FALSE;

  /* Encode */
  memset(&alg_key, 0, sizeof(alg_key));
  if (!silc_asn1_encode(asn1, &alg_key,
			SILC_ASN1_OPTS(SILC_ASN1_ALLOC),
			SILC_ASN1_SEQUENCE,
			  SILC_ASN1_SHORT_INT(0),
			  SILC_ASN1_INT(&key->p),
			  SILC_ASN1_INT(&key->q),
			  SILC_ASN1_INT(&key->g),
			  SILC_ASN1_INT(&key->y),
			  SILC_ASN1_INT(&key->x),
			SILC_ASN1_END, SILC_ASN1_END))
    goto err;

  ret = silc_buffer_steal(&alg_key, ret_len);
  silc_asn1_free(asn1);

  return ret;

 err:
  silc_asn1_free(asn1);
  return NULL;
}

/* Return key length */

SILC_PKCS_ALG_PRIVATE_KEY_BITLEN(silc_dsa_private_key_bitlen)
{
  DsaPrivateKey *key = private_key;
  return key->bits;
}

/* Free private key */

SILC_PKCS_ALG_PRIVATE_KEY_FREE(silc_dsa_private_key_free)
{
  DsaPrivateKey *key = private_key;

  silc_mp_uninit(&key->p);
  silc_mp_uninit(&key->q);
  silc_mp_uninit(&key->g);
  silc_mp_uninit(&key->y);
  silc_mp_uninit(&key->x);
  silc_free(key);
}

/* Encryption.  Not supported */

SILC_PKCS_ALG_ENCRYPT(silc_dsa_encrypt)
{
  SILC_LOG_WARNING(("DSA encryption is not supported"));
  encrypt_cb(FALSE, NULL, 0, context);
  return NULL;
}

/* Decryption.  Not supported */

SILC_PKCS_ALG_DECRYPT(silc_dsa_decrypt)
{
  SILC_LOG_WARNING(("DSA decryption is not supported"));
  decrypt_cb(FALSE, NULL, 0, context);
  return NULL;
}

/* Sign */

SILC_PKCS_ALG_SIGN(silc_dsa_sign)
{
  DsaPrivateKey *key = private_key;
  unsigned char kbuf[512], hashr[SILC_HASH_MAXLEN];
  SilcBufferStruct sig;
  SilcMPInt tmp, k, kinv, r, s;
  SilcStack stack;
  SilcAsn1 asn1;

  SILC_LOG_DEBUG(("Sign"));

  if (key->group_order > sizeof(kbuf)) {
    sign_cb(FALSE, NULL, 0, context);
    return NULL;
  }

  if (!rng) {
    SILC_LOG_ERROR(("DSA signing requires random number generator"));
    sign_cb(FALSE, NULL, 0, context);
    return NULL;
  }

  /* Compute hash if requested */
  if (compute_hash) {
    silc_hash_make(hash, src, src_len, hashr);
    src = hashr;
    src_len = silc_hash_len(hash);
  }

  stack = silc_stack_alloc(2048, silc_crypto_stack());

  asn1 = silc_asn1_alloc(stack);
  if (!asn1) {
    silc_stack_free(stack);
    sign_cb(FALSE, NULL, 0, context);
    return NULL;
  }

  silc_mp_sinit(stack, &k);
  silc_mp_sinit(stack, &kinv);
  silc_mp_sinit(stack, &r);
  silc_mp_sinit(stack, &s);
  silc_mp_sinit(stack, &tmp);

  do {
    do {
      /* Generate random k */
      do {
	silc_rng_get_rn_data(rng, key->group_order, kbuf, sizeof(kbuf));
	silc_mp_bin2mp(kbuf, key->group_order, &k);
	silc_mp_gcd(&tmp, &k, &key->q);
      } while (silc_mp_cmp_ui(&tmp, 1) != 0);

      /* Compute kinv = k^-1 mod q */
      silc_mp_modinv(&kinv, &k, &key->q);

      /* Compute signature part r = g^k mod p mod q */
      silc_mp_pow_mod(&r, &key->g, &k, &key->p);
      silc_mp_mod(&r, &r, &key->q);
    } while (silc_mp_cmp_ui(&r, 0) == 0);

    /* Compute signature part s = (src + x * r) / k mod q */
    silc_mp_bin2mp(src, src_len, &tmp);
    silc_mp_mul(&s, &key->x, &r);
    silc_mp_add(&s, &s, &tmp);
    silc_mp_mul(&s, &s, &kinv);
    silc_mp_mod(&s, &s, &key->q);
  } while (silc_mp_cmp_ui(&s, 0) == 0);

  /* Encode the signature.  This format is compliant with PKIX. */
  memset(&sig, 0, sizeof(sig));
  if (!silc_asn1_encode(asn1, &sig,
			SILC_ASN1_SEQUENCE,
			  SILC_ASN1_INT(&r),
			  SILC_ASN1_INT(&s),
			SILC_ASN1_END, SILC_ASN1_END)) {
    sign_cb(FALSE, NULL, 0, context);
    goto out;
  }

  /* Deliver result */
  sign_cb(TRUE, silc_buffer_data(&sig), silc_buffer_len(&sig), context);

 out:
  memset(kbuf, 0, sizeof(kbuf));
  if (compute_hash)
    memset(hashr, 0, sizeof(hashr));
  silc_mp_suninit(stack, &k);
  silc_mp_suninit(stack, &kinv);
  silc_mp_suninit(stack, &r);
  silc_mp_suninit(stack, &s);
  silc_mp_suninit(stack, &tmp);
  silc_asn1_free(asn1);
  silc_stack_free(stack);

  return NULL;
}

/* Verify */

SILC_PKCS_ALG_VERIFY(silc_dsa_verify)
{
  DsaPublicKey *key = public_key;
  unsigned char hashr[SILC_HASH_MAXLEN];
  SilcBool ret = FALSE;
  SilcBufferStruct sig;
  SilcMPInt r, s, v, w, u1, u2;
  SilcStack stack;
  SilcAsn1 asn1;

  SILC_LOG_DEBUG(("Verify"));

  stack = silc_stack_alloc(2048, silc_crypto_stack());

  asn1 = silc_asn1_alloc(stack);
  if (!asn1) {
    silc_stack_free(stack);
    verify_cb(FALSE, context);
    return NULL;
  }

  /* Decode the signature */
  silc_buffer_set(&sig, signature, signature_len);
  if (!silc_asn1_decode(asn1, &sig,
			SILC_ASN1_OPTS(SILC_ASN1_ALLOC),
			SILC_ASN1_SEQUENCE,
			  SILC_ASN1_INT(&r),
			  SILC_ASN1_INT(&s),
			SILC_ASN1_END, SILC_ASN1_END)) {
    silc_asn1_free(asn1);
    silc_stack_free(stack);
    verify_cb(FALSE, context);
    return NULL;
  }

  if (silc_mp_cmp_ui(&r, 0) == 0 ||
      silc_mp_cmp_ui(&s, 0) == 0 ||
      silc_mp_cmp(&r, &key->q) >= 0 ||
      silc_mp_cmp(&s, &key->q) >= 0) {
    silc_asn1_free(asn1);
    silc_stack_free(stack);
    verify_cb(FALSE, context);
    return NULL;
  }

  /* Hash data if requested */
  if (hash) {
    silc_hash_make(hash, data, data_len, hashr);
    data = hashr;
    data_len = silc_hash_len(hash);
  }

  silc_mp_sinit(stack, &v);
  silc_mp_sinit(stack, &w);
  silc_mp_sinit(stack, &u1);
  silc_mp_sinit(stack, &u2);

  /* Compute w = s^-1 mod q */
  silc_mp_modinv(&w, &s, &key->q);

  /* Compute u1 = data * w mod q */
  silc_mp_bin2mp(data, data_len, &u1);
  silc_mp_mul(&u1, &u1, &w);
  silc_mp_mod(&u1, &u1, &key->q);

  /* Compute u2 = r * w mod q */
  silc_mp_mul(&u2, &r, &w);
  silc_mp_mod(&u2, &u2, &key->q);

  /* Compute v = g ^ u1 * y ^ u2 mod p mod q */
  silc_mp_pow_mod(&u1, &key->g, &u1, &key->p);
  silc_mp_pow_mod(&u2, &key->y, &u2, &key->p);
  silc_mp_mul(&v, &u1, &u2);
  silc_mp_mod(&v, &v, &key->p);
  silc_mp_mod(&v, &v, &key->q);

  /* Compare */
  if (silc_mp_cmp(&r, &v) == 0)
    ret = TRUE;

  /* Deliver result */
  verify_cb(ret, context);

  if (hash)
    memset(hashr, 0, sizeof(hashr));
  silc_mp_suninit(stack, &v);
  silc_mp_suninit(stack, &w);
  silc_mp_suninit(stack, &u1);
  silc_mp_suninit(stack, &u2);
  silc_asn1_free(asn1);
  silc_stack_free(stack);

  return NULL;
}
