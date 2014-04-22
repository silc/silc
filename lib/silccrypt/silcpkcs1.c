/*

  silcpkcs1.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 - 2014 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silc.h"
#include "rsa.h"
#include "silcpkcs1_i.h"

/************************** PKCS #1 message format ***************************/

/* Minimum padding in block */
#define SILC_PKCS1_MIN_PADDING 8

/* Encodes PKCS#1 data block from the `data' according to the block type
   indicated by `bt'.  When encoding signatures the `bt' must be
   SILC_PKCS1_BT_PRV1 and when encoding encryption blocks the `bt' must
   be SILC_PKCS1_BT_PUB.  The encoded data is copied into the `dest_data'
   buffer which is size of `dest_data_size'.  If the `dest_data' is not
   able to hold the encoded block this returns FALSE.  The `rng' must be
   set when `bt' is SILC_PKCS1_BT_PUB.  This function returns TRUE on
   success. */

SilcBool silc_pkcs1_encode(SilcPkcs1BlockType bt,
			   const unsigned char *data,
			   SilcUInt32 data_len,
			   unsigned char *dest_data,
			   SilcUInt32 dest_data_size,
			   SilcRng rng)
{
  SilcInt32 padlen;
  int i;

  SILC_LOG_DEBUG(("PKCS#1 encoding, bt %d", bt));

  if (!data || !dest_data ||
      dest_data_size < SILC_PKCS1_MIN_PADDING + 3 ||
      dest_data_size < data_len) {
    SILC_LOG_DEBUG(("Data to be encoded is too long"));
    return FALSE;
  }

  /* Start of block */
  dest_data[0] = 0x00;
  dest_data[1] = (unsigned char)bt;

  padlen = (SilcInt32)dest_data_size - (SilcInt32)data_len - 3;
  if (padlen < SILC_PKCS1_MIN_PADDING) {
    SILC_LOG_DEBUG(("Data to be encoded is too long"));
    return FALSE;
  }

  /* Encode according to block type */
  switch (bt) {
  case SILC_PKCS1_BT_PRV0:
  case SILC_PKCS1_BT_PRV1:
    /* Signature */
    memset(dest_data + 2, bt == SILC_PKCS1_BT_PRV1 ? 0xff : 0x00, padlen);
    break;

  case SILC_PKCS1_BT_PUB:
    /* Encryption */
    if (!rng) {
      SILC_LOG_ERROR(("Cannot encrypt: random number generator not provided"));
      return FALSE;
    }

    /* It is guaranteed this routine does not return zero byte. */
    for (i = 2; i < padlen; i++)
      dest_data[i] = silc_rng_get_byte_fast(rng);

    break;
  }

  /* Copy the data */
  dest_data[padlen + 2] = 0x00;
  memcpy(dest_data + padlen + 3, data, data_len);

  return TRUE;
}

/* Decodes the PKCS#1 encoded block according to the block type `bt'.
   When verifying signatures the `bt' must be SILC_PKCS1_BT_PRV1 and
   when decrypting it must be SILC_PKCS1_BT_PUB.  This copies the
   decoded data into `dest_data' which is size of `dest_data_size'.  If
   the deocded block does not fit to `dest_data' this returns FALSE.
   Returns TRUE on success. */

SilcBool silc_pkcs1_decode(SilcPkcs1BlockType bt,
			   const unsigned char *data,
			   SilcUInt32 data_len,
			   unsigned char *dest_data,
			   SilcUInt32 dest_data_size,
			   SilcUInt32 *dest_len)
{
  SilcUInt32 i = 0;

  SILC_LOG_DEBUG(("PKCS#1 decoding, bt %d", bt));

  /* Sanity checks */
  if (!data || !dest_data || dest_data_size < 3 ||
      data[0] != 0x00 || data[1] != (unsigned char)bt) {
    SILC_LOG_DEBUG(("Malformed block"));
    return FALSE;
  }

  /* Decode according to block type */
  switch (bt) {
  case SILC_PKCS1_BT_PRV0:
    /* Do nothing */
    break;

  case SILC_PKCS1_BT_PRV1:
    /* Verification */
    for (i = 2; i < data_len; i++)
      if (data[i] != 0xff)
	break;
    break;

  case SILC_PKCS1_BT_PUB:
    /* Decryption */
    for (i = 2; i < data_len; i++)
      if (data[i] == 0x00)
	break;
    break;
  }

  /* Sanity checks */
  if (i >= data_len) {
    SILC_LOG_DEBUG(("Malformed block"));
    return FALSE;
  }
  if (i < SILC_PKCS1_MIN_PADDING) {
    SILC_LOG_DEBUG(("Malformed block"));
    return FALSE;
  }
  if (data[i++] != 0x00) {
    SILC_LOG_DEBUG(("Malformed block"));
    return FALSE;
  }
  if (i >= data_len) {
    SILC_LOG_DEBUG(("Malformed block"));
    return FALSE;
  }
  if (dest_data_size < data_len - i) {
    SILC_LOG_DEBUG(("Destination buffer too small"));
    return FALSE;
  }

  /* Copy the data */
  memcpy(dest_data, data + i, data_len - i);

  /* Return data length */
  if (dest_len)
    *dest_len = data_len - i;

  return TRUE;
}


/***************************** PKCS #1 PKCS API ******************************/

/* Generates RSA key pair. */

SilcBool silc_pkcs1_generate_key(SilcUInt32 keylen,
				 SilcRng rng,
				 void **ret_public_key,
				 void **ret_private_key)
{
  SilcUInt32 prime_bits = keylen / 2;
  SilcMPInt p, q;
  SilcBool found = FALSE;

  if (keylen < 768 || keylen > 16384)
    return FALSE;

  silc_mp_init(&p);
  silc_mp_init(&q);

  /* Find p and q */
  while (!found) {
    silc_math_gen_prime(&p, prime_bits, FALSE, rng);
    silc_math_gen_prime(&q, prime_bits, FALSE, rng);
    if ((silc_mp_cmp(&p, &q)) != 0)
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
  if (!silc_rsa_generate_keys(keylen, &p, &q, ret_public_key, ret_private_key))
    return FALSE;

  silc_mp_uninit(&p);
  silc_mp_uninit(&q);

  return TRUE;
}

/* Import PKCS #1 compliant public key */

int silc_pkcs1_import_public_key(unsigned char *key,
				 SilcUInt32 key_len,
				 void **ret_public_key)
{
  SilcAsn1 asn1 = NULL;
  SilcBufferStruct alg_key;
  RsaPublicKey *pubkey;

  if (!ret_public_key)
    return 0;

  asn1 = silc_asn1_alloc();
  if (!asn1)
    return 0;

  /* Allocate RSA public key */
  *ret_public_key = pubkey = silc_calloc(1, sizeof(*pubkey));
  if (!pubkey)
    goto err;

  /* Parse the PKCS #1 public key */
  silc_buffer_set(&alg_key, key, key_len);
  if (!silc_asn1_decode(asn1, &alg_key,
			SILC_ASN1_OPTS(SILC_ASN1_ALLOC),
			SILC_ASN1_SEQUENCE,
			  SILC_ASN1_INT(&pubkey->n),
			  SILC_ASN1_INT(&pubkey->e),
			SILC_ASN1_END, SILC_ASN1_END))
    goto err;

  /* Set key length */
  pubkey->bits = ((silc_mp_sizeinbase(&pubkey->n, 2) + 7) / 8) * 8;

  silc_asn1_free(asn1);

  return key_len;

 err:
  silc_free(pubkey);
  silc_asn1_free(asn1);
  return 0;
}

/* Export PKCS #1 compliant public key */

unsigned char *silc_pkcs1_export_public_key(void *public_key,
					    SilcUInt32 *ret_len)
{
  RsaPublicKey *key = public_key;
  SilcAsn1 asn1 = NULL;
  SilcBufferStruct alg_key;
  unsigned char *ret;

  asn1 = silc_asn1_alloc();
  if (!asn1)
    goto err;

  /* Encode to PKCS #1 public key */
  memset(&alg_key, 0, sizeof(alg_key));
  if (!silc_asn1_encode(asn1, &alg_key,
			SILC_ASN1_OPTS(SILC_ASN1_ALLOC),
			SILC_ASN1_SEQUENCE,
			  SILC_ASN1_INT(&key->n),
			  SILC_ASN1_INT(&key->e),
			SILC_ASN1_END, SILC_ASN1_END))
    goto err;

  ret = silc_buffer_steal(&alg_key, ret_len);
  silc_asn1_free(asn1);

  return ret;

 err:
  if (asn1)
    silc_asn1_free(asn1);
  return NULL;
}

/* Returns key length */

SilcUInt32 silc_pkcs1_public_key_bitlen(void *public_key)
{
  RsaPublicKey *key = public_key;
  return key->bits;
}

/* Copy public key */

void *silc_pkcs1_public_key_copy(void *public_key)
{
  RsaPublicKey *key = public_key, *new_key;

  new_key = silc_calloc(1, sizeof(*new_key));
  if (!new_key)
    return NULL;

  silc_mp_init(&new_key->n);
  silc_mp_init(&new_key->e);
  silc_mp_set(&new_key->n, &key->n);
  silc_mp_set(&new_key->e, &key->e);
  new_key->bits = key->bits;

  return new_key;
}

/* Compare public keys */

SilcBool silc_pkcs1_public_key_compare(void *key1, void *key2)
{
  RsaPublicKey *k1 = key1, *k2 = key2;

  if (k1->bits != k2->bits)
    return FALSE;
  if (silc_mp_cmp(&k1->e, &k2->e) != 0)
    return FALSE;
  if (silc_mp_cmp(&k1->n, &k2->n) != 0)
    return FALSE;

  return TRUE;
}

/* Frees public key */

void silc_pkcs1_public_key_free(void *public_key)
{
  RsaPublicKey *key = public_key;

  silc_mp_uninit(&key->n);
  silc_mp_uninit(&key->e);
  silc_free(key);
}

/* Import PKCS #1 compliant private key */

int silc_pkcs1_import_private_key(unsigned char *key,
				  SilcUInt32 key_len,
				  void **ret_private_key)
{
  SilcAsn1 asn1;
  SilcBufferStruct alg_key;
  RsaPrivateKey *privkey;
  SilcUInt32 ver;

  if (!ret_private_key)
    return 0;

  asn1 = silc_asn1_alloc();
  if (!asn1)
    return 0;

  /* Allocate RSA private key */
  *ret_private_key = privkey = silc_calloc(1, sizeof(*privkey));
  if (!privkey)
    goto err;

  /* Parse the PKCS #1 private key */
  silc_buffer_set(&alg_key, key, key_len);
  if (!silc_asn1_decode(asn1, &alg_key,
			SILC_ASN1_OPTS(SILC_ASN1_ALLOC),
			SILC_ASN1_SEQUENCE,
			  SILC_ASN1_SHORT_INT(&ver),
			  SILC_ASN1_INT(&privkey->n),
			  SILC_ASN1_INT(&privkey->e),
			  SILC_ASN1_INT(&privkey->d),
			  SILC_ASN1_INT(&privkey->p),
			  SILC_ASN1_INT(&privkey->q),
			  SILC_ASN1_INT(&privkey->dP),
			  SILC_ASN1_INT(&privkey->dQ),
			  SILC_ASN1_INT(&privkey->qP),
			SILC_ASN1_END, SILC_ASN1_END))
    goto err;

  if (ver != 0)
    goto err;

  /* Set key length */
  privkey->bits = ((silc_mp_sizeinbase(&privkey->n, 2) + 7) / 8) * 8;

  silc_asn1_free(asn1);

  return key_len;

 err:
  silc_free(privkey);
  silc_asn1_free(asn1);
  return 0;
}

/* Export PKCS #1 compliant private key */

unsigned char *silc_pkcs1_export_private_key(void *private_key,
					     SilcUInt32 *ret_len)
{
  RsaPrivateKey *key = private_key;
  SilcAsn1 asn1;
  SilcBufferStruct alg_key;
  unsigned char *ret;

  asn1 = silc_asn1_alloc();
  if (!asn1)
    return FALSE;

  /* Encode to PKCS #1 private key */
  memset(&alg_key, 0, sizeof(alg_key));
  if (!silc_asn1_encode(asn1, &alg_key,
			SILC_ASN1_OPTS(SILC_ASN1_ALLOC),
			SILC_ASN1_SEQUENCE,
			  SILC_ASN1_SHORT_INT(0),
			  SILC_ASN1_INT(&key->n),
			  SILC_ASN1_INT(&key->e),
			  SILC_ASN1_INT(&key->d),
			  SILC_ASN1_INT(&key->p),
			  SILC_ASN1_INT(&key->q),
			  SILC_ASN1_INT(&key->dP),
			  SILC_ASN1_INT(&key->dQ),
			  SILC_ASN1_INT(&key->qP),
			SILC_ASN1_END, SILC_ASN1_END))
    goto err;

  ret = silc_buffer_steal(&alg_key, ret_len);
  silc_asn1_free(asn1);

  return ret;

 err:
  silc_asn1_free(asn1);
  return NULL;
}

/* Returns key length */

SilcUInt32 silc_pkcs1_private_key_bitlen(void *private_key)
{
  RsaPrivateKey *key = private_key;
  return key->bits;
}

/* Frees private key */

void silc_pkcs1_private_key_free(void *private_key)
{
  RsaPrivateKey *key = private_key;

  silc_mp_uninit(&key->n);
  silc_mp_uninit(&key->e);
  silc_mp_uninit(&key->d);
  silc_mp_uninit(&key->dP);
  silc_mp_uninit(&key->dQ);
  silc_mp_uninit(&key->qP);
  silc_mp_uninit(&key->p);
  silc_mp_uninit(&key->q);
  silc_free(key);
}

/* PKCS #1 RSA routines */

SilcBool silc_pkcs1_encrypt(void *public_key,
			    unsigned char *src,
			    SilcUInt32 src_len,
			    unsigned char *dst,
			    SilcUInt32 dst_size,
			    SilcUInt32 *ret_dst_len,
			    SilcRng rng)
{
  RsaPublicKey *key = public_key;
  SilcMPInt mp_tmp;
  SilcMPInt mp_dst;
  unsigned char padded[65536 + 1];
  SilcUInt32 len = (key->bits + 7) / 8;

  if (sizeof(padded) < len)
    return FALSE;
  if (dst_size < len)
    return FALSE;

  /* Pad data */
  if (!silc_pkcs1_encode(SILC_PKCS1_BT_PUB, src, src_len,
			 padded, len, rng))
    return FALSE;

  silc_mp_init(&mp_tmp);
  silc_mp_init(&mp_dst);

  /* Data to MP */
  silc_mp_bin2mp(padded, len, &mp_tmp);

  /* Encrypt */
  silc_rsa_public_operation(key, &mp_tmp, &mp_dst);

  /* MP to data */
  silc_mp_mp2bin_noalloc(&mp_dst, dst, len);
  *ret_dst_len = len;

  memset(padded, 0, sizeof(padded));
  silc_mp_uninit(&mp_tmp);
  silc_mp_uninit(&mp_dst);

  return TRUE;
}

SilcBool silc_pkcs1_decrypt(void *private_key,
			    unsigned char *src,
			    SilcUInt32 src_len,
			    unsigned char *dst,
			    SilcUInt32 dst_size,
			    SilcUInt32 *ret_dst_len)
{
  RsaPrivateKey *key = private_key;
  SilcMPInt mp_tmp;
  SilcMPInt mp_dst;
  unsigned char *padded, unpadded[65536 + 1];
  SilcUInt32 padded_len;

  if (dst_size < (key->bits + 7) / 8)
    return FALSE;

  silc_mp_init(&mp_tmp);
  silc_mp_init(&mp_dst);

  /* Data to MP */
  silc_mp_bin2mp(src, src_len, &mp_tmp);

  /* Decrypt */
  silc_rsa_private_operation(key, &mp_tmp, &mp_dst);

  /* MP to data */
  padded = silc_mp_mp2bin(&mp_dst, (key->bits + 7) / 8, &padded_len);
  if (!padded) {
    silc_mp_uninit(&mp_tmp);
    silc_mp_uninit(&mp_dst);
    return FALSE;
  }

  /* Unpad data */
  if (!silc_pkcs1_decode(SILC_PKCS1_BT_PUB, padded, padded_len,
			 unpadded, sizeof(unpadded), ret_dst_len)) {
    memset(padded, 0, padded_len);
    silc_free(padded);
    silc_mp_uninit(&mp_tmp);
    silc_mp_uninit(&mp_dst);
    return FALSE;
  }

  /* Copy to destination */
  memcpy(dst, unpadded, *ret_dst_len);

  memset(padded, 0, padded_len);
  memset(unpadded, 0, sizeof(unpadded));
  silc_free(padded);
  silc_mp_uninit(&mp_tmp);
  silc_mp_uninit(&mp_dst);

  return TRUE;
}

/* PKCS #1 sign with appendix, hash OID included in the signature */

SilcBool silc_pkcs1_sign(void *private_key,
			 unsigned char *src,
			 SilcUInt32 src_len,
			 unsigned char *signature,
			 SilcUInt32 signature_size,
			 SilcUInt32 *ret_signature_len,
			 SilcBool compute_hash,
			 SilcHash hash)
{
  RsaPrivateKey *key = private_key;
  unsigned char padded[65536 + 1], hashr[SILC_HASH_MAXLEN];
  SilcMPInt mp_tmp;
  SilcMPInt mp_dst;
  SilcBufferStruct di;
  SilcUInt32 len = (key->bits + 7) / 8;
  const char *oid;
  SilcAsn1 asn1;

  SILC_LOG_DEBUG(("Sign"));

  if (sizeof(padded) < len)
    return FALSE;
  if (signature_size < len)
    return FALSE;

  oid = silc_hash_get_oid(hash);
  if (!oid)
    return FALSE;

  asn1 = silc_asn1_alloc();
  if (!asn1)
    return FALSE;

  /* Compute hash */
  if (compute_hash) {
    silc_hash_make(hash, src, src_len, hashr);
    src = hashr;
    src_len = silc_hash_len(hash);
  }

  /* Encode digest info */
  memset(&di, 0, sizeof(di));
  if (!silc_asn1_encode(asn1, &di,
			SILC_ASN1_SEQUENCE,
			  SILC_ASN1_SEQUENCE,
			    SILC_ASN1_OID(oid),
			    SILC_ASN1_NULL,
			  SILC_ASN1_END,
			  SILC_ASN1_OCTET_STRING(src, src_len),
			SILC_ASN1_END, SILC_ASN1_END)) {
    silc_asn1_free(asn1);
    return FALSE;
  }
  SILC_LOG_HEXDUMP(("DigestInfo"), silc_buffer_data(&di),
		   silc_buffer_len(&di));

  /* Pad data */
  if (!silc_pkcs1_encode(SILC_PKCS1_BT_PRV1, silc_buffer_data(&di),
			 silc_buffer_len(&di), padded, len, NULL)) {
    silc_asn1_free(asn1);
    return FALSE;
  }

  silc_mp_init(&mp_tmp);
  silc_mp_init(&mp_dst);

  /* Data to MP */
  silc_mp_bin2mp(padded, len, &mp_tmp);

  /* Sign */
  silc_rsa_private_operation(key, &mp_tmp, &mp_dst);

  /* MP to data */
  silc_mp_mp2bin_noalloc(&mp_dst, signature, len);
  *ret_signature_len = len;

  memset(padded, 0, sizeof(padded));
  silc_mp_uninit(&mp_tmp);
  silc_mp_uninit(&mp_dst);
  if (compute_hash)
    memset(hashr, 0, sizeof(hashr));
  silc_asn1_free(asn1);

  return TRUE;
}

/* PKCS #1 verification with appendix. */

SilcBool silc_pkcs1_verify(void *public_key,
			   unsigned char *signature,
			   SilcUInt32 signature_len,
			   unsigned char *data,
			   SilcUInt32 data_len,
			   SilcHash hash)
{
  RsaPublicKey *key = public_key;
  SilcBool ret = FALSE;
  SilcMPInt mp_tmp2;
  SilcMPInt mp_dst;
  unsigned char *verify = NULL, unpadded[65536 + 1], hashr[SILC_HASH_MAXLEN];
  SilcUInt32 verify_len, len = (key->bits + 7) / 8;
  SilcBufferStruct di, ldi;
  SilcHash ihash = NULL;
  SilcAsn1 asn1 = NULL;
  char *oid;

  SILC_LOG_DEBUG(("Verify signature"));

  asn1 = silc_asn1_alloc();
  if (!asn1)
    return FALSE;

  silc_mp_init(&mp_tmp2);
  silc_mp_init(&mp_dst);

  /* Format the signature into MP int */
  silc_mp_bin2mp(signature, signature_len, &mp_tmp2);

  /* Verify */
  silc_rsa_public_operation(key, &mp_tmp2, &mp_dst);

  /* MP to data */
  verify = silc_mp_mp2bin(&mp_dst, len, &verify_len);
  if (!verify)
    goto err;

  /* Unpad data */
  if (!silc_pkcs1_decode(SILC_PKCS1_BT_PRV1, verify, verify_len,
			 unpadded, sizeof(unpadded), &len))
    goto err;
  silc_buffer_set(&di, unpadded, len);

  /* If hash isn't given, allocate the one given in digest info */
  if (!hash) {
    /* Decode digest info */
    if (!silc_asn1_decode(asn1, &di,
			  SILC_ASN1_OPTS(SILC_ASN1_ACCUMUL),
			  SILC_ASN1_SEQUENCE,
			    SILC_ASN1_SEQUENCE,
			      SILC_ASN1_OID(&oid),
			    SILC_ASN1_END,
			  SILC_ASN1_END, SILC_ASN1_END))
      goto err;

    if (!silc_hash_alloc_by_oid(oid, &ihash)) {
      SILC_LOG_DEBUG(("Unknown OID %s", oid));
      goto err;
    }
    hash = ihash;
  }

  /* Hash the data */
  silc_hash_make(hash, data, data_len, hashr);
  data = hashr;
  data_len = silc_hash_len(hash);
  oid = (char *)silc_hash_get_oid(hash);

  /* Encode digest info for comparison */
  memset(&ldi, 0, sizeof(ldi));
  if (!silc_asn1_encode(asn1, &ldi,
			SILC_ASN1_OPTS(SILC_ASN1_ACCUMUL),
			SILC_ASN1_SEQUENCE,
			  SILC_ASN1_SEQUENCE,
			    SILC_ASN1_OID(oid),
			    SILC_ASN1_NULL,
			  SILC_ASN1_END,
			  SILC_ASN1_OCTET_STRING(data, data_len),
			SILC_ASN1_END, SILC_ASN1_END))
    goto err;

  SILC_LOG_HEXDUMP(("DigestInfo remote"), silc_buffer_data(&di),
		   silc_buffer_len(&di));
  SILC_LOG_HEXDUMP(("DigestInfo local"), silc_buffer_data(&ldi),
		   silc_buffer_len(&ldi));

  /* Compare */
  if (silc_buffer_len(&di) == silc_buffer_len(&ldi) &&
      !memcmp(silc_buffer_data(&di), silc_buffer_data(&ldi),
	      silc_buffer_len(&ldi)))
    ret = TRUE;

  memset(verify, 0, verify_len);
  memset(unpadded, 0, sizeof(unpadded));
  silc_free(verify);
  silc_mp_uninit(&mp_tmp2);
  silc_mp_uninit(&mp_dst);
  if (hash)
    memset(hashr, 0, sizeof(hashr));
  if (ihash)
    silc_hash_free(ihash);
  silc_asn1_free(asn1);

  return ret;

 err:
  if (verify) {
    memset(verify, 0, verify_len);
    silc_free(verify);
  }
  silc_mp_uninit(&mp_tmp2);
  silc_mp_uninit(&mp_dst);
  if (ihash)
    silc_hash_free(ihash);
  silc_asn1_free(asn1);
  return FALSE;
}

/* PKCS #1 sign without hash oid */

SilcBool silc_pkcs1_sign_no_oid(void *private_key,
				unsigned char *src,
				SilcUInt32 src_len,
				unsigned char *signature,
				SilcUInt32 signature_size,
				SilcUInt32 *ret_signature_len,
				SilcBool compute_hash,
				SilcHash hash)
{
  RsaPrivateKey *key = private_key;
  SilcMPInt mp_tmp;
  SilcMPInt mp_dst;
  unsigned char padded[65536 + 1], hashr[SILC_HASH_MAXLEN];
  SilcUInt32 len = (key->bits + 7) / 8;

  SILC_LOG_DEBUG(("Sign"));

  if (sizeof(padded) < len)
    return FALSE;
  if (signature_size < len)
    return FALSE;

  /* Compute hash if requested */
  if (compute_hash) {
    silc_hash_make(hash, src, src_len, hashr);
    src = hashr;
    src_len = silc_hash_len(hash);
  }

  /* Pad data */
  if (!silc_pkcs1_encode(SILC_PKCS1_BT_PRV1, src, src_len,
			 padded, len, NULL))
    return FALSE;

  silc_mp_init(&mp_tmp);
  silc_mp_init(&mp_dst);

  /* Data to MP */
  silc_mp_bin2mp(padded, len, &mp_tmp);

  /* Sign */
  silc_rsa_private_operation(key, &mp_tmp, &mp_dst);

  /* MP to data */
  silc_mp_mp2bin_noalloc(&mp_dst, signature, len);
  *ret_signature_len = len;

  memset(padded, 0, sizeof(padded));
  silc_mp_uninit(&mp_tmp);
  silc_mp_uninit(&mp_dst);
  if (compute_hash)
    memset(hashr, 0, sizeof(hashr));

  return TRUE;
}

/* PKCS #1 verify without hash oid */

SilcBool silc_pkcs1_verify_no_oid(void *public_key,
				  unsigned char *signature,
				  SilcUInt32 signature_len,
				  unsigned char *data,
				  SilcUInt32 data_len,
				  SilcHash hash)
{
  RsaPublicKey *key = public_key;
  SilcBool ret = FALSE;
  SilcMPInt mp_tmp2;
  SilcMPInt mp_dst;
  unsigned char *verify, unpadded[65536 + 1], hashr[SILC_HASH_MAXLEN];
  SilcUInt32 verify_len, len = (key->bits + 7) / 8;

  SILC_LOG_DEBUG(("Verify signature"));

  silc_mp_init(&mp_tmp2);
  silc_mp_init(&mp_dst);

  /* Format the signature into MP int */
  silc_mp_bin2mp(signature, signature_len, &mp_tmp2);

  /* Verify */
  silc_rsa_public_operation(key, &mp_tmp2, &mp_dst);

  /* MP to data */
  verify = silc_mp_mp2bin(&mp_dst, len, &verify_len);
  if (!verify) {
    silc_mp_uninit(&mp_tmp2);
    silc_mp_uninit(&mp_dst);
    return FALSE;
  }

  /* Unpad data */
  if (!silc_pkcs1_decode(SILC_PKCS1_BT_PRV1, verify, verify_len,
			 unpadded, sizeof(unpadded), &len)) {
    memset(verify, 0, verify_len);
    silc_free(verify);
    silc_mp_uninit(&mp_tmp2);
    silc_mp_uninit(&mp_dst);
    return FALSE;
  }

  /* Hash data if requested */
  if (hash) {
    silc_hash_make(hash, data, data_len, hashr);
    data = hashr;
    data_len = silc_hash_len(hash);
  }

  /* Compare */
  if (len == data_len && !memcmp(data, unpadded, len))
    ret = TRUE;

  memset(verify, 0, verify_len);
  memset(unpadded, 0, sizeof(unpadded));
  silc_free(verify);
  silc_mp_uninit(&mp_tmp2);
  silc_mp_uninit(&mp_dst);
  if (hash)
    memset(hashr, 0, sizeof(hashr));

  return ret;
}
