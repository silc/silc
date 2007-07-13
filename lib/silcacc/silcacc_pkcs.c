/*

  silcacc_pkcs.c

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

/************************** Types and definitions ***************************/

#define SILC_ACC_KEY_MAGIC 0xfde09137

SILC_PKCS_GET_ALGORITHM(silc_acc_pkcs_get_algorithm);
SILC_PKCS_IMPORT_PUBLIC_KEY_FILE(silc_acc_pkcs_import_public_key_file);
SILC_PKCS_IMPORT_PUBLIC_KEY(silc_acc_pkcs_import_public_key);
SILC_PKCS_EXPORT_PUBLIC_KEY_FILE(silc_acc_pkcs_export_public_key_file);
SILC_PKCS_EXPORT_PUBLIC_KEY(silc_acc_pkcs_export_public_key);
SILC_PKCS_PUBLIC_KEY_BITLEN(silc_acc_pkcs_public_key_bitlen);
SILC_PKCS_PUBLIC_KEY_COPY(silc_acc_pkcs_public_key_copy);
SILC_PKCS_PUBLIC_KEY_COMPARE(silc_acc_pkcs_public_key_compare);
SILC_PKCS_PUBLIC_KEY_FREE(silc_acc_pkcs_public_key_free);
SILC_PKCS_IMPORT_PRIVATE_KEY_FILE(silc_acc_pkcs_import_private_key_file);
SILC_PKCS_IMPORT_PRIVATE_KEY(silc_acc_pkcs_import_private_key);
SILC_PKCS_EXPORT_PRIVATE_KEY_FILE(silc_acc_pkcs_export_private_key_file);
SILC_PKCS_EXPORT_PRIVATE_KEY(silc_acc_pkcs_export_private_key);
SILC_PKCS_PRIVATE_KEY_BITLEN(silc_acc_pkcs_private_key_bitlen);
SILC_PKCS_PRIVATE_KEY_FREE(silc_acc_pkcs_private_key_free);
SILC_PKCS_ENCRYPT(silc_acc_pkcs_encrypt);
SILC_PKCS_DECRYPT(silc_acc_pkcs_decrypt);
SILC_PKCS_SIGN(silc_acc_pkcs_sign);
SILC_PKCS_VERIFY(silc_acc_pkcs_verify);

/* Accelerator public key */
typedef struct {
  SilcUInt32 magic;
  int pkcs_index;		/* Accelerator PKCS index */
  SilcAccelerator acc;		/* The accelerator */
  void *context;		/* Accelerator context */
  SilcPublicKey accelerated;	/* Associated public key */
} *SilcAcceleratorPublicKey;

/* Accelerator private key */
typedef struct {
  SilcUInt32 magic;
  int pkcs_index;		/* Accelerator PKCS index */
  SilcAccelerator acc;		/* The accelerator */
  void *context;		/* Accelerator context */
  SilcPrivateKey accelerated;	/* Associated private key */
} *SilcAcceleratorPrivateKey;

/*************************** Accelerator PKCS API ***************************/

/* The PKCS API for the accelerated public key and private key is simply
   a wrapper for the underlaying key.  Encrypt, decrypt, sign and verify
   operations are accelerated by calling the accelerator operations. */

const SilcPKCSObject silc_acc_pkcs =
{
  SILC_PKCS_SILC,

  /* Wrappers */
  silc_acc_pkcs_get_algorithm,
  silc_acc_pkcs_import_public_key_file,
  silc_acc_pkcs_import_public_key,
  silc_acc_pkcs_export_public_key_file,
  silc_acc_pkcs_export_public_key,
  silc_acc_pkcs_public_key_bitlen,
  silc_acc_pkcs_public_key_copy,
  silc_acc_pkcs_public_key_compare,
  silc_acc_pkcs_public_key_free,
  silc_acc_pkcs_import_private_key_file,
  silc_acc_pkcs_import_private_key,
  silc_acc_pkcs_export_private_key_file,
  silc_acc_pkcs_export_private_key,
  silc_acc_pkcs_private_key_bitlen,
  silc_acc_pkcs_private_key_free,

  /* Accelerated */
  silc_acc_pkcs_encrypt,
  silc_acc_pkcs_decrypt,
  silc_acc_pkcs_sign,
  silc_acc_pkcs_verify
};

SILC_PKCS_GET_ALGORITHM(silc_acc_pkcs_get_algorithm)
{
  SilcAcceleratorPublicKey pub = public_key;
  return pub->accelerated->pkcs->get_algorithm(pub->accelerated->pkcs,
					       pub->accelerated->public_key);
}

SILC_PKCS_IMPORT_PUBLIC_KEY_FILE(silc_acc_pkcs_import_public_key_file)
{
  /* Not implemented */
  return FALSE;
}

SILC_PKCS_IMPORT_PUBLIC_KEY(silc_acc_pkcs_import_public_key)
{
  /* Not implemented */
  return FALSE;
}

SILC_PKCS_EXPORT_PUBLIC_KEY_FILE(silc_acc_pkcs_export_public_key_file)
{
  SilcAcceleratorPublicKey pub = public_key;
  return pub->accelerated->pkcs->
    export_public_key_file(pub->accelerated->pkcs, NULL,
			   pub->accelerated->public_key,
			   encoding, ret_len);
}

SILC_PKCS_EXPORT_PUBLIC_KEY(silc_acc_pkcs_export_public_key)
{
  SilcAcceleratorPublicKey pub = public_key;
  return pub->accelerated->pkcs->export_public_key(pub->accelerated->pkcs,
						   NULL,
						   pub->accelerated->public_key,
						   ret_len);
}

SILC_PKCS_PUBLIC_KEY_BITLEN(silc_acc_pkcs_public_key_bitlen)
{
  SilcAcceleratorPublicKey pub = public_key;
  return pub->accelerated->pkcs->
    public_key_bitlen(pub->accelerated->pkcs,
		      pub->accelerated->public_key);
}

SILC_PKCS_PUBLIC_KEY_COPY(silc_acc_pkcs_public_key_copy)
{
  SilcAcceleratorPublicKey pub = public_key;
  return pub->accelerated->pkcs->public_key_copy(pub->accelerated->pkcs,
						 pub->accelerated->public_key);
}

SILC_PKCS_PUBLIC_KEY_COMPARE(silc_acc_pkcs_public_key_compare)
{
  SilcAcceleratorPublicKey pub;

  pub = key2;
  if (pub->magic == SILC_ACC_KEY_MAGIC)
    key2 = pub->accelerated->public_key;

  pub = key1;

  return pub->accelerated->pkcs->
    public_key_compare(pub->accelerated->pkcs,
		       pub->accelerated->public_key, key2);
}

SILC_PKCS_IMPORT_PRIVATE_KEY_FILE(silc_acc_pkcs_import_private_key_file)
{
  /* Not implemented */
  return FALSE;
}

SILC_PKCS_IMPORT_PRIVATE_KEY(silc_acc_pkcs_import_private_key)
{
  /* Not implemented */
  return FALSE;
}

SILC_PKCS_EXPORT_PRIVATE_KEY_FILE(silc_acc_pkcs_export_private_key_file)
{
  SilcAcceleratorPrivateKey prv = private_key;
  return prv->accelerated->pkcs->
    export_private_key_file(prv->accelerated->pkcs, stack,
			    prv->accelerated->private_key, passphrase,
			    passphrase_len, encoding, rng, ret_len);
}

SILC_PKCS_EXPORT_PRIVATE_KEY(silc_acc_pkcs_export_private_key)
{
  SilcAcceleratorPrivateKey prv = private_key;
  return prv->accelerated->pkcs->
    export_private_key(prv->accelerated->pkcs, stack,
		       prv->accelerated->private_key, ret_len);
}

SILC_PKCS_PRIVATE_KEY_BITLEN(silc_acc_pkcs_private_key_bitlen)
{
  SilcAcceleratorPrivateKey prv = private_key;
  return prv->accelerated->pkcs->
    private_key_bitlen(prv->accelerated->pkcs,
		       prv->accelerated->private_key);
}

/* Accelerator routines follow */

SILC_PKCS_PUBLIC_KEY_FREE(silc_acc_pkcs_public_key_free)
{
  SilcAcceleratorPublicKey pub = public_key;
  pub->acc->pkcs[pub->pkcs_index].
    public_key_free(&pub->acc->pkcs[pub->pkcs_index], pub->context);
}

SILC_PKCS_PRIVATE_KEY_FREE(silc_acc_pkcs_private_key_free)
{
  SilcAcceleratorPrivateKey prv = private_key;
  prv->acc->pkcs[prv->pkcs_index].
    private_key_free(&prv->acc->pkcs[prv->pkcs_index], prv->context);
}

SILC_PKCS_ENCRYPT(silc_acc_pkcs_encrypt)
{
  SilcAcceleratorPublicKey pub = public_key;

  /* Accelerate */
  return pub->acc->pkcs[pub->pkcs_index].encrypt(
		       &pub->acc->pkcs[pub->pkcs_index], pub->context, src,
		       src_len, rng, encrypt_cb, context);
}

SILC_PKCS_DECRYPT(silc_acc_pkcs_decrypt)
{
  SilcAcceleratorPrivateKey prv = private_key;

  /* Accelerate */
  return prv->acc->pkcs[prv->pkcs_index].decrypt(
		       &prv->acc->pkcs[prv->pkcs_index], prv->context, src,
		       src_len, decrypt_cb, context);
}

SILC_PKCS_SIGN(silc_acc_pkcs_sign)
{
  SilcAcceleratorPrivateKey prv = private_key;

  /* Accelerate */
  return prv->acc->pkcs[prv->pkcs_index].sign(
		       &prv->acc->pkcs[prv->pkcs_index], prv->context, src,
		       src_len, compute_hash, hash, sign_cb, context);
}

SILC_PKCS_VERIFY(silc_acc_pkcs_verify)
{
  SilcAcceleratorPublicKey pub = public_key;

  /* Accelerate */
  return pub->acc->pkcs[pub->pkcs_index].verify(
		       &pub->acc->pkcs[pub->pkcs_index], pub->context,
		       signature, signature_len, data, data_len, hash,
		       verify_cb, context);
}

/*************************** SILC Accelerator API ***************************/

/* Accelerate public key */

SilcPublicKey silc_acc_public_key(SilcAccelerator acc,
				  SilcPublicKey public_key)
{
  SilcPublicKey pubkey;
  SilcAcceleratorPublicKey acc_pubkey;
  const SilcPKCSAlgorithm *alg;
  int i;

  if (!acc || !public_key)
    return NULL;

  SILC_LOG_DEBUG(("Accelerate public key %p with accelerator %s",
		  public_key, acc->name));

  if (!acc->pkcs) {
    SILC_LOG_ERROR(("Accelerator '%s' does not support public key "
		    "acceleration", acc->name));
    return NULL;
  }

  if (silc_acc_get_public_key(NULL, public_key)) {
    SILC_LOG_DEBUG(("Pubilc key %p is already accelerated", public_key));
    return NULL;
  }

  /* Check that accelerator supports this public key algorithm */
  alg = silc_pkcs_get_algorithm(public_key);
  if (!alg)
    return NULL;
  for (i = 0; acc->pkcs[i].name; i++) {
    if ((!strcmp(acc->pkcs[i].name, alg->name) &&
	 !strcmp(acc->pkcs[i].scheme, alg->scheme)) ||
	!strcmp(acc->pkcs[i].name, "any")) {
      alg = NULL;
      break;
    }
  }
  if (alg) {
    SILC_LOG_DEBUG(("Accelerator %s does not support %s/%s acceleration",
		    acc->name, alg->name, alg->scheme));
    return NULL;
  }

  pubkey = silc_calloc(1, sizeof(*pubkey));
  if (!pubkey)
    return NULL;

  /* Allocate PKCS operations */
  pubkey->pkcs = silc_calloc(1, sizeof(*pubkey->pkcs));
  if (!pubkey->pkcs) {
    silc_free(pubkey);
    return NULL;
  }
  *pubkey->pkcs = silc_acc_pkcs;
  pubkey->pkcs->type = silc_pkcs_get_type(public_key);
  pubkey->alg = silc_pkcs_get_algorithm(public_key);

  /* Allocate accelerator public key */
  acc_pubkey = silc_calloc(1, sizeof(*acc_pubkey));
  if (!acc_pubkey) {
    silc_free(pubkey->pkcs);
    silc_free(pubkey);
    return NULL;
  }
  acc_pubkey->magic = SILC_ACC_KEY_MAGIC;
  acc_pubkey->accelerated = public_key;
  acc_pubkey->acc = acc;
  acc_pubkey->pkcs_index = i;

  /* Accelerate the public key.  Returns accelerator context. */
  if (!acc->pkcs->import_public_key(&acc->pkcs[i], public_key, 0,
				    &acc_pubkey->context)) {
    SILC_LOG_ERROR(("Error accelerating public key with accelerator '%s'",
		    acc->name));
    silc_free(acc_pubkey);
    silc_free(pubkey->pkcs);
    silc_free(pubkey);
    return NULL;
  }
  pubkey->public_key = acc_pubkey;

  SILC_LOG_DEBUG(("New accelerated public key %p", pubkey));

  return pubkey;
}

/* Accelerate private key */

SilcPrivateKey silc_acc_private_key(SilcAccelerator acc,
				    SilcPrivateKey private_key)
{
  SilcPrivateKey privkey;
  SilcAcceleratorPrivateKey acc_privkey;
  const SilcPKCSAlgorithm *alg;
  int i;

  if (!acc || !private_key)
    return NULL;

  SILC_LOG_DEBUG(("Accelerate private key %p with accelerator %s",
		  private_key, acc->name));

  if (!acc->pkcs) {
    SILC_LOG_ERROR(("Accelerator '%s' does not support private key "
		    "acceleration", acc->name));
    return NULL;
  }

  if (silc_acc_get_private_key(NULL, private_key)) {
    SILC_LOG_DEBUG(("Private key %p is already accelerated", private_key));
    return NULL;
  }

  /* Check that accelerator supports this private key algorithm */
  alg = silc_pkcs_get_algorithm(private_key);
  if (!alg)
    return NULL;
  for (i = 0; acc->pkcs[i].name; i++) {
    if ((!strcmp(acc->pkcs[i].name, alg->name) &&
	 !strcmp(acc->pkcs[i].scheme, alg->scheme)) ||
	!strcmp(acc->pkcs[i].name, "any")) {
      alg = NULL;
      break;
    }
  }
  if (alg) {
    SILC_LOG_DEBUG(("Accelerator %s does not support %s/%s acceleration",
		    acc->name, alg->name, alg->scheme));
    return NULL;
  }

  privkey = silc_calloc(1, sizeof(*privkey));
  if (!privkey)
    return NULL;

  /* Allocate PKCS operations */
  privkey->pkcs = silc_calloc(1, sizeof(*privkey->pkcs));
  if (!privkey->pkcs) {
    silc_free(privkey);
    return NULL;
  }
  *privkey->pkcs = silc_acc_pkcs;
  privkey->pkcs->type = silc_pkcs_get_type(private_key);
  privkey->alg = silc_pkcs_get_algorithm(private_key);

  /* Allocate accelerator public key */
  acc_privkey = silc_calloc(1, sizeof(*acc_privkey));
  if (!acc_privkey) {
    silc_free(privkey->pkcs);
    silc_free(privkey);
    return NULL;
  }
  acc_privkey->magic = SILC_ACC_KEY_MAGIC;
  acc_privkey->accelerated = private_key;
  acc_privkey->acc = acc;
  acc_privkey->pkcs_index = i;

  /* Accelerate the public key.  Returns accelerator context. */
  if (!acc->pkcs->import_private_key(&acc->pkcs[i], private_key, 0,
				     &acc_privkey->context)) {
    SILC_LOG_ERROR(("Error accelerating private key with accelerator '%s'",
		    acc->name));
    silc_free(acc_privkey);
    silc_free(privkey->pkcs);
    silc_free(privkey);
    return NULL;
  }
  privkey->private_key = acc_privkey;

  SILC_LOG_DEBUG(("New accelerated private key %p", privkey));

  return privkey;
}

/* Get associated public key */

SilcPublicKey silc_acc_get_public_key(SilcAccelerator acc,
				      SilcPublicKey public_key)
{
  SilcAcceleratorPublicKey pubkey;

  if (!public_key)
    return NULL;

  if (public_key->pkcs->get_algorithm != silc_acc_pkcs_get_algorithm)
    return NULL;

  pubkey = public_key->public_key;

  return pubkey->accelerated;
}

/* Get associated private key */

SilcPrivateKey silc_acc_get_private_key(SilcAccelerator acc,
					SilcPrivateKey private_key)
{
  SilcAcceleratorPrivateKey privkey;

  if (!private_key)
    return NULL;

  if (private_key->pkcs->get_algorithm != silc_acc_pkcs_get_algorithm)
    return NULL;

  privkey = private_key->private_key;

  return privkey->accelerated;
}
