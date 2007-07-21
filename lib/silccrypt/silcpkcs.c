/*

  silcpkcs.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

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
#include "silcpk_i.h"
#include "silcpkcs1_i.h"
#include "dsa.h"
#ifdef SILC_DIST_SSH
#include "silcssh_pkcs.h"
#endif /* SILC_DIST_SSH */

#ifndef SILC_SYMBIAN
/* Dynamically registered list of PKCS. */
SilcDList silc_pkcs_list = NULL;
SilcDList silc_pkcs_alg_list = NULL;
#define SILC_PKCS_LIST silc_pkcs_list
#define SILC_PKCS_ALG_LIST silc_pkcs_alg_list
#else
#define SILC_PKCS_LIST TRUE
#define SILC_PKCS_ALG_LIST TRUE
#endif /* SILC_SYMBIAN */

/* Static list of PKCS for silc_pkcs_register_default(). */
const SilcPKCSObject silc_default_pkcs[] =
{
  /* SILC PKCS */
  {
    SILC_PKCS_SILC,
    silc_pkcs_silc_get_algorithm,
    silc_pkcs_silc_import_public_key_file,
    silc_pkcs_silc_import_public_key,
    silc_pkcs_silc_export_public_key_file,
    silc_pkcs_silc_export_public_key,
    silc_pkcs_silc_public_key_bitlen,
    silc_pkcs_silc_public_key_copy,
    silc_pkcs_silc_public_key_compare,
    silc_pkcs_silc_public_key_free,
    silc_pkcs_silc_import_private_key_file,
    silc_pkcs_silc_import_private_key,
    silc_pkcs_silc_export_private_key_file,
    silc_pkcs_silc_export_private_key,
    silc_pkcs_silc_private_key_bitlen,
    silc_pkcs_silc_private_key_free,
    silc_pkcs_silc_encrypt,
    silc_pkcs_silc_decrypt,
    silc_pkcs_silc_sign,
    silc_pkcs_silc_verify,
  },

#ifdef SILC_DIST_SSH
  /* SSH2 PKCS */
  {
    SILC_PKCS_SSH2,
    silc_pkcs_ssh_get_algorithm,
    silc_pkcs_ssh_import_public_key_file,
    silc_pkcs_ssh_import_public_key,
    silc_pkcs_ssh_export_public_key_file,
    silc_pkcs_ssh_export_public_key,
    silc_pkcs_ssh_public_key_bitlen,
    silc_pkcs_ssh_public_key_copy,
    silc_pkcs_ssh_public_key_compare,
    silc_pkcs_ssh_public_key_free,
    silc_pkcs_ssh_import_private_key_file,
    silc_pkcs_ssh_import_private_key,
    silc_pkcs_ssh_export_private_key_file,
    silc_pkcs_ssh_export_private_key,
    silc_pkcs_ssh_private_key_bitlen,
    silc_pkcs_ssh_private_key_free,
    silc_pkcs_ssh_encrypt,
    silc_pkcs_ssh_decrypt,
    silc_pkcs_ssh_sign,
    silc_pkcs_ssh_verify,
  },
#endif /* SILC_DIST_SSH */

  {
    0, NULL, NULL, NULL, NULL, NULL,
       NULL, NULL, NULL, NULL, NULL
  }
};

/* Builtin PKCS algorithms */
const SilcPKCSAlgorithm silc_default_pkcs_alg[] =
{
  /* PKCS #1, Version 1.5 without hash OIDs */
  {
    "rsa",
    "pkcs1-no-oid",
    "sha1,md5",
    silc_pkcs1_generate_key,
    silc_pkcs1_import_public_key,
    silc_pkcs1_export_public_key,
    silc_pkcs1_public_key_bitlen,
    silc_pkcs1_public_key_copy,
    silc_pkcs1_public_key_compare,
    silc_pkcs1_public_key_free,
    silc_pkcs1_import_private_key,
    silc_pkcs1_export_private_key,
    silc_pkcs1_private_key_bitlen,
    silc_pkcs1_private_key_free,
    silc_pkcs1_encrypt,
    silc_pkcs1_decrypt,
    silc_pkcs1_sign_no_oid,
    silc_pkcs1_verify_no_oid
  },

  /* PKCS #1, Version 1.5 */
  {
    "rsa",
    "pkcs1",
    "sha1,md5",
    silc_pkcs1_generate_key,
    silc_pkcs1_import_public_key,
    silc_pkcs1_export_public_key,
    silc_pkcs1_public_key_bitlen,
    silc_pkcs1_public_key_copy,
    silc_pkcs1_public_key_compare,
    silc_pkcs1_public_key_free,
    silc_pkcs1_import_private_key,
    silc_pkcs1_export_private_key,
    silc_pkcs1_private_key_bitlen,
    silc_pkcs1_private_key_free,
    silc_pkcs1_encrypt,
    silc_pkcs1_decrypt,
    silc_pkcs1_sign,
    silc_pkcs1_verify
  },

  /* DSS */
  {
    "dsa",
    "dss",
    "sha1",
    silc_dsa_generate_key,
    silc_dsa_import_public_key,
    silc_dsa_export_public_key,
    silc_dsa_public_key_bitlen,
    silc_dsa_public_key_copy,
    silc_dsa_public_key_compare,
    silc_dsa_public_key_free,
    silc_dsa_import_private_key,
    silc_dsa_export_private_key,
    silc_dsa_private_key_bitlen,
    silc_dsa_private_key_free,
    silc_dsa_encrypt,
    silc_dsa_decrypt,
    silc_dsa_sign,
    silc_dsa_verify
  },

#ifdef SILC_DIST_SSH
  /* PKCS #1, Version 1.5 without hash OIDs, SSH2 style public keys */
  {
    "rsa",
    "ssh",
    "sha1",
    silc_pkcs1_generate_key,
    silc_ssh_rsa_import_public_key,
    silc_ssh_rsa_export_public_key,
    silc_pkcs1_public_key_bitlen,
    silc_pkcs1_public_key_copy,
    silc_pkcs1_public_key_compare,
    silc_pkcs1_public_key_free,
    silc_pkcs1_import_private_key,
    silc_pkcs1_export_private_key,
    silc_pkcs1_private_key_bitlen,
    silc_pkcs1_private_key_free,
    silc_pkcs1_encrypt,
    silc_pkcs1_decrypt,
    silc_pkcs1_sign,
    silc_pkcs1_verify
  },

  /* DSS, SSH2 style public keys */
  {
    "dsa",
    "ssh",
    "sha1",
    silc_dsa_generate_key,
    silc_ssh_dsa_import_public_key,
    silc_ssh_dsa_export_public_key,
    silc_dsa_public_key_bitlen,
    silc_dsa_public_key_copy,
    silc_dsa_public_key_compare,
    silc_dsa_public_key_free,
    silc_dsa_import_private_key,
    silc_dsa_export_private_key,
    silc_dsa_private_key_bitlen,
    silc_dsa_private_key_free,
    silc_dsa_encrypt,
    silc_dsa_decrypt,
    silc_dsa_sign,
    silc_dsa_verify
  },
#endif /* SILC_DIST_SSH */

  {
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL
  }
};

/* Register a new PKCS */

SilcBool silc_pkcs_register(const SilcPKCSObject *pkcs)
{
#ifndef SILC_SYMBIAN
  SilcPKCSObject *newpkcs;

  SILC_LOG_DEBUG(("Registering new PKCS"));

  /* Check if exists already */
  if (silc_pkcs_list) {
    SilcPKCSObject *entry;
    silc_dlist_start(silc_pkcs_list);
    while ((entry = silc_dlist_get(silc_pkcs_list)) != SILC_LIST_END) {
      if (entry->type == pkcs->type)
        return FALSE;
    }
  }

  newpkcs = silc_calloc(1, sizeof(*newpkcs));
  if (!newpkcs)
    return FALSE;
  *newpkcs = *pkcs;

  /* Add to list */
  if (silc_pkcs_list == NULL)
    silc_pkcs_list = silc_dlist_init();
  silc_dlist_add(silc_pkcs_list, newpkcs);

#endif /* SILC_SYMBIAN */
  return TRUE;
}

/* Unregister a PKCS */

SilcBool silc_pkcs_unregister(SilcPKCSObject *pkcs)
{
#ifndef SILC_SYMBIAN
  SilcPKCSObject *entry;

  SILC_LOG_DEBUG(("Unregistering PKCS"));

  if (!silc_pkcs_list)
    return FALSE;

  silc_dlist_start(silc_pkcs_list);
  while ((entry = silc_dlist_get(silc_pkcs_list)) != SILC_LIST_END) {
    if (pkcs == SILC_ALL_PKCS || entry == pkcs) {
      silc_dlist_del(silc_pkcs_list, entry);
      silc_free(entry);

      if (silc_dlist_count(silc_pkcs_list) == 0) {
	silc_dlist_uninit(silc_pkcs_list);
	silc_pkcs_list = NULL;
      }

      return TRUE;
    }
  }

#endif /* SILC_SYMBIAN */
  return FALSE;
}

/* Register algorithm */

SilcBool silc_pkcs_algorithm_register(const SilcPKCSAlgorithm *pkcs)
{
#ifndef SILC_SYMBIAN
  SilcPKCSAlgorithm *newalg;

  SILC_LOG_DEBUG(("Registering new PKCS algorithm %s",
		  pkcs->name));

  /* Check if exists already */
  if (silc_pkcs_alg_list) {
    SilcPKCSAlgorithm *entry;
    silc_dlist_start(silc_pkcs_alg_list);
    while ((entry = silc_dlist_get(silc_pkcs_alg_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, pkcs->name) &&
	  entry->scheme && pkcs->scheme &&
	  !strcmp(entry->scheme, pkcs->scheme))
        return FALSE;
    }
  }

  newalg = silc_calloc(1, sizeof(*newalg));
  if (!newalg)
    return FALSE;

  *newalg = *pkcs;
  newalg->name = strdup(pkcs->name);
  if (!newalg->name)
    return FALSE;
  if (pkcs->scheme) {
    newalg->scheme = strdup(pkcs->scheme);
    if (!newalg->scheme)
      return FALSE;
  }
  newalg->hash = strdup(pkcs->hash);
  if (!newalg->hash)
    return FALSE;

  /* Add to list */
  if (silc_pkcs_alg_list == NULL)
    silc_pkcs_alg_list = silc_dlist_init();
  silc_dlist_add(silc_pkcs_alg_list, newalg);

#endif /* SILC_SYMBIAN */
  return TRUE;
}

/* Unregister algorithm */

SilcBool silc_pkcs_algorithm_unregister(SilcPKCSAlgorithm *pkcs)
{
#ifndef SILC_SYMBIAN
  SilcPKCSAlgorithm*entry;

  SILC_LOG_DEBUG(("Unregistering PKCS algorithm"));

  if (!silc_pkcs_alg_list)
    return FALSE;

  silc_dlist_start(silc_pkcs_alg_list);
  while ((entry = silc_dlist_get(silc_pkcs_alg_list)) != SILC_LIST_END) {
    if (pkcs == SILC_ALL_PKCS_ALG || entry == pkcs) {
      silc_dlist_del(silc_pkcs_alg_list, entry);
      silc_free(entry->name);
      silc_free(entry->scheme);
      silc_free(entry->hash);
      silc_free(entry);

      if (silc_dlist_count(silc_pkcs_alg_list) == 0) {
	silc_dlist_uninit(silc_pkcs_alg_list);
	silc_pkcs_alg_list = NULL;
      }

      return TRUE;
    }
  }

#endif /* SILC_SYMBIAN */
  return FALSE;
}

/* Function that registers all the default PKCS and PKCS algorithms. */

SilcBool silc_pkcs_register_default(void)
{
  /* We use builtin PKCS and algorithms */
  return TRUE;
}

/* Unregister all PKCS and algorithms */

SilcBool silc_pkcs_unregister_all(void)
{
#ifndef SILC_SYMBIAN
  SilcPKCSObject *entry;
  SilcPKCSAlgorithm *alg;

  if (silc_pkcs_list) {
    silc_dlist_start(silc_pkcs_list);
    while ((entry = silc_dlist_get(silc_pkcs_list)) != SILC_LIST_END) {
      silc_pkcs_unregister(entry);
      if (!silc_pkcs_list)
	break;
    }
  }

  if (silc_pkcs_alg_list) {
    silc_dlist_start(silc_pkcs_alg_list);
    while ((alg = silc_dlist_get(silc_pkcs_alg_list)) != SILC_LIST_END) {
      silc_pkcs_algorithm_unregister(alg);
      if (!silc_pkcs_alg_list)
	break;
    }
  }

#endif /* SILC_SYMBIAN */
  return TRUE;
}

/* Returns comma separated list of supported PKCS algorithms */

char *silc_pkcs_get_supported(void)
{
  SilcPKCSAlgorithm *entry, *entry2;
  char *list = NULL;
  int i, len = 0;

#ifndef SILC_SYMBIAN
  if (silc_pkcs_alg_list) {
    silc_dlist_start(silc_pkcs_alg_list);
    while ((entry = silc_dlist_get(silc_pkcs_alg_list)) != SILC_LIST_END) {
      len += strlen(entry->name);
      list = silc_realloc(list, len + 1);
      if (!list)
	return NULL;

      memcpy(list + (len - strlen(entry->name)),
	     entry->name, strlen(entry->name));
      memcpy(list + len, ",", 1);
      len++;
    }
  }
#endif /* SILC_SYMBIAN */

  for (i = 0; silc_default_pkcs_alg[i].name; i++) {
    entry = (SilcPKCSAlgorithm *)&(silc_default_pkcs_alg[i]);

    if (silc_pkcs_alg_list) {
      silc_dlist_start(silc_pkcs_alg_list);
      while ((entry2 = silc_dlist_get(silc_pkcs_alg_list)) != SILC_LIST_END) {
	if (!strcmp(entry2->name, entry->name))
	  break;
      }
      if (entry2)
	continue;
    }

    len += strlen(entry->name);
    list = silc_realloc(list, len + 1);
    if (!list)
      return NULL;

    memcpy(list + (len - strlen(entry->name)),
	   entry->name, strlen(entry->name));
    memcpy(list + len, ",", 1);
    len++;
  }

  list[len - 1] = 0;

  return list;
}

/* Finds PKCS object */

const SilcPKCSObject *silc_pkcs_find_pkcs(SilcPKCSType type)
{
  SilcPKCSObject *entry;
  int i;

#ifndef SILC_SYMBIAN
  if (silc_pkcs_list) {
    silc_dlist_start(silc_pkcs_list);
    while ((entry = silc_dlist_get(silc_pkcs_list)) != SILC_LIST_END) {
      if (entry->type == type)
	return (const SilcPKCSObject *)entry;
    }
  }
#endif /* SILC_SYMBIAN */

  for (i = 0; silc_default_pkcs[i].type; i++) {
    entry = (SilcPKCSObject *)&(silc_default_pkcs[i]);
    if (entry->type == type)
      return (const SilcPKCSObject *)entry;
  }

  return NULL;
}

/* Finds PKCS algorithms object */

const SilcPKCSAlgorithm *silc_pkcs_find_algorithm(const char *algorithm,
						  const char *scheme)
{
  SilcPKCSAlgorithm *entry;
  int i;

#ifndef SILC_SYMBIAN
  if (silc_pkcs_alg_list) {
    silc_dlist_start(silc_pkcs_alg_list);
    while ((entry = silc_dlist_get(silc_pkcs_alg_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, algorithm) &&
	  (!scheme || !entry->scheme || !strcmp(entry->scheme, scheme)))
	return (const SilcPKCSAlgorithm *)entry;
    }
  }
#endif /* SILC_SYMBIAN */

  for (i = 0; silc_default_pkcs_alg[i].name; i++) {
    entry = (SilcPKCSAlgorithm *)&(silc_default_pkcs_alg[i]);
    if (!strcmp(entry->name, algorithm) &&
	(!scheme || !entry->scheme || !strcmp(entry->scheme, scheme)))
      return (const SilcPKCSAlgorithm *)entry;
  }

  return NULL;
}

/* Returns PKCS context */

const SilcPKCSObject *silc_pkcs_get_pkcs(void *key)
{
  SilcPublicKey public_key = key;
  return public_key->pkcs;
}

/* Returns PKCS algorithm context */

const SilcPKCSAlgorithm *silc_pkcs_get_algorithm(void *key)
{
  SilcPublicKey public_key = key;
  return public_key->alg;
}

/* Return algorithm name */

const char *silc_pkcs_get_name(void *key)
{
  const SilcPKCSAlgorithm *pkcs = silc_pkcs_get_algorithm(key);
  return pkcs->name;
}

/* Returns PKCS type */

SilcPKCSType silc_pkcs_get_type(void *key)
{
  SilcPublicKey public_key = key;
  return public_key->pkcs->type;
}

/* Allocates new public key from the key data */

SilcBool silc_pkcs_public_key_alloc(SilcPKCSType type,
				    unsigned char *key,
				    SilcUInt32 key_len,
				    SilcPublicKey *ret_public_key)
{
  const SilcPKCSObject *pkcs;
  SilcPublicKey public_key;

  if (!ret_public_key)
    return FALSE;

  /* Allocate public key context */
  public_key = silc_calloc(1, sizeof(*public_key));
  if (!public_key)
    return FALSE;

  pkcs = silc_pkcs_find_pkcs(type);
  public_key->pkcs = (SilcPKCSObject *)pkcs;
  if (!public_key->pkcs) {
    silc_free(public_key);
    return FALSE;
  }

  /* Import the PKCS public key */
  if (!pkcs->import_public_key(pkcs, NULL, key, key_len,
			       &public_key->public_key,
			       &public_key->alg)) {
    silc_free(public_key);
    return FALSE;
  }

  *ret_public_key = public_key;

  return TRUE;
}

/* Frees the public key */

void silc_pkcs_public_key_free(SilcPublicKey public_key)
{
  public_key->pkcs->public_key_free(public_key->pkcs, public_key->public_key);
  silc_free(public_key);
}

/* Exports public key */

unsigned char *silc_pkcs_public_key_encode(SilcStack stack,
					   SilcPublicKey public_key,
					   SilcUInt32 *ret_len)
{
  return public_key->pkcs->export_public_key(public_key->pkcs, stack,
					     public_key->public_key, ret_len);
}

/* Return key length */

SilcUInt32 silc_pkcs_public_key_get_len(SilcPublicKey public_key)
{
  return public_key->pkcs->public_key_bitlen(public_key->pkcs,
					     public_key->public_key);
}

/* Returns internal PKCS public key context */

void *silc_pkcs_public_key_get_pkcs(SilcPKCSType type,
				    SilcPublicKey public_key)
{
  if (public_key->pkcs->type != type)
    return NULL;
  return public_key->public_key;
}

/* Returns internal PKCS private key context */

void *silc_pkcs_private_key_get_pkcs(SilcPKCSType type,
				     SilcPrivateKey private_key)
{
  if (private_key->pkcs->type != type)
    return NULL;
  return private_key->private_key;
}

/* Allocates new private key from key data */

SilcBool silc_pkcs_private_key_alloc(SilcPKCSType type,
				     unsigned char *key,
				     SilcUInt32 key_len,
				     SilcPrivateKey *ret_private_key)
{
  const SilcPKCSObject *pkcs;
  SilcPrivateKey private_key;

  if (!ret_private_key)
    return FALSE;

  /* Allocate private key context */
  private_key = silc_calloc(1, sizeof(*private_key));
  if (!private_key)
    return FALSE;

  pkcs = silc_pkcs_find_pkcs(type);
  private_key->pkcs = (SilcPKCSObject *)pkcs;
  if (!private_key->pkcs) {
    silc_free(private_key);
    return FALSE;
  }

  /* Import the PKCS private key */
  if (!pkcs->import_private_key(pkcs, NULL, key, key_len,
				&private_key->private_key,
				&private_key->alg)) {
    silc_free(private_key);
    return FALSE;
  }

  *ret_private_key = private_key;

  return TRUE;
}

/* Return key length */

SilcUInt32 silc_pkcs_private_key_get_len(SilcPrivateKey private_key)
{
  return private_key->pkcs->private_key_bitlen(private_key->pkcs,
					       private_key->private_key);
}

/* Frees the private key */

void silc_pkcs_private_key_free(SilcPrivateKey private_key)
{
  private_key->pkcs->private_key_free(private_key->pkcs,
				      private_key->private_key);
  silc_free(private_key);
}

/* Encrypts */

SilcAsyncOperation silc_pkcs_encrypt(SilcPublicKey public_key,
				     unsigned char *src, SilcUInt32 src_len,
				     SilcRng rng,
				     SilcPKCSEncryptCb encrypt_cb,
				     void *context)
{
  return public_key->pkcs->encrypt(public_key->pkcs,
				   public_key->public_key, src, src_len,
				   rng, encrypt_cb, context);
}

/* Decrypts */

SilcAsyncOperation silc_pkcs_decrypt(SilcPrivateKey private_key,
				     unsigned char *src, SilcUInt32 src_len,
				     SilcPKCSDecryptCb decrypt_cb,
				     void *context)
{
  return private_key->pkcs->decrypt(private_key->pkcs,
				    private_key->private_key, src, src_len,
				    decrypt_cb, context);
}

/* Generates signature */

SilcAsyncOperation silc_pkcs_sign(SilcPrivateKey private_key,
				  unsigned char *src,
				  SilcUInt32 src_len,
				  SilcBool compute_hash,
				  SilcHash hash,
				  SilcRng rng,
				  SilcPKCSSignCb sign_cb,
				  void *context)
{
  return private_key->pkcs->sign(private_key->pkcs,
				 private_key->private_key, src, src_len,
				 compute_hash, hash, rng, sign_cb, context);
}

/* Verifies signature */

SilcAsyncOperation silc_pkcs_verify(SilcPublicKey public_key,
				    unsigned char *signature,
				    SilcUInt32 signature_len,
				    unsigned char *data,
				    SilcUInt32 data_len,
				    SilcHash hash,
				    SilcRng rng,
				    SilcPKCSVerifyCb verify_cb,
				    void *context)
{
  return public_key->pkcs->verify(public_key->pkcs,
				  public_key->public_key, signature,
				  signature_len, data, data_len, hash, rng,
				  verify_cb, context);
}

/* Compares two public keys and returns TRUE if they are same key, and
   FALSE if they are not same. */

SilcBool silc_pkcs_public_key_compare(SilcPublicKey key1, SilcPublicKey key2)
{
  if (key1->pkcs->type != key2->pkcs->type)
    return FALSE;

  return key1->pkcs->public_key_compare(key1->pkcs,
					key1->public_key, key2->public_key);
}

/* Copies the public key indicated by `public_key' and returns new allocated
   public key which is indentical to the `public_key'. */

SilcPublicKey silc_pkcs_public_key_copy(SilcPublicKey public_key)
{
  SilcPublicKey key = silc_calloc(1, sizeof(*key));
  if (!key)
    return NULL;

  key->pkcs = public_key->pkcs;
  key->public_key = public_key->pkcs->public_key_copy(public_key->pkcs,
						      public_key->public_key);
  if (!key->public_key) {
    silc_free(key);
    return NULL;
  }

  return key;
}

/* Loads any kind of public key */

SilcBool silc_pkcs_load_public_key(const char *filename,
				   SilcPKCSType type,
				   SilcPublicKey *ret_public_key)
{
  unsigned char *data;
  SilcUInt32 data_len;
  SilcPublicKey public_key;

  SILC_LOG_DEBUG(("Loading public key file '%s'", filename));

  if (!ret_public_key)
    return FALSE;

  data = silc_file_readfile(filename, &data_len, NULL);
  if (!data) {
    SILC_LOG_ERROR(("No such file: %s", filename));
    return FALSE;
  }

  /* Allocate public key context */
  *ret_public_key = public_key = silc_calloc(1, sizeof(*public_key));
  if (!public_key) {
    silc_free(data);
    return FALSE;
  }

  if (type == SILC_PKCS_ANY) {
    /* Try loading all types until one succeeds. */
    for (type = SILC_PKCS_SILC; type <= SILC_PKCS_SPKI; type++) {
      public_key->pkcs = (SilcPKCSObject *)silc_pkcs_find_pkcs(type);
      if (!public_key->pkcs)
	continue;

      if (public_key->pkcs->import_public_key_file(public_key->pkcs,
						   data, data_len,
						   SILC_PKCS_FILE_BASE64,
						   &public_key->public_key,
						   &public_key->alg)) {
	silc_free(data);
	return TRUE;
      }

      if (public_key->pkcs->import_public_key_file(public_key->pkcs,
						   data, data_len,
						   SILC_PKCS_FILE_BIN,
						   &public_key->public_key,
						   &public_key->alg)) {
	silc_free(data);
	return TRUE;
      }
    }
  } else {
    /* Load specific type */
    public_key->pkcs = (SilcPKCSObject *)silc_pkcs_find_pkcs(type);
    if (!public_key->pkcs) {
      silc_free(data);
      silc_free(public_key);
      *ret_public_key = NULL;
      SILC_LOG_ERROR(("Unsupported public key type"));
      return FALSE;
    }

    if (public_key->pkcs->import_public_key_file(public_key->pkcs,
						 data, data_len,
						 SILC_PKCS_FILE_BASE64,
						 &public_key->public_key,
						 &public_key->alg)) {
      silc_free(data);
      return TRUE;
    }

    if (public_key->pkcs->import_public_key_file(public_key->pkcs,
						 data, data_len,
						 SILC_PKCS_FILE_BIN,
						 &public_key->public_key,
						 &public_key->alg)) {
      silc_free(data);
      return TRUE;
    }
  }

  silc_free(data);
  silc_free(public_key);
  *ret_public_key = NULL;
  SILC_LOG_ERROR(("Unsupported public key type"));
  return FALSE;
}

/* Saves public key into a file */

SilcBool silc_pkcs_save_public_key(const char *filename,
				   SilcPublicKey public_key,
				   SilcPKCSFileEncoding encoding)
{
  unsigned char *data;
  SilcUInt32 data_len;
  SilcStack stack;

  stack = silc_stack_alloc(2048, silc_crypto_stack());

  /* Export the public key file */
  data = public_key->pkcs->export_public_key_file(public_key->pkcs,
						  stack,
						  public_key->public_key,
						  encoding, &data_len);
  if (!data) {
    silc_stack_free(stack);
    return FALSE;
  }

  /* Write to file */
  if (silc_file_writefile(filename, data, data_len)) {
    silc_sfree(stack, data);
    silc_stack_free(stack);
    return FALSE;
  }

  silc_sfree(stack, data);
  silc_stack_free(stack);
  return TRUE;
}

/* Loads any kind of private key */

SilcBool silc_pkcs_load_private_key(const char *filename,
				    const unsigned char *passphrase,
				    SilcUInt32 passphrase_len,
				    SilcPKCSType type,
				    SilcPrivateKey *ret_private_key)
{
  unsigned char *data;
  SilcUInt32 data_len;
  SilcPrivateKey private_key;

  SILC_LOG_DEBUG(("Loading private key file '%s'", filename));

  if (!ret_private_key)
    return FALSE;

  data = silc_file_readfile(filename, &data_len, NULL);
  if (!data) {
    SILC_LOG_ERROR(("No such file: %s", filename));
    return FALSE;
  }

  /* Allocate private key context */
  *ret_private_key = private_key = silc_calloc(1, sizeof(*private_key));
  if (!private_key) {
    silc_free(data);
    return FALSE;
  }

  if (type == SILC_PKCS_ANY) {
    /* Try loading all types until one succeeds. */
    for (type = SILC_PKCS_SILC; type <= SILC_PKCS_SPKI; type++) {
      private_key->pkcs = (SilcPKCSObject *)silc_pkcs_find_pkcs(type);
      if (!private_key->pkcs)
	continue;

      if (private_key->pkcs->import_private_key_file(
					      private_key->pkcs,
					      data, data_len,
					      passphrase,
					      passphrase_len,
					      SILC_PKCS_FILE_BIN,
					      &private_key->private_key,
					      &private_key->alg)) {
	silc_free(data);
	return TRUE;
      }

      if (private_key->pkcs->import_private_key_file(
					      private_key->pkcs,
					      data, data_len,
					      passphrase,
					      passphrase_len,
					      SILC_PKCS_FILE_BASE64,
					      &private_key->private_key,
					      &private_key->alg)) {
	silc_free(data);
	return TRUE;
      }
    }
  } else {
    /* Load specific type */
    private_key->pkcs = (SilcPKCSObject *)silc_pkcs_find_pkcs(type);
    if (!private_key->pkcs) {
      silc_free(data);
      silc_free(private_key);
      *ret_private_key = NULL;
      SILC_LOG_ERROR(("Unsupported private key type"));
      return FALSE;
    }

    if (private_key->pkcs->import_private_key_file(
					      private_key->pkcs,
					      data, data_len,
					      passphrase,
					      passphrase_len,
					      SILC_PKCS_FILE_BIN,
					      &private_key->private_key,
					      &private_key->alg)) {
      silc_free(data);
      return TRUE;
    }

    if (private_key->pkcs->import_private_key_file(
					      private_key->pkcs,
					      data, data_len,
					      passphrase,
					      passphrase_len,
					      SILC_PKCS_FILE_BASE64,
					      &private_key->private_key,
					      &private_key->alg)) {
      silc_free(data);
      return TRUE;
    }
  }

  silc_free(data);
  silc_free(private_key);
  *ret_private_key = NULL;
  return FALSE;
}

/* Saves private key into a file */

SilcBool silc_pkcs_save_private_key(const char *filename,
				    SilcPrivateKey private_key,
				    const unsigned char *passphrase,
				    SilcUInt32 passphrase_len,
				    SilcPKCSFileEncoding encoding,
				    SilcRng rng)
{
  unsigned char *data;
  SilcUInt32 data_len;
  SilcStack stack;

  stack = silc_stack_alloc(2048, silc_crypto_stack());

  /* Export the private key file */
  data = private_key->pkcs->export_private_key_file(private_key->pkcs, stack,
						    private_key->private_key,
						    passphrase,
						    passphrase_len,
						    encoding, rng, &data_len);
  if (!data) {
    silc_stack_free(stack);
    return FALSE;
  }

  /* Write to file */
  if (silc_file_writefile(filename, data, data_len)) {
    silc_sfree(stack, data);
    silc_stack_free(stack);
    return FALSE;
  }

  silc_sfree(stack, data);
  silc_stack_free(stack);
  return TRUE;
}

/* Hash public key of any type. */

SilcUInt32 silc_hash_public_key(void *key, void *user_context)
{
  SilcPublicKey public_key = key;
  unsigned char *pk;
  SilcUInt32 pk_len;
  SilcUInt32 hash = 0;
  SilcStack stack = NULL;

  if (silc_crypto_stack())
    stack = silc_stack_alloc(2048, silc_crypto_stack());

  pk = silc_pkcs_public_key_encode(stack, public_key, &pk_len);
  if (!pk) {
    silc_stack_free(stack);
    return hash;
  }

  hash = silc_hash_data(pk, SILC_32_TO_PTR(pk_len));

  silc_sfree(stack, pk);
  silc_stack_free(stack);

  return hash;
}

/* Compares two SILC Public keys. It may be used as SilcHashTable
   comparison function. */

SilcBool silc_hash_public_key_compare(void *key1, void *key2,
				      void *user_context)
{
  return silc_pkcs_public_key_compare(key1, key2);
}
