/*

  silcpkcs.c

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
/* $Id$ */

#include "silc.h"
#include "silcpk_i.h"
#include "silcpkcs1_i.h"

#ifndef SILC_EPOC
/* Dynamically registered list of PKCS. */
SilcDList silc_pkcs_list = NULL;
SilcDList silc_pkcs_alg_list = NULL;
#define SILC_PKCS_LIST silc_pkcs_list
#define SILC_PKCS_ALG_LIST silc_pkcs_alg_list
#else
#define SILC_PKCS_LIST TRUE
#define SILC_PKCS_ALG_LIST TRUE
#endif /* SILC_EPOC */

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

  {
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL,
    NULL, NULL
  }
};

/* Register a new PKCS into SILC. */

SilcBool silc_pkcs_register(const SilcPKCSObject *pkcs)
{
#ifndef SILC_EPOC
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

#endif /* SILC_EPOC */
  return TRUE;
}

/* Unregister a PKCS from the SILC. */

SilcBool silc_pkcs_unregister(SilcPKCSObject *pkcs)
{
#ifndef SILC_EPOC
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

#endif /* SILC_EPOC */
  return FALSE;
}

/* Register algorithm */

SilcBool silc_pkcs_algorithm_register(const SilcPKCSAlgorithm *pkcs)
{
#ifndef SILC_EPOC
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

#endif /* SILC_EPOC */
  return TRUE;
}

/* Unregister algorithm */

SilcBool silc_pkcs_algorithm_unregister(SilcPKCSAlgorithm *pkcs)
{
#ifndef SILC_EPOC
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

#endif /* SILC_EPOC */
  return FALSE;
}

/* Function that registers all the default PKCS and PKCS algorithms. */

SilcBool silc_pkcs_register_default(void)
{
#ifndef SILC_EPOC
  int i;

  for (i = 0; silc_default_pkcs[i].type; i++)
    silc_pkcs_register(&(silc_default_pkcs[i]));

  for (i = 0; silc_default_pkcs_alg[i].name; i++)
    silc_pkcs_algorithm_register(&(silc_default_pkcs_alg[i]));

#endif /* SILC_EPOC */
  return TRUE;
}

SilcBool silc_pkcs_unregister_all(void)
{
#ifndef SILC_EPOC
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

#endif /* SILC_EPOC */
  return TRUE;
}

/* Returns comma separated list of supported PKCS algorithms */

char *silc_pkcs_get_supported(void)
{
  SilcPKCSAlgorithm *entry;
  char *list = NULL;
  int len = 0;

#ifndef SILC_EPOC
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
#else
  {
    int i;
    for (i = 0; silc_default_pkcs_alg[i].name; i++) {
      entry = (SilcPKCSAlgorithm *)&(silc_default_pkcs_alg[i]);
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
#endif /* SILC_EPOC */

  list[len - 1] = 0;

  return list;
}

/* Finds PKCS object */

const SilcPKCSObject *silc_pkcs_find_pkcs(SilcPKCSType type)
{
  SilcPKCSObject *entry;

#ifndef SILC_EPOC
  if (silc_pkcs_list) {
    silc_dlist_start(silc_pkcs_list);
    while ((entry = silc_dlist_get(silc_pkcs_list)) != SILC_LIST_END) {
      if (entry->type == type)
	return (const SilcPKCSObject *)entry;
    }
  }
#else
  {
    int i;
    for (i = 0; silc_default_pkcs[i].name; i++) {
      entry = (SilcPKCSObject *)&(silc_default_pkcs[i]);
      if (entry->type == type)
	return (const SilcPKCSObject *)entry;
    }
  }
#endif /* SILC_EPOC */

  return NULL;
}

/* Finds PKCS algorithms object */

const SilcPKCSAlgorithm *silc_pkcs_find_algorithm(const char *algorithm,
						  const char *scheme)
{
  SilcPKCSAlgorithm *entry;

#ifndef SILC_EPOC
  if (silc_pkcs_alg_list) {
    silc_dlist_start(silc_pkcs_alg_list);
    while ((entry = silc_dlist_get(silc_pkcs_alg_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, algorithm) &&
	  (!scheme || !entry->scheme || !strcmp(entry->scheme, scheme)))
	return (const SilcPKCSAlgorithm *)entry;
    }
  }
#else
  {
    int i;
    for (i = 0; silc_default_pkcs_alg[i].name; i++) {
      entry = (SilcPKCSAlgorithm *)&(silc_default_pkcs_alg[i]);
      if (!strcmp(entry->name, algorithm) &&
	  (!scheme || !entry->scheme || !strcmp(entry->scheme, scheme)))
	return (const SilcPKCSAlgorithm *)entry;
    }
  }
#endif /* SILC_EPOC */

  return NULL;
}

/* Returns PKCS context */

const SilcPKCSObject *silc_pkcs_get_pkcs(SilcPublicKey public_key)
{
  return public_key->pkcs;
}

/* Returns PKCS algorithm context */

const SilcPKCSAlgorithm *silc_pkcs_get_algorithm(SilcPublicKey public_key)
{
  return public_key->pkcs->get_algorithm(public_key->public_key);
}

/* Return algorithm name */

const char *silc_pkcs_get_name(SilcPublicKey public_key)
{
  const SilcPKCSAlgorithm *pkcs = silc_pkcs_get_algorithm(public_key);
  return pkcs->name;
}

/* Returns PKCS type */

SilcPKCSType silc_pkcs_get_type(SilcPublicKey public_key)
{
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

  public_key->pkcs = pkcs = silc_pkcs_find_pkcs(type);
  if (!public_key->pkcs) {
    silc_free(public_key);
    return FALSE;
  }

  /* Import the PKCS public key */
  if (!pkcs->import_public_key(key, key_len, &public_key->public_key)) {
    silc_free(public_key);
    return FALSE;
  }

  *ret_public_key = public_key;

  return TRUE;
}

/* Frees the public key */

void silc_pkcs_public_key_free(SilcPublicKey public_key)
{
  public_key->pkcs->public_key_free(public_key->public_key);
}

/* Exports public key */

unsigned char *silc_pkcs_public_key_encode(SilcPublicKey public_key,
					   SilcUInt32 *ret_len)
{
  return public_key->pkcs->export_public_key(public_key->public_key,
					     ret_len);
}

/* Return key length */

SilcUInt32 silc_pkcs_public_key_get_len(SilcPublicKey public_key)
{
  return public_key->pkcs->public_key_bitlen(public_key->public_key);
}

/* Returns internal PKCS public key context */

void *silc_pkcs_get_context(SilcPKCSType type, SilcPublicKey public_key)
{
  if (public_key->pkcs->type != type)
    return FALSE;
  return public_key->public_key;
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

  private_key->pkcs = pkcs = silc_pkcs_find_pkcs(type);
  if (!private_key->pkcs) {
    silc_free(private_key);
    return FALSE;
  }

  /* Import the PKCS private key */
  if (!pkcs->import_private_key(key, key_len, &private_key->private_key)) {
    silc_free(private_key);
    return FALSE;
  }

  *ret_private_key = private_key;

  return TRUE;
}

/* Return key length */

SilcUInt32 silc_pkcs_private_key_get_len(SilcPrivateKey private_key)
{
  return private_key->pkcs->private_key_bitlen(private_key->private_key);
}

/* Frees the private key */

void silc_pkcs_private_key_free(SilcPrivateKey private_key)
{
  private_key->pkcs->private_key_free(private_key->private_key);
}

/* Encrypts */

SilcBool silc_pkcs_encrypt(SilcPublicKey public_key,
			   unsigned char *src, SilcUInt32 src_len,
			   unsigned char *dst, SilcUInt32 dst_size,
			   SilcUInt32 *dst_len)
{
  return public_key->pkcs->encrypt(public_key->public_key, src, src_len,
				   dst, dst_size, dst_len);
}

/* Decrypts */

SilcBool silc_pkcs_decrypt(SilcPrivateKey private_key,
			   unsigned char *src, SilcUInt32 src_len,
			   unsigned char *dst, SilcUInt32 dst_size,
			   SilcUInt32 *dst_len)
{
  return private_key->pkcs->decrypt(private_key->private_key, src, src_len,
				    dst, dst_size, dst_len);
}

/* Generates signature */

SilcBool silc_pkcs_sign(SilcPrivateKey private_key,
			unsigned char *src, SilcUInt32 src_len,
			unsigned char *dst, SilcUInt32 dst_size,
			SilcUInt32 *dst_len, SilcHash hash)
{
  return private_key->pkcs->sign(private_key->private_key, src, src_len,
				 dst, dst_size, dst_len, hash);
}

/* Verifies signature */

SilcBool silc_pkcs_verify(SilcPublicKey public_key,
			  unsigned char *signature,
			  SilcUInt32 signature_len,
			  unsigned char *data,
			  SilcUInt32 data_len, SilcHash hash)
{
  return public_key->pkcs->verify(public_key->public_key, signature,
				  signature_len, data, data_len, hash);
}

/* Compares two public keys and returns TRUE if they are same key, and
   FALSE if they are not same. */

SilcBool silc_pkcs_public_key_compare(SilcPublicKey key1, SilcPublicKey key2)
{
  if (key1->pkcs->type != key2->pkcs->type)
    return FALSE;

  return key1->pkcs->public_key_compare(key1->public_key, key2->public_key);
}

/* Copies the public key indicated by `public_key' and returns new allocated
   public key which is indentical to the `public_key'. */

SilcPublicKey silc_pkcs_public_key_copy(SilcPublicKey public_key)
{
  SilcPublicKey key = silc_calloc(1, sizeof(*key));
  if (!key)
    return NULL;

  key->pkcs = public_key->pkcs;
  key->public_key = public_key->pkcs->public_key_copy(public_key->public_key);
  if (!key->public_key) {
    silc_free(key);
    return NULL;
  }

  return key;
}

/* Loads any kind of public key */

SilcBool silc_pkcs_load_public_key(const char *filename,
				   SilcPublicKey *ret_public_key)
{
  unsigned char *data;
  SilcUInt32 data_len;
  SilcPublicKey public_key;
  SilcPKCSType type;

  SILC_LOG_DEBUG(("Loading public key file '%s'", filename));

  if (!ret_public_key)
    return FALSE;

  data = silc_file_readfile(filename, &data_len);
  if (!data)
    return FALSE;

  /* Allocate public key context */
  *ret_public_key = public_key = silc_calloc(1, sizeof(*public_key));
  if (!public_key) {
    silc_free(data);
    return FALSE;
  }

  /* Try loading all types until one succeeds. */
  for (type = SILC_PKCS_SILC; type <= SILC_PKCS_SPKI; type++) {
    public_key->pkcs = silc_pkcs_find_pkcs(type);
    if (!public_key->pkcs)
      continue;

    if (public_key->pkcs->import_public_key_file(data, data_len,
						 SILC_PKCS_FILE_BASE64,
						 &public_key->public_key))
      return TRUE;

    if (public_key->pkcs->import_public_key_file(data, data_len,
						 SILC_PKCS_FILE_BIN,
						 &public_key->public_key))
      return TRUE;
  }

  silc_free(data);
  silc_free(public_key);
  return FALSE;
}

/* Saves public key into a file */

SilcBool silc_pkcs_save_public_key(const char *filename,
				   SilcPublicKey public_key,
				   SilcPKCSFileEncoding encoding)
{
  unsigned char *data;
  SilcUInt32 data_len;

  /* Export the public key file */
  data = public_key->pkcs->export_public_key_file(public_key->public_key,
						  encoding, &data_len);
  if (!data)
    return FALSE;

  /* Write to file */
  if (silc_file_writefile(filename, data, data_len)) {
    silc_free(data);
    return FALSE;
  }

  silc_free(data);
  return TRUE;
}

/* Loads any kind of private key */

SilcBool silc_pkcs_load_private_key(const char *filename,
				    const unsigned char *passphrase,
				    SilcUInt32 passphrase_len,
				    SilcPrivateKey *ret_private_key)
{
  unsigned char *data;
  SilcUInt32 data_len;
  SilcPrivateKey private_key;
  SilcPKCSType type;

  SILC_LOG_DEBUG(("Loading private key file '%s'", filename));

  if (!ret_private_key)
    return FALSE;

  data = silc_file_readfile(filename, &data_len);
  if (!data)
    return FALSE;

  /* Allocate private key context */
  *ret_private_key = private_key = silc_calloc(1, sizeof(*private_key));
  if (!private_key) {
    silc_free(data);
    return FALSE;
  }

  /* Try loading all types until one succeeds. */
  for (type = SILC_PKCS_SILC; type <= SILC_PKCS_SPKI; type++) {
    private_key->pkcs = silc_pkcs_find_pkcs(type);
    if (!private_key->pkcs)
      continue;

    if (private_key->pkcs->import_private_key_file(data, data_len,
						   passphrase,
						   passphrase_len,
						   SILC_PKCS_FILE_BIN,
						   &private_key->private_key))
      return TRUE;

    if (private_key->pkcs->import_private_key_file(data, data_len,
						   passphrase,
						   passphrase_len,
						   SILC_PKCS_FILE_BASE64,
						   &private_key->private_key))
      return TRUE;
  }

  silc_free(data);
  silc_free(private_key);
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

  /* Export the private key file */
  data = private_key->pkcs->export_private_key_file(private_key->private_key,
						    passphrase,
						    passphrase_len,
						    encoding, rng, &data_len);
  if (!data)
    return FALSE;

  /* Write to file */
  if (silc_file_writefile(filename, data, data_len)) {
    silc_free(data);
    return FALSE;
  }

  silc_free(data);
  return TRUE;
}
