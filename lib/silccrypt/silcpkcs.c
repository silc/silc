/*

  silcpkcs.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"

#include "rsa.h"

/* The main SILC PKCS structure. */
struct SilcPKCSStruct {
  void *context;		/* Algorithm internal context */
  SilcPKCSObject *pkcs;		/* Algorithm implementation */
  SilcUInt32 key_len;		/* Key length in bits */
};

#ifndef SILC_EPOC
/* Dynamically registered list of PKCS. */
SilcDList silc_pkcs_list = NULL;
#define SILC_PKCS_LIST silc_pkcs_list
#else
#define SILC_PKCS_LIST TRUE
#endif /* SILC_EPOC */

/* Static list of PKCS for silc_pkcs_register_default(). */
const SilcPKCSObject silc_default_pkcs[] =
{
  /* RSA with PKCS #1 (Uses directly routines from Raw RSA operations) */
  { "rsa",
    silc_rsa_init, silc_rsa_clear_keys, silc_rsa_get_public_key,
    silc_rsa_get_private_key, silc_rsa_set_public_key,
    silc_rsa_set_private_key, silc_rsa_context_len,
    silc_pkcs1_encrypt, silc_pkcs1_decrypt,
    silc_pkcs1_sign, silc_pkcs1_verify },

  /* Raw RSA operations */
  { "rsa-raw",
    silc_rsa_init, silc_rsa_clear_keys, silc_rsa_get_public_key,
    silc_rsa_get_private_key, silc_rsa_set_public_key,
    silc_rsa_set_private_key, silc_rsa_context_len,
    silc_rsa_encrypt, silc_rsa_decrypt,
    silc_rsa_sign, silc_rsa_verify },

  { NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL }
};

/* Register a new PKCS into SILC. This is used at the initialization of
   the SILC. */

SilcBool silc_pkcs_register(const SilcPKCSObject *pkcs)
{
#ifndef SILC_EPOC
  SilcPKCSObject *new;

  SILC_LOG_DEBUG(("Registering new PKCS `%s'", pkcs->name));

  /* Check if exists already */
  if (silc_pkcs_list) {
    SilcPKCSObject *entry;
    silc_dlist_start(silc_pkcs_list);
    while ((entry = silc_dlist_get(silc_pkcs_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, pkcs->name))
        return FALSE;
    }
  }

  new = silc_calloc(1, sizeof(*new));
  new->name = strdup(pkcs->name);
  new->init = pkcs->init;
  new->clear_keys = pkcs->clear_keys;
  new->get_public_key = pkcs->get_public_key;
  new->get_private_key = pkcs->get_private_key;
  new->set_public_key = pkcs->set_public_key;
  new->set_private_key = pkcs->set_private_key;
  new->context_len = pkcs->context_len;
  new->encrypt = pkcs->encrypt;
  new->decrypt = pkcs->decrypt;
  new->sign = pkcs->sign;
  new->verify = pkcs->verify;

  /* Add to list */
  if (silc_pkcs_list == NULL)
    silc_pkcs_list = silc_dlist_init();
  silc_dlist_add(silc_pkcs_list, new);

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
      silc_free(entry->name);
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

/* Function that registers all the default PKCS (all builtin PKCS).
   The application may use this to register the default PKCS if specific
   PKCS in any specific order is not wanted. */

SilcBool silc_pkcs_register_default(void)
{
#ifndef SILC_EPOC
  int i;

  for (i = 0; silc_default_pkcs[i].name; i++)
    silc_pkcs_register(&(silc_default_pkcs[i]));

#endif /* SILC_EPOC */
  return TRUE;
}

SilcBool silc_pkcs_unregister_all(void)
{
#ifndef SILC_EPOC
  SilcPKCSObject *entry;

  if (!silc_pkcs_list)
    return FALSE;

  silc_dlist_start(silc_pkcs_list);
  while ((entry = silc_dlist_get(silc_pkcs_list)) != SILC_LIST_END) {
    silc_pkcs_unregister(entry);
    if (!silc_pkcs_list)
      break;
  }
#endif /* SILC_EPOC */
  return TRUE;
}

/* Allocates a new SilcPKCS object. The new allocated object is returned
   to the 'new_pkcs' argument. */

SilcBool silc_pkcs_alloc(const unsigned char *name, SilcPKCS *new_pkcs)
{
  SilcPKCSObject *entry = NULL;

  SILC_LOG_DEBUG(("Allocating new PKCS object"));

#ifndef SILC_EPOC
  if (silc_pkcs_list) {
    silc_dlist_start(silc_pkcs_list);
    while ((entry = silc_dlist_get(silc_pkcs_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, name))
	break;
    }
  }
#else
  {
    /* On EPOC which don't have globals we check our constant hash list. */
    int i;
    for (i = 0; silc_default_pkcs[i].name; i++) {
      if (!strcmp(silc_default_pkcs[i].name, name)) {
	entry = (SilcPKCSObject *)&(silc_default_pkcs[i]);
	break;
      }
    }
  }
#endif /* SILC_EPOC */

  if (entry) {
    *new_pkcs = silc_calloc(1, sizeof(**new_pkcs));
    (*new_pkcs)->pkcs = entry;
    (*new_pkcs)->context = silc_calloc(1, entry->context_len());
    return TRUE;
  }

  return FALSE;
}

/* Free's the PKCS object */

void silc_pkcs_free(SilcPKCS pkcs)
{
  if (pkcs) {
    pkcs->pkcs->clear_keys(pkcs->context);
    silc_free(pkcs->context);
  }
  silc_free(pkcs);
}

/* Return TRUE if PKCS algorithm `name' is supported. */

SilcBool silc_pkcs_is_supported(const unsigned char *name)
{
#ifndef SILC_EPOC
  SilcPKCSObject *entry;

  if (silc_pkcs_list) {
    silc_dlist_start(silc_pkcs_list);
    while ((entry = silc_dlist_get(silc_pkcs_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, name))
	return TRUE;
    }
  }
#else
  {
    int i;
    for (i = 0; silc_default_pkcs[i].name; i++)
      if (!strcmp(silc_default_pkcs[i].name, name))
	return TRUE;
  }
#endif /* SILC_EPOC */
  return FALSE;
}

/* Returns comma separated list of supported PKCS algorithms */

char *silc_pkcs_get_supported(void)
{
  SilcPKCSObject *entry;
  char *list = NULL;
  int len = 0;

#ifndef SILC_EPOC
  if (silc_pkcs_list) {
    silc_dlist_start(silc_pkcs_list);
    while ((entry = silc_dlist_get(silc_pkcs_list)) != SILC_LIST_END) {
      len += strlen(entry->name);
      list = silc_realloc(list, len + 1);

      memcpy(list + (len - strlen(entry->name)),
	     entry->name, strlen(entry->name));
      memcpy(list + len, ",", 1);
      len++;
    }
  }
#else
  {
    int i;
    for (i = 0; silc_default_pkcs[i].name; i++) {
      entry = (SilcPKCSObject *)&(silc_default_pkcs[i]);
      len += strlen(entry->name);
      list = silc_realloc(list, len + 1);

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

/* Generate new key pair into the `pkcs' context. */

SilcBool silc_pkcs_generate_key(SilcPKCS pkcs, SilcUInt32 bits_key_len,
			    SilcRng rng)
{
  SilcBool ret = pkcs->pkcs->init(pkcs->context, bits_key_len, rng);
  if (ret)
    pkcs->key_len = bits_key_len;
  return ret;
}

/* Returns the length of the key */

SilcUInt32 silc_pkcs_get_key_len(SilcPKCS pkcs)
{
  return pkcs->key_len;
}

const char *silc_pkcs_get_name(SilcPKCS pkcs)
{
  return pkcs->pkcs->name;
}

/* Returns SILC style public key */

unsigned char *silc_pkcs_get_public_key(SilcPKCS pkcs, SilcUInt32 *len)
{
  return pkcs->pkcs->get_public_key(pkcs->context, len);
}

/* Returns SILC style private key */

unsigned char *silc_pkcs_get_private_key(SilcPKCS pkcs, SilcUInt32 *len)
{
  return pkcs->pkcs->get_private_key(pkcs->context, len);
}

/* Sets public key from SilcPublicKey. */

SilcUInt32 silc_pkcs_public_key_set(SilcPKCS pkcs, SilcPublicKey public_key)
{
  pkcs->key_len = pkcs->pkcs->set_public_key(pkcs->context, public_key->pk,
					     public_key->pk_len);
  return pkcs->key_len;
}

/* Sets public key from data. */

SilcUInt32 silc_pkcs_public_key_data_set(SilcPKCS pkcs, unsigned char *pk,
				     SilcUInt32 pk_len)
{
  pkcs->key_len = pkcs->pkcs->set_public_key(pkcs->context, pk, pk_len);
  return pkcs->key_len;
}

/* Sets private key from SilcPrivateKey. */

SilcUInt32 silc_pkcs_private_key_set(SilcPKCS pkcs, SilcPrivateKey private_key)
{
  SilcUInt32 key_len;
  key_len = pkcs->pkcs->set_private_key(pkcs->context, private_key->prv,
					private_key->prv_len);
  if (!pkcs->key_len)
    pkcs->key_len = key_len;
  return pkcs->key_len;
}

/* Sets private key from data. */

SilcUInt32 silc_pkcs_private_key_data_set(SilcPKCS pkcs, unsigned char *prv,
					  SilcUInt32 prv_len)
{
  SilcUInt32 key_len;
  key_len = pkcs->pkcs->set_private_key(pkcs->context, prv, prv_len);
  if (!pkcs->key_len)
    pkcs->key_len = key_len;
  return pkcs->key_len;
}

/* Encrypts */

SilcBool silc_pkcs_encrypt(SilcPKCS pkcs, unsigned char *src, SilcUInt32 src_len,
		       unsigned char *dst, SilcUInt32 *dst_len)
{
  return pkcs->pkcs->encrypt(pkcs->context, src, src_len, dst, dst_len);
}

/* Decrypts */

SilcBool silc_pkcs_decrypt(SilcPKCS pkcs, unsigned char *src, SilcUInt32 src_len,
		       unsigned char *dst, SilcUInt32 *dst_len)
{
  return pkcs->pkcs->decrypt(pkcs->context, src, src_len, dst, dst_len);
}

/* Generates signature */

SilcBool silc_pkcs_sign(SilcPKCS pkcs, unsigned char *src, SilcUInt32 src_len,
		    unsigned char *dst, SilcUInt32 *dst_len)
{
  return pkcs->pkcs->sign(pkcs->context, src, src_len, dst, dst_len);
}

/* Verifies signature */

SilcBool silc_pkcs_verify(SilcPKCS pkcs, unsigned char *signature,
		      SilcUInt32 signature_len, unsigned char *data,
		      SilcUInt32 data_len)
{
  return pkcs->pkcs->verify(pkcs->context, signature, signature_len,
			    data, data_len);
}

/* Generates signature with hash. The hash is signed. */

SilcBool silc_pkcs_sign_with_hash(SilcPKCS pkcs, SilcHash hash,
			      unsigned char *src, SilcUInt32 src_len,
			      unsigned char *dst, SilcUInt32 *dst_len)
{
  unsigned char hashr[SILC_HASH_MAXLEN];
  SilcUInt32 hash_len;
  int ret;

  silc_hash_make(hash, src, src_len, hashr);
  hash_len = silc_hash_len(hash);

  SILC_LOG_HEXDUMP(("Hash"), hashr, hash_len);

  ret = pkcs->pkcs->sign(pkcs->context, hashr, hash_len, dst, dst_len);
  memset(hashr, 0, sizeof(hashr));

  return ret;
}

/* Verifies signature with hash. The `data' is hashed and verified against
   the `signature'. */

SilcBool silc_pkcs_verify_with_hash(SilcPKCS pkcs, SilcHash hash,
				unsigned char *signature,
				SilcUInt32 signature_len,
				unsigned char *data,
				SilcUInt32 data_len)
{
  unsigned char hashr[SILC_HASH_MAXLEN];
  SilcUInt32 hash_len;
  int ret;

  silc_hash_make(hash, data, data_len, hashr);
  hash_len = silc_hash_len(hash);

  SILC_LOG_HEXDUMP(("Hash"), hashr, hash_len);

  ret = pkcs->pkcs->verify(pkcs->context, signature, signature_len,
			   hashr, hash_len);
  memset(hashr, 0, sizeof(hashr));

  return ret;
}

/* Encodes and returns SILC public key identifier. If some of the
   arguments is NULL those are not encoded into the identifier string.
   Protocol says that at least username and host must be provided. */

char *silc_pkcs_encode_identifier(char *username, char *host, char *realname,
				  char *email, char *org, char *country)
{
  SilcBuffer buf;
  char *identifier;
  SilcUInt32 len, tlen = 0;

  if (!username || !host)
    return NULL;

  len = (username ? strlen(username) : 0) +
	(host     ? strlen(host)     : 0) +
	(realname ? strlen(realname) : 0) +
	(email    ? strlen(email)    : 0) +
	(org      ? strlen(org)      : 0) +
	(country  ? strlen(country)  : 0);

  if (len < 3)
    return NULL;

  len += 3 + 5 + 5 + 4 + 4 + 4;
  buf = silc_buffer_alloc(len);
  silc_buffer_pull_tail(buf, len);

  if (username) {
    silc_buffer_format(buf,
		       SILC_STR_UI32_STRING("UN="),
		       SILC_STR_UI32_STRING(username),
		       SILC_STR_END);
    silc_buffer_pull(buf, 3 + strlen(username));
    tlen = 3 + strlen(username);
  }

  if (host) {
    silc_buffer_format(buf,
		       SILC_STR_UI32_STRING(", "),
		       SILC_STR_UI32_STRING("HN="),
		       SILC_STR_UI32_STRING(host),
		       SILC_STR_END);
    silc_buffer_pull(buf, 5 + strlen(host));
    tlen += 5 + strlen(host);
  }

  if (realname) {
    silc_buffer_format(buf,
		       SILC_STR_UI32_STRING(", "),
		       SILC_STR_UI32_STRING("RN="),
		       SILC_STR_UI32_STRING(realname),
		       SILC_STR_END);
    silc_buffer_pull(buf, 5 + strlen(realname));
    tlen += 5 + strlen(realname);
  }

  if (email) {
    silc_buffer_format(buf,
		       SILC_STR_UI32_STRING(", "),
		       SILC_STR_UI32_STRING("E="),
		       SILC_STR_UI32_STRING(email),
		       SILC_STR_END);
    silc_buffer_pull(buf, 4 + strlen(email));
    tlen += 4 + strlen(email);
  }

  if (org) {
    silc_buffer_format(buf,
		       SILC_STR_UI32_STRING(", "),
		       SILC_STR_UI32_STRING("O="),
		       SILC_STR_UI32_STRING(org),
		       SILC_STR_END);
    silc_buffer_pull(buf, 4 + strlen(org));
    tlen += 4 + strlen(org);
  }

  if (country) {
    silc_buffer_format(buf,
		       SILC_STR_UI32_STRING(", "),
		       SILC_STR_UI32_STRING("C="),
		       SILC_STR_UI32_STRING(country),
		       SILC_STR_END);
    silc_buffer_pull(buf, 4 + strlen(country));
    tlen += 4 + strlen(country);
  }

  silc_buffer_push(buf, buf->data - buf->head);
  identifier = silc_calloc(tlen + 1, sizeof(*identifier));
  memcpy(identifier, buf->data, tlen);
  silc_buffer_free(buf);

  return identifier;
}

/* Decodes the provided `identifier' and returns allocated context for
   the identifier. */

SilcPublicKeyIdentifier silc_pkcs_decode_identifier(char *identifier)
{
  SilcPublicKeyIdentifier ident;
  char *cp, *item;
  int len;

  ident = silc_calloc(1, sizeof(*ident));

  cp = identifier;
  while (cp) {
    len = strcspn(cp, ",");
    if (len < 1) {
      cp = NULL;
      break;
    }
    if (len - 1 >= 0 && cp[len - 1] == '\\') {
      while (cp) {
	if (len + 1 > strlen(cp)) {
	  cp = NULL;
	  break;
	}
	cp += len + 1;
	len = strcspn(cp, ",") + len;
	if (len < 1) {
	  cp = NULL;
	  break;
	}
	if (len - 1 >= 0 && cp[len - 1] != '\\')
	  break;
      }
    }

    if (!cp)
      break;

    item = silc_calloc(len + 1, sizeof(char));
    if (len > strlen(cp))
      break;
    memcpy(item, cp, len);

    if (strstr(item, "UN="))
      ident->username = strdup(item + strcspn(cp, "=") + 1);
    else if (strstr(item, "HN="))
      ident->host = strdup(item + strcspn(cp, "=") + 1);
    else if (strstr(item, "RN="))
      ident->realname = strdup(item + strcspn(cp, "=") + 1);
    else if (strstr(item, "E="))
      ident->email = strdup(item + strcspn(cp, "=") + 1);
    else if (strstr(item, "O="))
      ident->org = strdup(item + strcspn(cp, "=") + 1);
    else if (strstr(item, "C="))
      ident->country = strdup(item + strcspn(cp, "=") + 1);

    cp += len;
    if (strlen(cp) < 1)
      cp = NULL;
    else
      cp += 1;

    if (item)
      silc_free(item);
  }

  return ident;
}

/* Free's decoded public key identifier context. Call this to free the
   context returned by the silc_pkcs_decode_identifier. */

void silc_pkcs_free_identifier(SilcPublicKeyIdentifier identifier)
{
  silc_free(identifier->username);
  silc_free(identifier->host);
  silc_free(identifier->realname);
  silc_free(identifier->email);
  silc_free(identifier->org);
  silc_free(identifier->country);
  silc_free(identifier);
}

/* Allocates SILC style public key formed from sent arguments. All data
   is duplicated. */

SilcPublicKey silc_pkcs_public_key_alloc(const char *name,
					 const char *identifier,
					 const unsigned char *pk,
					 SilcUInt32 pk_len)
{
  SilcPublicKey public_key;
  char *tmp = NULL;

  public_key = silc_calloc(1, sizeof(*public_key));
  public_key->name = strdup(name);
  public_key->pk_len = pk_len;
  public_key->pk = silc_memdup(pk, pk_len);
  public_key->pk_type = SILC_SKE_PK_TYPE_SILC;

  if (!silc_utf8_valid(identifier, strlen(identifier))) {
    int len = silc_utf8_encoded_len(identifier, strlen(identifier), 0);
    tmp = silc_calloc(len + 1, sizeof(*tmp));
    silc_utf8_encode(identifier, strlen(identifier), 0, tmp, len);
    identifier = tmp;
  }

  public_key->identifier = strdup(identifier);
  public_key->len = 2 + strlen(name) + 2 + strlen(identifier) + pk_len;
  silc_free(tmp);

  return public_key;
}

/* Free's public key */

void silc_pkcs_public_key_free(SilcPublicKey public_key)
{
  if (public_key) {
    silc_free(public_key->name);
    silc_free(public_key->identifier);
    silc_free(public_key->pk);
    silc_free(public_key);
  }
}

/* Allocates SILC private key formed from sent arguments. All data is
   duplicated. */

SilcPrivateKey silc_pkcs_private_key_alloc(const char *name,
					   const unsigned char *prv,
					   SilcUInt32 prv_len)
{
  SilcPrivateKey private_key;

  private_key = silc_calloc(1, sizeof(*private_key));
  private_key->name = strdup(name);
  private_key->prv_len = prv_len;
  private_key->prv = silc_memdup(prv, prv_len);

  return private_key;
}

/* Free's private key */

void silc_pkcs_private_key_free(SilcPrivateKey private_key)
{
  if (private_key) {
    silc_free(private_key->name);
    if (private_key->prv) {
      memset(private_key->prv, 0, private_key->prv_len);
      silc_free(private_key->prv);
    }
    silc_free(private_key);
  }
}

/* Encodes SILC style public key from SilcPublicKey. Returns the encoded
   data. */

unsigned char *
silc_pkcs_public_key_encode(SilcPublicKey public_key, SilcUInt32 *len)
{
  return silc_pkcs_public_key_data_encode(public_key->pk,
					  public_key->pk_len,
					  public_key->name,
					  public_key->identifier, len);
}

/* Encodes SILC style public key. Returns the encoded data. */

unsigned char *
silc_pkcs_public_key_data_encode(unsigned char *pk, SilcUInt32 pk_len,
				 char *pkcs, char *identifier,
				 SilcUInt32 *len)
{
  SilcBuffer buf;
  unsigned char *ret;
  SilcUInt32 totlen;

  totlen = 2 + strlen(pkcs) + 2 + strlen(identifier) + pk_len;
  buf = silc_buffer_alloc_size(totlen + 4);
  if (!buf)
    return NULL;

  silc_buffer_format(buf,
		     SILC_STR_UI_INT(totlen),
		     SILC_STR_UI_SHORT(strlen(pkcs)),
		     SILC_STR_UI32_STRING(pkcs),
		     SILC_STR_UI_SHORT(strlen(identifier)),
		     SILC_STR_UI32_STRING(identifier),
		     SILC_STR_UI_XNSTRING(pk, pk_len),
		     SILC_STR_END);

  ret = silc_buffer_steal(buf, len);
  silc_buffer_free(buf);
  return ret;
}

/* Decodes SILC style public key. Returns TRUE if the decoding was
   successful. Allocates new public key as well. */

SilcBool silc_pkcs_public_key_decode(unsigned char *data, SilcUInt32 data_len,
				 SilcPublicKey *public_key)
{
  SilcBufferStruct buf;
  SilcPKCS alg;
  SilcUInt16 pkcs_len, identifier_len;
  SilcUInt32 totlen, key_len;
  unsigned char *pkcs_name = NULL, *ident = NULL, *key_data = NULL;
  int ret;

  silc_buffer_set(&buf, data, data_len);

  /* Get length */
  ret = silc_buffer_unformat(&buf,
			     SILC_STR_UI_INT(&totlen),
			     SILC_STR_END);
  if (ret == -1)
    return FALSE;

#if 1 /* Backwards support, remove! */
  if (totlen == data_len)
    totlen -= 4;
#endif

  if (totlen + 4 != data_len)
    return FALSE;

  /* Get algorithm name and identifier */
  silc_buffer_pull(&buf, 4);
  ret =
    silc_buffer_unformat(&buf,
			 SILC_STR_UI16_NSTRING_ALLOC(&pkcs_name, &pkcs_len),
			 SILC_STR_UI16_NSTRING_ALLOC(&ident, &identifier_len),
			 SILC_STR_END);
  if (ret == -1)
    goto err;

  if (pkcs_len < 1 || identifier_len < 3 ||
      pkcs_len + identifier_len > totlen)
    goto err;

  /* See if we support this algorithm (check only if PKCS are registered) */
  if (SILC_PKCS_LIST && !silc_pkcs_is_supported(pkcs_name)) {
    SILC_LOG_DEBUG(("Unknown PKCS %s", pkcs_name));
    goto err;
  }

  /* Protocol says that at least UN and HN must be provided as identifier,
     check for these. */
  if (!strstr(ident, "UN=") && !strstr(ident, "HN=")) {
    SILC_LOG_DEBUG(("The public does not have the required UN= and HN= "
		    "identifiers"));
    goto err;
  }

  /* Get key data. We assume that rest of the buffer is key data. */
  silc_buffer_pull(&buf, 2 + pkcs_len + 2 + identifier_len);
  key_len = silc_buffer_len(&buf);
  ret = silc_buffer_unformat(&buf,
			     SILC_STR_UI_XNSTRING_ALLOC(&key_data, key_len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  /* Try to set the key. If this fails the key must be malformed. This
     code assumes that the PKCS routine checks the format of the key.
     (check only if PKCS are registered) */
  if (SILC_PKCS_LIST) {
    silc_pkcs_alloc(pkcs_name, &alg);
    if (!alg->pkcs->set_public_key(alg->context, key_data, key_len))
      goto err;
    silc_pkcs_free(alg);
  }

  if (public_key) {
    *public_key = silc_calloc(1, sizeof(**public_key));
    (*public_key)->len = totlen;
    (*public_key)->name = pkcs_name;
    (*public_key)->identifier = ident;
    (*public_key)->pk = key_data;
    (*public_key)->pk_len = key_len;
    (*public_key)->pk_type = SILC_SKE_PK_TYPE_SILC;
  }

  return TRUE;

 err:
  silc_free(pkcs_name);
  silc_free(ident);
  silc_free(key_data);
  return FALSE;
}

/* Encodes Public Key Payload for transmitting public keys and certificates. */

SilcBuffer silc_pkcs_public_key_payload_encode(SilcPublicKey public_key)
{
  SilcBuffer buffer;
  unsigned char *pk;
  SilcUInt32 pk_len;

  if (!public_key)
    return NULL;

  pk = silc_pkcs_public_key_encode(public_key, &pk_len);
  if (!pk)
    return NULL;

  buffer = silc_buffer_alloc_size(4 + pk_len);
  if (!buffer) {
    silc_free(pk);
    return NULL;
  }

  silc_buffer_format(buffer,
		     SILC_STR_UI_SHORT(pk_len),
		     SILC_STR_UI_SHORT(public_key->pk_type),
		     SILC_STR_UI_XNSTRING(pk, pk_len),
		     SILC_STR_END);

  silc_free(pk);
  return buffer;
}

/* Decode Public Key Payload and decodes the public key inside it to
   to `payload'. */

SilcBool silc_pkcs_public_key_payload_decode(unsigned char *data,
					 SilcUInt32 data_len,
					 SilcPublicKey *public_key)
{
  SilcBufferStruct buf;
  SilcUInt16 pk_len, pk_type;
  unsigned char *pk;
  int ret;

  if (!public_key)
    return FALSE;

  silc_buffer_set(&buf, data, data_len);
  ret = silc_buffer_unformat(&buf,
			     SILC_STR_UI_SHORT(&pk_len),
			     SILC_STR_UI_SHORT(&pk_type),
			     SILC_STR_END);
  if (ret < 0 || pk_len > data_len - 4)
    return FALSE;

  /* For now we support only SILC public keys */
  if (pk_type != SILC_SKE_PK_TYPE_SILC)
    return FALSE;

  silc_buffer_pull(&buf, 4);
  ret = silc_buffer_unformat(&buf,
			     SILC_STR_UI_XNSTRING(&pk, pk_len),
			     SILC_STR_END);
  silc_buffer_push(&buf, 4);
  if (ret < 0)
    return FALSE;

  if (!silc_pkcs_public_key_decode(pk, pk_len, public_key))
    return FALSE;
  (*public_key)->pk_type = SILC_SKE_PK_TYPE_SILC;

  return TRUE;
}

/* Compares two public keys and returns TRUE if they are same key, and
   FALSE if they are not same. */

SilcBool silc_pkcs_public_key_compare(SilcPublicKey key1, SilcPublicKey key2)
{
  if (key1 == key2)
    return TRUE;

  if (key1->len == key2->len &&
      key1->name && key2->name && key1->identifier && key2->identifier &&
      !strcmp(key1->name, key2->name) &&
      !strcmp(key1->identifier, key2->identifier) &&
      !memcmp(key1->pk, key2->pk, key1->pk_len) &&
      key1->pk_len == key2->pk_len)
    return TRUE;

  return FALSE;
}

/* Copies the public key indicated by `public_key' and returns new allocated
   public key which is indentical to the `public_key'. */

SilcPublicKey silc_pkcs_public_key_copy(SilcPublicKey public_key)
{
  SilcPublicKey key = silc_calloc(1, sizeof(*key));
  if (!key)
    return NULL;

  key->len = public_key->len;
  key->name = silc_memdup(public_key->name, strlen(public_key->name));
  key->identifier = silc_memdup(public_key->identifier,
				strlen(public_key->identifier));
  key->pk = silc_memdup(public_key->pk, public_key->pk_len);
  key->pk_len = public_key->pk_len;
  key->pk_type = public_key->pk_type;

  return key;
}

/* Encodes SILC private key from SilcPrivateKey. Returns the encoded data. */

unsigned char *
silc_pkcs_private_key_encode(SilcPrivateKey private_key, SilcUInt32 *len)
{
  return silc_pkcs_private_key_data_encode(private_key->prv,
					   private_key->prv_len,
					   private_key->name, len);
}

/* Encodes SILC private key. Returns the encoded data. */

unsigned char *
silc_pkcs_private_key_data_encode(unsigned char *prv, SilcUInt32 prv_len,
				  char *pkcs, SilcUInt32 *len)
{
  SilcBuffer buf;
  unsigned char *ret;
  SilcUInt32 totlen;

  totlen = 2 + strlen(pkcs) + prv_len;
  buf = silc_buffer_alloc_size(totlen);
  if (!buf)
    return NULL;

  silc_buffer_format(buf,
		     SILC_STR_UI_SHORT(strlen(pkcs)),
		     SILC_STR_UI32_STRING(pkcs),
		     SILC_STR_UI_XNSTRING(prv, prv_len),
		     SILC_STR_END);

  ret = silc_buffer_steal(buf, len);
  silc_buffer_free(buf);
  return ret;
}

/* Decodes SILC style private key. Returns TRUE if the decoding was
   successful. Allocates new private key as well. */

SilcBool silc_pkcs_private_key_decode(unsigned char *data, SilcUInt32 data_len,
				  SilcPrivateKey *private_key)
{
  SilcBufferStruct buf;
  SilcPKCS alg;
  SilcUInt16 pkcs_len;
  SilcUInt32 key_len;
  unsigned char *pkcs_name = NULL, *key_data = NULL;
  int ret;

  silc_buffer_set(&buf, data, data_len);

  /* Get algorithm name and identifier */
  ret =
    silc_buffer_unformat(&buf,
			 SILC_STR_UI16_NSTRING_ALLOC(&pkcs_name, &pkcs_len),
			 SILC_STR_END);
  if (ret == -1) {
    SILC_LOG_DEBUG(("Cannot decode private key buffer"));
    goto err;
  }

  if (pkcs_len < 1 || pkcs_len > silc_buffer_truelen(&buf)) {
    SILC_LOG_DEBUG(("Malformed private key buffer"));
    goto err;
  }

  /* See if we support this algorithm (check only if PKCS are registered). */
  if (SILC_PKCS_LIST && !silc_pkcs_is_supported(pkcs_name)) {
    SILC_LOG_DEBUG(("Unknown PKCS `%s'", pkcs_name));
    goto err;
  }

  /* Get key data. We assume that rest of the buffer is key data. */
  silc_buffer_pull(&buf, 2 + pkcs_len);
  key_len = silc_buffer_len(&buf);
  ret = silc_buffer_unformat(&buf,
			     SILC_STR_UI_XNSTRING_ALLOC(&key_data, key_len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  /* Try to set the key. If this fails the key must be malformed. This
     code assumes that the PKCS routine checks the format of the key.
     (check only if PKCS are registered) */
  if (SILC_PKCS_LIST) {
    silc_pkcs_alloc(pkcs_name, &alg);
    if (!alg->pkcs->set_private_key(alg->context, key_data, key_len)) {
      SILC_LOG_DEBUG(("Could not set private key data"));
      goto err;
    }
    silc_pkcs_free(alg);
  }

  if (private_key) {
    *private_key = silc_calloc(1, sizeof(**private_key));
    (*private_key)->name = pkcs_name;
    (*private_key)->prv = key_data;
    (*private_key)->prv_len = key_len;
  }

  return TRUE;

 err:
  silc_free(pkcs_name);
  silc_free(key_data);
  return FALSE;
}

/* Internal routine to save public key */

static SilcBool silc_pkcs_save_public_key_internal(const char *filename,
					       unsigned char *data,
					       SilcUInt32 data_len,
					       SilcUInt32 encoding)
{
  SilcBuffer buf;
  SilcUInt32 len;
  unsigned char *tmp = NULL;

  switch(encoding) {
  case SILC_PKCS_FILE_BIN:
    break;
  case SILC_PKCS_FILE_PEM:
    tmp = data = silc_pem_encode_file(data, data_len);
    data_len = strlen(data);
    break;
  }

  len = data_len + (strlen(SILC_PKCS_PUBLIC_KEYFILE_BEGIN) +
		    strlen(SILC_PKCS_PUBLIC_KEYFILE_END));
  buf = silc_buffer_alloc_size(len);
  if (!buf) {
    silc_free(tmp);
    return FALSE;
  }

  silc_buffer_format(buf,
		     SILC_STR_UI32_STRING(SILC_PKCS_PUBLIC_KEYFILE_BEGIN),
		     SILC_STR_UI_XNSTRING(data, data_len),
		     SILC_STR_UI32_STRING(SILC_PKCS_PUBLIC_KEYFILE_END),
		     SILC_STR_END);

  /* Save into file */
  if (silc_file_writefile(filename, buf->data, silc_buffer_len(buf))) {
    silc_free(tmp);
    silc_buffer_free(buf);
    return FALSE;
  }

  silc_free(tmp);
  silc_buffer_free(buf);
  return TRUE;
}

/* Saves public key into file */

SilcBool silc_pkcs_save_public_key(const char *filename, SilcPublicKey public_key,
			       SilcUInt32 encoding)
{
  unsigned char *data;
  SilcUInt32 data_len;
  SilcBool ret;

  data = silc_pkcs_public_key_encode(public_key, &data_len);
  ret = silc_pkcs_save_public_key_internal(filename, data, data_len,
					   encoding);
  silc_free(data);
  return ret;
}

/* Saves public key into file */

SilcBool silc_pkcs_save_public_key_data(const char *filename, unsigned char *data,
				    SilcUInt32 data_len, SilcUInt32 encoding)
{
  return silc_pkcs_save_public_key_internal(filename, data, data_len,
					    encoding);
}

#define SILC_PKCS_PRIVATE_KEY_MAGIC 0x738df531

/* Internal routine to save private key. */

static SilcBool silc_pkcs_save_private_key_internal(const char *filename,
						unsigned char *data,
						SilcUInt32 data_len,
						unsigned char *key,
						SilcUInt32 key_len,
						SilcUInt32 encoding)
{
  SilcCipher aes;
  SilcHash sha1;
  SilcHmac sha1hmac;
  SilcBuffer buf, enc;
  SilcUInt32 len, blocklen, padlen;
  unsigned char tmp[32], keymat[64];
  int i;

  memset(tmp, 0, sizeof(tmp));
  memset(keymat, 0, sizeof(keymat));

  /* Allocate the AES cipher */
  if (!silc_cipher_alloc("aes-256-cbc", &aes)) {
    SILC_LOG_ERROR(("Could not allocate AES cipher, probably not registered"));
    return FALSE;
  }
  blocklen = silc_cipher_get_block_len(aes);
  if (blocklen * 2 > sizeof(tmp))
    return FALSE;

  /* Allocate SHA1 hash */
  if (!silc_hash_alloc("sha1", &sha1)) {
    SILC_LOG_ERROR(("Could not allocate SHA1 hash, probably not registered"));
    silc_cipher_free(aes);
    return FALSE;
  }

  /* Allocate HMAC */
  if (!silc_hmac_alloc("hmac-sha1-96", NULL, &sha1hmac)) {
    SILC_LOG_ERROR(("Could not allocate SHA1 HMAC, probably not registered"));
    silc_hash_free(sha1);
    silc_cipher_free(aes);
    return FALSE;
  }

  /* Derive the encryption key from the provided key material.  The key
     is 256 bits length, and derived by taking hash of the data, then
     re-hashing the data and the previous digest, and using the first and
     second digest as the key. */
  silc_hash_init(sha1);
  silc_hash_update(sha1, key, key_len);
  silc_hash_final(sha1, keymat);
  silc_hash_init(sha1);
  silc_hash_update(sha1, key, key_len);
  silc_hash_update(sha1, keymat, 16);
  silc_hash_final(sha1, keymat + 16);

  /* Set the key to the cipher */
  silc_cipher_set_key(aes, keymat, 256);

  /* Encode the buffer to be encrypted.  Add padding to it too, at least
     block size of the cipher. */

  /* Allocate buffer for encryption */
  len = silc_hmac_len(sha1hmac);
  padlen = 16 + (16 - ((data_len + 4) % blocklen));
  enc = silc_buffer_alloc_size(4 + 4 + data_len + padlen + len);
  if (!enc) {
    silc_hmac_free(sha1hmac);
    silc_hash_free(sha1);
    silc_cipher_free(aes);
    return FALSE;
  }

  /* Generate padding */
  for (i = 0; i < padlen; i++)
    tmp[i] = silc_rng_global_get_byte_fast();

  /* Put magic number */
  SILC_PUT32_MSB(SILC_PKCS_PRIVATE_KEY_MAGIC, enc->data);
  silc_buffer_pull(enc, 4);

  /* Encode the buffer */
  silc_buffer_format(enc,
		     SILC_STR_UI_INT(data_len),
		     SILC_STR_UI_XNSTRING(data, data_len),
		     SILC_STR_UI_XNSTRING(tmp, padlen),
		     SILC_STR_END);

  /* Encrypt. */
  silc_cipher_encrypt(aes, enc->data, enc->data, silc_buffer_len(enc) - len,
		      silc_cipher_get_iv(aes));

  silc_buffer_push(enc, 4);

  /* Compute HMAC over the encrypted data and append the MAC to data.
     The key is the first digest of the original key material. */
  data_len = silc_buffer_len(enc) - len;
  silc_hmac_init_with_key(sha1hmac, keymat, 16);
  silc_hmac_update(sha1hmac, enc->data, data_len);
  silc_buffer_pull(enc, data_len);
  silc_hmac_final(sha1hmac, enc->data, NULL);
  silc_buffer_push(enc, data_len);

  /* Cleanup */
  memset(keymat, 0, sizeof(keymat));
  memset(tmp, 0, sizeof(tmp));
  silc_hmac_free(sha1hmac);
  silc_hash_free(sha1);
  silc_cipher_free(aes);

  data = enc->data;
  data_len = silc_buffer_len(enc);

  switch (encoding) {
  case SILC_PKCS_FILE_BIN:
    break;
  case SILC_PKCS_FILE_PEM:
    data = silc_pem_encode_file(data, data_len);
    data_len = strlen(data);
    break;
  }

  /* Encode the data and save to file */
  len = data_len + (strlen(SILC_PKCS_PRIVATE_KEYFILE_BEGIN) +
		    strlen(SILC_PKCS_PRIVATE_KEYFILE_END));
  buf = silc_buffer_alloc_size(len);
  silc_buffer_format(buf,
		     SILC_STR_UI32_STRING(SILC_PKCS_PRIVATE_KEYFILE_BEGIN),
		     SILC_STR_UI_XNSTRING(data, data_len),
		     SILC_STR_UI32_STRING(SILC_PKCS_PRIVATE_KEYFILE_END),
		     SILC_STR_END);

  /* Save into a file */
  if (silc_file_writefile_mode(filename, buf->data,
			       silc_buffer_len(buf), 0600)) {
    silc_buffer_clear(buf);
    silc_buffer_free(buf);
    silc_buffer_clear(enc);
    silc_buffer_free(enc);
    return FALSE;
  }

  silc_buffer_clear(buf);
  silc_buffer_free(buf);
  silc_buffer_clear(enc);
  silc_buffer_free(enc);
  return TRUE;
}

/* Saves private key into file. */

SilcBool silc_pkcs_save_private_key(const char *filename,
				SilcPrivateKey private_key,
				unsigned char *passphrase,
				SilcUInt32 passphrase_len,
				SilcUInt32 encoding)
{
  unsigned char *data;
  SilcUInt32 data_len;
  SilcBool ret;

  data = silc_pkcs_private_key_encode(private_key, &data_len);
  ret = silc_pkcs_save_private_key_internal(filename, data, data_len,
					    passphrase, passphrase_len,
					    encoding);
  memset(data, 0, data_len);
  silc_free(data);
  return ret;
}

/* Loads public key from file and allocates new public key. Returns TRUE
   if loading was successful. */

SilcBool silc_pkcs_load_public_key(const char *filename, SilcPublicKey *public_key,
			       SilcUInt32 encoding)
{
  unsigned char *cp, *old, *data, byte;
  SilcUInt32 i, data_len, len;

  SILC_LOG_DEBUG(("Loading public key `%s' with %s encoding", filename,
		  encoding == SILC_PKCS_FILE_PEM ? "Base64" :
		  encoding == SILC_PKCS_FILE_BIN ? "Binary" : "Unkonwn"));

  old = data = silc_file_readfile(filename, &data_len);
  if (!data)
    return FALSE;

  /* Check start of file and remove header from the data. */
  len = strlen(SILC_PKCS_PUBLIC_KEYFILE_BEGIN);
  cp = data;
  for (i = 0; i < len; i++) {
    byte = cp[0];
    cp++;
    if (byte != SILC_PKCS_PUBLIC_KEYFILE_BEGIN[i]) {
      memset(old, 0, data_len);
      silc_free(old);
      return FALSE;
    }
  }
  data = cp;

  /* Decode public key */
  if (public_key) {
    len = data_len - (strlen(SILC_PKCS_PUBLIC_KEYFILE_BEGIN) +
		      strlen(SILC_PKCS_PUBLIC_KEYFILE_END));

    switch(encoding) {
    case SILC_PKCS_FILE_BIN:
      break;
    case SILC_PKCS_FILE_PEM:
      data = silc_pem_decode(data, len, &len);
      memset(old, 0, data_len);
      silc_free(old);
      old = data;
      data_len = len;
      break;
    }

    if (!data || !silc_pkcs_public_key_decode(data, len, public_key)) {
      memset(old, 0, data_len);
      silc_free(old);
      return FALSE;
    }
  }

  memset(old, 0, data_len);
  silc_free(old);
  return TRUE;
}

/* Load private key from file and allocates new private key. Returns TRUE
   if loading was successful. */

SilcBool silc_pkcs_load_private_key(const char *filename,
				SilcPrivateKey *private_key,
				unsigned char *passphrase,
				SilcUInt32 passphrase_len,
				SilcUInt32 encoding)
{
  SilcCipher aes;
  SilcHash sha1;
  SilcHmac sha1hmac;
  SilcUInt32 blocklen;
  unsigned char tmp[32], keymat[64];
  unsigned char *cp, *old, *data, byte;
  SilcUInt32 i, data_len, len, magic, mac_len;

  SILC_LOG_DEBUG(("Loading private key `%s' with %s encoding", filename,
		  encoding == SILC_PKCS_FILE_PEM ? "Base64" :
		  encoding == SILC_PKCS_FILE_BIN ? "Binary" : "Unkonwn"));

  old = data = silc_file_readfile(filename, &data_len);
  if (!data)
    return FALSE;

  /* Check start of file and remove header from the data. */
  len = strlen(SILC_PKCS_PRIVATE_KEYFILE_BEGIN);
  cp = data;
  for (i = 0; i < len; i++) {
    byte = cp[0];
    cp++;
    if (byte != SILC_PKCS_PRIVATE_KEYFILE_BEGIN[i]) {
      memset(old, 0, data_len);
      silc_free(old);
      return FALSE;
    }
  }
  data = cp;

  /* Decode private key */
  len = data_len - (strlen(SILC_PKCS_PRIVATE_KEYFILE_BEGIN) +
		    strlen(SILC_PKCS_PRIVATE_KEYFILE_END));

  switch(encoding) {
  case SILC_PKCS_FILE_BIN:
    break;
  case SILC_PKCS_FILE_PEM:
    data = silc_pem_decode(data, len, &len);
    if (!data) {
      memset(old, 0, data_len);
      silc_free(old);
      return FALSE;
    }
    break;
  }

  memset(tmp, 0, sizeof(tmp));
  memset(keymat, 0, sizeof(keymat));

  /* Private key files without the specific magic number are assumed
     to be the old-style private keys that are not encrypted. */
  SILC_GET32_MSB(magic, data);
  if (magic != SILC_PKCS_PRIVATE_KEY_MAGIC) {
    SILC_LOG_DEBUG(("Private key does not have correct magic!"));

    /* Now decode the actual private key */
    if (!silc_pkcs_private_key_decode(data, len, private_key)) {
      memset(old, 0, data_len);
      silc_free(old);
      return FALSE;
    }

    memset(old, 0, data_len);
    silc_free(old);
    return TRUE;
  }

  /* Allocate the AES cipher */
  if (!silc_cipher_alloc("aes-256-cbc", &aes)) {
    SILC_LOG_ERROR(("Could not allocate AES cipher, probably not registered"));
    memset(old, 0, data_len);
    silc_free(old);
    return FALSE;
  }
  blocklen = silc_cipher_get_block_len(aes);
  if (blocklen * 2 > sizeof(tmp)) {
    memset(old, 0, data_len);
    silc_free(old);
    return FALSE;
  }

  /* Allocate SHA1 hash */
  if (!silc_hash_alloc("sha1", &sha1)) {
    SILC_LOG_ERROR(("Could not allocate SHA1 hash, probably not registered"));
    silc_cipher_free(aes);
    memset(old, 0, data_len);
    silc_free(old);
    return FALSE;
  }

  /* Allocate HMAC */
  if (!silc_hmac_alloc("hmac-sha1-96", NULL, &sha1hmac)) {
    SILC_LOG_ERROR(("Could not allocate SHA1 HMAC, probably not registered"));
    silc_hash_free(sha1);
    silc_cipher_free(aes);
    memset(old, 0, data_len);
    silc_free(old);
    return FALSE;
  }

  /* Derive the decryption key from the provided key material.  The key
     is 256 bits length, and derived by taking hash of the data, then
     re-hashing the data and the previous digest, and using the first and
     second digest as the key. */
  silc_hash_init(sha1);
  silc_hash_update(sha1, passphrase, passphrase_len);
  silc_hash_final(sha1, keymat);
  silc_hash_init(sha1);
  silc_hash_update(sha1, passphrase, passphrase_len);
  silc_hash_update(sha1, keymat, 16);
  silc_hash_final(sha1, keymat + 16);

  /* Set the key to the cipher */
  silc_cipher_set_key(aes, keymat, 256);

  /* First, verify the MAC of the private key data */
  mac_len = silc_hmac_len(sha1hmac);
  silc_hmac_init_with_key(sha1hmac, keymat, 16);
  silc_hmac_update(sha1hmac, data, len - mac_len);
  silc_hmac_final(sha1hmac, tmp, NULL);
  if (memcmp(tmp, data + (len - mac_len), mac_len)) {
    SILC_LOG_DEBUG(("Integrity check for private key failed"));
    memset(keymat, 0, sizeof(keymat));
    memset(tmp, 0, sizeof(tmp));
    silc_hmac_free(sha1hmac);
    silc_hash_free(sha1);
    silc_cipher_free(aes);
    memset(old, 0, data_len);
    silc_free(old);
    return FALSE;
  }
  data += 4;
  len -= 4;

  /* Decrypt the private key buffer */
  silc_cipher_decrypt(aes, data, data, len - mac_len, NULL);
  SILC_GET32_MSB(i, data);
  if (i > len) {
    SILC_LOG_DEBUG(("Bad private key length in buffer!"));
    memset(keymat, 0, sizeof(keymat));
    memset(tmp, 0, sizeof(tmp));
    silc_hmac_free(sha1hmac);
    silc_hash_free(sha1);
    silc_cipher_free(aes);
    memset(old, 0, data_len);
    silc_free(old);
    return FALSE;
  }
  data += 4;
  len = i;

  /* Cleanup */
  memset(keymat, 0, sizeof(keymat));
  memset(tmp, 0, sizeof(tmp));
  silc_hmac_free(sha1hmac);
  silc_hash_free(sha1);
  silc_cipher_free(aes);

  /* Now decode the actual private key */
  if (!silc_pkcs_private_key_decode(data, len, private_key)) {
    memset(old, 0, data_len);
    silc_free(old);
    return FALSE;
  }

  memset(old, 0, data_len);
  silc_free(old);
  return TRUE;
}
