/*

  silcpkcs.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"

#include "rsa.h"
#include "pkcs1.h"

/* Dynamically registered list of PKCS. */
SilcDList silc_pkcs_list = NULL;

/* Static list of PKCS for silc_pkcs_register_default(). */
SilcPKCSObject silc_default_pkcs[] =
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

bool silc_pkcs_register(SilcPKCSObject *pkcs)
{
  SilcPKCSObject *new;

  SILC_LOG_DEBUG(("Registering new PKCS `%s'", pkcs->name));

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

  return TRUE;
}

/* Unregister a PKCS from the SILC. */

bool silc_pkcs_unregister(SilcPKCSObject *pkcs)
{
  SilcPKCSObject *entry;

  SILC_LOG_DEBUG(("Unregistering PKCS"));

  if (!silc_pkcs_list)
    return FALSE;

  silc_dlist_start(silc_pkcs_list);
  while ((entry = silc_dlist_get(silc_pkcs_list)) != SILC_LIST_END) {
    if (pkcs == SILC_ALL_PKCS || entry == pkcs) {
      silc_dlist_del(silc_pkcs_list, entry);

      if (silc_dlist_count(silc_pkcs_list) == 0) {
	silc_dlist_uninit(silc_pkcs_list);
	silc_pkcs_list = NULL;
      }

      return TRUE;
    }
  }

  return FALSE;
}

/* Function that registers all the default PKCS (all builtin PKCS). 
   The application may use this to register the default PKCS if specific
   PKCS in any specific order is not wanted. */

bool silc_pkcs_register_default(void)
{
  int i;

  for (i = 0; silc_default_pkcs[i].name; i++)
    silc_pkcs_register(&(silc_default_pkcs[i]));

  return TRUE;
}

/* Allocates a new SilcPKCS object. The new allocated object is returned
   to the 'new_pkcs' argument. */

bool silc_pkcs_alloc(const unsigned char *name, SilcPKCS *new_pkcs)
{
  SilcPKCSObject *entry;

  SILC_LOG_DEBUG(("Allocating new PKCS object"));

  if (silc_pkcs_list) {
    silc_dlist_start(silc_pkcs_list);
    while ((entry = silc_dlist_get(silc_pkcs_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, name)) {
	*new_pkcs = silc_calloc(1, sizeof(**new_pkcs));
	(*new_pkcs)->pkcs = entry;
	(*new_pkcs)->context = silc_calloc(1, entry->context_len());
	(*new_pkcs)->get_key_len = silc_pkcs_get_key_len;
	return TRUE;
      }
    }
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

int silc_pkcs_is_supported(const unsigned char *name)
{
  SilcPKCSObject *entry;

  if (silc_pkcs_list) {
    silc_dlist_start(silc_pkcs_list);
    while ((entry = silc_dlist_get(silc_pkcs_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, name))
	return TRUE;
    }
  }

  return FALSE;
}

/* Returns comma separated list of supported PKCS algorithms */

char *silc_pkcs_get_supported(void)
{
  SilcPKCSObject *entry;
  char *list = NULL;
  int len;

  len = 0;
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
    list[len - 1] = 0;
  }

  return list;
}

/* Returns the length of the key */

SilcUInt32 silc_pkcs_get_key_len(SilcPKCS pkcs)
{
  return pkcs->key_len;
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

int silc_pkcs_private_key_set(SilcPKCS pkcs, SilcPrivateKey private_key)
{
  return pkcs->pkcs->set_private_key(pkcs->context, private_key->prv, 
				     private_key->prv_len);
}

/* Sets private key from data. */

int silc_pkcs_private_key_data_set(SilcPKCS pkcs, unsigned char *prv,
				   SilcUInt32 prv_len)
{
  return pkcs->pkcs->set_private_key(pkcs->context, prv, prv_len);
}

/* Encrypts */

int silc_pkcs_encrypt(SilcPKCS pkcs, unsigned char *src, SilcUInt32 src_len,
		      unsigned char *dst, SilcUInt32 *dst_len)
{
  return pkcs->pkcs->encrypt(pkcs->context, src, src_len, dst, dst_len);
}

/* Decrypts */

int silc_pkcs_decrypt(SilcPKCS pkcs, unsigned char *src, SilcUInt32 src_len,
		      unsigned char *dst, SilcUInt32 *dst_len)
{
  return pkcs->pkcs->decrypt(pkcs->context, src, src_len, dst, dst_len);
}

/* Generates signature */

int silc_pkcs_sign(SilcPKCS pkcs, unsigned char *src, SilcUInt32 src_len,
		   unsigned char *dst, SilcUInt32 *dst_len)
{
  return pkcs->pkcs->sign(pkcs->context, src, src_len, dst, dst_len);
}

/* Verifies signature */

int silc_pkcs_verify(SilcPKCS pkcs, unsigned char *signature, 
		     SilcUInt32 signature_len, unsigned char *data, 
		     SilcUInt32 data_len)
{
  return pkcs->pkcs->verify(pkcs->context, signature, signature_len, 
			    data, data_len);
}

/* Generates signature with hash. The hash is signed. */

int silc_pkcs_sign_with_hash(SilcPKCS pkcs, SilcHash hash,
			     unsigned char *src, SilcUInt32 src_len,
			     unsigned char *dst, SilcUInt32 *dst_len)
{
  unsigned char hashr[32];
  SilcUInt32 hash_len;
  int ret;

  silc_hash_make(hash, src, src_len, hashr);
  hash_len = hash->hash->hash_len;

  SILC_LOG_HEXDUMP(("Hash"), hashr, hash_len);

  ret = pkcs->pkcs->sign(pkcs->context, hashr, hash_len, dst, dst_len);
  memset(hashr, 0, sizeof(hashr));

  return ret;
}

/* Verifies signature with hash. The `data' is hashed and verified against
   the `signature'. */

int silc_pkcs_verify_with_hash(SilcPKCS pkcs, SilcHash hash, 
			       unsigned char *signature, 
			       SilcUInt32 signature_len, 
			       unsigned char *data, 
			       SilcUInt32 data_len)
{
  unsigned char hashr[32];
  SilcUInt32 hash_len;
  int ret;

  silc_hash_make(hash, data, data_len, hashr);
  hash_len = hash->hash->hash_len;

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
    if (len - 1 >= 0 && cp[len - 1] == '\\') {
      while (cp) {
	cp += len + 1;
	len = strcspn(cp, ",") + len;
	if (len - 1 >= 0 && cp[len - 1] != '\\')
	  break;
      }
    }

    item = silc_calloc(len + 1, sizeof(char));
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
    if (strlen(cp) == 0)
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

SilcPublicKey silc_pkcs_public_key_alloc(char *name, char *identifier,
					 unsigned char *pk, 
					 SilcUInt32 pk_len)
{
  SilcPublicKey public_key;

  public_key = silc_calloc(1, sizeof(*public_key));
  public_key->len = 4 + 2 + strlen(name) + 2 + strlen(identifier) + pk_len;
  public_key->name = strdup(name);
  public_key->identifier = strdup(identifier);
  public_key->pk_len = pk_len;
  public_key->pk = silc_calloc(pk_len, sizeof(*public_key->pk));
  memcpy(public_key->pk, pk, pk_len);

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

SilcPrivateKey silc_pkcs_private_key_alloc(char *name, unsigned char *prv,
					   SilcUInt32 prv_len)
{
  SilcPrivateKey private_key;

  private_key = silc_calloc(1, sizeof(*private_key));
  private_key->name = strdup(name);
  private_key->prv_len = prv_len;
  private_key->prv = silc_calloc(prv_len, sizeof(*private_key->prv));
  memcpy(private_key->prv, prv, prv_len);

  return private_key;
}

/* Free's private key */

void silc_pkcs_private_key_free(SilcPrivateKey private_key)
{
  if (private_key) {
    silc_free(private_key->name);
    silc_free(private_key->prv);
    silc_free(private_key);
  }
}

/* Encodes SILC style public key from SilcPublicKey. Returns the encoded
   data. */

unsigned char *
silc_pkcs_public_key_encode(SilcPublicKey public_key, SilcUInt32 *len)
{
  SilcBuffer buf;
  unsigned char *ret;

  buf = silc_buffer_alloc(public_key->len);
  silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));

  silc_buffer_format(buf,
		     SILC_STR_UI_INT(public_key->len),
		     SILC_STR_UI_SHORT(strlen(public_key->name)),
		     SILC_STR_UI32_STRING(public_key->name),
		     SILC_STR_UI_SHORT(strlen(public_key->identifier)),
		     SILC_STR_UI32_STRING(public_key->identifier),
		     SILC_STR_UI_XNSTRING(public_key->pk, 
					  public_key->pk_len),
		     SILC_STR_END);
  if (len)
    *len = public_key->len;

  ret = silc_calloc(buf->len, sizeof(*ret));
  memcpy(ret, buf->data, buf->len);
  silc_buffer_free(buf);

  return ret;
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

  totlen = 4 + 2 + strlen(pkcs) + 2 + strlen(identifier) + pk_len;
  buf = silc_buffer_alloc(totlen);
  silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));

  silc_buffer_format(buf,
		     SILC_STR_UI_INT(totlen),
		     SILC_STR_UI_SHORT(strlen(pkcs)),
		     SILC_STR_UI32_STRING(pkcs),
		     SILC_STR_UI_SHORT(strlen(identifier)),
		     SILC_STR_UI32_STRING(identifier),
		     SILC_STR_UI_XNSTRING(pk, pk_len),
		     SILC_STR_END);
  if (len)
    *len = totlen;

  ret = silc_calloc(buf->len, sizeof(*ret));
  memcpy(ret, buf->data, buf->len);
  silc_buffer_free(buf);

  return ret;
}

/* Decodes SILC style public key. Returns TRUE if the decoding was
   successful. Allocates new public key as well. */

int silc_pkcs_public_key_decode(unsigned char *data, SilcUInt32 data_len,
				SilcPublicKey *public_key)
{
  SilcBuffer buf;
  SilcPKCS alg;
  SilcUInt16 pkcs_len, identifier_len;
  SilcUInt32 totlen, key_len;
  unsigned char *pkcs_name = NULL, *ident = NULL, *key_data = NULL;
  int ret;

  buf = silc_buffer_alloc(data_len);
  silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));
  silc_buffer_put(buf, data, data_len);

  /* Get length */
  ret = silc_buffer_unformat(buf,
			     SILC_STR_UI_INT(&totlen),
			     SILC_STR_END);
  if (ret == -1) {
    silc_buffer_free(buf);
    return FALSE;
  }

  if (totlen != data_len) {
    silc_buffer_free(buf);
    return FALSE;
  }

  /* Get algorithm name and identifier */
  silc_buffer_pull(buf, 4);
  ret =
    silc_buffer_unformat(buf,
			 SILC_STR_UI16_NSTRING_ALLOC(&pkcs_name, &pkcs_len),
			 SILC_STR_UI16_NSTRING_ALLOC(&ident, &identifier_len),
			 SILC_STR_END);
  if (ret == -1)
    goto err;

  if (pkcs_len < 1 || identifier_len < 3 || 
      pkcs_len + identifier_len > totlen)
    goto err;

  /* See if we support this algorithm (check only if PKCS are registered) */
  if (silc_pkcs_list && !silc_pkcs_is_supported(pkcs_name)) {
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
  silc_buffer_pull(buf, 2 + pkcs_len + 2 + identifier_len);
  key_len = buf->len;
  ret = silc_buffer_unformat(buf,
			     SILC_STR_UI_XNSTRING_ALLOC(&key_data, key_len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  /* Try to set the key. If this fails the key must be malformed. This
     code assumes that the PKCS routine checks the format of the key. 
     (check only if PKCS are registered) */
  if (silc_pkcs_list) {
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
  }

  silc_buffer_free(buf);
  return TRUE;

 err:
  if (pkcs_name)
    silc_free(pkcs_name);
  if (ident)
    silc_free(ident);
  if (key_data)
    silc_free(key_data);
  silc_buffer_free(buf);
  return FALSE;
}

/* Compares two public keys and returns TRUE if they are same key, and
   FALSE if they are not same. */

bool silc_pkcs_public_key_compare(SilcPublicKey key1, SilcPublicKey key2)
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

/* Encodes SILC private key from SilcPrivateKey. Returns the encoded data. */

unsigned char *
silc_pkcs_private_key_encode(SilcPrivateKey private_key, SilcUInt32 *len)
{
  SilcBuffer buf;
  unsigned char *ret;
  SilcUInt32 totlen;

  totlen = 2 + strlen(private_key->name) + private_key->prv_len;
  buf = silc_buffer_alloc(totlen);
  silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));

  silc_buffer_format(buf,
		     SILC_STR_UI_SHORT(strlen(private_key->name)),
		     SILC_STR_UI32_STRING(private_key->name),
		     SILC_STR_UI_XNSTRING(private_key->prv, 
					  private_key->prv_len),
		     SILC_STR_END);
  if (len)
    *len = totlen;

  ret = silc_calloc(buf->len, sizeof(*ret));
  memcpy(ret, buf->data, buf->len);
  silc_buffer_free(buf);

  return ret;
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
  buf = silc_buffer_alloc(totlen);
  silc_buffer_pull_tail(buf, totlen);

  silc_buffer_format(buf,
		     SILC_STR_UI_SHORT(strlen(pkcs)),
		     SILC_STR_UI32_STRING(pkcs),
		     SILC_STR_UI_XNSTRING(prv, prv_len),
		     SILC_STR_END);
  if (len)
    *len = totlen;

  ret = silc_calloc(buf->len, sizeof(*ret));
  memcpy(ret, buf->data, buf->len);
  silc_buffer_free(buf);

  return ret;
}

/* Decodes SILC style public key. Returns TRUE if the decoding was
   successful. Allocates new private key as well. */

int silc_pkcs_private_key_decode(unsigned char *data, SilcUInt32 data_len,
				 SilcPrivateKey *private_key)
{
  SilcBuffer buf;
  SilcPKCS alg;
  SilcUInt16 pkcs_len;
  SilcUInt32 key_len;
  unsigned char *pkcs_name = NULL, *key_data = NULL;
  int ret;

  buf = silc_buffer_alloc(data_len);
  silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));
  silc_buffer_put(buf, data, data_len);

  /* Get algorithm name and identifier */
  ret = 
    silc_buffer_unformat(buf,
			 SILC_STR_UI16_NSTRING_ALLOC(&pkcs_name, &pkcs_len),
			 SILC_STR_END);
  if (ret == -1)
    goto err;

  if (pkcs_len < 1 || pkcs_len > buf->truelen)
    goto err;

  /* See if we support this algorithm (check only if PKCS are registered). */
  if (silc_pkcs_list && !silc_pkcs_is_supported(pkcs_name)) {
    SILC_LOG_DEBUG(("Unknown PKCS `%s'", pkcs_name));
    goto err;
  }

  /* Get key data. We assume that rest of the buffer is key data. */
  silc_buffer_pull(buf, 2 + pkcs_len);
  key_len = buf->len;
  ret = silc_buffer_unformat(buf,
			     SILC_STR_UI_XNSTRING_ALLOC(&key_data, key_len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  /* Try to set the key. If this fails the key must be malformed. This
     code assumes that the PKCS routine checks the format of the key. 
     (check only if PKCS are registered) */
  if (silc_pkcs_list) {
    silc_pkcs_alloc(pkcs_name, &alg);
    if (!alg->pkcs->set_private_key(alg->context, key_data, key_len))
      goto err;
    silc_pkcs_free(alg);
  }
  
  if (private_key) {
    *private_key = silc_calloc(1, sizeof(**private_key));
    (*private_key)->name = pkcs_name;
    (*private_key)->prv = key_data;
    (*private_key)->prv_len = key_len;
  }

  silc_buffer_free(buf);
  return TRUE;

 err:
  if (pkcs_name)
    silc_free(pkcs_name);
  if (key_data)
    silc_free(key_data);
  silc_buffer_free(buf);
  return FALSE;
}

/* Internal routine to save public key */

static int silc_pkcs_save_public_key_internal(char *filename,
					      unsigned char *data,
					      SilcUInt32 data_len,
					      SilcUInt32 encoding)
{
  SilcBuffer buf;
  SilcUInt32 len;

  switch(encoding) {
  case SILC_PKCS_FILE_BIN:
    break;
  case SILC_PKCS_FILE_PEM:
    data = silc_encode_pem_file(data, data_len);
    data_len = strlen(data);
    break;
  }

  len = data_len + (strlen(SILC_PKCS_PUBLIC_KEYFILE_BEGIN) +
		    strlen(SILC_PKCS_PUBLIC_KEYFILE_END));
  buf = silc_buffer_alloc(len);
  silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));

  silc_buffer_format(buf,
		     SILC_STR_UI32_STRING(SILC_PKCS_PUBLIC_KEYFILE_BEGIN),
		     SILC_STR_UI_XNSTRING(data, data_len),
		     SILC_STR_UI32_STRING(SILC_PKCS_PUBLIC_KEYFILE_END),
		     SILC_STR_END);

  /* Save into file */
  if (silc_file_writefile(filename, buf->data, buf->len)) {
    silc_buffer_free(buf);
    return FALSE;
  }

  silc_buffer_free(buf);
  return TRUE;
}

/* Saves public key into file */

int silc_pkcs_save_public_key(char *filename, SilcPublicKey public_key,
			      SilcUInt32 encoding)
{
  unsigned char *data;
  SilcUInt32 data_len;

  data = silc_pkcs_public_key_encode(public_key, &data_len);
  return silc_pkcs_save_public_key_internal(filename, data, data_len,
					    encoding);
}

/* Saves public key into file */

int silc_pkcs_save_public_key_data(char *filename, unsigned char *data,
				   SilcUInt32 data_len,
				   SilcUInt32 encoding)
{
  return silc_pkcs_save_public_key_internal(filename, data, data_len,
					    encoding);
}

/* Internal routine to save private key. */

static int silc_pkcs_save_private_key_internal(char *filename,
					       unsigned char *data,
					       SilcUInt32 data_len,
					       SilcUInt32 encoding)
{
  SilcBuffer buf;
  SilcUInt32 len;

  switch(encoding) {
  case SILC_PKCS_FILE_BIN:
    break;
  case SILC_PKCS_FILE_PEM:
    data = silc_encode_pem_file(data, data_len);
    data_len = strlen(data);
    break;
  }

  len = data_len + (strlen(SILC_PKCS_PRIVATE_KEYFILE_BEGIN) +
		    strlen(SILC_PKCS_PRIVATE_KEYFILE_END));
  buf = silc_buffer_alloc(len);
  silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));

  silc_buffer_format(buf,
		     SILC_STR_UI32_STRING(SILC_PKCS_PRIVATE_KEYFILE_BEGIN),
		     SILC_STR_UI_XNSTRING(data, data_len),
		     SILC_STR_UI32_STRING(SILC_PKCS_PRIVATE_KEYFILE_END),
		     SILC_STR_END);

  /* Save into a file */
  if (silc_file_writefile_mode(filename, buf->data, buf->len, 0600)) {
    silc_buffer_free(buf);
    return FALSE;
  }

  silc_buffer_free(buf);
  return TRUE;
}

/* Saves private key into file. */
/* XXX The buffer should be encrypted if passphrase is provided. */

int silc_pkcs_save_private_key(char *filename, SilcPrivateKey private_key, 
			       unsigned char *passphrase,
			       SilcUInt32 encoding)
{
  unsigned char *data;
  SilcUInt32 data_len;

  data = silc_pkcs_private_key_encode(private_key, &data_len);
  return silc_pkcs_save_private_key_internal(filename, data, data_len,
					     encoding);
}

/* Saves private key into file. */
/* XXX The buffer should be encrypted if passphrase is provided. */

int silc_pkcs_save_private_key_data(char *filename, unsigned char *data, 
				    SilcUInt32 data_len,
				    unsigned char *passphrase,
				    SilcUInt32 encoding)
{
  return silc_pkcs_save_private_key_internal(filename, data, data_len,
					     encoding);
}

/* Loads public key from file and allocates new public key. Returns TRUE
   is loading was successful. */

int silc_pkcs_load_public_key(char *filename, SilcPublicKey *public_key,
			      SilcUInt32 encoding)
{
  unsigned char *cp, *old, *data, byte;
  SilcUInt32 i, data_len, len;

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
      data = silc_decode_pem(data, len, &len);
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
/* XXX Should support encrypted private key files */

int silc_pkcs_load_private_key(char *filename, SilcPrivateKey *private_key,
			       SilcUInt32 encoding)
{
  unsigned char *cp, *old, *data, byte;
  SilcUInt32 i, data_len, len;

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
  if (private_key) {
    len = data_len - (strlen(SILC_PKCS_PRIVATE_KEYFILE_BEGIN) +
		      strlen(SILC_PKCS_PRIVATE_KEYFILE_END));

    switch(encoding) {
    case SILC_PKCS_FILE_BIN:
      break;
    case SILC_PKCS_FILE_PEM:
      data = silc_decode_pem(data, len, &len);
      break;
    }

    if (!data || !silc_pkcs_private_key_decode(data, len, private_key)) {
      memset(old, 0, data_len);
      silc_free(old);
      return FALSE;
    }
  }

  memset(old, 0, data_len);
  silc_free(old);
  return TRUE;
}
