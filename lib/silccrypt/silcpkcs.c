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

/* List of all PKCS's in SILC. PKCS's don't support SIM's thus
   only static declarations are possible. XXX: I hope this to change
   real soon. */
SilcPKCSObject silc_pkcs_list[] =
{
  /* RSA with PKCS #1 (Uses directly routines from Raw RSA operations) */
  /*
  { "rsa", &silc_rsa_data_context, 
    silc_rsa_init, silc_rsa_clear_keys, silc_rsa_get_public_key,
    silc_rsa_get_private_key, silc_rsa_set_public_key,
    silc_rsa_set_private_key, silc_rsa_context_len,
    silc_rsa_data_context_len, silc_rsa_set_arg,
    silc_pkcs1_encrypt, silc_pkcs1_decrypt,
    silc_pkcs1_sign, silc_pkcs1_verify },
  */

  /* Raw RSA operations */
  { "rsa", &silc_rsa_data_context, 
    silc_rsa_init, silc_rsa_clear_keys, silc_rsa_get_public_key,
    silc_rsa_get_private_key, silc_rsa_set_public_key,
    silc_rsa_set_private_key, silc_rsa_context_len,
    silc_rsa_data_context_len, silc_rsa_set_arg,
    silc_rsa_encrypt, silc_rsa_decrypt,
    silc_rsa_sign, silc_rsa_verify },

  { NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL }
};

/* Allocates a new SilcPKCS object. The new allocated object is returned
   to the 'new_pkcs' argument. This function also initializes the data
   context structure. Function returns 1 on success and 0 on error.

*/
int silc_pkcs_alloc(const unsigned char *name, SilcPKCS *new_pkcs)
{
  int i;

  SILC_LOG_DEBUG(("Allocating new PKCS object"));

  for (i = 0; silc_pkcs_list[i].name; i++) {
    if (!strcmp(silc_pkcs_list[i].name, name))
      break;
  }

  if (silc_pkcs_list[i].name == NULL)
    return FALSE;

  *new_pkcs = silc_calloc(1, sizeof(**new_pkcs));

  /* Set the pointers */
  (*new_pkcs)->pkcs = &silc_pkcs_list[i];
  (*new_pkcs)->pkcs->data_context = 
    silc_calloc(1, (*new_pkcs)->pkcs->data_context_len());
  (*new_pkcs)->context = silc_calloc(1, (*new_pkcs)->pkcs->context_len());
  (*new_pkcs)->get_key_len = silc_pkcs_get_key_len;

  return TRUE;
}

/* Free's the PKCS object */

void silc_pkcs_free(SilcPKCS pkcs)
{
  if (pkcs)
    silc_free(pkcs->context);
}

/* Return TRUE if PKCS algorithm `name' is supported. */

int silc_pkcs_is_supported(const unsigned char *name)
{
  int i;

  for (i = 0; silc_pkcs_list[i].name; i++) {
    if (!strcmp(silc_pkcs_list[i].name, name))
      return TRUE;
  }

  return FALSE;
}

/* Returns comma separated list of supported PKCS algorithms */

char *silc_pkcs_get_supported()
{
  char *list = NULL;
  int i, len;

  len = 0;
  for (i = 0; silc_pkcs_list[i].name; i++) {
    len += strlen(silc_pkcs_list[i].name);
    list = silc_realloc(list, len + 1);

    memcpy(list + (len - strlen(silc_pkcs_list[i].name)), 
	   silc_pkcs_list[i].name, strlen(silc_pkcs_list[i].name));
    memcpy(list + len, ",", 1);
    len++;
  }

  list[len - 1] = 0;

  return list;
}

/* Returns the length of the key */

unsigned int silc_pkcs_get_key_len(SilcPKCS self)
{
  return self->key_len;
}

/* Returns SILC style public key */

unsigned char *silc_pkcs_get_public_key(SilcPKCS pkcs, unsigned int *len)
{
  return pkcs->pkcs->get_public_key(pkcs->context, len);
}

/* Returns SILC style private key */

unsigned char *silc_pkcs_get_private_key(SilcPKCS pkcs, unsigned int *len)
{
  return pkcs->pkcs->get_private_key(pkcs->context, len);
}

/* Sets public key from SilcPublicKey. */

int silc_pkcs_public_key_set(SilcPKCS pkcs, SilcPublicKey public_key)
{
  return pkcs->pkcs->set_public_key(pkcs->context, public_key->pk, 
				    public_key->pk_len);
}

/* Sets public key from data. */

int silc_pkcs_public_key_data_set(SilcPKCS pkcs, unsigned char *pk,
				  unsigned int pk_len)
{
  return pkcs->pkcs->set_public_key(pkcs->context, pk, pk_len);
}

/* Sets private key from SilcPrivateKey. */

int silc_pkcs_private_key_set(SilcPKCS pkcs, SilcPrivateKey private_key)
{
  return pkcs->pkcs->set_private_key(pkcs->context, private_key->prv, 
				     private_key->prv_len);
}

/* Sets private key from data. */

int silc_pkcs_private_key_data_set(SilcPKCS pkcs, unsigned char *prv,
				   unsigned int prv_len)
{
  return pkcs->pkcs->set_private_key(pkcs->context, prv, prv_len);
}

/* Encrypts */

int silc_pkcs_encrypt(SilcPKCS pkcs, unsigned char *src, unsigned int src_len,
		      unsigned char *dst, unsigned int *dst_len)
{
  return pkcs->pkcs->encrypt(pkcs->context, src, src_len, dst, dst_len);
}

/* Decrypts */

int silc_pkcs_decrypt(SilcPKCS pkcs, unsigned char *src, unsigned int src_len,
		      unsigned char *dst, unsigned int *dst_len)
{
  return pkcs->pkcs->decrypt(pkcs->context, src, src_len, dst, dst_len);
}

/* Generates signature */

int silc_pkcs_sign(SilcPKCS pkcs, unsigned char *src, unsigned int src_len,
		   unsigned char *dst, unsigned int *dst_len)
{
  return pkcs->pkcs->sign(pkcs->context, src, src_len, dst, dst_len);
}

/* Verifies signature */

int silc_pkcs_verify(SilcPKCS pkcs, unsigned char *signature, 
		     unsigned int signature_len, unsigned char *data, 
		     unsigned int data_len)
{
  return pkcs->pkcs->verify(pkcs->context, signature, signature_len, 
			    data, data_len);
}

/* Generates signature with hash. The hash is signed. */

int silc_pkcs_sign_with_hash(SilcPKCS pkcs, SilcHash hash,
			     unsigned char *src, unsigned int src_len,
			     unsigned char *dst, unsigned int *dst_len)
{
  unsigned char hashr[32];
  unsigned int hash_len;
  int ret;

  silc_hash_make(hash, src, src_len, hashr);
  hash_len = hash->hash->hash_len;

  ret = pkcs->pkcs->sign(pkcs->context, hashr, hash_len, dst, dst_len);
  memset(hashr, 0, sizeof(hashr));

  return ret;
}

/* Verifies signature with hash. The `data' is hashed and verified against
   the `signature'. */

int silc_pkcs_verify_with_hash(SilcPKCS pkcs, SilcHash hash, 
			       unsigned char *signature, 
			       unsigned int signature_len, 
			       unsigned char *data, 
			       unsigned int data_len)
{
  unsigned char hashr[32];
  unsigned int hash_len;
  int ret;

  silc_hash_make(hash, data, data_len, hashr);
  hash_len = hash->hash->hash_len;

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
  unsigned int len, tlen = 0;

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

/* Allocates SILC style public key formed from sent arguments. All data
   is duplicated. */

SilcPublicKey silc_pkcs_public_key_alloc(char *name, char *identifier,
					 unsigned char *pk, 
					 unsigned int pk_len)
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
					   unsigned int prv_len)
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
silc_pkcs_public_key_encode(SilcPublicKey public_key, unsigned int *len)
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
silc_pkcs_public_key_data_encode(unsigned char *pk, unsigned int pk_len,
				 char *pkcs, char *identifier, 
				 unsigned int *len)
{
  SilcBuffer buf;
  unsigned char *ret;
  unsigned int totlen;

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

int silc_pkcs_public_key_decode(unsigned char *data, unsigned int data_len,
				SilcPublicKey *public_key)
{
  SilcBuffer buf;
  SilcPKCS alg;
  unsigned short pkcs_len, identifier_len;
  unsigned int totlen, key_len;
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

  /* See if we support this algorithm */
  if (!silc_pkcs_is_supported(pkcs_name))
    goto err;

  /* Protocol says that at least UN and HN must be provided as identifier,
     check for these. */
  if (!strstr(ident, "UN=") && !strstr(ident, "HN="))
    goto err;

  /* Get key data. We assume that rest of the buffer is key data. */
  silc_buffer_pull(buf, 2 + pkcs_len + 2 + identifier_len);
  key_len = buf->len;
  ret = silc_buffer_unformat(buf,
			     SILC_STR_UI_XNSTRING_ALLOC(&key_data, key_len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  /* Try to set the key. If this fails the key must be malformed. This
     code assumes that the PKCS routine checks the format of the key. */
  silc_pkcs_alloc(pkcs_name, &alg);
  if (!alg->pkcs->set_public_key(alg->context, key_data, key_len))
    goto err;
  silc_pkcs_free(alg);
  
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

/* Encodes SILC private key from SilcPrivateKey. Returns the encoded data. */

unsigned char *
silc_pkcs_private_key_encode(SilcPrivateKey private_key, unsigned int *len)
{
  SilcBuffer buf;
  unsigned char *ret;
  unsigned int totlen;

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
silc_pkcs_private_key_data_encode(unsigned char *prv, unsigned int prv_len,
				  char *pkcs, unsigned int *len)
{
  SilcBuffer buf;
  unsigned char *ret;
  unsigned int totlen;

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

int silc_pkcs_private_key_decode(unsigned char *data, unsigned int data_len,
				 SilcPrivateKey *private_key)
{
  SilcBuffer buf;
  SilcPKCS alg;
  unsigned short pkcs_len;
  unsigned int key_len;
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

  /* See if we support this algorithm */
  if (!silc_pkcs_is_supported(pkcs_name))
    goto err;

  /* Get key data. We assume that rest of the buffer is key data. */
  silc_buffer_pull(buf, 2 + pkcs_len);
  key_len = buf->len;
  ret = silc_buffer_unformat(buf,
			     SILC_STR_UI_XNSTRING_ALLOC(&key_data, key_len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  /* Try to set the key. If this fails the key must be malformed. This
     code assumes that the PKCS routine checks the format of the key. */
  silc_pkcs_alloc(pkcs_name, &alg);
  if (!alg->pkcs->set_private_key(alg->context, key_data, key_len))
    goto err;
  silc_pkcs_free(alg);
  
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
					      unsigned int data_len,
					      unsigned int encoding)
{
  SilcBuffer buf;
  unsigned int len;

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
  if (silc_file_write(filename, buf->data, buf->len)) {
    silc_buffer_free(buf);
    return FALSE;
  }

  silc_buffer_free(buf);
  return TRUE;
}

/* Saves public key into file */

int silc_pkcs_save_public_key(char *filename, SilcPublicKey public_key,
			      unsigned int encoding)
{
  unsigned char *data;
  unsigned int data_len;

  data = silc_pkcs_public_key_encode(public_key, &data_len);
  return silc_pkcs_save_public_key_internal(filename, data, data_len,
					    encoding);
}

/* Saves public key into file */

int silc_pkcs_save_public_key_data(char *filename, unsigned char *data,
				   unsigned int data_len,
				   unsigned int encoding)
{
  return silc_pkcs_save_public_key_internal(filename, data, data_len,
					    encoding);
}

/* Internal routine to save private key. */

static int silc_pkcs_save_private_key_internal(char *filename,
					       unsigned char *data,
					       unsigned int data_len,
					       unsigned int encoding)
{
  SilcBuffer buf;
  unsigned int len;

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
  if (silc_file_write_mode(filename, buf->data, buf->len, 0600)) {
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
			       unsigned int encoding)
{
  unsigned char *data;
  unsigned int data_len;

  data = silc_pkcs_private_key_encode(private_key, &data_len);
  return silc_pkcs_save_private_key_internal(filename, data, data_len,
					     encoding);
}

/* Saves private key into file. */
/* XXX The buffer should be encrypted if passphrase is provided. */

int silc_pkcs_save_private_key_data(char *filename, unsigned char *data, 
				    unsigned int data_len,
				    unsigned char *passphrase,
				    unsigned int encoding)
{
  return silc_pkcs_save_private_key_internal(filename, data, data_len,
					     encoding);
}

/* Loads public key from file and allocates new public key. Returns TRUE
   is loading was successful. */

int silc_pkcs_load_public_key(char *filename, SilcPublicKey *public_key,
			      unsigned int encoding)
{
  unsigned char *cp, *old, *data, byte;
  unsigned int i, data_len, len;

  old = data = silc_file_read(filename, &data_len);
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
			       unsigned int encoding)
{
  unsigned char *cp, *old, *data, byte;
  unsigned int i, data_len, len;

  old = data = silc_file_read(filename, &data_len);
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
