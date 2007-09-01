/*

  silcpk.c

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

#include "silc.h"
#include "silcpk_i.h"

/****************************** Key generation *******************************/

/* Generate new SILC key pair. */

SilcBool silc_pkcs_silc_generate_key(const char *algorithm,
				     SilcUInt32 bits_key_len,
				     const char *identifier,
				     SilcRng rng,
				     SilcPublicKey *ret_public_key,
				     SilcPrivateKey *ret_private_key)
{
  SilcSILCPublicKey pubkey;
  SilcSILCPrivateKey privkey;
  const SilcPKCSAlgorithm *alg;
  const SilcPKCSObject *pkcs;
  SilcUInt32 version;

  SILC_LOG_DEBUG(("Generating SILC %s key pair with key length %d bits",
		  algorithm, bits_key_len));

  if (!rng)
    return FALSE;

  pkcs = silc_pkcs_find_pkcs(SILC_PKCS_SILC);
  if (!pkcs)
    return FALSE;

  /* Allocate SILC public key */
  pubkey = silc_calloc(1, sizeof(*pubkey));
  if (!pubkey)
    return FALSE;

  /* Decode identifier */
  if (!silc_pkcs_silc_decode_identifier(identifier, &pubkey->identifier))
    return FALSE;

  if (pubkey->identifier.version && atoi(pubkey->identifier.version) >= 2)
    version = 2;
  else
    version = 1;

  /* Allocate algorithm */
  alg = silc_pkcs_find_algorithm(algorithm, (version == 1 ? "pkcs1-no-oid" :
					     "pkcs1"));
  if (!alg) {
    silc_free(pubkey);
    return FALSE;
  }
  pubkey->pkcs = alg;

  /* Allocate SILC private key */
  privkey = silc_calloc(1, sizeof(*privkey));
  if (!privkey) {
    silc_free(pubkey);
    return FALSE;
  }
  privkey->pkcs = alg;

  /* Allocate public key */
  *ret_public_key = silc_calloc(1, sizeof(**ret_public_key));
  if (!(*ret_public_key)) {
    silc_free(pubkey);
    silc_free(privkey);
    return FALSE;
  }
  (*ret_public_key)->pkcs = pkcs;
  (*ret_public_key)->public_key = pubkey;

  /* Allocate private key */
  *ret_private_key = silc_calloc(1, sizeof(**ret_private_key));
  if (!(*ret_private_key)) {
    silc_free(pubkey);
    silc_free(privkey);
    silc_free(*ret_public_key);
    return FALSE;
  }
  (*ret_private_key)->pkcs = pkcs;
  (*ret_private_key)->private_key = privkey;

  /* Generate the algorithm key pair */
  if (!alg->generate_key(bits_key_len, rng, &pubkey->public_key,
			 &privkey->private_key)) {
    silc_free(pubkey);
    silc_free(privkey);
    silc_free(*ret_public_key);
    silc_free(*ret_private_key);
    return FALSE;
  }

  return TRUE;
}


/**************************** Utility functions ******************************/

/* Decodes the provided `identifier' */

SilcBool silc_pkcs_silc_decode_identifier(const char *identifier,
					  SilcPublicKeyIdentifier ident)
{
  char *cp, *item;
  int len;

  /* Protocol says that at least UN and HN must be provided as identifier */
  if (!strstr(identifier, "UN=") || !strstr(identifier, "HN=")) {
    SILC_LOG_DEBUG(("The public does not have the required UN= and HN= "
		    "identifiers"));
    return FALSE;
  }

  cp = (char *)identifier;
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
    if (!item)
      return FALSE;
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
    else if (strstr(item, "V="))
      ident->version = strdup(item + strcspn(cp, "=") + 1);

    cp += len;
    if (strlen(cp) < 1)
      cp = NULL;
    else
      cp += 1;

    if (item)
      silc_free(item);
  }

  return TRUE;
}

/* Encodes and returns SILC public key identifier.  If some of the
   arguments is NULL those are not encoded into the identifier string.
   Protocol says that at least username and host must be provided. */

char *silc_pkcs_silc_encode_identifier(char *username, char *host,
				       char *realname, char *email,
				       char *org, char *country,
				       char *version)
{
  SilcBufferStruct buf;
  char *identifier;

  if (!username || !host)
    return NULL;
  if (strlen(username) < 1 || strlen(host) < 1)
    return NULL;

  memset(&buf, 0, sizeof(buf));

  if (username)
    silc_buffer_format(&buf,
		       SILC_STR_ADVANCE,
		       SILC_STR_UI32_STRING("UN="),
		       SILC_STR_UI32_STRING(username),
		       SILC_STR_END);

  if (host)
    silc_buffer_format(&buf,
		       SILC_STR_ADVANCE,
		       SILC_STR_UI32_STRING(", "),
		       SILC_STR_UI32_STRING("HN="),
		       SILC_STR_UI32_STRING(host),
		       SILC_STR_END);

  if (realname)
    silc_buffer_format(&buf,
		       SILC_STR_ADVANCE,
		       SILC_STR_UI32_STRING(", "),
		       SILC_STR_UI32_STRING("RN="),
		       SILC_STR_UI32_STRING(realname),
		       SILC_STR_END);

  if (email)
    silc_buffer_format(&buf,
		       SILC_STR_ADVANCE,
		       SILC_STR_UI32_STRING(", "),
		       SILC_STR_UI32_STRING("E="),
		       SILC_STR_UI32_STRING(email),
		       SILC_STR_END);

  if (org)
    silc_buffer_format(&buf,
		       SILC_STR_ADVANCE,
		       SILC_STR_UI32_STRING(", "),
		       SILC_STR_UI32_STRING("O="),
		       SILC_STR_UI32_STRING(org),
		       SILC_STR_END);

  if (country)
    silc_buffer_format(&buf,
		       SILC_STR_ADVANCE,
		       SILC_STR_UI32_STRING(", "),
		       SILC_STR_UI32_STRING("C="),
		       SILC_STR_UI32_STRING(country),
		       SILC_STR_END);

  if (version) {
    if (strlen(version) > 1 || !isdigit(version[0])) {
      silc_buffer_purge(&buf);
      return NULL;
    }
    silc_buffer_format(&buf,
		       SILC_STR_ADVANCE,
		       SILC_STR_UI32_STRING(", "),
		       SILC_STR_UI32_STRING("V="),
		       SILC_STR_UI32_STRING(version),
		       SILC_STR_END);
  }

  silc_buffer_format(&buf, SILC_STR_UI_CHAR(0), SILC_STR_END);

  identifier = silc_buffer_steal(&buf, NULL);
  return identifier;
}

/* Return SILC public key version */

int silc_pkcs_silc_public_key_version(SilcPublicKey public_key)
{
  SilcSILCPublicKey silc_pubkey;

  if (silc_pkcs_get_type(public_key) != SILC_PKCS_SILC)
    return -1;

  silc_pubkey = public_key->public_key;

  /* If version identifire is not present it is version 1. */
  if (!silc_pubkey->identifier.version)
    return 1;

  return atoi(silc_pubkey->identifier.version);
}

/*************************** Public key routines *****************************/

/* Returns PKCS algorithm context */

const SilcPKCSAlgorithm *silc_pkcs_silc_get_algorithm(void *public_key)
{
  SilcSILCPublicKey silc_pubkey = public_key;
  return silc_pubkey->pkcs;
}

/* Imports SILC protocol style public key from SILC public key file */

SilcBool silc_pkcs_silc_import_public_key_file(unsigned char *filedata,
					       SilcUInt32 filedata_len,
					       SilcPKCSFileEncoding encoding,
					       void **ret_public_key)
{
  SilcUInt32 i, len;
  unsigned char *data = NULL;
  int ret;

  SILC_LOG_DEBUG(("Parsing SILC public key file"));

  if (!ret_public_key)
    return FALSE;

  /* Check start of file and remove header from the data. */
  len = strlen(SILC_PKCS_PUBLIC_KEYFILE_BEGIN);
  if (filedata_len < len + strlen(SILC_PKCS_PUBLIC_KEYFILE_END)) {
    SILC_LOG_ERROR(("Malformed SILC public key header"));
    return FALSE;
  }
  for (i = 0; i < len; i++) {
    if (*filedata != SILC_PKCS_PUBLIC_KEYFILE_BEGIN[i]) {
      SILC_LOG_ERROR(("Malformed SILC public key header"));
      return FALSE;
    }
    filedata++;
  }
  filedata_len -= (strlen(SILC_PKCS_PUBLIC_KEYFILE_BEGIN) +
		   strlen(SILC_PKCS_PUBLIC_KEYFILE_END));

  switch (encoding) {
  case SILC_PKCS_FILE_BIN:
    break;

  case SILC_PKCS_FILE_BASE64:
    data = silc_base64_decode(filedata, filedata_len, &filedata_len);
    if (!data)
      return FALSE;
    filedata = data;
    break;
  }

  ret = silc_pkcs_silc_import_public_key(filedata, filedata_len,
					 ret_public_key);
  silc_free(data);

  return ret ? TRUE : FALSE;
}

/* Imports SILC protocol style public key */

int silc_pkcs_silc_import_public_key(unsigned char *key,
				     SilcUInt32 key_len,
				     void **ret_public_key)
{
  const SilcPKCSAlgorithm *pkcs;
  SilcBufferStruct buf, alg_key;
  SilcSILCPublicKey silc_pubkey = NULL;
  SilcAsn1 asn1 = NULL;
  SilcUInt32 totlen, keydata_len;
  SilcUInt16 pkcs_len, identifier_len;
  unsigned char *pkcs_name = NULL, *ident = NULL, *key_data = NULL;
  int ret;

  SILC_LOG_DEBUG(("Parsing SILC public key"));

  if (!ret_public_key)
    return 0;

  silc_buffer_set(&buf, key, key_len);

  /* Get length */
  ret = silc_buffer_unformat(&buf,
			     SILC_STR_ADVANCE,
			     SILC_STR_UI_INT(&totlen),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  /* Backwards compatibility */
  if (totlen == key_len)
    totlen -= 4;

  if (totlen + 4 != key_len)
    goto err;

  /* Get algorithm name and identifier */
  ret =
    silc_buffer_unformat(&buf,
			 SILC_STR_ADVANCE,
			 SILC_STR_UI16_NSTRING_ALLOC(&pkcs_name, &pkcs_len),
			 SILC_STR_UI16_NSTRING_ALLOC(&ident, &identifier_len),
			 SILC_STR_END);
  if (ret == -1)
    goto err;

  if (pkcs_len < 1 || identifier_len < 3 ||
      pkcs_len + identifier_len > totlen)
    goto err;

  /* Get key data */
  keydata_len = silc_buffer_len(&buf);
  ret = silc_buffer_unformat(&buf,
			     SILC_STR_DATA(&key_data, keydata_len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  /* Allocate SILC public key context */
  silc_pubkey = silc_calloc(1, sizeof(*silc_pubkey));
  if (!silc_pubkey)
    goto err;

  /* Decode SILC identifier */
  if (!silc_pkcs_silc_decode_identifier(ident, &silc_pubkey->identifier))
    goto err;

  asn1 = silc_asn1_alloc();
  if (!asn1)
    goto err;

  SILC_LOG_DEBUG(("Public key version %s",
		  (!silc_pubkey->identifier.version ? "1" :
		   silc_pubkey->identifier.version)));

  if (!strcmp(pkcs_name, "rsa")) {
    /* Parse the SILC RSA public key */
    SilcUInt32 e_len, n_len;
    SilcMPInt n, e;

    /* Get PKCS object.  Different PKCS #1 scheme is used with different
       versions. */
    if (!silc_pubkey->identifier.version ||
	atoi(silc_pubkey->identifier.version) <= 1) {
      /* Version 1 */
      pkcs = silc_pkcs_find_algorithm(pkcs_name, "pkcs1-no-oid");
    } else {
      /* Version 2 and newer */
      pkcs = silc_pkcs_find_algorithm(pkcs_name, "pkcs1");
    }
    if (!pkcs) {
      SILC_LOG_DEBUG(("Unsupported PKCS algorithm: rsa"));
      goto err;
    }
    silc_pubkey->pkcs = pkcs;

    if (keydata_len < 4)
      goto err;
    SILC_GET32_MSB(e_len, key_data);
    if (!e_len || e_len + 4 > keydata_len)
      goto err;
    silc_mp_init(&e);
    silc_mp_bin2mp(key_data + 4, e_len, &e);
    if (keydata_len < 4 + e_len + 4) {
      silc_mp_uninit(&e);
      goto err;
    }
    SILC_GET32_MSB(n_len, key_data + 4 + e_len);
    if (!n_len || e_len + 4 + n_len + 4 > keydata_len) {
      silc_mp_uninit(&e);
      goto err;
    }
    silc_mp_init(&n);
    silc_mp_bin2mp(key_data + 4 + e_len + 4, n_len, &n);

    /* Encode to PKCS #1 format */
    memset(&alg_key, 0, sizeof(alg_key));
    if (!silc_asn1_encode(asn1, &alg_key,
			  SILC_ASN1_SEQUENCE,
			    SILC_ASN1_INT(&n),
			    SILC_ASN1_INT(&e),
			  SILC_ASN1_END, SILC_ASN1_END)) {
      silc_mp_uninit(&e);
      silc_mp_uninit(&n);
      goto err;
    }

    silc_mp_uninit(&e);
    silc_mp_uninit(&n);

  } else if (!strcmp(pkcs_name, "dsa")) {
    SILC_NOT_IMPLEMENTED("DSA SILC Public Key");
    goto err;

  } else {
    SILC_LOG_DEBUG(("Unsupported PKCS algorithm"));
    goto err;
  }

  /* Import PKCS algorithm public key */
  if (!pkcs->import_public_key(alg_key.data, silc_buffer_len(&alg_key),
			       &silc_pubkey->public_key))
    goto err;

  silc_free(pkcs_name);
  silc_free(ident);
  silc_asn1_free(asn1);

  *ret_public_key = silc_pubkey;

  return key_len;

 err:
  silc_free(pkcs_name);
  silc_free(ident);
  silc_free(silc_pubkey);
  if (asn1)
    silc_asn1_free(asn1);
  return 0;
}

/* Exports public key as SILC protocol style public key file */

unsigned char *
silc_pkcs_silc_export_public_key_file(void *public_key,
				      SilcPKCSFileEncoding encoding,
				      SilcUInt32 *ret_len)
{
  SilcBuffer buf;
  unsigned char *key, *data;
  SilcUInt32 key_len;

  SILC_LOG_DEBUG(("Encoding SILC public key file"));

  /* Export key */
  key = silc_pkcs_silc_export_public_key(public_key, &key_len);
  if (!key)
    return NULL;

  switch (encoding) {
  case SILC_PKCS_FILE_BIN:
    break;

  case SILC_PKCS_FILE_BASE64:
    data = silc_base64_encode_file(key, key_len);
    if (!data)
      return NULL;
    silc_free(key);
    key = data;
    key_len = strlen(data);
    break;
  }

  /* Encode SILC public key file */
  buf = silc_buffer_alloc_size(key_len +
			       (strlen(SILC_PKCS_PUBLIC_KEYFILE_BEGIN) +
				strlen(SILC_PKCS_PUBLIC_KEYFILE_END)));
  if (!buf) {
    silc_free(key);
    return NULL;
  }

  if (silc_buffer_format(buf,
			 SILC_STR_UI32_STRING(SILC_PKCS_PUBLIC_KEYFILE_BEGIN),
			 SILC_STR_UI_XNSTRING(key, key_len),
			 SILC_STR_UI32_STRING(SILC_PKCS_PUBLIC_KEYFILE_END),
			 SILC_STR_END) < 0) {
    silc_buffer_free(buf);
    silc_free(key);
    return NULL;
  }

  silc_free(key);
  key = silc_buffer_steal(buf, ret_len);
  silc_buffer_free(buf);

  return key;
}

/* Exports public key as SILC protocol style public key */

unsigned char *silc_pkcs_silc_export_public_key(void *public_key,
						SilcUInt32 *ret_len)
{
  SilcSILCPublicKey silc_pubkey = public_key;
  const SilcPKCSAlgorithm *pkcs = silc_pubkey->pkcs;
  SilcBufferStruct alg_key;
  SilcBuffer buf = NULL;
  SilcAsn1 asn1 = NULL;
  unsigned char *pk = NULL, *key = NULL, *ret;
  SilcUInt32 pk_len, key_len, totlen;
  char *identifier;

  SILC_LOG_DEBUG(("Encoding SILC public key"));

  /* Export PKCS algorithm public key */
  if (pkcs->export_public_key)
    pk = pkcs->export_public_key(silc_pubkey->public_key, &pk_len);
  if (!pk) {
    SILC_LOG_ERROR(("Error exporting PKCS algorithm key"));
    return NULL;
  }
  silc_buffer_set(&alg_key, pk, pk_len);

  /* Encode identifier */
  identifier =
    silc_pkcs_silc_encode_identifier(silc_pubkey->identifier.username,
				     silc_pubkey->identifier.host,
				     silc_pubkey->identifier.realname,
				     silc_pubkey->identifier.email,
				     silc_pubkey->identifier.org,
				     silc_pubkey->identifier.country,
				     silc_pubkey->identifier.version);
  if (!identifier) {
    SILC_LOG_ERROR(("Error encoding SILC public key identifier"));
    goto err;
  }

  asn1 = silc_asn1_alloc();
  if (!asn1)
    goto err;

  if (!strcmp(pkcs->name, "rsa")) {
    /* Parse the PKCS #1 public key */
    SilcMPInt n, e;
    SilcUInt32 n_len, e_len;
    unsigned char *nb, *eb;

    memset(&n, 0, sizeof(n));
    memset(&e, 0, sizeof(e));
    if (!silc_asn1_decode(asn1, &alg_key,
			  SILC_ASN1_SEQUENCE,
			    SILC_ASN1_INT(&n),
			    SILC_ASN1_INT(&e),
			  SILC_ASN1_END, SILC_ASN1_END))
      goto err;

    /* Encode to SILC RSA public key */
    eb = silc_mp_mp2bin(&e, 0, &e_len);
    if (!eb)
      goto err;
    nb = silc_mp_mp2bin(&n, 0, &n_len);
    if (!nb)
      goto err;
    key_len = e_len + 4 + n_len + 4;
    key = silc_calloc(key_len, sizeof(*key));
    if (!key)
      goto err;

    /* Put e length and e */
    SILC_PUT32_MSB(e_len, key);
    memcpy(key + 4, eb, e_len);

    /* Put n length and n. */
    SILC_PUT32_MSB(n_len, key + 4 + e_len);
    memcpy(key + 4 + e_len + 4, nb, n_len);

    silc_free(nb);
    silc_free(eb);

  } else if (!strcmp(pkcs->name, "dsa")) {
    SILC_NOT_IMPLEMENTED("SILC DSA Public Key");
    goto err;

  } else {
    SILC_LOG_ERROR(("Unsupported PKCS algorithm: %s", pkcs->name));
    goto err;
  }

  /* Encode SILC Public Key */
  totlen = 2 + strlen(pkcs->name) + 2 + strlen(identifier) + key_len;
  buf = silc_buffer_alloc_size(totlen + 4);
  if (!buf)
    goto err;
  if (silc_buffer_format(buf,
			 SILC_STR_UI_INT(totlen),
			 SILC_STR_UI_SHORT(strlen(pkcs->name)),
			 SILC_STR_UI32_STRING(pkcs->name),
			 SILC_STR_UI_SHORT(strlen(identifier)),
			 SILC_STR_UI32_STRING(identifier),
			 SILC_STR_UI_XNSTRING(key, key_len),
			 SILC_STR_END) < 0)
    goto err;

  ret = silc_buffer_steal(buf, ret_len);
  silc_buffer_free(buf);
  silc_free(key);
  silc_free(identifier);
  silc_buffer_purge(&alg_key);
  silc_asn1_free(asn1);

  return ret;

 err:
  silc_free(identifier);
  silc_free(pk);
  silc_free(key);
  if (buf)
    silc_buffer_free(buf);
  if (asn1)
    silc_asn1_free(asn1);
  return NULL;
}

/* Return key length */

SilcUInt32 silc_pkcs_silc_public_key_bitlen(void *public_key)
{
  SilcSILCPublicKey silc_pubkey = public_key;
  return silc_pubkey->pkcs->public_key_bitlen(silc_pubkey->public_key);
}

/* Copy public key */

void *silc_pkcs_silc_public_key_copy(void *public_key)
{
  SilcSILCPublicKey silc_pubkey = public_key, new_pubkey;
  SilcPublicKeyIdentifier ident = &silc_pubkey->identifier;

  new_pubkey = silc_calloc(1, sizeof(*new_pubkey));
  if (!new_pubkey)
    return NULL;
  new_pubkey->pkcs = silc_pubkey->pkcs;

  new_pubkey->public_key =
    silc_pubkey->pkcs->public_key_copy(silc_pubkey->public_key);
  if (!new_pubkey->public_key) {
    silc_free(new_pubkey);
    return NULL;
  }

  if (ident->username)
    new_pubkey->identifier.username =
      silc_memdup(ident->username, strlen(ident->username));
  if (ident->host)
    new_pubkey->identifier.host =
      silc_memdup(ident->host, strlen(ident->host));
  if (ident->realname)
    new_pubkey->identifier.realname =
      silc_memdup(ident->realname, strlen(ident->realname));
  if (ident->email)
    new_pubkey->identifier.email =
      silc_memdup(ident->email, strlen(ident->email));
  if (ident->org)
    new_pubkey->identifier.org =
      silc_memdup(ident->org, strlen(ident->org));
  if (ident->country)
    new_pubkey->identifier.country =
      silc_memdup(ident->country, strlen(ident->country));
  if (ident->version)
    new_pubkey->identifier.version =
      silc_memdup(ident->version, strlen(ident->version));

  return new_pubkey;
}

/* Compares public keys */

SilcBool silc_pkcs_silc_public_key_compare(void *key1, void *key2)
{
  SilcSILCPublicKey k1 = key1, k2 = key2;

  if (strcmp(k1->pkcs->name, k2->pkcs->name))
    return FALSE;

  if ((k1->identifier.username && !k2->identifier.username) ||
      (!k1->identifier.username && k2->identifier.username) ||
      (k1->identifier.username && k2->identifier.username &&
       strcmp(k1->identifier.username, k2->identifier.username)))
    return FALSE;

  if ((k1->identifier.host && !k2->identifier.host) ||
      (!k1->identifier.host && k2->identifier.host) ||
      (k1->identifier.host && k2->identifier.host &&
       strcmp(k1->identifier.host, k2->identifier.host)))
    return FALSE;

  if ((k1->identifier.realname && !k2->identifier.realname) ||
      (!k1->identifier.realname && k2->identifier.realname) ||
      (k1->identifier.realname && k2->identifier.realname &&
       strcmp(k1->identifier.realname, k2->identifier.realname)))
    return FALSE;

  if ((k1->identifier.email && !k2->identifier.email) ||
      (!k1->identifier.email && k2->identifier.email) ||
      (k1->identifier.email && k2->identifier.email &&
       strcmp(k1->identifier.email, k2->identifier.email)))
    return FALSE;

  if ((k1->identifier.org && !k2->identifier.org) ||
      (!k1->identifier.org && k2->identifier.org) ||
      (k1->identifier.org && k2->identifier.org &&
       strcmp(k1->identifier.org, k2->identifier.org)))
    return FALSE;

  if ((k1->identifier.country && !k2->identifier.country) ||
      (!k1->identifier.country && k2->identifier.country) ||
      (k1->identifier.country && k2->identifier.country &&
       strcmp(k1->identifier.country, k2->identifier.country)))
    return FALSE;

  if ((k1->identifier.version && !k2->identifier.version) ||
      (!k1->identifier.version && k2->identifier.version) ||
      (k1->identifier.version && k2->identifier.version &&
       strcmp(k1->identifier.version, k2->identifier.version)))
    return FALSE;

  return k1->pkcs->public_key_compare(k1->public_key, k2->public_key);
}

/* Frees public key */

void silc_pkcs_silc_public_key_free(void *public_key)
{
  SilcSILCPublicKey silc_pubkey = public_key;

  silc_pubkey->pkcs->public_key_free(silc_pubkey->public_key);

  silc_free(silc_pubkey->identifier.username);
  silc_free(silc_pubkey->identifier.host);
  silc_free(silc_pubkey->identifier.realname);
  silc_free(silc_pubkey->identifier.email);
  silc_free(silc_pubkey->identifier.org);
  silc_free(silc_pubkey->identifier.country);
  silc_free(silc_pubkey->identifier.version);
  silc_free(silc_pubkey);
}


/*************************** Private key routines ****************************/

/* Private key file magic */
#define SILC_PKCS_PRIVATE_KEY_MAGIC 0x738df531

/* Imports SILC implementation style private key file */

SilcBool silc_pkcs_silc_import_private_key_file(unsigned char *filedata,
						SilcUInt32 filedata_len,
						const char *passphrase,
						SilcUInt32 passphrase_len,
						SilcPKCSFileEncoding encoding,
						void **ret_private_key)
{
  SilcCipher aes;
  SilcHash sha1;
  SilcHmac sha1hmac;
  SilcUInt32 blocklen;
  unsigned char tmp[32], keymat[64], *data = NULL;
  SilcUInt32 i, len, magic, mac_len;
  int ret;

  SILC_LOG_DEBUG(("Parsing SILC private key file"));

  /* Check start of file and remove header from the data. */
  len = strlen(SILC_PKCS_PRIVATE_KEYFILE_BEGIN);
  if (filedata_len < len + strlen(SILC_PKCS_PRIVATE_KEYFILE_END)) {
    SILC_LOG_ERROR(("Malformed SILC private key header"));
    return FALSE;
  }
  for (i = 0; i < len; i++) {
    if (*filedata != SILC_PKCS_PRIVATE_KEYFILE_BEGIN[i]) {
      SILC_LOG_ERROR(("Malformed SILC private key header"));
      return FALSE;
    }
    filedata++;
  }

  len = filedata_len - (strlen(SILC_PKCS_PRIVATE_KEYFILE_BEGIN) +
			strlen(SILC_PKCS_PRIVATE_KEYFILE_END));

  switch (encoding) {
  case SILC_PKCS_FILE_BIN:
    break;

  case SILC_PKCS_FILE_BASE64:
    data = silc_base64_decode(filedata, filedata_len, &len);
    if (!data)
      return FALSE;
    filedata = data;
    break;
  }

  memset(tmp, 0, sizeof(tmp));
  memset(keymat, 0, sizeof(keymat));

  /* Check file magic */
  SILC_GET32_MSB(magic, filedata);
  if (magic != SILC_PKCS_PRIVATE_KEY_MAGIC) {
    SILC_LOG_DEBUG(("Private key does not have correct magic"));
    return FALSE;
  }

  /* Allocate the AES cipher */
  if (!silc_cipher_alloc("aes-256-cbc", &aes)) {
    SILC_LOG_ERROR(("Could not allocate AES cipher, probably not registered"));
    return FALSE;
  }
  blocklen = silc_cipher_get_block_len(aes);
  if (blocklen * 2 > sizeof(tmp)) {
    silc_cipher_free(aes);
    return FALSE;
  }

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
  silc_cipher_set_key(aes, keymat, 256, FALSE);

  /* First, verify the MAC of the private key data */
  mac_len = silc_hmac_len(sha1hmac);
  silc_hmac_init_with_key(sha1hmac, keymat, 16);
  silc_hmac_update(sha1hmac, filedata, len - mac_len);
  silc_hmac_final(sha1hmac, tmp, NULL);
  if (memcmp(tmp, filedata + (len - mac_len), mac_len)) {
    SILC_LOG_DEBUG(("Integrity check for private key failed"));
    memset(keymat, 0, sizeof(keymat));
    memset(tmp, 0, sizeof(tmp));
    silc_hmac_free(sha1hmac);
    silc_hash_free(sha1);
    silc_cipher_free(aes);
    return FALSE;
  }
  filedata += 4;
  len -= 4;

  /* Decrypt the private key buffer */
  silc_cipher_decrypt(aes, filedata, filedata, len - mac_len, NULL);
  SILC_GET32_MSB(i, filedata);
  if (i > len) {
    SILC_LOG_DEBUG(("Bad private key length in buffer!"));
    memset(keymat, 0, sizeof(keymat));
    memset(tmp, 0, sizeof(tmp));
    silc_hmac_free(sha1hmac);
    silc_hash_free(sha1);
    silc_cipher_free(aes);
    return FALSE;
  }
  filedata += 4;
  len = i;

  /* Cleanup */
  memset(keymat, 0, sizeof(keymat));
  memset(tmp, 0, sizeof(tmp));
  silc_hmac_free(sha1hmac);
  silc_hash_free(sha1);
  silc_cipher_free(aes);

  /* Import the private key */
  ret = silc_pkcs_silc_import_private_key(filedata, len, ret_private_key);

  silc_free(data);

  return ret ? TRUE : FALSE;
}

/* Private key version */
#define SILC_PRIVATE_KEY_VERSION_1 0x82171273
#define SILC_PRIVATE_KEY_VERSION_2 0xf911a3d1

/* Imports SILC implementation style private key */

int silc_pkcs_silc_import_private_key(unsigned char *key,
				      SilcUInt32 key_len,
				      void **ret_private_key)
{
  SilcBufferStruct buf;
  const SilcPKCSAlgorithm *pkcs;
  SilcBufferStruct alg_key;
  SilcSILCPrivateKey silc_privkey = NULL;
  SilcAsn1 asn1 = NULL;
  SilcUInt16 pkcs_len;
  SilcUInt32 keydata_len;
  unsigned char *pkcs_name = NULL, *key_data;
  int ret;

  SILC_LOG_DEBUG(("Parsing SILC private key"));

  if (!ret_private_key)
    return 0;

  silc_buffer_set(&buf, key, key_len);

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

  /* Get key data. We assume that rest of the buffer is key data. */
  silc_buffer_pull(&buf, 2 + pkcs_len);
  keydata_len = silc_buffer_len(&buf);
  ret = silc_buffer_unformat(&buf,
			     SILC_STR_UI_XNSTRING(&key_data, keydata_len),
			     SILC_STR_END);
  if (ret == -1)
    goto err;

  /* Allocate SILC private key context */
  silc_privkey = silc_calloc(1, sizeof(*silc_privkey));
  if (!silc_privkey)
    goto err;

  asn1 = silc_asn1_alloc();
  if (!asn1)
    goto err;

  if (!strcmp(pkcs_name, "rsa")) {
    /* Parse the RSA SILC private key */
    SilcBufferStruct k;
    SilcMPInt n, e, d, dp, dq, qp, p, q;
    unsigned char *tmp;
    SilcUInt32 len, ver;

    if (keydata_len < 4)
      goto err;
    silc_buffer_set(&k, key_data, keydata_len);

    /* Get version.  Key without the version is old style private key
       and we need to do some computation to get it to correct format. */
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_INT(&ver),
			     SILC_STR_END) < 0)
      goto err;
    silc_buffer_pull(&k, 4);

    if (ver != SILC_PRIVATE_KEY_VERSION_1 &&
	ver != SILC_PRIVATE_KEY_VERSION_2) {
      len = ver;
      ver = 0;
    } else {
      if (silc_buffer_unformat(&k,
			       SILC_STR_UI_INT(&len),
			       SILC_STR_END) < 0)
	goto err;
      silc_buffer_pull(&k, 4);
    }

    /* Get PKCS object.  Different PKCS #1 scheme is used with different
       versions. */
    if (ver == 0 || ver == SILC_PRIVATE_KEY_VERSION_1) {
      /* Version 0 and 1 */
      pkcs = silc_pkcs_find_algorithm(pkcs_name, "pkcs1-no-oid");
    } else {
      /* Version 2 and newer */
      pkcs = silc_pkcs_find_algorithm(pkcs_name, "pkcs1");
    }
    if (!pkcs) {
      SILC_LOG_DEBUG(("Unsupported PKCS algorithm"));
      goto err;
    }
    silc_privkey->pkcs = pkcs;

    SILC_LOG_DEBUG(("Private key version %s",
		    (ver == SILC_PRIVATE_KEY_VERSION_1 ? "1" :
		     ver == SILC_PRIVATE_KEY_VERSION_2 ? "2" : "0")));

    /* Get e */
    if (silc_buffer_unformat(&k,
			     SILC_STR_DATA(&tmp, len),
			     SILC_STR_END) < 0)
      goto err;
    silc_mp_init(&e);
    silc_mp_bin2mp(tmp, len, &e);
    silc_buffer_pull(&k, len);

    /* Get n */
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_INT(&len),
			     SILC_STR_END) < 0)
      goto err;
    silc_buffer_pull(&k, 4);
    if (silc_buffer_unformat(&k,
			     SILC_STR_DATA(&tmp, len),
			     SILC_STR_END) < 0)
      goto err;
    silc_mp_init(&n);
    silc_mp_bin2mp(tmp, len, &n);
    silc_buffer_pull(&k, len);

    /* Get d */
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_INT(&len),
			     SILC_STR_END) < 0)
      goto err;
    silc_buffer_pull(&k, 4);
    if (silc_buffer_unformat(&k,
			     SILC_STR_DATA(&tmp, len),
			     SILC_STR_END) < 0)
      goto err;
    silc_mp_init(&d);
    silc_mp_bin2mp(tmp, len, &d);
    silc_buffer_pull(&k, len);

    /* Get dP */
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_INT(&len),
			     SILC_STR_END) < 0)
      goto err;
    silc_buffer_pull(&k, 4);
    if (silc_buffer_unformat(&k,
			     SILC_STR_DATA(&tmp, len),
			     SILC_STR_END) < 0)
      goto err;
    silc_mp_init(&dp);
    silc_mp_bin2mp(tmp, len, &dp);
    silc_buffer_pull(&k, len);

    /* Get dQ */
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_INT(&len),
			     SILC_STR_END) < 0)
      goto err;
    silc_buffer_pull(&k, 4);
    if (silc_buffer_unformat(&k,
			     SILC_STR_DATA(&tmp, len),
			     SILC_STR_END) < 0)
      goto err;
    silc_mp_init(&dq);
    silc_mp_bin2mp(tmp, len, &dq);
    silc_buffer_pull(&k, len);

    if (ver == 0) {
      /* Old version */

      /* Get pQ len */
      if (silc_buffer_unformat(&k,
			       SILC_STR_UI_INT(&len),
			       SILC_STR_END) < 0)
	goto err;
      silc_buffer_pull(&k, 4);
      if (silc_buffer_len(&k) < len)
	goto err;
      silc_buffer_pull(&k, len);

      /* Get qP len */
      if (silc_buffer_unformat(&k,
			       SILC_STR_UI_INT(&len),
			       SILC_STR_END) < 0)
	goto err;
      silc_buffer_pull(&k, 4);
      if (silc_buffer_len(&k) < len)
	goto err;
      silc_buffer_pull(&k, len);
    } else {
      /* New version */

      /* Get qP */
      if (silc_buffer_unformat(&k,
			       SILC_STR_UI_INT(&len),
			       SILC_STR_END) < 0)
	goto err;
      silc_buffer_pull(&k, 4);
      if (silc_buffer_unformat(&k,
			       SILC_STR_DATA(&tmp, len),
			       SILC_STR_END) < 0)
	goto err;
      silc_mp_init(&qp);
      silc_mp_bin2mp(tmp, len, &qp);
      silc_buffer_pull(&k, len);
    }

    /* Get p */
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_INT(&len),
			     SILC_STR_END) < 0)
      goto err;
    silc_buffer_pull(&k, 4);
    if (silc_buffer_unformat(&k,
			     SILC_STR_DATA(&tmp, len),
			     SILC_STR_END) < 0)
      goto err;
    silc_mp_init(&p);
    silc_mp_bin2mp(tmp, len, &p);
    silc_buffer_pull(&k, len);

    /* Get q */
    if (silc_buffer_unformat(&k,
			     SILC_STR_UI_INT(&len),
			     SILC_STR_END) < 0)
      goto err;
    silc_buffer_pull(&k, 4);
    if (silc_buffer_unformat(&k,
			     SILC_STR_DATA(&tmp, len),
			     SILC_STR_END) < 0)
      goto err;
    silc_mp_init(&q);
    silc_mp_bin2mp(tmp, len, &q);
    silc_buffer_pull(&k, len);

    if (ver == 0) {
      /* Old version.  Compute to new version */
      SILC_LOG_DEBUG(("Old version private key"));
      silc_mp_init(&qp);
      silc_mp_modinv(&qp, &q, &p);
    }

    /* Encode to PKCS #1 format */
    memset(&alg_key, 0, sizeof(alg_key));
    if (!silc_asn1_encode(asn1, &alg_key,
			  SILC_ASN1_SEQUENCE,
			    SILC_ASN1_SHORT_INT(0),
			    SILC_ASN1_INT(&n),
			    SILC_ASN1_INT(&e),
			    SILC_ASN1_INT(&d),
			    SILC_ASN1_INT(&p),
			    SILC_ASN1_INT(&q),
			    SILC_ASN1_INT(&dp),
			    SILC_ASN1_INT(&dq),
			    SILC_ASN1_INT(&qp),
			  SILC_ASN1_END, SILC_ASN1_END))
      goto err;

    silc_mp_uninit(&n);
    silc_mp_uninit(&e);
    silc_mp_uninit(&e);
    silc_mp_uninit(&d);
    silc_mp_uninit(&p);
    silc_mp_uninit(&q);
    silc_mp_uninit(&dp);
    silc_mp_uninit(&dq);
    silc_mp_uninit(&qp);

  } else if (!strcmp(pkcs_name, "dsa")) {
    SILC_NOT_IMPLEMENTED("DSA SILC Private Key");
    goto err;

  } else {
    SILC_LOG_DEBUG(("Unsupported PKCS algorithm"));
    goto err;
  }

  /* Import PKCS algorithm private key */
  if (!pkcs->import_private_key(alg_key.data, silc_buffer_len(&alg_key),
				&silc_privkey->private_key))
    goto err;

  silc_free(pkcs_name);
  silc_asn1_free(asn1);

  *ret_private_key = silc_privkey;

  return key_len;

 err:
  silc_free(pkcs_name);
  silc_free(silc_privkey);
  if (asn1)
    silc_asn1_free(asn1);
  SILC_LOG_ERROR(("Malformed SILC private key "));
  return 0;
}

/* Exports private key as SILC implementation style private key file */

unsigned char *
silc_pkcs_silc_export_private_key_file(void *private_key,
				       const char *passphrase,
				       SilcUInt32 passphrase_len,
				       SilcPKCSFileEncoding encoding,
				       SilcRng rng,
				       SilcUInt32 *ret_len)
{
  SilcCipher aes;
  SilcHash sha1;
  SilcHmac sha1hmac;
  SilcBuffer buf, enc;
  SilcUInt32 len, blocklen, padlen, key_len;
  unsigned char *key, *data;
  unsigned char tmp[32], keymat[64];
  int i;

  SILC_LOG_DEBUG(("Encoding SILC private key file"));

  /* Export the private key */
  key = silc_pkcs_silc_export_private_key(private_key, &key_len);
  if (!key)
    return NULL;

  memset(tmp, 0, sizeof(tmp));
  memset(keymat, 0, sizeof(keymat));

  /* Allocate the AES cipher */
  if (!silc_cipher_alloc("aes-256-cbc", &aes)) {
    SILC_LOG_ERROR(("Could not allocate AES cipher, probably not registered"));
    silc_free(key);
    return NULL;
  }
  blocklen = silc_cipher_get_block_len(aes);
  if (blocklen * 2 > sizeof(tmp)) {
    silc_cipher_free(aes);
    silc_free(key);
    return NULL;
  }

  /* Allocate SHA1 hash */
  if (!silc_hash_alloc("sha1", &sha1)) {
    SILC_LOG_ERROR(("Could not allocate SHA1 hash, probably not registered"));
    silc_cipher_free(aes);
    return NULL;
  }

  /* Allocate HMAC */
  if (!silc_hmac_alloc("hmac-sha1-96", NULL, &sha1hmac)) {
    SILC_LOG_ERROR(("Could not allocate SHA1 HMAC, probably not registered"));
    silc_hash_free(sha1);
    silc_cipher_free(aes);
    return NULL;
  }

  /* Derive the encryption key from the provided key material.  The key
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
  silc_cipher_set_key(aes, keymat, 256, TRUE);

  /* Encode the buffer to be encrypted.  Add padding to it too, at least
     block size of the cipher. */

  /* Allocate buffer for encryption */
  len = silc_hmac_len(sha1hmac);
  padlen = 16 + (16 - ((key_len + 4) % blocklen));
  enc = silc_buffer_alloc_size(4 + 4 + key_len + padlen + len);
  if (!enc) {
    silc_hmac_free(sha1hmac);
    silc_hash_free(sha1);
    silc_cipher_free(aes);
    return FALSE;
  }

  /* Generate padding */
  for (i = 0; i < padlen; i++)
    tmp[i] = silc_rng_get_byte_fast(rng);

  /* Put magic number */
  SILC_PUT32_MSB(SILC_PKCS_PRIVATE_KEY_MAGIC, enc->data);
  silc_buffer_pull(enc, 4);

  /* Encode the buffer */
  silc_buffer_format(enc,
		     SILC_STR_UI_INT(key_len),
		     SILC_STR_UI_XNSTRING(key, key_len),
		     SILC_STR_UI_XNSTRING(tmp, padlen),
		     SILC_STR_END);
  silc_free(key);

  /* Encrypt. */
  silc_cipher_encrypt(aes, enc->data, enc->data, silc_buffer_len(enc) - len,
		      silc_cipher_get_iv(aes));

  silc_buffer_push(enc, 4);

  /* Compute HMAC over the encrypted data and append the MAC to data.
     The key is the first digest of the original key material. */
  key_len = silc_buffer_len(enc) - len;
  silc_hmac_init_with_key(sha1hmac, keymat, 16);
  silc_hmac_update(sha1hmac, enc->data, key_len);
  silc_buffer_pull(enc, key_len);
  silc_hmac_final(sha1hmac, enc->data, NULL);
  silc_buffer_push(enc, key_len);

  /* Cleanup */
  memset(keymat, 0, sizeof(keymat));
  memset(tmp, 0, sizeof(tmp));
  silc_hmac_free(sha1hmac);
  silc_hash_free(sha1);
  silc_cipher_free(aes);

  switch (encoding) {
  case SILC_PKCS_FILE_BIN:
    break;

  case SILC_PKCS_FILE_BASE64:
    data = silc_base64_encode_file(enc->data, silc_buffer_len(enc));
    if (!data) {
      silc_buffer_clear(enc);
      silc_buffer_free(enc);
      return NULL;
    }
    silc_free(silc_buffer_steal(enc, NULL));
    silc_buffer_set(enc, data, strlen(data));
    break;
  }

  key = enc->data;
  key_len = silc_buffer_len(enc);

  /* Encode the data and save to file */
  len = key_len + (strlen(SILC_PKCS_PRIVATE_KEYFILE_BEGIN) +
		   strlen(SILC_PKCS_PRIVATE_KEYFILE_END));
  buf = silc_buffer_alloc_size(len);
  if (!buf) {
    silc_buffer_free(enc);
    return NULL;
  }
  silc_buffer_format(buf,
		     SILC_STR_UI32_STRING(SILC_PKCS_PRIVATE_KEYFILE_BEGIN),
		     SILC_STR_UI_XNSTRING(key, key_len),
		     SILC_STR_UI32_STRING(SILC_PKCS_PRIVATE_KEYFILE_END),
		     SILC_STR_END);

  silc_buffer_free(enc);
  data = silc_buffer_steal(buf, ret_len);
  silc_buffer_free(buf);

  return data;
}

/* Exports private key as SILC implementation style private key */

unsigned char *silc_pkcs_silc_export_private_key(void *private_key,
						 SilcUInt32 *ret_len)
{
  SilcSILCPrivateKey silc_privkey = private_key;
  const SilcPKCSAlgorithm *pkcs = silc_privkey->pkcs;
  SilcBufferStruct alg_key;
  SilcBuffer buf = NULL;
  SilcAsn1 asn1 = NULL;
  unsigned char *prv = NULL, *key = NULL, *ret;
  SilcUInt32 prv_len, key_len, totlen;

  SILC_LOG_DEBUG(("Encoding SILC private key"));

  /* Export PKCS algorithm private key */
  if (pkcs->export_private_key)
    prv = pkcs->export_private_key(silc_privkey->private_key, &prv_len);
  if (!prv)
    return NULL;
  silc_buffer_set(&alg_key, prv, prv_len);

  asn1 = silc_asn1_alloc();
  if (!asn1)
    goto err;

  if (!strcmp(pkcs->name, "rsa")) {
    /* Parse the PKCS #1 private key */
    SilcMPInt n, e, d, dp, dq, qp, p, q;
    SilcUInt32 e_len, n_len, d_len, dp_len, dq_len,
      qp_len, p_len, q_len, len = 0;
    unsigned char *nb, *eb, *db, *dpb, *dqb, *qpb, *pb, *qb;

    if (!silc_asn1_decode(asn1, &alg_key,
			  SILC_ASN1_SEQUENCE,
			    SILC_ASN1_INT(NULL),
			    SILC_ASN1_INT(&n),
			    SILC_ASN1_INT(&e),
			    SILC_ASN1_INT(&d),
			    SILC_ASN1_INT(&p),
			    SILC_ASN1_INT(&q),
			    SILC_ASN1_INT(&dp),
			    SILC_ASN1_INT(&dq),
			    SILC_ASN1_INT(&qp),
			  SILC_ASN1_END, SILC_ASN1_END))
      goto err;

    /* Encode to SILC RSA private key */
    eb = silc_mp_mp2bin(&e, 0, &e_len);
    nb = silc_mp_mp2bin(&n, 0, &n_len);
    db = silc_mp_mp2bin(&d, 0, &d_len);
    dpb = silc_mp_mp2bin(&dp, 0, &dp_len);
    dqb = silc_mp_mp2bin(&dq, 0, &dq_len);
    qpb = silc_mp_mp2bin(&qp, 0, &qp_len);
    pb = silc_mp_mp2bin(&p, 0, &p_len);
    qb = silc_mp_mp2bin(&q, 0, &q_len);
    len = 4 + e_len + 4 + n_len + 4 + d_len + 4+ dp_len + 4 +
      dq_len + 4 + qp_len + 4 + p_len + 4 + q_len + 4;

    buf = silc_buffer_alloc_size(len);
    if (!buf)
      goto err;
    if (silc_buffer_format(buf,
			   SILC_STR_UI_INT(SILC_PRIVATE_KEY_VERSION_1),
			   SILC_STR_UI_INT(e_len),
			   SILC_STR_UI_XNSTRING(eb, e_len),
			   SILC_STR_UI_INT(n_len),
			   SILC_STR_UI_XNSTRING(nb, n_len),
			   SILC_STR_UI_INT(d_len),
			   SILC_STR_UI_XNSTRING(db, d_len),
			   SILC_STR_UI_INT(dp_len),
			   SILC_STR_UI_XNSTRING(dpb, dp_len),
			   SILC_STR_UI_INT(dq_len),
			   SILC_STR_UI_XNSTRING(dqb, dq_len),
			   SILC_STR_UI_INT(qp_len),
			   SILC_STR_UI_XNSTRING(qpb, qp_len),
			   SILC_STR_UI_INT(p_len),
			   SILC_STR_UI_XNSTRING(pb, p_len),
			   SILC_STR_UI_INT(q_len),
			   SILC_STR_UI_XNSTRING(qb, q_len),
			   SILC_STR_END) < 0)
      goto err;

    key = silc_buffer_steal(buf, &key_len);
    silc_buffer_free(buf);
    silc_free(nb);
    silc_free(eb);
    silc_free(db);
    silc_free(dpb);
    silc_free(dqb);
    silc_free(qpb);
    silc_free(pb);
    silc_free(qb);

  } else if (!strcmp(pkcs->name, "dsa")) {
    SILC_NOT_IMPLEMENTED("SILC DSA Private Key");
    goto err;

  } else {
    SILC_LOG_DEBUG(("Unsupported PKCS algorithm"));
    goto err;
  }

  /* Encode SILC private key */
  totlen = 2 + strlen(pkcs->name) + key_len;
  buf = silc_buffer_alloc_size(totlen);
  if (!buf)
    goto err;
  if (silc_buffer_format(buf,
			 SILC_STR_UI_SHORT(strlen(pkcs->name)),
			 SILC_STR_UI32_STRING(pkcs->name),
			 SILC_STR_UI_XNSTRING(key, key_len),
			 SILC_STR_END) < 0)
    goto err;

  ret = silc_buffer_steal(buf, ret_len);
  silc_buffer_free(buf);
  silc_free(prv);
  silc_free(key);
  silc_asn1_free(asn1);

  return ret;

 err:
  silc_free(prv);
  silc_free(key);
  if (buf)
    silc_buffer_free(buf);
  return NULL;
}

/* Return key length */

SilcUInt32 silc_pkcs_silc_private_key_bitlen(void *private_key)
{
  SilcSILCPrivateKey silc_privkey = private_key;
  return silc_privkey->pkcs->private_key_bitlen(silc_privkey->private_key);
}

/* Frees private key */

void silc_pkcs_silc_private_key_free(void *private_key)
{
  SilcSILCPrivateKey silc_privkey = private_key;

  silc_privkey->pkcs->private_key_free(silc_privkey->private_key);

  silc_free(silc_privkey);
}


/***************************** PKCS operations ******************************/

/* Encrypts as specified in SILC protocol specification */

SilcBool silc_pkcs_silc_encrypt(void *public_key,
				unsigned char *src,
				SilcUInt32 src_len,
				unsigned char *dst,
				SilcUInt32 dst_size,
				SilcUInt32 *ret_dst_len,
				SilcRng rng)
{
  SilcSILCPublicKey silc_pubkey = public_key;

  if (!silc_pubkey->pkcs->encrypt)
    return FALSE;

  return silc_pubkey->pkcs->encrypt(silc_pubkey->public_key,
				    src, src_len,
				    dst, dst_size, ret_dst_len, rng);
}

/* Decrypts as specified in SILC protocol specification */

SilcBool silc_pkcs_silc_decrypt(void *private_key,
				unsigned char *src,
				SilcUInt32 src_len,
				unsigned char *dst,
				SilcUInt32 dst_size,
				SilcUInt32 *ret_dst_len)
{
  SilcSILCPrivateKey silc_privkey = private_key;

  if (!silc_privkey->pkcs->decrypt)
    return FALSE;

  return silc_privkey->pkcs->decrypt(silc_privkey->private_key,
				     src, src_len,
				     dst, dst_size, ret_dst_len);
}

/* Signs as specified in SILC protocol specification */

SilcBool silc_pkcs_silc_sign(void *private_key,
			     unsigned char *src,
			     SilcUInt32 src_len,
			     unsigned char *signature,
			     SilcUInt32 signature_size,
			     SilcUInt32 *ret_signature_len,
			     SilcBool compute_hash,
			     SilcHash hash)
{
  SilcSILCPrivateKey silc_privkey = private_key;

  if (!silc_privkey->pkcs->sign)
    return FALSE;

  return silc_privkey->pkcs->sign(silc_privkey->private_key,
				  src, src_len,
				  signature, signature_size,
				  ret_signature_len, compute_hash, hash);
}

/* Verifies as specified in SILC protocol specification */

SilcBool silc_pkcs_silc_verify(void *public_key,
			       unsigned char *signature,
			       SilcUInt32 signature_len,
			       unsigned char *data,
			       SilcUInt32 data_len,
			       SilcHash hash)
{
  SilcSILCPublicKey silc_pubkey = public_key;

  if (!silc_pubkey->pkcs->verify)
    return FALSE;

  return silc_pubkey->pkcs->verify(silc_pubkey->public_key,
				   signature, signature_len,
				   data, data_len, hash);
}
