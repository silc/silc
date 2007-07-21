/*

  silcssh.c

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

/************************* Static utility functions *************************/

/* Key fields destructor */

static void silc_ssh_field_dest(void *key, void *context, void *user_context)
{
  silc_free(key);
  silc_free(context);
}

/* Parse header line from key.  Doesn't return the line termination
   characters. */

SilcBool silc_ssh_parse_line(SilcBuffer key, SilcBuffer line,
			     SilcBool cont)
{
  char *tmp;
  int i, data_len;
  SilcBool valid = cont;

  data_len = silc_buffer_len(key);
  tmp = silc_buffer_data(key);
  for (i = 0; i < data_len; i++) {
    /* All header lines must have ':' character */
    if (!cont && tmp[i] == ':')
      valid = TRUE;

    if ((data_len - i >= 1 && tmp[i] == '\r') ||
	(data_len - i >= 1 && tmp[i] == '\n')) {

      if (!valid)
	return FALSE;

      if (line)
	silc_buffer_set(line, tmp, i);

      if (data_len - i >= 2 && tmp[i] == '\r' && tmp[i + 1] == '\n')
	silc_buffer_pull(key, i + 2);
      else
	silc_buffer_pull(key, i + 1);

      return TRUE;
    }
  }

  return FALSE;
}

/* Allocate fields hash table */

SilcHashTable silc_ssh_allocate_fields(void)
{
  return silc_hash_table_alloc(NULL, 0, silc_hash_string, NULL,
			       silc_hash_string_compare, NULL,
			       silc_ssh_field_dest, NULL, TRUE);
}

/* Parse key headers and return them into a hash table */

SilcHashTable silc_ssh_parse_headers(SilcBuffer key)
{
  SilcHashTable fields;
  unsigned char *field, *value;
  SilcBufferStruct line, v;
  SilcBool quoted = FALSE;

  SILC_LOG_DEBUG(("Parsing SSH key headers"));

  fields = silc_ssh_allocate_fields();
  if (!fields)
    return NULL;

  /* Parse the fields */
  while (silc_buffer_len(key) > 0) {
    if (!silc_ssh_parse_line(key, &line, FALSE))
      break;

    /* Get field */

    field = strchr(silc_buffer_data(&line), ':');
    if (!field)
      goto err;
    if (field - silc_buffer_data(&line) > 64)
      goto err;
    field = silc_memdup(silc_buffer_data(&line),
			field - silc_buffer_data(&line));
    if (!field)
      goto err;

    /* Skip ':' and following whitespace */
    if (!silc_buffer_pull(&line, strlen(field) + 2))
      goto err;

    /* Get value */

    memset(&v, 0, sizeof(v));
    silc_buffer_format(&v,
		       SILC_STR_DATA(silc_buffer_data(&line),
				     silc_buffer_len(&line)),
		       SILC_STR_END);

    /* Handle quoted Comment lines by removing the quotation */
    if (*silc_buffer_data(&v) == '"' && !strcmp(field, "Comment"))
      quoted = TRUE;

    /* Handle wrapping value lines */
    while (silc_buffer_len(&v) > 0) {
      if (*silc_buffer_data(&v) == '\\') {
	if (!silc_ssh_parse_line(key, &line, TRUE))
	  goto err;
	silc_buffer_format(&v,
			   SILC_STR_DATA(silc_buffer_data(&line),
					 silc_buffer_len(&line)),
			   SILC_STR_END);
	continue;
      }
      silc_buffer_pull(&v, 1);
    }
    silc_buffer_start(&v);

    if (silc_buffer_len(&v) > 1024)
      goto err;

    if (quoted) {
      /* If the last character is quotation also, remove the quotation */
      if (*(silc_buffer_data(&v) + silc_buffer_len(&v) - 1) == '"') {
	silc_buffer_pull(&v, 1);
	silc_buffer_push_tail(&v, 1);
      }
    }

    value = silc_memdup(silc_buffer_data(&v), silc_buffer_len(&v));
    if (!value)
      goto err;
    silc_buffer_purge(&v);

    /* Add to hash table */
    SILC_LOG_DEBUG(("Header '%s' '%s'", field, value));
    silc_hash_table_add(fields, field, value);
  }

  return fields;

 err:
  SILC_LOG_ERROR(("Malformed SSH2 key headers"));
  silc_hash_table_free(fields);
  return NULL;
}

/******************************* SILC SSH API *******************************/

/* Generate key pair */

SilcBool silc_ssh_generate_key(const char *algorithm,
			       int bits_len, SilcRng rng,
			       SilcPublicKey *ret_public_key,
			       SilcPrivateKey *ret_private_key)
{
  SilcSshPublicKey pubkey;
  SilcSshPrivateKey privkey;
  const SilcPKCSAlgorithm *alg;
  const SilcPKCSObject *pkcs;

  SILC_LOG_DEBUG(("Generating SSH2 %s key pair with key length %d bits",
		  algorithm, bits_len));

  if (!rng)
    return FALSE;

  pkcs = silc_pkcs_find_pkcs(SILC_PKCS_SSH2);
  if (!pkcs)
    return FALSE;

  /* Allocate SSH public key */
  pubkey = silc_calloc(1, sizeof(*pubkey));
  if (!pubkey)
    return FALSE;

  /* Allocate algorithm */
  alg = silc_pkcs_find_algorithm(algorithm, "ssh");
  if (!alg) {
    SILC_LOG_ERROR(("Public key algorithm %s/ssh not supported", algorithm));
    silc_free(pubkey);
    return FALSE;
  }
  pubkey->pkcs = alg;
  pubkey->type = SILC_SSH_KEY_OPENSSH;

  /* Allocate SSH private key */
  privkey = silc_calloc(1, sizeof(*privkey));
  if (!privkey) {
    silc_free(pubkey);
    return FALSE;
  }
  privkey->pkcs = alg;
  privkey->type = SILC_SSH_KEY_OPENSSH;

  /* Allocate public key */
  *ret_public_key = silc_calloc(1, sizeof(**ret_public_key));
  if (!(*ret_public_key)) {
    silc_free(pubkey);
    silc_free(privkey);
    return FALSE;
  }
  (*ret_public_key)->pkcs = (SilcPKCSObject *)pkcs;
  (*ret_public_key)->alg = alg;
  (*ret_public_key)->public_key = pubkey;

  /* Allocate private key */
  *ret_private_key = silc_calloc(1, sizeof(**ret_private_key));
  if (!(*ret_private_key)) {
    silc_free(pubkey);
    silc_free(privkey);
    silc_free(*ret_public_key);
    return FALSE;
  }
  (*ret_private_key)->pkcs = (SilcPKCSObject *)pkcs;
  (*ret_private_key)->alg = alg;
  (*ret_private_key)->private_key = privkey;

  /* Generate the algorithm key pair */
  if (!alg->generate_key(alg, bits_len, rng, &pubkey->public_key,
			 &privkey->private_key)) {
    silc_free(pubkey);
    silc_free(privkey);
    silc_free(*ret_public_key);
    silc_free(*ret_private_key);
    return FALSE;
  }

  return TRUE;
}

/* Decode SSH public key. */

int silc_ssh_public_key_decode(unsigned char *key, SilcUInt32 key_len,
			       SilcSshPublicKey *ret_public_key)
{
  SilcSshPublicKey public_key;
  const SilcPKCSAlgorithm *alg;
  SilcBufferStruct keybuf;
  char *type = NULL;

  SILC_LOG_DEBUG(("Parse SSH2 public key"));

  if (!ret_public_key)
    return 0;

  public_key = silc_calloc(1, sizeof(*public_key));
  if (!public_key)
    return 0;

  silc_buffer_set(&keybuf, key, key_len);

  SILC_LOG_HEXDUMP(("SSH public key, len %d", key_len), key, key_len);

  /* Parse public key type */
  if (silc_buffer_unformat(&keybuf,
			   SILC_STR_ADVANCE,
			   SILC_STR_UI32_STRING_ALLOC(&type),
			   SILC_STR_END) < 0) {
    SILC_LOG_ERROR(("Malformed SSH2 public key"));
    goto err;
  }

  SILC_LOG_DEBUG(("SSH2 public key type %s", type));

  if (!strcmp(type, "ssh-rsa")) {
    /* RSA public key */
    alg = silc_pkcs_find_algorithm("rsa", "ssh");
    if (!alg) {
      SILC_LOG_ERROR(("Unsupported SSH2 public key type '%s'", type));
      goto err;
    }
    public_key->pkcs = alg;

  } else if (!strcmp(type, "ssh-dss")) {
    /* DSS public key */
    alg = silc_pkcs_find_algorithm("dsa", "ssh");
    if (!alg) {
      SILC_LOG_ERROR(("Unsupported SSH2 public key type '%s'", type));
      goto err;
    }
    public_key->pkcs = alg;

  } else {
    SILC_LOG_ERROR(("Unsupported SSH2 public key type '%s'", type));
    goto err;
  }

  /* Parse the algorithm specific public key */
  if (!alg->import_public_key(alg, silc_buffer_data(&keybuf),
			      silc_buffer_len(&keybuf),
			      &public_key->public_key))
    goto err;

  silc_free(type);

  *ret_public_key = public_key;

  return key_len;

 err:
  silc_free(type);
  silc_free(public_key);
  return 0;
}

/* Encode SSH public key */

unsigned char *silc_ssh_public_key_encode(SilcStack stack,
					  SilcSshPublicKey public_key,
					  SilcUInt32 *ret_key_len)
{
  const SilcPKCSAlgorithm *alg = public_key->pkcs;
  SilcBufferStruct buf;
  unsigned char *pk = NULL, tmp[16];
  SilcUInt32 pk_len;

  SILC_LOG_DEBUG(("Encode SSH2 public key"));

  /* Get algorithm name */
  if (!strcmp(alg->name, "rsa"))
    silc_snprintf(tmp, sizeof(tmp), "ssh-rsa");
  else if (!strcmp(alg->name, "dsa"))
    silc_snprintf(tmp, sizeof(tmp), "ssh-dss");
  else
    return NULL;

  /* Export PKCS algorithm public key */
  if (alg->export_public_key)
    pk = alg->export_public_key(alg, stack, public_key->public_key, &pk_len);
  if (!pk) {
    SILC_LOG_ERROR(("Error exporting PKCS algorithm key"));
    return NULL;
  }

  /* Encode public key */
  memset(&buf, 0, sizeof(buf));
  if (silc_buffer_sformat(stack, &buf,
			  SILC_STR_UI_INT(strlen(tmp)),
			  SILC_STR_UI32_STRING(tmp),
			  SILC_STR_UI_XNSTRING(pk, pk_len),
			  SILC_STR_END) < 0) {
    silc_sfree(stack, pk);
    return NULL;
  }

  silc_sfree(stack, pk);
  pk = silc_buffer_steal(&buf, ret_key_len);

  return pk;
}

/* Free public key */

void silc_ssh_public_key_free(SilcSshPublicKey public_key)
{
  if (public_key->fields)
    silc_hash_table_free(public_key->fields);
  silc_free(public_key);
}

/* Return public key header field value */

const char *silc_ssh_public_key_get_field(SilcSshPublicKey public_key,
					  const char *field)
{
  char *value;

  if (!field || !public_key->fields)
    return NULL;

  if (!silc_hash_table_find(public_key->fields, (void *)field,
			    NULL, (void *)&value))
    return NULL;

  return (const char *)value;
}

/* Add public key header value */

SilcBool silc_ssh_public_key_add_field(SilcSshPublicKey public_key,
				       const char *field,
				       const char *value)
{
  if (!field || !value)
    return FALSE;

  if (!public_key->fields) {
    public_key->fields =
      silc_hash_table_alloc(NULL, 0, silc_hash_string, NULL,
			    silc_hash_string_compare, NULL,
			    silc_ssh_field_dest, NULL, TRUE);
    if (!public_key->fields)
      return FALSE;
  }

  return silc_hash_table_add(public_key->fields, strdup(field), strdup(value));
}

/* Set public key type */

void silc_ssh_public_key_set_type(SilcSshPublicKey public_key,
				  SilcSshKeyType type)
{
  public_key->type = type;
}
