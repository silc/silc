/*

  silcssh_pkcs.c

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
#include "rsa.h"
#include "dsa.h"
#include "silcssh_pkcs.h"

/************************** Types and definitions ***************************/

/* RFC 4716 public key file markers */
#define SILC_SSH_PUBLIC_KEY_BEGIN "---- BEGIN SSH2 PUBLIC KEY ----"
#define SILC_SSH_PUBLIC_KEY_END "---- END SSH2 PUBLIC KEY ----"

/* OpenSSH private key file markers */
#define SILC_SSH_RSA_BEGIN "-----BEGIN RSA PRIVATE KEY-----"
#define SILC_SSH_RSA_END "-----END RSA PRIVATE KEY-----"
#define SILC_SSH_DSA_BEGIN "-----BEGIN DSA PRIVATE KEY-----"
#define SILC_SSH_DSA_END "-----END DSA PRIVATE KEY-----"

/****************************** SSH2 PKCS API *******************************/

/* Get algorithm context */

SILC_PKCS_GET_ALGORITHM(silc_pkcs_ssh_get_algorithm)
{
  SilcSshPublicKey pubkey = public_key;
  return pubkey->pkcs;
}

/* Import public key file */

SILC_PKCS_IMPORT_PUBLIC_KEY_FILE(silc_pkcs_ssh_import_public_key_file)
{
  SilcSshPublicKey pubkey;
  SilcBufferStruct keybuf, line;
  SilcHashTable fields;
  unsigned char *data;
  SilcSshKeyType type;
  int ret;

  SILC_LOG_DEBUG(("Parsing SSH2 public key file"));

  if (!ret_public_key)
    return FALSE;
  if (encoding == SILC_PKCS_FILE_BIN)
    return FALSE;

  silc_buffer_set(&keybuf, filedata, filedata_len);

  /* Check for RFC 4716 style public key markers */
  if (!silc_ssh_parse_line(&keybuf, &line, TRUE)) {
    SILC_LOG_DEBUG(("Malformed SSH2 public key markers"));
    return FALSE;
  }
  if ((silc_buffer_len(&keybuf) < (strlen(SILC_SSH_PUBLIC_KEY_BEGIN) +
				   strlen(SILC_SSH_PUBLIC_KEY_END))) ||
      strncmp(silc_buffer_data(&line), SILC_SSH_PUBLIC_KEY_BEGIN,
	      silc_buffer_len(&line))) {
    /* We assume the key is OpenSSH style public key. */
    type = SILC_SSH_KEY_OPENSSH;
    silc_buffer_set(&keybuf, filedata, filedata_len);

    /* Get subject name from the end of the file */
    if (!silc_buffer_strchr(&keybuf, ' ', FALSE)) {
      SILC_LOG_DEBUG(("Malformed SSH2 public key"));
      return FALSE;
    }
    if (!silc_buffer_pull(&keybuf, 1)) {
      SILC_LOG_DEBUG(("Malformed SSH2 public key"));
      return FALSE;
    }
    if (!silc_buffer_len(&keybuf)) {
      SILC_LOG_DEBUG(("Malformed SSH2 public key"));
      return FALSE;
    }

    /* Add subject name to public key headers */
    fields = silc_ssh_allocate_fields();
    if (!fields)
      return FALSE;
    silc_hash_table_add(fields, strdup("Subject"),
			silc_memdup(silc_buffer_data(&keybuf),
				    silc_buffer_len(&keybuf)));

    filedata_len = silc_buffer_headlen(&keybuf) - 1;
    SILC_LOG_DEBUG(("Add Subject header to public key"));

    /* Skip algorithm name */
    silc_buffer_start(&keybuf);
    if (!silc_buffer_strchr(&keybuf, ' ', TRUE)) {
      SILC_LOG_DEBUG(("Malformed SSH2 public key"));
      silc_hash_table_free(fields);
      return FALSE;
    }
    if (!silc_buffer_pull(&keybuf, 1)) {
      SILC_LOG_DEBUG(("Malformed SSH2 public key"));
      silc_hash_table_free(fields);
      return FALSE;
    }
    if (silc_buffer_len(&keybuf) < filedata_len) {
      SILC_LOG_DEBUG(("Malformed SSH2 public key"));
      silc_hash_table_free(fields);
      return FALSE;
    }

    filedata = silc_buffer_data(&keybuf);
    SILC_LOG_DEBUG(("Public key is OpenSSH public key"));

  } else {
    /* RFC 4716 style public key */
    type = SILC_SSH_KEY_SSH2;

    filedata = silc_buffer_data(&keybuf);
    filedata_len = silc_buffer_len(&keybuf) - strlen(SILC_SSH_PUBLIC_KEY_END);
    silc_buffer_set(&keybuf, filedata, filedata_len);

    /* Parse public key headers */
    fields = silc_ssh_parse_headers(&keybuf);
    if (!fields)
      return FALSE;

    filedata = silc_buffer_data(&keybuf);
    filedata_len = silc_buffer_len(&keybuf);

    SILC_LOG_DEBUG(("Public key is standard SSH2 public key"));
  }

  /* Decode */
  data = silc_base64_decode(NULL, filedata, filedata_len, &filedata_len);
  if (!data) {
    silc_hash_table_free(fields);
    return FALSE;
  }
  filedata = data;

  /* Decode the public key */
  ret = silc_pkcs_ssh_import_public_key(pkcs, NULL, filedata, filedata_len,
					(void *)&pubkey, ret_alg);
  silc_free(data);

  if (ret) {
    pubkey->fields = fields;
    pubkey->type = type;
    *ret_public_key = pubkey;
    SILC_LOG_DEBUG(("SSH2 public key file imported successfully"));
    return TRUE;
  }

  silc_hash_table_free(fields);
  return FALSE;
}

/* Import public key */

SILC_PKCS_IMPORT_PUBLIC_KEY(silc_pkcs_ssh_import_public_key)
{
  SilcSshPublicKey pubkey;
  int ret;

  ret = silc_ssh_public_key_decode(key, key_len, &pubkey);
  if (ret) {
    if (ret_alg)
      *ret_alg = pubkey->pkcs;
    if (ret_public_key)
      *ret_public_key = pubkey;
  }

  return ret;
}

/* Export public key file */

SILC_PKCS_EXPORT_PUBLIC_KEY_FILE(silc_pkcs_ssh_export_public_key_file)
{
  SilcSshPublicKey pubkey = public_key;
  SilcHashTableList htl;
  SilcBufferStruct buf, fields;
  unsigned char *key, *data;
  SilcUInt32 key_len;
  char *field, *value, tmp[1024], tmp2[1024 + 24];
  int i, j, c;

  SILC_LOG_DEBUG(("Encoding %s public key file",
		  pubkey->type == SILC_SSH_KEY_SSH2 ? "SSH2" : "OpenSSH"));

  /* Export key */
  key = silc_pkcs_ssh_export_public_key(pkcs, stack, pubkey, &key_len);
  if (!key)
    return NULL;

  /* Base64 encode the key data */
  if (pubkey->type == SILC_SSH_KEY_SSH2)
    data = silc_base64_encode_file(stack, key, key_len);
  else
    data = silc_base64_encode(stack, key, key_len);
  if (!data)
    return NULL;
  silc_sfree(stack, key);
  key = data;
  key_len = strlen(data);

  memset(&buf, 0, sizeof(buf));
  memset(&fields, 0, sizeof(fields));
  memset(tmp, 0, sizeof(tmp));
  memset(tmp2, 0, sizeof(tmp2));

  switch (pubkey->type) {
  case SILC_SSH_KEY_SSH2:
    /* RFC 4716 style public key file */

    if (pubkey->fields) {
      /* Encode public key headers */
      silc_hash_table_list(pubkey->fields, &htl);
      while (silc_hash_table_get(&htl, (void *)&field, (void *)&value)) {
	/* Wrap lines with over 72 characters */
	silc_snprintf(tmp, sizeof(tmp), "%s: %s", field, value);
	for (i = 0, j = 0, c = 1; i < strlen(tmp); i++, c++) {
	  if (c == 72) {
	    tmp2[j++] = '\\';
	    tmp2[j++] = '\n';
	    i--;
	    c = 0;
	    continue;
	  }

	  tmp2[j++] = tmp[i];
	}
	tmp2[j++] = '\n';

	if (silc_buffer_sstrformat(stack, &fields, tmp2, SILC_STRFMT_END) < 0) {
	  silc_buffer_spurge(stack, &fields);
	  silc_sfree(stack, key);
	  return NULL;
	}

	memset(tmp2, 0, sizeof(tmp2));
      }
      silc_hash_table_list_reset(&htl);
    }

    /* Encode the file */
    if (silc_buffer_sformat(stack, &buf,
			    SILC_STR_UI32_STRING(SILC_SSH_PUBLIC_KEY_BEGIN),
			    SILC_STR_UI32_STRING("\n"),
			    SILC_STR_UI_XNSTRING(silc_buffer_data(&fields),
						 silc_buffer_len(&fields)),
			    SILC_STR_UI_XNSTRING(key, key_len),
			    SILC_STR_UI32_STRING("\n"),
			    SILC_STR_UI32_STRING(SILC_SSH_PUBLIC_KEY_END),
			    SILC_STR_UI32_STRING("\n"),
			    SILC_STR_END) < 0) {
      silc_buffer_spurge(stack, &fields);
      silc_sfree(stack, key);
      return NULL;
    }

    break;

  case SILC_SSH_KEY_OPENSSH:
    /* OpenSSH style public key file */

    if (!strcmp(pubkey->pkcs->name, "rsa"))
      silc_snprintf(tmp, sizeof(tmp), "ssh-rsa ");
    else if (!strcmp(pubkey->pkcs->name, "dsa"))
      silc_snprintf(tmp, sizeof(tmp), "ssh-dss ");

    /* Get subject */
    value = (char *)silc_ssh_public_key_get_field(pubkey, "Subject");

    /* Encode the file */
    if (silc_buffer_sformat(stack, &buf,
			    SILC_STR_UI32_STRING(tmp),
			    SILC_STR_UI_XNSTRING(key, key_len),
			    SILC_STR_UI32_STRING(" "),
			    SILC_STR_UI32_STRING(value),
			    SILC_STR_UI32_STRING("\n"),
			    SILC_STR_END) < 0) {
      silc_buffer_spurge(stack, &buf);
      silc_sfree(stack, key);
      return NULL;
    }

    break;

  default:
    silc_sfree(stack, key);
    return NULL;
    break;
  }

  silc_sfree(stack, key);
  key = silc_buffer_steal(&buf, ret_len);

  silc_buffer_spurge(stack, &fields);

  return key;
}

/* Export public key */

SILC_PKCS_EXPORT_PUBLIC_KEY(silc_pkcs_ssh_export_public_key)
{
  return silc_ssh_public_key_encode(stack, public_key, ret_len);
}

/* Return key length in bits */

SILC_PKCS_PUBLIC_KEY_BITLEN(silc_pkcs_ssh_public_key_bitlen)
{
  SilcSshPublicKey pubkey = public_key;
  return pubkey->pkcs->public_key_bitlen(pubkey->pkcs, pubkey->public_key);
}

/* Copy public key */

SILC_PKCS_PUBLIC_KEY_COPY(silc_pkcs_ssh_public_key_copy)
{
  SilcSshPublicKey pubkey = public_key, new_pubkey;
  SilcHashTableList htl;
  char *field, *value;

  new_pubkey = silc_calloc(1, sizeof(*new_pubkey));
  if (!new_pubkey)
    return NULL;
  new_pubkey->pkcs = pubkey->pkcs;
  new_pubkey->type = pubkey->type;

  new_pubkey->public_key =
    pubkey->pkcs->public_key_copy(pubkey->pkcs, pubkey->public_key);
  if (!new_pubkey->public_key) {
    silc_free(new_pubkey);
    return NULL;
  }

  if (pubkey->fields) {
    new_pubkey->fields = silc_ssh_allocate_fields();
    if (!new_pubkey->fields) {
      pubkey->pkcs->public_key_free(pubkey->pkcs, pubkey->public_key);
      silc_free(new_pubkey);
      return NULL;
    }

    silc_hash_table_list(pubkey->fields, &htl);
    while (silc_hash_table_get(&htl, (void *)&field, (void *)&value))
      silc_hash_table_add(new_pubkey->fields, strdup(field), strdup(value));
    silc_hash_table_list_reset(&htl);
  }

  return new_pubkey;
}

/* Compare two public keys */

SILC_PKCS_PUBLIC_KEY_COMPARE(silc_pkcs_ssh_public_key_compare)
{
  SilcSshPublicKey k1 = key1, k2 = key2;
  SilcHashTableList htl;
  char *field, *value, *value2;

  if (strcmp(k1->pkcs->name, k2->pkcs->name))
    return FALSE;

  if (k1->fields && !k2->fields)
    return FALSE;
  if (!k1->fields && k2->fields)
    return FALSE;

  if (k1->fields && k2->fields) {
    if (silc_hash_table_count(k1->fields) != silc_hash_table_count(k2->fields))
      return FALSE;

    silc_hash_table_list(k1->fields, &htl);
    while (silc_hash_table_get(&htl, (void *)&field, (void *)&value)) {
      value2 = (char *)silc_ssh_public_key_get_field(k2, field);
      if (!value2)
	return FALSE;
      if (strcmp(value, value2))
	return FALSE;
    }
    silc_hash_table_list_reset(&htl);
  }

  return k1->pkcs->public_key_compare(k1->pkcs, k1->public_key,
				      k2->public_key);
}

/* Free public key */

SILC_PKCS_PUBLIC_KEY_FREE(silc_pkcs_ssh_public_key_free)
{
  silc_ssh_public_key_free(public_key);
}

/* Import private key file.  Supports only OpenSSH (OpenSSL to be exact)
   private key files. */

SILC_PKCS_IMPORT_PRIVATE_KEY_FILE(silc_pkcs_ssh_import_private_key_file)
{
  const SilcPKCSAlgorithm *alg;
  SilcSshPrivateKey privkey = NULL;
  SilcHashTable fields;
  SilcBufferStruct keybuf, line;
  unsigned char *data, iv[8], key[32];
  SilcSshKeyType type;
  char *proctype, *dekinfo;
  SilcCipher des;
  SilcHash md5;
  int ret;

  SILC_LOG_DEBUG(("Parsing SSH2 private key file"));

  if (!ret_private_key)
    return FALSE;
  if (encoding == SILC_PKCS_FILE_BIN)
    return FALSE;

  silc_buffer_set(&keybuf, filedata, filedata_len);

  /* Check for private key markers */
  if (!silc_ssh_parse_line(&keybuf, &line, TRUE)) {
    SILC_LOG_DEBUG(("Malformed SSH2 private key markers"));
    return FALSE;
  }
  if ((silc_buffer_len(&keybuf) < (strlen(SILC_SSH_RSA_BEGIN) +
				   strlen(SILC_SSH_RSA_END))) ||
      (strncmp(silc_buffer_data(&line), SILC_SSH_RSA_BEGIN,
	       silc_buffer_len(&line)) &&
       strncmp(silc_buffer_data(&line), SILC_SSH_DSA_BEGIN,
	       silc_buffer_len(&line)))) {
    SILC_LOG_DEBUG(("Malformed SSH2 private key markers"));
    return FALSE;
  }

  /* Get PKCS algorithm */
  if (!strncmp(silc_buffer_data(&line), SILC_SSH_RSA_BEGIN,
	       silc_buffer_len(&line))) {
    alg = silc_pkcs_find_algorithm("rsa", "ssh");
    if (!alg) {
      SILC_LOG_ERROR(("Unsupported PKCS algorithm rsa/ssh"));
      return FALSE;
    }
  } else if (!strncmp(silc_buffer_data(&line), SILC_SSH_DSA_BEGIN,
		      silc_buffer_len(&line))) {
    alg = silc_pkcs_find_algorithm("dsa", "ssh");
    if (!alg) {
      SILC_LOG_ERROR(("Unsupported PKCS algorithm dsa/ssh"));
      return FALSE;
    }
  } else
    return FALSE;

  type = SILC_SSH_KEY_OPENSSH;
  filedata = silc_buffer_data(&keybuf);

  /* Skip end marker */
  if (!silc_buffer_strchr(&keybuf, '-', FALSE)) {
    SILC_LOG_DEBUG(("Malformed SSH2 private key markers"));
    return FALSE;
  }
  filedata_len = silc_buffer_data(&keybuf) - filedata;
  silc_buffer_set(&keybuf, filedata, filedata_len);

  /* Parse private key headers.  They define how the private key has been
     encrypted. */
  fields = silc_ssh_parse_headers(&keybuf);
  if (!fields)
    return FALSE;

  /* Skip empty line after headers */
  if (silc_hash_table_count(fields) > 0)
    silc_ssh_parse_line(&keybuf, NULL, TRUE);

  filedata = silc_buffer_data(&keybuf);
  filedata_len = silc_buffer_len(&keybuf);

  /* Decode */
  data = silc_base64_decode(NULL, filedata, filedata_len, &filedata_len);
  if (!data) {
    SILC_LOG_DEBUG(("Malformed SSH2 private key"));
    goto err;
  }
  filedata = data;

  SILC_LOG_DEBUG(("Private key is %s", (silc_hash_table_count(fields) ?
					"encrypted" : "not encrypted")));

  if (silc_hash_table_count(fields) > 0 && passphrase) {
    /* Decrypt */

    /* Get encryption info */
    if (!silc_hash_table_find(fields, "Proc-Type", NULL, (void *)&proctype)) {
      SILC_LOG_ERROR(("Malformed SSH2 private key"));
      goto err;
    }
    if (strcmp(proctype, "4,ENCRYPTED")) {
      SILC_LOG_ERROR(("Malformed SSH2 private key"));
      goto err;
    }

    /* OpenSSH uses 3DES-EDE only */
    if (!silc_hash_table_find(fields, "DEK-Info", NULL, (void *)&dekinfo)) {
      SILC_LOG_ERROR(("Malformed SSH2 private key"));
      goto err;
    }
    if (strncmp(dekinfo, "DES-EDE3-CBC", strlen("DES-EDE3-CBC"))) {
      SILC_LOG_ERROR(("Unsupported SSH2 private key cipher '%s'", dekinfo));
      goto err;
    }

    /* Allocate cipher */
    if (!silc_cipher_alloc("3des-168-cbc", &des)) {
      SILC_LOG_ERROR(("Unsupported algorithm 3des-168-cbc"));
      goto err;
    }

    /* Allocate hash */
    if (!silc_hash_alloc("md5", &md5)) {
      SILC_LOG_ERROR(("Unsupported hash algorithm md5"));
      goto err;
    }

    /* Get IV from private key file */
    dekinfo = strchr(dekinfo, ',');
    if (!dekinfo || strlen(dekinfo) < 16) {
      SILC_LOG_ERROR(("Malformed SSH2 private key"));
      goto err;
    }
    dekinfo++;
    silc_hex2data(dekinfo, iv, sizeof(iv), NULL);

    /* Generate key from passphrase and IV as salt.  The passphrase is
       hashed with the IV, then rehashed with the previous hash, passphrase
       and the IV to produce the final key, which is the concatenation of
       the two hashes. */
    silc_hash_init(md5);
    silc_hash_update(md5, passphrase, passphrase_len);
    silc_hash_update(md5, iv, 8);
    silc_hash_final(md5, key);
    silc_hash_init(md5);
    silc_hash_update(md5, key, 16);
    silc_hash_update(md5, passphrase, passphrase_len);
    silc_hash_update(md5, iv, 8);
    silc_hash_final(md5, key + 16);

    /* Decrypt */
    silc_cipher_set_key(des, key, 192, FALSE);
    if (!silc_cipher_decrypt(des, filedata, filedata, filedata_len, iv)) {
      SILC_LOG_ERROR(("Malformed SSH2 private key"));
      silc_cipher_free(des);
      silc_hash_free(md5);
      goto err;
    }

    silc_cipher_free(des);
    silc_hash_free(md5);
  }

  /* Decode the private key */
  ret = silc_pkcs_ssh_import_private_key(pkcs, alg, filedata, filedata_len,
					 (void *)&privkey, ret_alg);
  silc_free(data);

  if (ret) {
    privkey->fields = fields;
    privkey->type = type;
    *ret_private_key = privkey;
    SILC_LOG_DEBUG(("SSH2 private key file imported successfully"));
    return TRUE;
  }

 err:
  if (fields)
    silc_hash_table_free(fields);
  return FALSE;
}

/* Import private key.  The key format for RSA is PKCS#1 compliant and for
   DSA is equivalent to our DSA implementation, so we just simply call the
   algorithm specific import function to do the magic. */

SILC_PKCS_IMPORT_PRIVATE_KEY(silc_pkcs_ssh_import_private_key)
{
  SilcSshPrivateKey privkey;
  int ret;

  if (!ret_private_key || !alg)
    return 0;

  /* Allocate SSH private key context */
  privkey = silc_calloc(1, sizeof(*privkey));
  if (!privkey)
    return 0;

  /* Import PKCS algorithm private key */
  ret = alg->import_private_key(alg, key, key_len, &privkey->private_key);
  if (!ret) {
    silc_free(privkey);
    return 0;
  }

  privkey->pkcs = alg;
  privkey->type = SILC_SSH_KEY_OPENSSH;

  *ret_private_key = privkey;
  if (ret_alg)
    *ret_alg = alg;

  return ret;
}

/* Export private key file */

SILC_PKCS_EXPORT_PRIVATE_KEY_FILE(silc_pkcs_ssh_export_private_key_file)
{
  SilcSshPrivateKey privkey = private_key;
  const SilcPKCSAlgorithm *alg = privkey->pkcs;
  SilcBufferStruct buf;
  unsigned char *key, *keyenc, ivdata[8], iv[16 + 1], enc[32];
  SilcUInt32 key_len, pad_len;
  SilcCipher des = NULL;
  SilcHash md5 = NULL;

  SILC_LOG_DEBUG(("Encode SSH2 private key file"));

  /* Export the private key */
  key = silc_pkcs_ssh_export_private_key(pkcs, stack, private_key, &key_len);
  if (!key)
    return NULL;

  memset(&buf, 0, sizeof(buf));
  if (!strcmp(alg->name, "rsa")) {
    if (silc_buffer_sformat(stack, &buf,
			    SILC_STR_ADVANCE,
			    SILC_STR_UI32_STRING(SILC_SSH_RSA_BEGIN),
			    SILC_STR_UI32_STRING("\n"),
			    SILC_STR_END) < 0)
      goto err;
  } else if (!strcmp(alg->name, "dsa")) {
    if (silc_buffer_sformat(stack, &buf,
			    SILC_STR_ADVANCE,
			    SILC_STR_UI32_STRING(SILC_SSH_DSA_BEGIN),
			    SILC_STR_UI32_STRING("\n"),
			    SILC_STR_END) < 0)
      goto err;
  } else
    goto err;

  if (passphrase && strlen(passphrase) > 0) {
    /* Encrypt the key */

    /* Allocate cipher */
    if (!silc_cipher_alloc("3des-168-cbc", &des)) {
      SILC_LOG_ERROR(("Unsupported algorithm 3des-168-cbc"));
      goto err;
    }

    /* Allocate hash */
    if (!silc_hash_alloc("md5", &md5)) {
      SILC_LOG_ERROR(("Unsupported hash algorithm md5"));
      goto err;
    }

    /* Generate IV */
    silc_rng_get_rn_data(rng, sizeof(ivdata), ivdata, sizeof(ivdata));
    silc_data2hex(ivdata, sizeof(ivdata), iv, sizeof(iv));

    /* Encode header */
    if (silc_buffer_sformat(stack, &buf,
			    SILC_STR_ADVANCE,
			    SILC_STR_UI32_STRING("Proc-Type: 4,ENCRYPTED\n"),
			    SILC_STR_UI32_STRING("DEK-Info: DES-EDE3-CBC,"),
			    SILC_STR_UI32_STRING(iv),
			    SILC_STR_UI32_STRING("\n\n"),
			    SILC_STR_END) < 0)
      goto err;

    /* Generate key from passphrase and IV as salt.  The passphrase is
       hashed with the IV, then rehashed with the previous hash, passphrase
       and the IV to produce the final key, which is the concatenation of
       the two hashes. */
    silc_hash_init(md5);
    silc_hash_update(md5, passphrase, passphrase_len);
    silc_hash_update(md5, ivdata, 8);
    silc_hash_final(md5, enc);
    silc_hash_init(md5);
    silc_hash_update(md5, enc, 16);
    silc_hash_update(md5, passphrase, passphrase_len);
    silc_hash_update(md5, ivdata, 8);
    silc_hash_final(md5, enc + 16);

    /* Pad */
    pad_len = 8 - (key_len % 8);
    if (pad_len) {
      keyenc = silc_smalloc(stack, (key_len + pad_len) * sizeof(*keyenc));
      if (!key)
	goto err;
      memset(keyenc + key_len, 'F', pad_len);
      memcpy(keyenc, key, key_len);
    } else {
      keyenc = silc_memdup(key, key_len);
      if (!keyenc)
	goto err;
    }

    /* Encrypt */
    silc_cipher_set_key(des, enc, 192, TRUE);
    silc_cipher_encrypt(des, keyenc, keyenc, key_len + pad_len, ivdata);

    silc_sfree(stack, key);
    key = keyenc;
    key_len += pad_len;

    silc_cipher_free(des);
    silc_hash_free(md5);
  }

  /* Base64 encode */
  keyenc = silc_base64_encode_file(stack, key, key_len);
  if (!keyenc)
    goto err;

  silc_sfree(stack, key);
  key = keyenc;
  key_len = strlen(keyenc);

  /* Encode rest of the public key */
  if (!strcmp(alg->name, "rsa")) {
    if (silc_buffer_sformat(stack, &buf,
			    SILC_STR_ADVANCE,
			    SILC_STR_DATA(key, key_len),
			    SILC_STR_UI32_STRING("\n"),
			    SILC_STR_UI32_STRING(SILC_SSH_RSA_END),
			    SILC_STR_UI32_STRING("\n"),
			    SILC_STR_END) < 0)
      goto err;
  } else if (!strcmp(alg->name, "dsa")) {
    if (silc_buffer_sformat(stack, &buf,
			    SILC_STR_ADVANCE,
			    SILC_STR_DATA(key, key_len),
			    SILC_STR_UI32_STRING("\n"),
			    SILC_STR_UI32_STRING(SILC_SSH_DSA_END),
			    SILC_STR_UI32_STRING("\n"),
			    SILC_STR_END) < 0)
      goto err;
  }

  silc_sfree(stack, key);
  key = silc_buffer_steal(&buf, ret_len);
  return key;

 err:
  if (des)
    silc_cipher_free(des);
  if (md5)
    silc_hash_free(md5);
  silc_sfree(stack, key);
  return NULL;
}

/* Export private key */

SILC_PKCS_EXPORT_PRIVATE_KEY(silc_pkcs_ssh_export_private_key)
{
  SilcSshPrivateKey privkey = private_key;
  const SilcPKCSAlgorithm *alg = privkey->pkcs;

  SILC_LOG_DEBUG(("Encode SSH2 private key"));

  /* Export PKCS algorithm private key */
  if (alg->export_private_key)
    return alg->export_private_key(alg, stack,
				   privkey->private_key, ret_len);
  return NULL;
}

/* Return key length in bits */

SILC_PKCS_PRIVATE_KEY_BITLEN(silc_pkcs_ssh_private_key_bitlen)
{
  SilcSshPrivateKey privkey = private_key;
  return privkey->pkcs->private_key_bitlen(privkey->pkcs,
					   privkey->private_key);
}

/* Free private key */

SILC_PKCS_PRIVATE_KEY_FREE(silc_pkcs_ssh_private_key_free)
{
  SilcSshPrivateKey privkey = private_key;

  privkey->pkcs->private_key_free(privkey->pkcs,
				  privkey->private_key);

  if (privkey->fields)
    silc_hash_table_free(privkey->fields);
  silc_free(privkey);
}

/* Encrypt */

SILC_PKCS_ENCRYPT(silc_pkcs_ssh_encrypt)
{
  SilcSshPublicKey pubkey = public_key;

  if (!pubkey->pkcs->encrypt) {
    encrypt_cb(FALSE, NULL, 0, context);
    return NULL;
  }

  return pubkey->pkcs->encrypt(pubkey->pkcs, pubkey->public_key,
			       src, src_len, rng, encrypt_cb, context);
}

/* Decrypt */

SILC_PKCS_DECRYPT(silc_pkcs_ssh_decrypt)
{
  SilcSshPrivateKey privkey = private_key;

  if (!privkey->pkcs->decrypt) {
    decrypt_cb(FALSE, NULL, 0, context);
    return NULL;
  }

  return privkey->pkcs->decrypt(privkey->pkcs, privkey->private_key,
				src, src_len, decrypt_cb, context);
}

/* Sign */

SILC_PKCS_SIGN(silc_pkcs_ssh_sign)
{
  SilcSshPrivateKey privkey = private_key;

  if (!privkey->pkcs->sign) {
    sign_cb(FALSE, NULL, 0, context);
    return NULL;
  }

  return privkey->pkcs->sign(privkey->pkcs, privkey->private_key,
			     src, src_len,
			     compute_hash, hash, rng,
			     sign_cb, context);
}

/* Verify */

SILC_PKCS_VERIFY(silc_pkcs_ssh_verify)
{
  SilcSshPublicKey pubkey = public_key;

  if (!pubkey->pkcs->verify) {
    verify_cb(FALSE, context);
    return NULL;
  }

  return pubkey->pkcs->verify(pubkey->pkcs, pubkey->public_key,
			      signature, signature_len,
			      data, data_len, hash, rng,
			      verify_cb, context);
}

/************************** SSH2 PKCS RSA Alg API ***************************/

/* The SSH2 RSA PKCS Algorithm API.  We implement here only the necessary
   parts of the API and the common code is used from PKCS#1 Algorithm API
   in silccrypt/silcpkcs1.c.  Basically everything else is PKCS#1 except
   the format of the public key. */

/* Import RSA public key.  Both RFC 4716 and OpenSSH have same format. */

SILC_PKCS_ALG_IMPORT_PUBLIC_KEY(silc_ssh_rsa_import_public_key)
{
  SilcBufferStruct alg_key;
  RsaPublicKey *pubkey;
  unsigned char *n, *e;
  SilcUInt32 n_len, e_len;
  int ret;

  SILC_LOG_DEBUG(("Import public key"));

  if (!ret_public_key)
    return 0;

  /* Allocate RSA public key */
  *ret_public_key = pubkey = silc_calloc(1, sizeof(*pubkey));
  if (!pubkey)
    return 0;

  /* Parse SSH2 RSA public key */
  silc_buffer_set(&alg_key, key, key_len);
  ret = silc_buffer_unformat(&alg_key,
			     SILC_STR_UI32_NSTRING(&e, &e_len),
			     SILC_STR_UI32_NSTRING(&n, &n_len),
			     SILC_STR_END);
  if (ret < 0)
    goto err;
  if (!n_len || !e_len)
    goto err;

  /* Get MP integers */
  silc_mp_init(&pubkey->n);
  silc_mp_init(&pubkey->e);
  silc_mp_bin2mp(n, n_len, &pubkey->n);
  silc_mp_bin2mp(e, e_len, &pubkey->e);

  /* Set key length */
  pubkey->bits = ((silc_mp_sizeinbase(&pubkey->n, 2) + 7) / 8) * 8;

  return ret;

 err:
  silc_free(pubkey);
  return 0;
}

/* Export RSA public key.  Both RFC 4716 and OpenSSH have same format. */

SILC_PKCS_ALG_EXPORT_PUBLIC_KEY(silc_ssh_rsa_export_public_key)
{
  RsaPublicKey *pubkey = public_key;
  SilcBufferStruct alg_key;
  unsigned char *n = NULL, *e = NULL, *ret;
  SilcUInt32 n_len, e_len;

  SILC_LOG_DEBUG(("Export public key"));

  /* Encode MP integers */
  n = silc_mp_mp2bin(&pubkey->n, 0, &n_len);
  if (!n)
    goto err;
  e = silc_mp_mp2bin(&pubkey->e, 0, &e_len);
  if (!e)
    goto err;

  /* Encode SSH2 RSA public key */
  memset(&alg_key, 0, sizeof(alg_key));
  if (silc_buffer_sformat(stack, &alg_key,
			  SILC_STR_UI_INT(e_len),
			  SILC_STR_DATA(e, e_len),
			  SILC_STR_UI_INT(n_len),
			  SILC_STR_DATA(n, n_len),
			  SILC_STR_END) < 0)
    goto err;

  silc_free(n);
  silc_free(e);

  ret = silc_buffer_steal(&alg_key, ret_len);
  return ret;

 err:
  silc_free(n);
  silc_free(e);
  return NULL;
}

/************************** SSH2 PKCS DSA Alg API ***************************/

/* The SSH2 DSA PKCS Algorithm API.  We implement here only the necessary
   parts of the API and the common code is used from DSS Algorithm API
   in silccrypt/dsa.c. */

/* Import DSA public key.  Both RFC 4716 and OpenSSH have same format. */

SILC_PKCS_ALG_IMPORT_PUBLIC_KEY(silc_ssh_dsa_import_public_key)
{
  SilcBufferStruct alg_key;
  DsaPublicKey *pubkey;
  unsigned char *p, *q, *g, *y;
  SilcUInt32 p_len, q_len, g_len, y_len;
  int ret;

  SILC_LOG_DEBUG(("Import public key"));

  if (!ret_public_key)
    return 0;

  /* Allocate DSA public key */
  *ret_public_key = pubkey = silc_calloc(1, sizeof(*pubkey));
  if (!pubkey)
    return 0;

  /* Parse SSH2 DSA public key */
  silc_buffer_set(&alg_key, key, key_len);
  ret = silc_buffer_unformat(&alg_key,
			     SILC_STR_UI32_NSTRING(&p, &p_len),
			     SILC_STR_UI32_NSTRING(&q, &q_len),
			     SILC_STR_UI32_NSTRING(&g, &g_len),
			     SILC_STR_UI32_NSTRING(&y, &y_len),
			     SILC_STR_END);
  if (ret < 0)
    goto err;
  if (!p_len || !q_len || !g_len || !y_len)
    goto err;

  /* Get MP integers */
  silc_mp_init(&pubkey->p);
  silc_mp_init(&pubkey->q);
  silc_mp_init(&pubkey->g);
  silc_mp_init(&pubkey->y);
  silc_mp_bin2mp(p, p_len, &pubkey->p);
  silc_mp_bin2mp(q, q_len, &pubkey->q);
  silc_mp_bin2mp(g, g_len, &pubkey->g);
  silc_mp_bin2mp(y, y_len, &pubkey->y);

  /* Set key length */
  pubkey->bits = ((silc_mp_sizeinbase(&pubkey->p, 2) + 7) / 8) * 8;

  return ret;

 err:
  silc_free(pubkey);
  return 0;
}

/* Export DSA public key.  Both RFC 4716 and OpenSSH have same format. */

SILC_PKCS_ALG_EXPORT_PUBLIC_KEY(silc_ssh_dsa_export_public_key)
{
  DsaPublicKey *pubkey = public_key;
  SilcBufferStruct alg_key;
  unsigned char *p = NULL, *q = NULL, *g = NULL, *y = NULL, *ret;
  SilcUInt32 p_len, q_len, g_len, y_len;

  SILC_LOG_DEBUG(("Export public key"));

  /* Encode MP integers */
  p = silc_mp_mp2bin(&pubkey->p, 0, &p_len);
  if (!p)
    goto err;
  q = silc_mp_mp2bin(&pubkey->q, 0, &q_len);
  if (!q)
    goto err;
  g = silc_mp_mp2bin(&pubkey->g, 0, &g_len);
  if (!g)
    goto err;
  y = silc_mp_mp2bin(&pubkey->y, 0, &y_len);
  if (!y)
    goto err;

  /* Encode SSH2 DSA public key */
  memset(&alg_key, 0, sizeof(alg_key));
  if (silc_buffer_sformat(stack, &alg_key,
			  SILC_STR_UI_INT(p_len),
			  SILC_STR_DATA(p, p_len),
			  SILC_STR_UI_INT(q_len),
			  SILC_STR_DATA(q, q_len),
			  SILC_STR_UI_INT(g_len),
			  SILC_STR_DATA(g, g_len),
			  SILC_STR_UI_INT(y_len),
			  SILC_STR_DATA(y, y_len),
			  SILC_STR_END) < 0)
    goto err;

  silc_free(p);
  silc_free(q);
  silc_free(g);
  silc_free(y);

  ret = silc_buffer_steal(&alg_key, ret_len);
  return ret;

 err:
  silc_free(p);
  silc_free(q);
  silc_free(g);
  silc_free(y);
  return NULL;
}
