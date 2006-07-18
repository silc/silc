/*

  silccipher.c

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
#include "ciphers.h"		/* Includes cipher definitions */

/* The SilcCipher context */
struct SilcCipherStruct {
  SilcCipherObject *cipher;
  void *context;
  unsigned char iv[SILC_CIPHER_MAX_IV_SIZE];
};

#ifndef SILC_EPOC
/* Dynamically registered list of ciphers. */
SilcDList silc_cipher_list = NULL;
#endif /* SILC_EPOC */

/* Static list of ciphers for silc_cipher_register_default(). */
const SilcCipherObject silc_default_ciphers[] =
{
  { "aes-256-cbc", 16, 256, silc_aes_set_key,
    silc_aes_set_key_with_string, silc_aes_encrypt_cbc,
    silc_aes_decrypt_cbc, silc_aes_context_len },
  { "aes-192-cbc", 16, 192, silc_aes_set_key,
    silc_aes_set_key_with_string, silc_aes_encrypt_cbc,
    silc_aes_decrypt_cbc, silc_aes_context_len },
  { "aes-128-cbc", 16, 128, silc_aes_set_key,
    silc_aes_set_key_with_string, silc_aes_encrypt_cbc,
    silc_aes_decrypt_cbc, silc_aes_context_len },
  { "twofish-256-cbc", 16, 256, silc_twofish_set_key,
    silc_twofish_set_key_with_string,
    silc_twofish_encrypt_cbc, silc_twofish_decrypt_cbc,
    silc_twofish_context_len },
  { "twofish-192-cbc", 16, 192, silc_twofish_set_key,
    silc_twofish_set_key_with_string,
    silc_twofish_encrypt_cbc, silc_twofish_decrypt_cbc,
    silc_twofish_context_len },
  { "twofish-128-cbc", 16, 128, silc_twofish_set_key,
    silc_twofish_set_key_with_string,
    silc_twofish_encrypt_cbc, silc_twofish_decrypt_cbc,
    silc_twofish_context_len },
  { "cast-256-cbc", 16, 256, silc_cast_set_key, silc_cast_set_key_with_string,
    silc_cast_encrypt_cbc, silc_cast_decrypt_cbc,
    silc_cast_context_len },
  { "cast-192-cbc", 16, 192, silc_cast_set_key, silc_cast_set_key_with_string,
    silc_cast_encrypt_cbc, silc_cast_decrypt_cbc,
    silc_cast_context_len },
  { "cast-128-cbc", 16, 128, silc_cast_set_key, silc_cast_set_key_with_string,
    silc_cast_encrypt_cbc, silc_cast_decrypt_cbc,
    silc_cast_context_len },
#ifdef SILC_DEBUG
  { "none", 0, 0, silc_none_set_key, silc_none_set_key_with_string,
    silc_none_encrypt_cbc, silc_none_decrypt_cbc,
    silc_none_context_len },
#endif /* SILC_DEBUG */

  { NULL, 0, 0, NULL, NULL, NULL, NULL, NULL }
};

/* Register a new cipher into SILC. This is used at the initialization of
   the SILC. This function allocates a new object for the cipher to be
   registered. Therefore, if memory has been allocated for the object sent
   as argument it has to be free'd after this function returns succesfully. */

SilcBool silc_cipher_register(const SilcCipherObject *cipher)
{
#ifndef SILC_EPOC
  SilcCipherObject *new;

  SILC_LOG_DEBUG(("Registering new cipher `%s'", cipher->name));

  /* Check if exists already */
  if (silc_cipher_list) {
    SilcCipherObject *entry;
    silc_dlist_start(silc_cipher_list);
    while ((entry = silc_dlist_get(silc_cipher_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, cipher->name))
	return FALSE;
    }
  }

  new = silc_calloc(1, sizeof(*new));
  new->name = strdup(cipher->name);
  new->block_len = cipher->block_len;
  new->key_len = cipher->key_len;
  new->set_key = cipher->set_key;
  new->set_key_with_string = cipher->set_key_with_string;
  new->encrypt = cipher->encrypt;
  new->decrypt = cipher->decrypt;
  new->context_len = cipher->context_len;

  /* Add to list */
  if (silc_cipher_list == NULL)
    silc_cipher_list = silc_dlist_init();
  silc_dlist_add(silc_cipher_list, new);

#endif /* SILC_EPOC */
  return TRUE;
}

/* Unregister a cipher from the SILC. */

SilcBool silc_cipher_unregister(SilcCipherObject *cipher)
{
#ifndef SILC_EPOC
  SilcCipherObject *entry;

  SILC_LOG_DEBUG(("Unregistering cipher"));

  if (!silc_cipher_list)
    return FALSE;

  silc_dlist_start(silc_cipher_list);
  while ((entry = silc_dlist_get(silc_cipher_list)) != SILC_LIST_END) {
    if (cipher == SILC_ALL_CIPHERS || entry == cipher) {
      silc_dlist_del(silc_cipher_list, entry);
      silc_free(entry->name);
      silc_free(entry);

      if (silc_dlist_count(silc_cipher_list) == 0) {
	silc_dlist_uninit(silc_cipher_list);
	silc_cipher_list = NULL;
      }

      return TRUE;
    }
  }

#endif /* SILC_EPOC */
  return FALSE;
}

/* Function that registers all the default ciphers (all builtin ciphers).
   The application may use this to register the default ciphers if specific
   ciphers in any specific order is not wanted. */

SilcBool silc_cipher_register_default(void)
{
#ifndef SILC_EPOC
  int i;

  for (i = 0; silc_default_ciphers[i].name; i++)
    silc_cipher_register(&(silc_default_ciphers[i]));

#endif /* SILC_EPOC */
  return TRUE;
}

SilcBool silc_cipher_unregister_all(void)
{
#ifndef SILC_EPOC
  SilcCipherObject *entry;

  if (!silc_cipher_list)
    return FALSE;

  silc_dlist_start(silc_cipher_list);
  while ((entry = silc_dlist_get(silc_cipher_list)) != SILC_LIST_END) {
    silc_cipher_unregister(entry);
    if (!silc_cipher_list)
      break;
  }
#endif /* SILC_EPOC */
  return TRUE;
}

/* Allocates a new SILC cipher object. Function returns 1 on succes and 0
   on error. The allocated cipher is returned in new_cipher argument. The
   caller must set the key to the cipher after this function has returned
   by calling the ciphers set_key function. */

SilcBool silc_cipher_alloc(const unsigned char *name, SilcCipher *new_cipher)
{
  SilcCipherObject *entry = NULL;

  SILC_LOG_DEBUG(("Allocating new cipher object"));

#ifndef SILC_EPOC
  if (silc_cipher_list) {
    silc_dlist_start(silc_cipher_list);
    while ((entry = silc_dlist_get(silc_cipher_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, name))
	break;
    }
  }
#else
  {
    /* On EPOC which don't have globals we check our constant cipher list. */
    int i;
    for (i = 0; silc_default_ciphers[i].name; i++) {
      if (!strcmp(silc_default_ciphers[i].name, name)) {
	entry = (SilcCipherObject *)&(silc_default_ciphers[i]);
	break;
      }
    }
  }
#endif /* SILC_EPOC */

  if (entry) {
    *new_cipher = silc_calloc(1, sizeof(**new_cipher));
    (*new_cipher)->cipher = entry;
    (*new_cipher)->context = silc_calloc(1, entry->context_len());
    return TRUE;
  }

  return FALSE;
}

/* Free's the given cipher. */

void silc_cipher_free(SilcCipher cipher)
{
  if (cipher) {
    silc_free(cipher->context);
    silc_free(cipher);
  }
}

/* Returns TRUE if cipher `name' is supported. */

SilcBool silc_cipher_is_supported(const unsigned char *name)
{
#ifndef SILC_EPOC
  SilcCipherObject *entry;

  if (silc_cipher_list) {
    silc_dlist_start(silc_cipher_list);
    while ((entry = silc_dlist_get(silc_cipher_list)) != SILC_LIST_END) {
      if (!strcmp(entry->name, name))
	return TRUE;
    }
  }
#else
  {
    int i;
    for (i = 0; silc_default_ciphers[i].name; i++)
      if (!strcmp(silc_default_ciphers[i].name, name))
	return TRUE;
  }
#endif /* SILC_EPOC */
  return FALSE;
}

/* Returns comma separated list of supported ciphers. */

char *silc_cipher_get_supported(void)
{
  SilcCipherObject *entry;
  char *list = NULL;
  int len = 0;

#ifndef SILC_EPOC
  if (silc_cipher_list) {
    silc_dlist_start(silc_cipher_list);
    while ((entry = silc_dlist_get(silc_cipher_list)) != SILC_LIST_END) {
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
    for (i = 0; silc_default_ciphers[i].name; i++) {
      entry = (SilcCipherObject *)&(silc_default_ciphers[i]);
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

/* Encrypts */

SilcBool silc_cipher_encrypt(SilcCipher cipher, const unsigned char *src,
			     unsigned char *dst, SilcUInt32 len,
			     unsigned char *iv)
{
#ifdef SILC_DEBUG
  assert((len & (cipher->cipher->block_len - 1)) == 0);
#endif
  if (len & (cipher->cipher->block_len - 1))
    return FALSE;
  return cipher->cipher->encrypt(cipher->context, src, dst, len,
				 iv ? iv : cipher->iv);
}

/* Decrypts */

SilcBool silc_cipher_decrypt(SilcCipher cipher, const unsigned char *src,
			     unsigned char *dst, SilcUInt32 len,
			     unsigned char *iv)
{
#ifdef SILC_DEBUG
  /*  assert((len & (cipher->cipher->block_len - 1)) == 0); */
#endif
  if (len & (cipher->cipher->block_len - 1))
    return FALSE;
  return cipher->cipher->decrypt(cipher->context, src, dst, len,
				 iv ? iv : cipher->iv);
}

/* Sets the key for the cipher */

SilcBool silc_cipher_set_key(SilcCipher cipher, const unsigned char *key,
			     SilcUInt32 keylen)
{
  return cipher->cipher->set_key(cipher->context, key, keylen);
}

/* Sets the IV (initial vector) for the cipher. */

void silc_cipher_set_iv(SilcCipher cipher, const unsigned char *iv)
{
  memset(&cipher->iv, 0, sizeof(cipher->iv));
  memcpy(&cipher->iv, iv, cipher->cipher->block_len);
}

/* Returns the IV (initial vector) of the cipher. */

unsigned char *silc_cipher_get_iv(SilcCipher cipher)
{
  return cipher->iv;
}

/* Returns the key length of the cipher. */

SilcUInt32 silc_cipher_get_key_len(SilcCipher cipher)
{
  return cipher->cipher->key_len;
}

/* Returns the block size of the cipher. */

SilcUInt32 silc_cipher_get_block_len(SilcCipher cipher)
{
  return cipher->cipher->block_len;
}

/* Returns the name of the cipher */

const char *silc_cipher_get_name(SilcCipher cipher)
{
  return (const char *)cipher->cipher->name;
}
