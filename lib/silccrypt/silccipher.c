/*

  silccipher.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/*
 * $Id$
 * $Log$
 * Revision 1.3  2000/09/28 11:28:20  priikone
 * 	Changed cipher list order.
 *
 * Revision 1.2  2000/07/05 06:08:43  priikone
 * 	Global cosmetic change.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:54  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "silcincludes.h"

#include "ciphers.h"		/* Includes cipher definitions */

/* List of all ciphers in SILC. You can dynamically add new ciphers
   into the list. At the initialization of SILC this list is filled with
   the configured ciphers. */
struct SilcCipherListStruct {
  SilcCipherObject *cipher;
  struct SilcCipherListStruct *next;
};

/* Dynamically registered list of ciphers. */
struct SilcCipherListStruct *silc_cipher_list = NULL;

/* XXX: add the other good ciphers here as well */

/* Staticly declared list of ciphers. This is used if system doesn't
   support SIM's. */
SilcCipherObject silc_cipher_builtin_list[] =
{
  { "twofish", 16, 16, silc_twofish_set_key, silc_twofish_set_key_with_string,
    silc_twofish_encrypt_cbc, silc_twofish_decrypt_cbc, 
    silc_twofish_context_len },
  { "rc6", 16, 16, silc_rc6_set_key, silc_rc6_set_key_with_string,
    silc_rc6_encrypt_cbc, silc_rc6_decrypt_cbc, 
    silc_rc6_context_len },
  { "mars", 16, 16, silc_mars_set_key, silc_mars_set_key_with_string,
    silc_mars_encrypt_cbc, silc_mars_decrypt_cbc, 
    silc_mars_context_len },
  { "none", 0, 0, silc_none_set_key, silc_none_set_key_with_string,
    silc_none_encrypt_cbc, silc_none_decrypt_cbc, 
    silc_none_context_len },

  { NULL, 0, 0, NULL, NULL, NULL, NULL, NULL }
};

/* Register a new cipher into SILC. This is used at the initialization of
   the SILC. This function allocates a new object for the cipher to be
   registered. Therefore, if memory has been allocated for the object sent
   as argument it has to be free'd after this function returns succesfully. */

int silc_cipher_register(SilcCipherObject *cipher)
{
  struct SilcCipherListStruct *new, *c;

  SILC_LOG_DEBUG(("Registering new cipher"));

  new = silc_calloc(1, sizeof(*new));
  new->cipher = silc_calloc(1, sizeof(*new->cipher));

  /* Set the pointers */
  new->cipher->name = strdup(cipher->name);
  new->cipher->block_len = cipher->block_len;
  new->cipher->key_len = cipher->key_len;
  new->cipher->set_key = cipher->set_key;
  new->cipher->set_key_with_string = cipher->set_key_with_string;
  new->cipher->encrypt = cipher->encrypt;
  new->cipher->decrypt = cipher->decrypt;
  new->cipher->context_len = cipher->context_len;
  new->next = NULL;

  /* Add the new cipher to the list */
  if (!silc_cipher_list) {
    silc_cipher_list = new;
    return TRUE;
  }

  c = silc_cipher_list;
  while (c) {
    if (!c->next) {
      c->next = new;
      break;
    }
    c = c->next;
  }

  return TRUE;
}

/* Unregister a cipher from the SILC. */

int silc_cipher_unregister(SilcCipherObject *cipher)
{
  struct SilcCipherListStruct *c, *tmp;

  SILC_LOG_DEBUG(("Unregistering cipher"));

  c = silc_cipher_list;
  
  if (cipher == SILC_ALL_CIPHERS) {
    /* Unregister all ciphers */
    while (c) {
      tmp = c->next;
      silc_free(c->cipher->name);
      silc_free(c);
      c = tmp;
    }

    return TRUE;
  }

  /* Unregister the cipher */
  if (c->cipher == cipher) {
    tmp = c->next;
    silc_free(c->cipher->name);
    silc_free(c);
    silc_cipher_list = tmp;
    
    return TRUE;
  }

  while (c) {
    if (c->next->cipher == cipher) {

      tmp = c->next->next;
      silc_free(c->cipher->name);
      silc_free(c);
      c->next = tmp;

      return TRUE;
    }

    c = c->next;
  }

  return FALSE;
}

/* Allocates a new SILC cipher object. Function returns 1 on succes and 0 
   on error. The allocated cipher is returned in new_cipher argument. The
   caller must set the key to the cipher after this function has returned
   by calling the ciphers set_key function. */

int silc_cipher_alloc(const unsigned char *name, SilcCipher *new_cipher)
{
  struct SilcCipherListStruct *c;
  int i;

  SILC_LOG_DEBUG(("Allocating new cipher object"));

  /* Allocate the new object */
  *new_cipher = silc_calloc(1, sizeof(**new_cipher));
  
  if (silc_cipher_list) {

    c = silc_cipher_list;
    while (c) {
      if (!strcmp(c->cipher->name, name))
	break;
      c = c->next;
    }

    if (!c)
      goto check_builtin;

    /* Set the pointers */
    (*new_cipher)->cipher = c->cipher;
    (*new_cipher)->context = silc_calloc(1, c->cipher->context_len());
    (*new_cipher)->set_iv = silc_cipher_set_iv;
    (*new_cipher)->get_iv = silc_cipher_get_iv;
    (*new_cipher)->get_key_len = silc_cipher_get_key_len;
    (*new_cipher)->get_block_len = silc_cipher_get_block_len;
    
    return TRUE;
  }

 check_builtin:

  for (i = 0; silc_cipher_builtin_list[i].name; i++)
    if (!strcmp(silc_cipher_builtin_list[i].name, name))
      break;

  if (silc_cipher_builtin_list[i].name == NULL) {
    silc_free(*new_cipher);
    return FALSE;
  }

  /* Set the pointers */
  (*new_cipher)->cipher = &silc_cipher_builtin_list[i];
  (*new_cipher)->context = 
    silc_calloc(1, (*new_cipher)->cipher->context_len());
  (*new_cipher)->set_iv = silc_cipher_set_iv;
  (*new_cipher)->get_iv = silc_cipher_get_iv;
  (*new_cipher)->get_key_len = silc_cipher_get_key_len;
  (*new_cipher)->get_block_len = silc_cipher_get_block_len;
  memset(&(*new_cipher)->iv, 0, sizeof((*new_cipher)->iv));

  return TRUE;
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

int silc_cipher_is_supported(const unsigned char *name)
{
  struct SilcCipherListStruct *c;
  int i;

  if (silc_cipher_list) {
    c = silc_cipher_list;

    while (c) {
      if (!strcmp(c->cipher->name, name))
	return TRUE;
      c = c->next;
    }
  }

  for (i = 0; silc_cipher_builtin_list[i].name; i++)
    if (!strcmp(silc_cipher_builtin_list[i].name, name))
      return TRUE;

  return FALSE;
}

/* Returns comma separated list of supported ciphers. */

char *silc_cipher_get_supported()
{
  char *list = NULL;
  int i, len;
  struct SilcCipherListStruct *c;

  len = 0;
  if (silc_cipher_list) {
    c = silc_cipher_list;

    while (c) {
      len += strlen(c->cipher->name);
      list = silc_realloc(list, len + 1);
      
      memcpy(list + (len - strlen(c->cipher->name)), 
	     c->cipher->name, strlen(c->cipher->name));
      memcpy(list + len, ",", 1);
      len++;
      
      c = c->next;
    }
  }

  for (i = 0; silc_cipher_builtin_list[i].name; i++) {
    len += strlen(silc_cipher_builtin_list[i].name);
    list = silc_realloc(list, len + 1);
    
    memcpy(list + (len - strlen(silc_cipher_builtin_list[i].name)), 
	   silc_cipher_builtin_list[i].name, 
	   strlen(silc_cipher_builtin_list[i].name));
    memcpy(list + len, ",", 1);
    len++;
  }

  list[len - 1] = 0;

  return list;
}

/* Sets the IV (initial vector) for the cipher. */

void silc_cipher_set_iv(SilcCipher itself, const unsigned char *iv)
{
  memset(&itself->iv, 0, sizeof(itself->iv));
  memcpy(&itself->iv, iv, itself->cipher->block_len);
}

/* Returns the IV (initial vector) of the cipher. The IV is returned 
   to 'iv' argument. */

void silc_cipher_get_iv(SilcCipher itself, unsigned char *iv)
{
  memcpy(iv, &itself->iv, itself->cipher->block_len);
}

/* Returns the key length of the cipher. */
/* XXX */

unsigned int silc_cipher_get_key_len(SilcCipher itself, 
				     const unsigned char *name)
{

  return TRUE;
}

/* Returns the block size of the cipher. */
/* XXX */

unsigned int silc_cipher_get_block_len(SilcCipher itself)
{

  return TRUE;
}
