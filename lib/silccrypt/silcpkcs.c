/*

  silcpkcs.c

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

#include "silcincludes.h"

#include "rsa.h"

/* List of all PKCS's in SILC. PKCS's don't support SIM's thus
   only static declarations are possible. XXX: I hope this to change
   real soon. */
SilcPKCSObject silc_pkcs_list[] =
{
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
  if (*new_pkcs == NULL) {
    SILC_LOG_ERROR(("Could not allocate new PKCS object"));
    return FALSE;
  }

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

/* Sets public key */
/* XXX rewrite */

int silc_pkcs_set_public_key(SilcPKCS pkcs, unsigned char *pk, 
			     unsigned int pk_len)
{
  return pkcs->pkcs->set_public_key(pkcs->context, pk, pk_len);
}

/* Sets private key */

int silc_pkcs_set_private_key(SilcPKCS pkcs, unsigned char *prv, 
			      unsigned int prv_len)
{
  return pkcs->pkcs->set_private_key(pkcs->context, prv, prv_len);
}

/* Saves public key into file */

int silc_pkcs_save_public_key(SilcPKCS pkcs, char *filename,
			      unsigned char *pk, unsigned int pk_len)
{
  SilcBuffer buf;
  int ret = TRUE;

  buf = silc_buffer_alloc(strlen(pkcs->pkcs->name) + 2 + pk_len
			  + strlen(SILC_PKCS_PUBLIC_KEYFILE_BEGIN) 
			  + strlen(SILC_PKCS_PUBLIC_KEYFILE_END));

  silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));

  silc_buffer_format(buf,
		     SILC_STR_UI32_STRING(SILC_PKCS_PUBLIC_KEYFILE_BEGIN),
		     SILC_STR_UI32_STRING(pkcs->pkcs->name),
		     SILC_STR_UI_SHORT(pk_len),
		     SILC_STR_UI_XNSTRING(pk, pk_len),
		     SILC_STR_UI32_STRING(SILC_PKCS_PUBLIC_KEYFILE_END),
		     SILC_STR_END);

  /* Save into a file */
  if (silc_file_write(filename, buf->data, buf->len)) {
    ret = FALSE;
    goto out;
  }

 out:
  silc_buffer_free(buf);
  return ret;
}

/* XXX The buffer should be encrypted */
/* XXX rewrite */

int silc_pkcs_save_private_key(SilcPKCS pkcs, char *filename,
			       unsigned char *prv, unsigned int prv_len,
			       char *passphrase)
{
  SilcBuffer buf;
  int ret = TRUE;

  buf = silc_buffer_alloc(strlen(pkcs->pkcs->name) + 2 + prv_len
			  + strlen(SILC_PKCS_PRIVATE_KEYFILE_BEGIN) 
			  + strlen(SILC_PKCS_PRIVATE_KEYFILE_END));
  silc_buffer_pull_tail(buf, SILC_BUFFER_END(buf));

  silc_buffer_format(buf,
		     SILC_STR_UI32_STRING(SILC_PKCS_PRIVATE_KEYFILE_BEGIN),
		     SILC_STR_UI32_STRING(pkcs->pkcs->name),
		     SILC_STR_UI_SHORT(prv_len),
		     SILC_STR_UI_XNSTRING(prv, prv_len),
		     SILC_STR_UI32_STRING(SILC_PKCS_PRIVATE_KEYFILE_END),
		     SILC_STR_END);

  /* Save into a file */
  if (silc_file_write(filename, buf->data, buf->len)) {
    ret = FALSE;
    goto out;
  }

 out:
  silc_buffer_free(buf);
  return ret;
}

/* Loads public key from file and allocates new PKCS object and
   sets the loaded key into it. */

int silc_pkcs_load_public_key(char *filename, SilcPKCS *ret_pkcs)
{

  return TRUE;
}

/* Loads private key from file and allocates new PKCS object and
   sets the loaded key into it. */

int silc_pkcs_load_private_key(char *filename, SilcPKCS *ret_pkcs)
{

  return TRUE;
}
