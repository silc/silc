/*

  silccrypto.c

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

#ifndef SILC_SYMBIAN
SilcStack crypto_stack = NULL;		/* Crypto Toolkit's global stack */
#endif /* SILC_SYMBIAN */

/* Init crypto */

SilcBool silc_crypto_init(SilcStack stack)
{
  SILC_LOG_DEBUG(("Initializing crypto"));

#ifndef SILC_SYMBIAN
  /* Stack allocation is allowed to fail */
  crypto_stack = silc_stack_alloc(0, stack);
#endif /* SILC_SYMBIAN */

  /* Init crypto library */
  if (!silc_cipher_register_default()) {
    SILC_LOG_ERROR(("Error registering ciphers"));
    goto err;
  }
  if (!silc_hash_register_default()) {
    SILC_LOG_ERROR(("Error registering hash functions"));
    goto err;
  }
  if (!silc_hmac_register_default()) {
    SILC_LOG_ERROR(("Error registering hash HMACs"));
    goto err;
  }
  if (!silc_pkcs_register_default()) {
    SILC_LOG_ERROR(("Error registering hash PKCSs"));
    goto err;
  }

#ifdef SILC_DIST_ACC
  /* Initialize accelerator library */
#endif /* SILC_DIST_ACC */

  return TRUE;

 err:
  silc_crypto_uninit();
  return FALSE;
}

/* Uninit crypto */

void silc_crypto_uninit(void)
{
  SILC_LOG_DEBUG(("Uninitializing crypto"));

#ifdef SILC_DIST_ACC
  /* Uninit accelerator library */
#endif /* SILC_DIST_ACC */

  /* Uninit crypto library */
  silc_pkcs_unregister_all();
  silc_hmac_unregister_all();
  silc_hash_unregister_all();
  silc_cipher_unregister_all();

#ifndef SILC_SYMBIAN
  silc_stack_free(crypto_stack);
#endif /* SILC_SYMBIAN */
}

/* Return stack */

SilcStack silc_crypto_stack(void)
{
#ifndef SILC_SYMBIAN
  return crypto_stack;
#else
  return NULL;
#endif /* SILC_SYMBIAN */
}
