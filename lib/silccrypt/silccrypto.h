/*

  silccrypto.h

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

/****h* silccrypt/SILC Crypto Toolkit API
 *
 * DESCRIPTION
 *
 * This interface is used to initialize and uninitialize the SILC Crypto
 * Toolkit.  SILC Crypto Toolkit is initialized by calling the
 * silc_crypto_init function.  It needs to be called only once per-process
 * but must be called before any crypto functions are used.
 *
 * In initialization all builtin ciphers, hash functions, HMACs, PKCSs
 * and other algorithms will be registered to the crypto library.  If user
 * wants to register new algorithms or change the order of the automatically
 * registered algorithms, user can do this by re-registering the algorithms
 * in desired order.
 *
 * A global SilcStack, a memory pool, can be associated with the Crypto
 * Toolkit.  If it is set in initialization, all routines in the Crypto
 * Toolkit will use that stack as its memory source.  Some interfaces and
 * libraries in the SILC Crypto Toolkit support also providing the SilcStack
 * as an additional argument, in which case a different stack from the global
 * one can be used.
 *
 ***/

#ifndef SILCCRYPTO_H
#define SILCCRYPTO_H

/****f* silccrypt/SilcCryptoAPI/silc_crypto_init
 *
 * SYNOPSIS
 *
 *    SilcBool silc_crypto_init(SilcStack stack);
 *
 * DESCRIPTION
 *
 *    Initialize SILC Crypto Toolkit.  This must be called once for every
 *    process.  It initializes all libraries and registers builtin algorithms
 *    to the crypto library.  If user wants to change the order of the
 *    registered algorithms, user can re-register them with their
 *    corresponding registering functions in the wanted order.
 *
 *    If `stack' is non-NULL, it will be used by some libraries as their main
 *    source for memory.  A child stack is created from the `stack'.  When
 *    silc_crypto_uninit is called the allocated memory is returned back to
 *    `stack' and the caller must then free `stack'.
 *
 *    Returns FALSE if the initialization failed.  If this happens the
 *    SILC Crypto Toolkit cannot be used.
 *
 ***/
SilcBool silc_crypto_init(SilcStack stack);

/****f* silccrypt/SilcCryptoAPI/silc_crypto_uninit
 *
 * SYNOPSIS
 *
 *    void silc_crypto_uninit(void);
 *
 * DESCRIPTION
 *
 *    Uninitializes the SILC Crypto Toolkit.  This should be called at the
 *    of the process before it is exited.
 *
 ***/
void silc_crypto_uninit(void);

/****f* silccrypt/SilcCryptoAPI/silc_crypto_stack
 *
 * SYNOPSIS
 *
 *    SilcStack silc_crypto_stack(void);
 *
 * DESCRIPTION
 *
 *    Returns the SILC Crypto Toolkit's global stack, the memory pool.
 *    Returns NULL if the stack does not exist.
 *
 *    A common way to use this is to allocate a child stack from the
 *    returned stack.  That operation is thread-safe, usually does not
 *    allocate any memory and is very fast.  Another way to use the stack
 *    is to push it when memory is needed and then pop it when it is not
 *    needed anymore.  Note however, that is not thread-safe if the stack
 *    is used in multi-threaded environment.
 *
 * EXAMPLE
 *
 *    SilcStack stack;
 *
 *    // Get child stack from global crypto stack
 *    stack = silc_stack_alloc(0, silc_crypto_stack());
 *    ...
 *
 *    // Return memory back to the global crypto stack
 *    silc_stack_free(stack);
 *
 ***/
SilcStack silc_crypto_stack(void);

#endif /* SILCCRYPTO_H */
