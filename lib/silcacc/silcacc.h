/*

  silcacc.h

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

/****h* silcskr/SILC Accelerator Interface
 *
 * DESCRIPTION
 *
 ***/

#ifndef SILCACC_H
#define SILCACC_H

/****s* silcacc/SilcAccAPI/SilcAccelerator
 *
 * NAME
 *
 *    typedef struct SilcAcceleratorObject { ... }
 *                            *SilcAccelerator, SilcAcceleratorStruct;
 *
 * DESCRIPTION
 *
 *    The accelerator context.  This is given as argument to silc_acc_register
 *    when registering new accelerator, and it is given as argument to all
 *    other silc_acc_* functions.  Registered accelerator context can be
 *    retrieved by calling silc_acc_find.
 *
 ***/
typedef struct SilcAcceleratorObject {
  const char *name;                         /* Accelerator's name */
  SilcBool (*init)(SilcSchedule schedule,
		   va_list va);		    /* Initialize accelerator */
  SilcBool (*uninit)(void);		    /* Uninitialize accelerator */
  const SilcPKCSAlgorithm *pkcs;            /* Accelerated PKCS algorithms */
#if 0
  const SilcDHObject *dh;                   /* Accelerated Diffie-Hellmans */
  const SilcCipherObject *cipher;	    /* Accelerated ciphers */
  const SilcHashObject *hash;		    /* Accelerated hashes */
  const SilcHmacObject *hmac;		    /* Accelerated HMACs */
  const SilcRngObject *rng;		    /* Accelerated RNG's */
#endif /* 0 */
} *SilcAccelerator, SilcAcceleratorStruct;

/****f* silcacc/SilcAccAPI/silc_acc_register
 *
 * SYNOPSIS
 *
 *    SilcBool silc_acc_register(const SilcAccelerator acc);
 *
 * DESCRIPTION
 *
 *    Register new accelerator to the accelerator library.  The `acc'
 *    is the accelerator context to be registered.
 *
 * NOTES
 *
 *    This needs to be called only when adding new accelerator to the
 *    library.  The accelerator library has some pre-registered accelerators
 *    that need not be registered with this call.
 *
 ***/
SilcBool silc_acc_register(const SilcAccelerator acc);

/****f* silcacc/SilcAccAPI/silc_acc_unregister
 *
 * SYNOPSIS
 *
 *    void silc_acc_unregister(SilcAccelerator acc);
 *
 * DESCRIPTION
 *
 *    Unregister the accelerator `acc' from the accelerator library.  The
 *    accelerator cannot be used anymore after this call has returned.
 *
 ***/
void silc_acc_unregister(SilcAccelerator acc);

/****f* silcacc/SilcAccAPI/silc_acc_find
 *
 * SYNOPSIS
 *
 *    SilcAccelerator silc_acc_find(const char *name);
 *
 * DESCRIPTION
 *
 *    Find accelerator by its name indicated by `name'.  Returns the
 *    accelerator context or NULL if such accelerator is not registered.
 *
 ***/
SilcAccelerator silc_acc_find(const char *name);

/****f* silcacc/SilcAccAPI/silc_acc_init
 *
 * SYNOPSIS
 *
 *    SilcBool silc_acc_init(SilcAccelerator acc, SilcSchedule schedule, ...);
 *
 * DESCRIPTION
 *
 *    Initialize accelerator `acc'.  Usually accelerator may be initialized
 *    only once and should be done after registering it.  The `schedule'
 *    must be given as argument, in case the accelerator needs to do operations
 *    through the scheduler.  The variable argument list is optional
 *    accelerator specific initialization arguments.  The argument list must
 *    be ended with NULL.  Returns FALSE if initialization failed.
 *
 * EXAMPLE
 *
 *    silc_acc_init(softacc, "min_threads", 2, "max_threads", 16, NULL);
 *
 ***/
SilcBool silc_acc_init(SilcAccelerator acc, SilcSchedule schedule, ...);

/****f* silcacc/SilcAccAPI/silc_acc_uninit
 *
 * SYNOPSIS
 *
 *    SilcBool silc_acc_uninit(SilcAccelerator acc);
 *
 * DESCRIPTION
 *
 *    Uninitialize the accelerator `acc'.  The accelerator may not be used
 *    after this call has returned.  Some accelerators may be re-initialized
 *    by calling silc_acc_init again.  Returns FALSE if error occurred
 *    during uninitializing.
 *
 ***/
SilcBool silc_acc_uninit(SilcAccelerator acc);

/****f* silcacc/SilcAccAPI/silc_acc_get_supported
 *
 * SYNOPSIS
 *
 *    SilcDList silc_acc_get_supported(void);
 *
 * DESCRIPTION
 *
 *    Returns list of registered accelerators.  The caller must free the
 *    returned list by calling silc_dlist_uninit.
 *
 ***/
SilcDList silc_acc_get_supported(void);

/****f* silcacc/SilcAccAPI/silc_acc_get_name
 *
 * SYNOPSIS
 *
 *    const char *silc_acc_get_name(SilcAccelerator acc);
 *
 * DESCRIPTION
 *
 *    Returns the name of the accelerator `acc'.
 *
 ***/
const char *silc_acc_get_name(SilcAccelerator acc);

/****f* silcacc/SilcAccAPI/silc_acc_public_key
 *
 * SYNOPSIS
 *
 *    SilcPublicKey silc_acc_public_key(SilcAccelerator acc,
 *                                      SilcPublicKey public_key);
 *
 * DESCRIPTION
 *
 *    Accelerate the public key indicated by `public_key'.  Returns new
 *    accelerated SilcPublicKey context.  It can be used just as normal
 *    public key and must be freed by calling silc_pkcs_public_key_free.
 *    The associated `public_key' is not freed when the accelerated public
 *    key is freed.  The `public_key' must not be freed as long as it is
 *    accelerated.
 *
 *    The associated `public_key' can be retrieved from the returned
 *    public key by calling silc_acc_get_public_key.
 *
 ***/
SilcPublicKey silc_acc_public_key(SilcAccelerator acc,
				  SilcPublicKey public_key);

/****f* silcacc/SilcAccAPI/silc_acc_private_key
 *
 * SYNOPSIS
 *
 *    SilcPrivateKey silc_acc_private_key(SilcAccelerator acc,
 *                                        SilcPrivateKey private_key);
 *
 * DESCRIPTION
 *
 *    Accelerate the private key indicated by `private_key'.  Returns new
 *    accelerated SilcPrivateKey context.  It can be used just as normal
 *    private key and must be freed by calling silc_pkcs_private_key_free.
 *    The associated `private_key' is not freed when the accelerated private
 *    key is freed.  The `private_key' must not be freed as long as it is
 *    accelerated.
 *
 *    The associated `private_key' can be retrieved from the returned
 *    private key by calling silc_acc_get_private_key.
 *
 ***/
SilcPrivateKey silc_acc_private_key(SilcAccelerator acc,
				    SilcPrivateKey private_key);

/****f* silcacc/SilcAccAPI/silc_acc_get_public_key
 *
 * SYNOPSIS
 *
 *    SilcPublicKey silc_acc_get_public_key(SilcAccelerator acc,
 *                                          SilcPublicKey public_key);
 *
 * DESCRIPTION
 *
 *    Returns the underlaying public key from the accelerated public key
 *    indicated by `public_key'.  Returns NULL if `public_key' is not
 *    accelerated public key.
 *
 ***/
SilcPublicKey silc_acc_get_public_key(SilcAccelerator acc,
				      SilcPublicKey public_key);

/****f* silcacc/SilcAccAPI/silc_acc_get_private_key
 *
 * SYNOPSIS
 *
 *    SilcPrivateKey silc_acc_get_private_key(SilcAccelerator acc,
 *                                            SilcPrivateKey private_key);
 *
 * DESCRIPTION
 *
 *    Returns the underlaying private key from the accelerated private key
 *    indicated by `private_key'.  Returns NULL if `private_key' is not
 *    accelerated private key.
 *
 ***/
SilcPrivateKey silc_acc_get_private_key(SilcAccelerator acc,
					SilcPrivateKey private_key);

#endif /* SILCACC_H */
