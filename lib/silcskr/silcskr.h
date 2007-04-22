/*

  silcskr.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcskr/SILC Key Repository
 *
 * DESCRIPTION
 *
 * SILC Key Repository
 *
 * SILC Key Repository is thread safe.  Same key repository context can be
 * safely used in multi threaded environment.
 *
 ***/

#ifndef SILCSKR_H
#define SILCSKR_H

/****s* silcskr/SilcSKRAPI/SilcSKR
 *
 * NAME
 *
 *    typedef struct SilcSKRObject *SilcSKR, SilcSKRStruct;
 *
 * DESCRIPTION
 *
 *    This context is the actual SILC Key Repository and is allocated
 *    by silc_skr_alloc (or initialized by silc_skr_init) and given as
 *    attribute to all silc_skr_* functions.  It is freed by the
 *    silc_skr_free (or uninitialized with silc_skr_uninit) function.
 *
 ***/
typedef struct SilcSKRObject *SilcSKR, SilcSKRStruct;

/****s* silcskr/SilcSKRAPI/SilcSKRFind
 *
 * NAME
 *
 *    typedef struct SilcSKRFindStruct *SilcSKRFind
 *
 * DESCRIPTION
 *
 *    This context contains the search constraints used find keys from the
 *    key repository.  It is allocated by silc_skr_find_alloc and freed
 *    by silc_skr_find_free.  The context is given as argument to all
 *    silc_skr_find* functions.
 *
 ***/
typedef struct SilcSKRFindStruct *SilcSKRFind;

/****d* silcskr/SilcSKRAPI/SilcSKRKeyUsage
 *
 * NAME
 *
 *    typedef enum { ... } SilcSKRKeyUsage;
 *
 * DESCRIPTION
 *
 *    Indicates the usage of the key.  Keys can be added for different
 *    reasons and for different purpose to the repository.  SilcSKRKeyUsage
 *    indicates for what reason the key exists in the repository.  The default
 *    usage is SILC_SKR_USAGE_ANY and allows any kind of usage for the key.
 *    If the usage should be limited then specific usage bitmask can be
 *    specified when adding the key.  When searching keys from the
 *    repository at least one of the key usage bits must be found in order
 *    to find the key.
 *
 * SOURCE
 */
typedef enum {
  SILC_SKR_USAGE_ANY                   = 0x0000,  /* Any usage */
  SILC_SKR_USAGE_AUTH                  = 0x0001,  /* Signatures/verification */
  SILC_SKR_USAGE_ENC                   = 0x0002,  /* Encryption/decryption */
  SILC_SKR_USAGE_KEY_AGREEMENT         = 0x0004,  /* Key agreement protocol */
  SILC_SKR_USAGE_IDENTIFICATION        = 0x0008,  /* Identifying key owner */
  SILC_SKR_USAGE_SERVICE_AUTHORIZATION = 0x0010,  /* Service authorization */

  /* From 0x0100 reserved for private/application use. */
} SilcSKRKeyUsage;
/***/

/****s* silcskr/SilcSKRAPI/SilcSKRKey
 *
 * NAME
 *
 *    typedef struct SilcSKRKeyStruct { ... } *SilcSKRKey;
 *
 * DESCRIPTION
 *
 *    This context holds the public key, optional public key specific
 *    context and public key usage bits.  This context is returned in
 *    the SilcSKRFindCallback list.  Each entry in the list is SIlcSKRKey.
 *
 * SOURCE
 *
 */
typedef struct SilcSKRKeyStruct {
  SilcSKRKeyUsage usage;	/* Key usage */
  SilcPublicKey key;		/* Public key */
  void *key_context;		/* Optional key specific context */
} *SilcSKRKey;
/***/

/****d* silcskr/SilcSKRAPI/SilcSKRStatus
 *
 * NAME
 *
 *    typedef enum { ... } SilcSKRStatus;
 *
 * DESCRIPTION
 *
 *    Indicates the status of the key repository procedures.  This is
 *    returned to SilcSKRFindCallback function to indicate the status
 *    of the finding.  This is a bitmask, and more than one status may
 *    be set at one time.
 *
 *    If there are no errors only SILC_SKR_OK is set.  If error occurred
 *    then at least SILC_SKR_ERROR is set, and possibly other error
 *    status also.
 *
 * SOURCE
 */
typedef enum {
  SILC_SKR_OK                 = 0x00000001, /* All is Ok */
  SILC_SKR_ERROR              = 0x00000002, /* Generic error status */
  SILC_SKR_ALREADY_EXIST      = 0x00000004, /* Key already exist */
  SILC_SKR_NOT_FOUND          = 0x00000008, /* No keys were found */
  SILC_SKR_NO_MEMORY          = 0x00000010, /* System out of memory */
  SILC_SKR_UNSUPPORTED_TYPE   = 0x00000020, /* Unsupported PKCS type */
} SilcSKRStatus;
/***/

/****f* silcskr/SilcSKRAPI/SilcSKRFindCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcSKRFindCallback)(SilcSKR skr, SilcSKRFind find,
 *                                        SilcSKRStatus status,
 *                                        SilcDList keys, void *context);
 *
 * DESCRIPTION
 *
 *    Callback that is given as argument to silc_skr_find and other find
 *    functions.  Returns the results of the finding.  If keys were found
 *    the `keys' is non-NULL and receiver must free it with silc_dlist_uninit.
 *    Each entry in the `keys' is SilcSKRKey context.  The list `keys' is
 *    already at start so calling silc_dlist_start is not necessary when
 *    traversing the list from the start.  If the `find' is non-NULL it must
 *    be freed with silc_skr_find_free.
 *
 ***/
typedef void (*SilcSKRFindCallback)(SilcSKR skr, SilcSKRFind find,
				    SilcSKRStatus status,
				    SilcDList keys, void *context);

/****f* silcskr/SilcSKRAPI/silc_skr_alloc
 *
 * SYNOPSIS
 *
 *    SilcSKR silc_skr_alloc(void);
 *
 * DESCRIPTION
 *
 *    Allocates key repository context.
 *
 ***/
SilcSKR silc_skr_alloc(void);

/****f* silcskr/SilcSKRAPI/silc_skr_free
 *
 * SYNOPSIS
 *
 *    void silc_skr_free(SilcSKR skr);
 *
 * DESCRIPTION
 *
 *    Free's the key repository context `skr' and all resources in it.
 *
 ***/
void silc_skr_free(SilcSKR skr);

/****f* silcskr/SilcSKRAPI/silc_skr_init
 *
 * SYNOPSIS
 *
 *    SilcBool silc_skr_init(SilcSKR skr);
 *
 * DESCRIPTION
 *
 *    Initializes a pre-allocated SilcSKR context.  This function is
 *    equivalent to silc_skr_alloc but takes pre-allocated context as
 *    argument.  Returns FALSE if initialization failed.
 *
 ***/
SilcBool silc_skr_init(SilcSKR skr);

/****f* silcskr/SilcSKRAPI/silc_skr_uninit
 *
 * SYNOPSIS
 *
 *    void silc_skr_uninit(SilcSKR skr);
 *
 * DESCRIPTION
 *
 *    Uninitializes a pre-allocated SilcSKR context.  Use this function if
 *    you called silc_skr_init.
 *
 ***/
void silc_skr_uninit(SilcSKR skr);

/****f* silcskr/SilcSKRAPI/silc_skr_add_public_key
 *
 * SYNOPSIS
 *
 *    SilcSKRStatus silc_skr_add_public_key(SilcSKR skr,
 *                                          SilcPublicKey public_key,
 *                                          SilcSKRKeyUsage usage,
 *                                          void *key_context);
 *
 * DESCRIPTION
 *
 *    Add a public key to repository.  The repository will steal `public_key'
 *    and caller must not free it.  The `key_context' is optional key specific
 *    context that will be saved in the repository with the key, and can be
 *    retrieved with the key.  Public key can be added only once to the
 *    repository.  To add same key more than once to repository different
 *    `key_context' must be used each time.
 *
 *    Returns SILC_SKR_OK if the key was added successfully, and error
 *    status if key could not be added, or has been added already.
 *
 * EXAMPLE
 *
 *    // Add a key to repository
 *    if (silc_skr_add_public_key(repository, public_key,
 *                                SILC_SKR_USAGE_ANY, NULL) != SILC_SKR_OK)
 *      goto error;
 *
 ***/
SilcSKRStatus silc_skr_add_public_key(SilcSKR skr,
				      SilcPublicKey public_key,
				      SilcSKRKeyUsage usage,
				      void *key_context);

/****f* silcskr/SilcSKRAPI/silc_skr_add_public_key_simple
 *
 * SYNOPSIS
 *
 *    SilcSKRStatus silc_skr_add_public_key_simple(SilcSKR skr,
 *                                                 SilcPublicKey public_key,
 *                                                 SilcSKRKeyUsage usage,
 *                                                 void *key_context);
 *
 * DESCRIPTION
 *
 *    Same as silc_skr_add_public_key but adds only the public key, usage
 *    bits and key context.  The key cannot be found with any other search
 *    constraint except setting the public key, usage bits and/or key
 *    context as search constraint.  This function can be used to add the
 *    key with as little memory as possible to the repository, and makes
 *    it a good way to cheaply store large amounts of public keys.
 *
 *    Returns SILC_SKR_OK if the key was added successfully, and error
 *    status if key could not be added, or has been added already.
 *
 ***/
SilcSKRStatus silc_skr_add_public_key_simple(SilcSKR skr,
					     SilcPublicKey public_key,
					     SilcSKRKeyUsage usage,
					     void *key_context);

/****f* silcskr/SilcSKRAPI/silc_skr_find_alloc
 *
 * SYNOPSIS
 *
 *    SilcSKRFind silc_skr_find_alloc(void);
 *
 * DESCRIPTION
 *
 *    Allocates SilcSKRFind context that will hold search constraints used
 *    to find specific keys from the repository.  Caller must free the
 *    context by calling silc_skr_find_free.
 *
 ***/
SilcSKRFind silc_skr_find_alloc(void);

/****f* silcskr/SilcSKRAPI/silc_skr_find_free
 *
 * SYNOPSIS
 *
 *    void silc_skr_find_free(SilcSKRFind find);
 *
 * DESCRIPTION
 *
 *    Free's the search constraints context `find' and all resources in it.
 *
 ***/
void silc_skr_find_free(SilcSKRFind find);

/****f* silcskr/SilcSKRAPI/silc_skr_find_add_pkcs_type
 *
 * SYNOPSIS
 *
 *    SilcBool silc_skr_find_add_pkcs_type(SilcSKRFind find,
 *                                         SilcPKCSType type);
 *
 * DESCRIPTION
 *
 *    Sets public key cryptosystem type as search constraint.  Will search
 *    only for the specific type of key(s).
 *
 ***/
SilcBool silc_skr_find_set_pkcs_type(SilcSKRFind find, SilcPKCSType type);

/****f* silcskr/SilcSKRAPI/silc_skr_find_set_username
 *
 * SYNOPSIS
 *
 *    SilcBool silc_skr_find_set_username(SilcSKRFind find,
 *                                        const char *username);
 *
 * DESCRIPTION
 *
 *    Sets username as search constraint.  This specific username must be
 *    present in the key.
 *
 *    This may be used with SILC_PKCS_SILC PKCS type only.
 *
 ***/
SilcBool silc_skr_find_set_username(SilcSKRFind find, const char *username);

/****f* silcskr/SilcSKRAPI/silc_skr_find_set_host
 *
 * SYNOPSIS
 *
 *    SilcBool silc_skr_find_set_host(SilcSKRFind find,
 *                                    const char *host);
 *
 * DESCRIPTION
 *
 *    Sets host as search constraint.  This specific host must be
 *    present in the key.  The `host' may be a hostname or IP address.
 *
 *    This may be used with SILC_PKCS_SILC PKCS type only.
 *
 ***/
SilcBool silc_skr_find_set_host(SilcSKRFind find, const char *host);

/****f* silcskr/SilcSKRAPI/silc_skr_find_set_realname
 *
 * SYNOPSIS
 *
 *    SilcBool silc_skr_find_set_realname(SilcSKRFind find,
 *                                        const char *realname);
 *
 * DESCRIPTION
 *
 *    Sets real name as search constraint.  This specific name must be
 *    present in the key.
 *
 *    This may be used with SILC_PKCS_SILC PKCS type only.
 *
 ***/
SilcBool silc_skr_find_set_realname(SilcSKRFind find, const char *realname);

/****f* silcskr/SilcSKRAPI/silc_skr_find_set_email
 *
 * SYNOPSIS
 *
 *    SilcBool silc_skr_find_set_email(SilcSKRFind find,
 *                                     const char *email);
 *
 * DESCRIPTION
 *
 *    Sets email address as search constraint.  This specific address must be
 *    present in the key.
 *
 *    This may be used with SILC_PKCS_SILC PKCS type only.
 *
 ***/
SilcBool silc_skr_find_set_email(SilcSKRFind find, const char *email);

/****f* silcskr/SilcSKRAPI/silc_skr_find_set_org
 *
 * SYNOPSIS
 *
 *    SilcBool silc_skr_find_set_org(SilcSKRFind find,
 *                                   const char *email);
 *
 * DESCRIPTION
 *
 *    Sets organization as search constraint.  This specific organization
 *    must be present in the key.
 *
 *    This may be used with SILC_PKCS_SILC PKCS type only.
 *
 ***/
SilcBool silc_skr_find_set_org(SilcSKRFind find, const char *org);

/****f* silcskr/SilcSKRAPI/silc_skr_find_set_country
 *
 * SYNOPSIS
 *
 *    SilcBool silc_skr_find_set_country(SilcSKRFind find,
 *                                       const char *email);
 *
 * DESCRIPTION
 *
 *    Sets country as search constraint.  This specific country must be
 *    present in the key.
 *
 *    This may be used with SILC_PKCS_SILC PKCS type only.
 *
 ***/
SilcBool silc_skr_find_set_country(SilcSKRFind find, const char *country);

/****f* silcskr/SilcSKRAPI/silc_skr_find_set_public_key
 *
 * SYNOPSIS
 *
 *    SilcBool silc_skr_find_set_public_key(SilcSKRFind find,
 *                                          SilcPublicKey public_key);
 *
 * DESCRIPTION
 *
 *    Sets public key as search constraint.  This specific key must be
 *    present in the key.
 *
 ***/
SilcBool silc_skr_find_set_public_key(SilcSKRFind find,
				      SilcPublicKey public_key);

/****f* silcskr/SilcSKRAPI/silc_skr_find_set_context
 *
 * SYNOPSIS
 *
 *    SilcBool silc_skr_find_set_context(SilcSKRFind find, void *context);
 *
 * DESCRIPTION
 *
 *    Sets public key specific context as search constraint.  This specific
 *    context must be associated with the key.  This is the context that
 *    was given as argument when adding the key to repository.
 *
 ***/
SilcBool silc_skr_find_set_context(SilcSKRFind find, void *context);

/****f* silcskr/SilcSKRAPI/silc_skr_find_set_usage
 *
 * SYNOPSIS
 *
 *    SilcBool silc_skr_find_set_usage(SilcSKRFind find,
 *                                     SilcSKRKeyUsage usage);
 *
 * DESCRIPTION
 *
 *    Sets key usage as search constraint.  At least one of the key usage
 *    bits must be present in the key.  This search constraint cannot be
 *    used alone to search keys.  At least one other search constraint
 *    must also be used.
 *
 ***/
SilcBool silc_skr_find_set_usage(SilcSKRFind find, SilcSKRKeyUsage usage);

/****f* silcskr/SilcSKRAPI/silc_skr_find
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation silc_skr_find(SilcSKR skr, SilcSchedule schedule,
 *                                     SilcSKRFind find,
 *                                     SilcSKRFindCallback callback,
 *                                     void *callback_context);
 *
 * DESCRIPTION
 *
 *    Finds key(s) from key repository `skr' by the search constraints
 *    `find'.  As the finding procedure may be asynchronous this returns
 *    SilcAsyncOperation that may be used to control (like abort) the
 *    operation.  The `callback' with `callback_context' will be called
 *    to return found keys.  If this returns NULL the finding was not
 *    asynchronous, and the `callback' has been called already.
 *
 * EXAMPLE
 *
 *   SilcSKRFind find;
 *
 *   // Find all SILC public keys originating from Finland
 *   find = silc_skr_find_alloc();
 *   silc_skr_find_set_pkcs_type(find, SILC_PKCS_SILC);
 *   silc_skr_find_set_country(find, "FI");
 *
 *   // Find
 *   silc_skr_find(skr, schedule, find, find_callback, cb_context);
 *
 ***/
SilcAsyncOperation silc_skr_find(SilcSKR skr, SilcSchedule schedule,
				 SilcSKRFind find,
				 SilcSKRFindCallback callback,
				 void *callback_context);

#include "silcskr_i.h"

#endif /* SILCSKR_H */
