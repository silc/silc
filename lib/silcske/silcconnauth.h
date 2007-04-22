/*

  silcconnauth.h

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

/****h* silcske/SILC Connection Authentication
 *
 * DESCRIPTION
 *
 * SILC Connection Authenetication protocol API is used to perform the
 * connection authentication after successful SILC Key Exchange protocol.
 * The interface supports authentication based on passphrases and digital
 * signatures.  It is also possible to have no authentication at all.
 *
 ***/

#ifndef SILCCONNAUTH_H
#define SILCCONNAUTH_H

/****s* silcske/SilcConnAuthAPI/SilcConnAuth
 *
 * NAME
 *
 *    typedef struct SilcConnAuthStruct *SilcConnAuth;
 *
 * DESCRIPTION
 *
 *    The connection authentication context allocated by silc_connauth_alloc
 *    and given as arguments to all silc_connauth_* functions.  It is freed
 *    by silc_connauth_free.
 *
 ***/
typedef struct SilcConnAuthStruct *SilcConnAuth;

/****d* silcske/SilcConnAuthAPI/SilcConnectionType
 *
 * NAME
 *
 *    typedef enum { ... } SilcConnectionType;
 *
 * DESCRIPTION
 *
 *    The type of the connection.
 *
 * SOURCE
 */
typedef enum {
  SILC_CONN_UNKNOWN  = 0,	/* Unknown type, cannot be sent */
  SILC_CONN_CLIENT   = 1,	/* Client connection */
  SILC_CONN_SERVER   = 2,	/* Server connection */
  SILC_CONN_ROUTER   = 3	/* Router connection */
} SilcConnectionType;
/***/

/****f* silcske/SilcConnAuthAPI/SilcConnAuthGetAuthData
 *
 * SYNOPSIS
 *
 *    typedef SilcBool
 *    (*SilcConnAuthGetAuthData)(SilcConnAuth connauth,
 *                               SilcConnectionType conn_type,
 *                               unsigned char **passphrase,
 *                               SilcUInt32 *passphrase_len,
 *                               SilcSKR *repository,
 *                               void *context);
 *
 * DESCRIPTION
 *
 *    Authentication callback to retrieve the authentication data from the
 *    application.  This is responder callback.  If the authentication
 *    method is passphrase it must be returned to `passphrase' pointer.
 *    If it is digital signatures the key repository pointer must be
 *    returned into `repository' pointer, which the library will use to
 *    find the correct public key to verify the digital signature.  If
 *    neither `passphrase' or `repository' is set but TRUE is returned,
 *    authentication is not required.
 *
 *    If this connection is not configured at all this returns FALSE which
 *    will result into authentication failure.  Otherwise TRUE must be
 *    returned.
 *
 ***/
typedef SilcBool (*SilcConnAuthGetAuthData)(SilcConnAuth connauth,
					    SilcConnectionType conn_type,
					    unsigned char **passphrase,
					    SilcUInt32 *passphrase_len,
					    SilcSKR *repository,
					    void *context);

/****f* silcske/SilcConnAuthAPI/SilcConnAuthCompletion
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcConnAuthCompletion)(SilcConnAuth connauth,
 *                                           SilcBool success,
 *                                           void *context);
 *
 * DESCRIPTION
 *
 *    Completion callback called to indicated the result of the connection
 *    authentication protocol.  If the `success' is FALSE the authentication
 *    was a failure.  The authentication protocol is over after this callback
 *    is called.
 *
 ***/
typedef void (*SilcConnAuthCompletion)(SilcConnAuth connauth,
				       SilcBool success,
				       void *context);

/****f* silcske/SilcConnAuthAPI/silc_connauth_alloc
 *
 * SYNOPSIS
 *
 *    SilcConnAuth silc_connauth_alloc(SilcSchedule schedule, SilcSKE ske,
 *                                     SilcUInt32 timeout_secs);
 *
 * DESCRIPTION
 *
 *    Allocates the connection authentication protocol context.  The `ske'
 *    is the successfully completed key exchange context.  The `timeout_secs'
 *    is the maximum time we are waiting for the protocol to finish before
 *    it is timedout.  Returns NULL on error.
 *
 ***/
SilcConnAuth silc_connauth_alloc(SilcSchedule schedule, SilcSKE ske,
				 SilcUInt32 timeout_secs);

/****f* silcske/SilcConnAuthAPI/silc_connauth_free
 *
 * SYNOPSIS
 *
 *    void silc_connauth_free(SilcConnAuth connauth);
 *
 * DESCRIPTION
 *
 *    Frees the connection authentication protocol context `connauth'.
 *
 ***/
void silc_connauth_free(SilcConnAuth connauth);

/****f* silcske/SilcConnAuthAPI/silc_connauth_get_ske
 *
 * SYNOPSIS
 *
 *    SilcSKE silc_connauth_get_ske(SilcConnAuth connauth);
 *
 * DESCRIPTION
 *
 *    Returns the associated SilcSKE context from the `connauth'.  It is the
 *    pointer given as argument to silc_connauth_alloc.
 *
 ***/
SilcSKE silc_connauth_get_ske(SilcConnAuth connauth);

/****f* silcske/SilcConnAuthAPI/silc_connauth_initiator
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation
 *    silc_connauth_initiator(SilcConnAuth connauth,
 *                            SilcConnectionType conn_type,
 *                            SilcAuthMethod auth_method, void *auth_data,
 *                            SilcUInt32 auth_data_len,
 *                            SilcConnAuthCompletion completion,
 *                            void *context);
 *
 * DESCRIPTION
 *
 *    Starts the connection authentication protocol as initiator.  The
 *    `conn_type' is the type of connection we are.  The `auth_method' is
 *    the authentication method.  If it is SILC_AUTH_PASSWORD the `auth_data'
 *    and `auth_data_len' is the passphrase and its length, respectively.
 *    If it is SILC_AUTH_PUBLIC_KEY the `auth_data' is the SilcPrivateKey
 *    used to produce the digital signature.  The `auth_data_len' is 0.
 *    The `completion' with `context' will be called after the protocol
 *    has completed.
 *
 *    This returns SilcAsyncOperation context which can be used to abort
 *    the protocol before it is completed.  Returns NULL on error.
 *
 ***/
SilcAsyncOperation
silc_connauth_initiator(SilcConnAuth connauth,
			SilcConnectionType conn_type,
			SilcAuthMethod auth_method, void *auth_data,
			SilcUInt32 auth_data_len,
			SilcConnAuthCompletion completion,
			void *context);

/****f* silcske/SilcConnAuthAPI/silc_connauth_responder
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation
 *    silc_connauth_responder(SilcConnAuth connauth,
 *                            SilcConnAuthGetAuthData get_auth_data,
 *                            SilcConnAuthCompletion completion,
 *                            void *context);
 *
 * DESCRIPTION
 *
 *    Starts the connection authentication protocol as responder.  The
 *    `get_auth_data' is called to retrieve the authentication data for
 *    this connection.  The `completion' will be called after the protocol
 *    has completed.
 *
 *    This returns SilcAsyncOperation context which can be used to abort
 *    the protocol before it is completed.  Returns NULL on error.
 *
 ***/
SilcAsyncOperation
silc_connauth_responder(SilcConnAuth connauth,
			SilcConnAuthGetAuthData get_auth_data,
			SilcConnAuthCompletion completion,
			void *context);

#endif /* SILCCONNAUTH_H */
