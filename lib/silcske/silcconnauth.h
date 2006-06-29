/*

  silcconnauth.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 Pekka Riikonen

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
 * SILC Connection Authentication protocol is closely related to the SILC
 * Key Exchange protocol.  After successful key exchange, additional
 * authentication is usually required to gain access to remote server or
 * service.  Connection authentication may be based on passphrase or
 * digital signatures.  It is also possible to have no authentication at
 * all.
 *
 ***/

#ifndef SILCCONNAUTH_H
#define SILCCONNAUTH_H

typedef struct SilcConnAuthStruct *SilcConnAuth;

typedef enum {
  SILC_CONN_UNKNOWN  = 0,
  SILC_CONN_CLIENT   = 1,	/* Client connection */
  SILC_CONN_SERVER   = 2,	/* Server connection */
  SILC_CONN_ROUTER   = 3	/* Router connection */
} SilcConnectionType;

typedef SilcBool (*SilcConnAuthGetAuthData)(SilcConnAuth connauth,
					    SilcConnectionType conn_type,
					    unsigned char **passphrase,
					    SilcUInt32 *passphrase_len,
					    SilcSKR *repository,
					    void *context);

typedef void (*SilcConnAuthCompletion)(SilcConnAuth connauth,
				       SilcBool success,
				       void *context);

SilcConnAuth silc_connauth_alloc(SilcSchedule schedule,
				 SilcSKE ske,
				 SilcUInt32 timeout_secs);
void silc_connauth_free(SilcConnAuth connauth);
SilcSKE silc_connauth_get_ske(SilcConnAuth connauth);
SilcAsyncOperation
silc_connauth_initiator(SilcConnAuth connauth,
			SilcConnectionType conn_type,
			SilcAuthMethod auth_method, void *auth_data,
			SilcUInt32 auth_data_len,
			SilcConnAuthCompletion completion,
			void *context);
SilcAsyncOperation
silc_connauth_responder(SilcConnAuth connauth,
			SilcConnAuthGetAuthData get_auth_data,
			SilcConnAuthCompletion completion,
			void *context);

#endif /* SILCCONNAUTH_H */
