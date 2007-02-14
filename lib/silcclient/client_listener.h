/*

  client_listener.h

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

#ifndef CLIENT_LISTENER_H
#define CLIENT_LISTENER_H

/* Forward declarations */
typedef struct SilcClientListenerStruct *SilcClientListener;

SilcClientListener
silc_client_listener_add(SilcClient client,
			 SilcSchedule schedule,
			 SilcClientConnectionParams *params,
			 SilcPublicKey public_key,
			 SilcPrivateKey private_key,
			 SilcClientConnectCallback callback,
			 void *context);
void silc_client_listener_free(SilcClientListener listener);
SilcUInt16 silc_client_listener_get_local_port(SilcClientListener listener);

#endif /* CLIENT_LISTENER_H */
