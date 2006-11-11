/*

  client_connect.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef CLIENT_CONNECT_H
#define CLIENT_CONNECT_H

/* States */
SILC_FSM_STATE(silc_client_st_connect);
SILC_FSM_STATE(silc_client_st_connect_key_exchange);
SILC_FSM_STATE(silc_client_st_connect_setup_udp);
SILC_FSM_STATE(silc_client_st_connect_auth);
SILC_FSM_STATE(silc_client_st_connect_auth_start);
SILC_FSM_STATE(silc_client_st_connected);
SILC_FSM_STATE(silc_client_st_connect_error);

#endif /* CLIENT_CONNECT_H */
