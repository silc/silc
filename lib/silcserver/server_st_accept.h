/*

  server_st_accept.h

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

#ifndef SERVER_ST_ACCEPT_H
#define SERVER_ST_ACCEPT_H

/***************************** State functions ******************************/

void silc_server_accept_connection_dest(SilcFSM fsm, void *fsm_context,
					void *destructor_context);
SILC_FSM_STATE(silc_server_st_accept_connection);
SILC_FSM_STATE(silc_server_st_accept_set_keys);
SILC_FSM_STATE(silc_server_st_accept_authenticated);
SILC_FSM_STATE(silc_server_st_accept_client);
SILC_FSM_STATE(silc_server_st_accept_resume_client);
SILC_FSM_STATE(silc_server_st_accept_server);
SILC_FSM_STATE(silc_server_st_accept_finish);
SILC_FSM_STATE(silc_server_st_accept_error);

#endif /* SERVER_ST_ACCEPT_H */
