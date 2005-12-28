/*

  server_st_packet.h

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

#ifndef SERVER_ST_PACKET_H
#define SERVER_ST_PACKET_H

SILC_FSM_STATE(silc_server_st_packet_received);
SILC_FSM_STATE(silc_server_st_packet_new_client);
SILC_FSM_STATE(silc_server_st_packet_new_server);
SILC_FSM_STATE(silc_server_st_packet_resume_client);

#endif /* SERVER_ST_PACKET_H */
