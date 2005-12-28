/*

  server_st_command_reply.h

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

#ifndef SERVER_ST_COMMAND_REPLY_H
#define SERVER_ST_COMMAND_REPLY_H

/***************************** State functions ******************************/

SILC_FSM_STATE(silc_server_st_packet_command_reply);
SILC_FSM_STATE(silc_server_st_command_reply_whois);
SILC_FSM_STATE(silc_server_st_command_reply_whowas);
SILC_FSM_STATE(silc_server_st_command_reply_identify);
SILC_FSM_STATE(silc_server_st_command_reply_list);
SILC_FSM_STATE(silc_server_st_command_reply_info);
SILC_FSM_STATE(silc_server_st_command_reply_stats);
SILC_FSM_STATE(silc_server_st_command_reply_ping);
SILC_FSM_STATE(silc_server_st_command_reply_join);
SILC_FSM_STATE(silc_server_st_command_reply_motd);
SILC_FSM_STATE(silc_server_st_command_reply_watch);
SILC_FSM_STATE(silc_server_st_command_reply_users);
SILC_FSM_STATE(silc_server_st_command_reply_getkey);
SILC_FSM_STATE(silc_server_st_command_reply_service);

#endif /* SERVER_ST_COMMAND_REPLY_H */
