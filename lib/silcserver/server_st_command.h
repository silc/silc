/*

  server_st_command.h

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

#ifndef SERVER_ST_COMMAND_H
#define SERVER_ST_COMMAND_H

/***************************** State functions ******************************/

SILC_FSM_STATE(silc_server_st_packet_command);
SILC_FSM_STATE(silc_server_st_command_nick);
SILC_FSM_STATE(silc_server_st_command_list);
SILC_FSM_STATE(silc_server_st_command_topic);
SILC_FSM_STATE(silc_server_st_command_invite);
SILC_FSM_STATE(silc_server_st_command_quit);
SILC_FSM_STATE(silc_server_st_command_kill);
SILC_FSM_STATE(silc_server_st_command_info);
SILC_FSM_STATE(silc_server_st_command_stats);
SILC_FSM_STATE(silc_server_st_command_ping);
SILC_FSM_STATE(silc_server_st_command_oper);
SILC_FSM_STATE(silc_server_st_command_join);
SILC_FSM_STATE(silc_server_st_command_motd);
SILC_FSM_STATE(silc_server_st_command_umode);
SILC_FSM_STATE(silc_server_st_command_cmode);
SILC_FSM_STATE(silc_server_st_command_cumode);
SILC_FSM_STATE(silc_server_st_command_kick);
SILC_FSM_STATE(silc_server_st_command_ban);
SILC_FSM_STATE(silc_server_st_command_detach);
SILC_FSM_STATE(silc_server_st_command_watch);
SILC_FSM_STATE(silc_server_st_command_silcoper);
SILC_FSM_STATE(silc_server_st_command_leave);
SILC_FSM_STATE(silc_server_st_command_users);
SILC_FSM_STATE(silc_server_st_command_getkey);
SILC_FSM_STATE(silc_server_st_command_service);

#endif /* SERVER_ST_COMMAND_H */
