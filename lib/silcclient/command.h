/*

  command.h

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

#ifndef COMMAND_H
#define COMMAND_H

SILC_FSM_STATE(silc_client_command);
SILC_FSM_STATE(silc_client_command_whois);
SILC_FSM_STATE(silc_client_command_whowas);
SILC_FSM_STATE(silc_client_command_identify);
SILC_FSM_STATE(silc_client_command_nick);
SILC_FSM_STATE(silc_client_command_list);
SILC_FSM_STATE(silc_client_command_topic);
SILC_FSM_STATE(silc_client_command_invite);
SILC_FSM_STATE(silc_client_command_quit);
SILC_FSM_STATE(silc_client_command_kill);
SILC_FSM_STATE(silc_client_command_info);
SILC_FSM_STATE(silc_client_command_ping);
SILC_FSM_STATE(silc_client_command_oper);
SILC_FSM_STATE(silc_client_command_join);
SILC_FSM_STATE(silc_client_command_motd);
SILC_FSM_STATE(silc_client_command_umode);
SILC_FSM_STATE(silc_client_command_cmode);
SILC_FSM_STATE(silc_client_command_cumode);
SILC_FSM_STATE(silc_client_command_kick);
SILC_FSM_STATE(silc_client_command_ban);
SILC_FSM_STATE(silc_client_command_detach);
SILC_FSM_STATE(silc_client_command_watch);
SILC_FSM_STATE(silc_client_command_silcoper);
SILC_FSM_STATE(silc_client_command_leave);
SILC_FSM_STATE(silc_client_command_users);
SILC_FSM_STATE(silc_client_command_getkey);
SILC_FSM_STATE(silc_client_command_service);

void silc_client_commands_register(SilcClient client);
void silc_client_commands_unregister(SilcClient client);

#endif /* COMMAND_H */
