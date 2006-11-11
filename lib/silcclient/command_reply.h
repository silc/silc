/*

  command_reply.h

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

#ifndef COMMAND_REPLY_H
#define COMMAND_REPLY_H

SILC_FSM_STATE(silc_client_command_reply);
SILC_FSM_STATE(silc_client_command_reply_wait);
SILC_FSM_STATE(silc_client_command_reply_process);
SILC_FSM_STATE(silc_client_command_reply_whois);
SILC_FSM_STATE(silc_client_command_reply_whowas);
SILC_FSM_STATE(silc_client_command_reply_identify);
SILC_FSM_STATE(silc_client_command_reply_nick);
SILC_FSM_STATE(silc_client_command_reply_list);
SILC_FSM_STATE(silc_client_command_reply_topic);
SILC_FSM_STATE(silc_client_command_reply_invite);
SILC_FSM_STATE(silc_client_command_reply_kill);
SILC_FSM_STATE(silc_client_command_reply_info);
SILC_FSM_STATE(silc_client_command_reply_stats);
SILC_FSM_STATE(silc_client_command_reply_ping);
SILC_FSM_STATE(silc_client_command_reply_oper);
SILC_FSM_STATE(silc_client_command_reply_join);
SILC_FSM_STATE(silc_client_command_reply_motd);
SILC_FSM_STATE(silc_client_command_reply_umode);
SILC_FSM_STATE(silc_client_command_reply_cmode);
SILC_FSM_STATE(silc_client_command_reply_cumode);
SILC_FSM_STATE(silc_client_command_reply_kick);
SILC_FSM_STATE(silc_client_command_reply_ban);
SILC_FSM_STATE(silc_client_command_reply_detach);
SILC_FSM_STATE(silc_client_command_reply_watch);
SILC_FSM_STATE(silc_client_command_reply_silcoper);
SILC_FSM_STATE(silc_client_command_reply_leave);
SILC_FSM_STATE(silc_client_command_reply_users);
SILC_FSM_STATE(silc_client_command_reply_getkey);
SILC_FSM_STATE(silc_client_command_reply_service);
SILC_FSM_STATE(silc_client_command_reply_quit);

#endif /* COMMAND_REPLY_H */
