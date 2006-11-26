/*

  client_notify.h

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

#ifndef CLIENT_NOTIFY_H
#define CLIENT_NOTIFY_H

SILC_FSM_STATE(silc_client_notify);
SILC_FSM_STATE(silc_client_notify_processed);
SILC_FSM_STATE(silc_client_notify_wait);
SILC_FSM_STATE(silc_client_notify_none);
SILC_FSM_STATE(silc_client_notify_invite);
SILC_FSM_STATE(silc_client_notify_join);
SILC_FSM_STATE(silc_client_notify_leave);
SILC_FSM_STATE(silc_client_notify_signoff);
SILC_FSM_STATE(silc_client_notify_topic_set);
SILC_FSM_STATE(silc_client_notify_nick_change);
SILC_FSM_STATE(silc_client_notify_cmode_change);
SILC_FSM_STATE(silc_client_notify_cumode_change);
SILC_FSM_STATE(silc_client_notify_motd);
SILC_FSM_STATE(silc_client_notify_channel_change);
SILC_FSM_STATE(silc_client_notify_kicked);
SILC_FSM_STATE(silc_client_notify_killed);
SILC_FSM_STATE(silc_client_notify_server_signoff);
SILC_FSM_STATE(silc_client_notify_error);
SILC_FSM_STATE(silc_client_notify_watch);

#endif /* CLIENT_NOTIFY_H */
