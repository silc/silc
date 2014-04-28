/*

  client_prvmsg.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 - 2014 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef CLIENT_PRVMSG_H
#define CLIENT_PRVMSG_H

SILC_FSM_STATE(silc_client_private_message);
SILC_FSM_STATE(silc_client_private_message_error);
SILC_FSM_STATE(silc_client_private_message_key);

SilcBool
silc_client_autoneg_private_message_key(SilcClient client,
					SilcClientConnection conn,
					SilcClientEntry client_entry,
					SilcPacket initiator_packet,
					SilcMessageFlags flags,
					SilcHash hash,
					unsigned char *data,
					SilcUInt32 data_len);

#endif /* CLIENT_PRVMSG_H */
