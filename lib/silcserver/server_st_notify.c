/*

  server_st_notify.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"
#include "silcserver.h"
#include "server_internal.h"

SILC_FSM_STATE(silc_server_st_packet_notify)
{
  SilcServerThread thread = fsm_context;
  SilcPacket packet = state_context;
  SilcEntryData data = silc_packet_get_context(packet->stream);

  return SILC_FSM_FINISH;
}
