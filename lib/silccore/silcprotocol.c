/*

  silcprotocol.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/*
 * Created: Tue Nov 25 19:25:33 GMT+0200 1997
 */
/*
 * $Id$
 * $Log$
 * Revision 1.1  2000/06/27 11:36:55  priikone
 * Initial revision
 *
 *
 */

#include "silcincludes.h"
#include "silcprotocol.h"

/* Allocates a new protocol object. The new allocated and initialized 
   protocol is returned to the new_protocol argument. The argument context
   is the context to be sent as argument for the protocol. The callback
   argument is the function to be called _after_ the protocol has finished. */

void silc_protocol_alloc(SilcProtocolType type, SilcProtocol *new_protocol,
			 void *context, SilcProtocolFinalCallback callback)
{
  int i;

  SILC_LOG_DEBUG(("Allocating new protocol type %d", type));

  for (i = 0; silc_protocol_list[i].callback; i++)
    if (silc_protocol_list[i].type == type)
      break;

  if (!silc_protocol_list[i].callback) {
    SILC_LOG_ERROR(("Requested protocol does not exists"));
    return;
  }

  *new_protocol = silc_calloc(1, sizeof(**new_protocol));
  if (*new_protocol == NULL) {
    SILC_LOG_ERROR(("Cannot allocate new protocol object"));
    return;
  }

  (*new_protocol)->protocol = (SilcProtocolObject *)&silc_protocol_list[i];
  (*new_protocol)->state = SILC_PROTOCOL_STATE_UNKNOWN;
  (*new_protocol)->context = context;
  (*new_protocol)->execute = silc_protocol_execute;
  (*new_protocol)->execute_final = silc_protocol_execute_final;
  (*new_protocol)->final_callback = callback;
}

/* Free's a protocol object. */

void silc_protocol_free(SilcProtocol protocol)
{
  if (protocol)
    silc_free(protocol);
}

/* Executes next state of the protocol. The state must be set before
   calling this function. */

void silc_protocol_execute(void *qptr, int type,
			   void *context, int fd,
			   long secs, long usecs)
{
  SilcProtocol protocol = (SilcProtocol)context;

  SILC_LOG_DEBUG(("Start"));

  if (secs + usecs) 
    silc_task_register(qptr, fd, protocol->protocol->callback, context, 
		       secs, usecs, 
		       SILC_TASK_TIMEOUT,
		       SILC_TASK_PRI_NORMAL);
  else
    protocol->protocol->callback(qptr, 0, context, fd);
}

/* Executes the final callback of the protocol. */

void silc_protocol_execute_final(void *qptr, int type,
				 void *context, int fd)
{
  SilcProtocol protocol = (SilcProtocol)context;
 
  SILC_LOG_DEBUG(("Start, state=%d", protocol->state));

  protocol->final_callback(qptr, 0, context, fd);
}
