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
/* $Id$ */

#include "silcincludes.h"
#include "silcprotocol.h"

/* Dynamically registered protocols */
SilcProtocolObject *silc_protocol_list = NULL;

/* Dynamically registers new protocol. The protocol is added into protocol
   list and can be unregistered with silc_protocol_unregister. */

void silc_protocol_register(SilcProtocolType type,
			    SilcProtocolCallback callback)
{
  SilcProtocolObject *new;

  new = silc_calloc(1, sizeof(*new));
  new->type = type;
  new->callback = callback;

  if (!silc_protocol_list)
    silc_protocol_list = new;
  else {
    new->next = silc_protocol_list;
    silc_protocol_list = new;
  }
}

/* Unregisters protocol. The unregistering is done by both protocol type
   and the protocol callback. */

void silc_protocol_unregister(SilcProtocolType type,
                              SilcProtocolCallback callback)
{
  SilcProtocolObject *protocol, *prev;

  protocol = silc_protocol_list;
  prev = NULL;
  while (protocol && (protocol->type != type && 
                      protocol->callback != callback)) {
    prev = protocol;
    protocol = protocol->next;
  }

  if (protocol) {
    if (prev)
      prev->next = protocol->next;
    else
      silc_protocol_list = protocol->next;

    silc_free(protocol);
  }
}

/* Allocates a new protocol object. The new allocated and initialized 
   protocol is returned to the new_protocol argument. The argument context
   is the context to be sent as argument for the protocol. The callback
   argument is the function to be called _after_ the protocol has finished. */

void silc_protocol_alloc(SilcProtocolType type, SilcProtocol *new_protocol,
			 void *context, SilcProtocolFinalCallback callback)
{
  SilcProtocolObject *protocol;

  SILC_LOG_DEBUG(("Allocating new protocol type %d", type));

  protocol = silc_protocol_list;
  while (protocol && protocol->type != type)
    protocol = protocol->next;

  if (!protocol) {
    SILC_LOG_ERROR(("Requested protocol does not exists"));
    *new_protocol = NULL;
    return;
  }

  *new_protocol = silc_calloc(1, sizeof(**new_protocol));
  (*new_protocol)->protocol = protocol;
  (*new_protocol)->state = SILC_PROTOCOL_STATE_UNKNOWN;
  (*new_protocol)->context = context;
  (*new_protocol)->final_callback = callback;
}

/* Frees a protocol object. */

void silc_protocol_free(SilcProtocol protocol)
{
  if (protocol)
    silc_free(protocol);
}

/* Executes next state of the protocol. The state must be set before
   calling this function. */

void silc_protocol_execute(SilcProtocol protocol, SilcSchedule schedule,
			   long secs, long usecs)
{
  if (secs + usecs) 
    silc_schedule_task_add(schedule, 0, 
			   protocol->protocol->callback, (void *)protocol, 
			   secs, usecs, 
			   SILC_TASK_TIMEOUT,
			   SILC_TASK_PRI_NORMAL);
  else
    protocol->protocol->callback(schedule, 0, 0, (void *)protocol);
}

/* Executes the final callback of the protocol. */

void silc_protocol_execute_final(SilcProtocol protocol, SilcSchedule schedule)
{
  protocol->final_callback(schedule, 0, 0, (void *)protocol);
}

/* Cancels the execution of the next state of the protocol. */

void silc_protocol_cancel(SilcProtocol protocol, SilcSchedule schedule)
{
  silc_schedule_task_del_by_callback(schedule, protocol->protocol->callback);
}
