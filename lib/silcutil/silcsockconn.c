/*

  silcsockconn.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"

/* Heartbeat context */
struct SilcSocketConnectionHBStruct {
  SilcUInt32 heartbeat;
  SilcSocketConnectionHBCb hb_callback;
  void *hb_context;
  SilcSchedule schedule;
  SilcTask hb_task;
  SilcSocketConnection sock;
};

/* Internal async host lookup context. */
typedef struct {
  SilcSocketHostLookupCb callback;
  void *context;
  SilcSchedule schedule;
  SilcSocketConnection sock;
  bool port;
} *SilcSocketHostLookup;

/* Allocates a new socket connection object. The allocated object is 
   returned to the new_socket argument. */

void silc_socket_alloc(int sock, SilcSocketType type, void *user_data, 
		       SilcSocketConnection *new_socket)
{
  SILC_LOG_DEBUG(("Allocating new socket connection object"));

  /* Set the pointers. Incoming and outgoing data buffers
     are allocated by the application when they are first used. */
  *new_socket = silc_calloc(1, sizeof(**new_socket));
  (*new_socket)->sock = sock;
  (*new_socket)->type = type;
  (*new_socket)->user_data = user_data;
  (*new_socket)->protocol = NULL;
  (*new_socket)->flags = 0;
  (*new_socket)->inbuf = NULL;
  (*new_socket)->outbuf = NULL;
  (*new_socket)->users++;
}

/* Free's the Socket connection object. */

void silc_socket_free(SilcSocketConnection sock)
{
  sock->users--;
  SILC_LOG_DEBUG(("Socket %p refcnt %d->%d", sock, sock->users + 1,
		  sock->users));
  if (sock->users < 1) {
    silc_buffer_free(sock->inbuf);
    silc_buffer_free(sock->outbuf);
    if (sock->hb) {
      silc_schedule_task_del(sock->hb->schedule, sock->hb->hb_task);
      silc_free(sock->hb);
    }
    silc_free(sock->qos);
    silc_free(sock->ip);
    silc_free(sock->hostname);

    memset(sock, 'F', sizeof(*sock));
    silc_free(sock);
  }
}

/* Increase the reference counter. */

SilcSocketConnection silc_socket_dup(SilcSocketConnection sock)
{
  sock->users++;
  SILC_LOG_DEBUG(("Socket %p refcnt %d->%d", sock, sock->users - 1,
		  sock->users));
  return sock;
}

/* Internal timeout callback to perform heartbeat */

SILC_TASK_CALLBACK(silc_socket_heartbeat)
{
  SilcSocketConnectionHB hb = (SilcSocketConnectionHB)context;

  if (!hb->heartbeat)
    return;

  if (SILC_IS_DISCONNECTING(hb->sock) ||
      SILC_IS_DISCONNECTED(hb->sock))
    return;

  if (hb->hb_callback)
    hb->hb_callback(hb->sock, hb->hb_context);

  hb->hb_task = silc_schedule_task_add(hb->schedule, hb->sock->sock, 
				       silc_socket_heartbeat,
				       context, hb->heartbeat, 0,
				       SILC_TASK_TIMEOUT,
				       SILC_TASK_PRI_LOW);
}

/* Sets the heartbeat timeout and prepares the socket for performing
   heartbeat in `heartbeat' intervals (seconds). The `hb_context' is
   allocated by the application and will be sent as argument to the
   `hb_callback' function that is called when the `heartbeat' timeout
   expires.  The callback `hb_context' won't be touched by the library
   but will be freed automatically when calling silc_socket_free.  The
   `schedule' is the application's scheduler. */

void silc_socket_set_heartbeat(SilcSocketConnection sock, 
			       SilcUInt32 heartbeat,
			       void *hb_context,
			       SilcSocketConnectionHBCb hb_callback,
			       SilcSchedule schedule)
{
  if (sock->hb) {
    silc_schedule_task_del(schedule, sock->hb->hb_task);
    silc_free(sock->hb);
  }

  sock->hb = silc_calloc(1, sizeof(*sock->hb));
  sock->hb->heartbeat = heartbeat;
  sock->hb->hb_context = hb_context;
  sock->hb->hb_callback = hb_callback;
  sock->hb->schedule = schedule;
  sock->hb->sock = sock;
  sock->hb->hb_task = silc_schedule_task_add(schedule, sock->sock,
					     silc_socket_heartbeat,
					     (void *)sock->hb, heartbeat, 0,
					     SILC_TASK_TIMEOUT,
					     SILC_TASK_PRI_LOW);
}

/* Sets a "Quality of Service" settings for socket connection `sock'.
   The `read_rate' specifies the maximum read operations per second.
   If more read operations are executed the limit will be applied for
   the reading.  The `read_limit_bytes' specifies the maximum data
   that is read.  It is guaranteed that silc_socket_read never returns
   more that `read_limit_bytes' of data.  If more is read the limit
   will be applied for the reading.  The `limit_sec' and `limit_usec'
   specifies the limit that is applied if `read_rate' and/or 
   `read_limit_bytes' is reached.  The `schedule' is the application's
   scheduler. */

void silc_socket_set_qos(SilcSocketConnection sock, 
			 SilcUInt32 read_rate,
			 SilcUInt32 read_limit_bytes,
			 SilcUInt32 limit_sec,
			 SilcUInt32 limit_usec,
			 SilcSchedule schedule)
{
  if (!sock->qos) {
    sock->qos = silc_calloc(1, sizeof(*sock->qos));
    if (!sock->qos)
      return;
  }
  sock->qos->read_rate = read_rate;
  sock->qos->read_limit_bytes = read_limit_bytes;
  sock->qos->limit_sec = limit_sec;
  sock->qos->limit_usec = limit_usec;
  sock->qos->schedule = schedule;
  memset(&sock->qos->next_limit, 0, sizeof(sock->qos->next_limit));
  sock->qos->cur_rate = 0;
}

/* Finishing timeout callback that will actually call the user specified
   host lookup callback. This is executed back in the calling thread and
   not in the lookup thread. */

SILC_TASK_CALLBACK(silc_socket_host_lookup_finish)
{
  SilcSocketHostLookup lookup = (SilcSocketHostLookup)context;

  SILC_UNSET_HOST_LOOKUP(lookup->sock);

  /* If the reference counter is 1 we know that we are the only one
     holding the socket and it thus is considered freed. The lookup
     is cancelled also and we will not call the final callback. */
  if (lookup->sock->users == 1) {
    SILC_LOG_DEBUG(("Async host lookup was cancelled"));
    silc_socket_free(lookup->sock);
    silc_free(lookup);
    return;
  }

  SILC_LOG_DEBUG(("Async host lookup finished"));

  silc_socket_free(lookup->sock);

  /* Call the final callback. */
  if (lookup->callback)
    lookup->callback(lookup->sock, lookup->context);

  silc_free(lookup);
}

/* The thread function that performs the actual lookup. */

static void *silc_socket_host_lookup_start(void *context)
{
  SilcSocketHostLookup lookup = (SilcSocketHostLookup)context;
  SilcSocketConnection sock = lookup->sock;
  SilcSchedule schedule = lookup->schedule;

  if (lookup->port)
    sock->port = silc_net_get_remote_port(sock->sock);

  silc_net_check_host_by_sock(sock->sock, &sock->hostname, &sock->ip);  
  if (!sock->hostname && sock->ip)
    sock->hostname = strdup(sock->ip);

  silc_schedule_task_add(schedule, sock->sock,
			 silc_socket_host_lookup_finish, lookup, 0, 1,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
  silc_schedule_wakeup(schedule);

  return NULL;
}

/* Performs asynchronous host name and IP address lookups for the
   specified socket connection. This may be called when the socket
   connection is created and the full IP address and fully qualified
   domain name information is desired. The `callback' with `context'
   will be called after the lookup is performed. The `schedule'
   is the application's scheduler which the lookup routine needs. If
   the socket connection is freed during the lookup the library will
   automatically cancel the lookup and the `callback' will not be called. */

void silc_socket_host_lookup(SilcSocketConnection sock,
			     bool port_lookup,
			     SilcSocketHostLookupCb callback,
			     void *context,
			     SilcSchedule schedule)
{
  SilcSocketHostLookup lookup;

  SILC_LOG_DEBUG(("Performing async host lookup"));

  if (SILC_IS_DISCONNECTING(sock) ||
      SILC_IS_DISCONNECTED(sock))
    return;

  lookup = silc_calloc(1, sizeof(*lookup));
  lookup->sock = silc_socket_dup(sock);	/* Increase reference counter */
  lookup->callback = callback;
  lookup->context = context;
  lookup->schedule = schedule;
  lookup->port = port_lookup;

  SILC_SET_HOST_LOOKUP(sock);
  silc_thread_create(silc_socket_host_lookup_start, lookup, FALSE);
}
