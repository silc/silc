/*

  silcsocketstream.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"

/************************** Types and definitions ***************************/

/* Stream operation functions (platform specific) */
int silc_socket_stream_read(SilcStream stream, unsigned char *buf,
			    SilcUInt32 buf_len);
int silc_socket_stream_write(SilcStream stream, const unsigned char *data,
			     SilcUInt32 data_len);
SilcBool silc_socket_stream_close(SilcStream stream);
void silc_socket_stream_destroy(SilcStream stream);
int silc_socket_udp_stream_read(SilcStream stream, unsigned char *buf,
				SilcUInt32 buf_len);
int silc_socket_udp_stream_write(SilcStream stream, const unsigned char *data,
				 SilcUInt32 data_len);
SilcBool silc_socket_stream_close(SilcStream stream);
void silc_socket_stream_destroy(SilcStream stream);
SilcBool silc_socket_stream_notifier(SilcStream stream,
				     SilcSchedule schedule,
				     SilcStreamNotifier callback,
				     void *context);
SilcSchedule silc_socket_stream_get_schedule(SilcStream stream);

/* Internal async host lookup context. */
typedef struct {
  SilcSocketStream stream;
  SilcResult status;
  SilcSocketStreamCallback callback;
  SilcAsyncOperation op;
  void *context;
  unsigned int require_fqdn : 1;
  unsigned int aborted      : 1;
} *SilcSocketHostLookup;


/************************ Static utility functions **************************/

/* Finishing timeout callback that will actually call the user specified
   host lookup callback.  This is executed back in the calling thread and
   not in the lookup thread. */

SILC_TASK_CALLBACK(silc_socket_host_lookup_finish)
{
  SilcSocketHostLookup lookup = context;
  SilcSocketStream stream = lookup->stream;

  if (lookup->aborted) {
    SILC_LOG_DEBUG(("Socket stream creation was aborted"));
    stream->schedule = NULL;
    silc_socket_stream_destroy(stream);
    silc_free(lookup);
    return;
  }

  if (lookup->status != SILC_OK) {
    SILC_LOG_DEBUG(("Socket stream lookup failed"));
    stream->schedule = NULL;
    silc_socket_stream_destroy(stream);
    stream = lookup->stream = NULL;
  }

  /* Return the created socket stream to the caller */
  if (lookup->callback)
    lookup->callback(lookup->status, stream, lookup->context);

  if (lookup->op)
    silc_async_free(lookup->op);
  silc_free(lookup);
}

/* The thread function that performs the actual lookup. */

static void *silc_socket_host_lookup_start(void *context)
{
  SilcSocketHostLookup lookup = (SilcSocketHostLookup)context;
  SilcSocketStream stream = lookup->stream;
  SilcSchedule schedule = stream->schedule;

  stream->port = silc_net_get_remote_port(stream->sock);

  silc_net_check_host_by_sock(stream->sock, &stream->hostname, &stream->ip);
  if (!stream->ip) {
    lookup->status = SILC_ERR_UNKNOWN_IP;
    goto out;
  }

  if (!stream->hostname && lookup->require_fqdn) {
    lookup->status = SILC_ERR_UNKNOWN_HOST;
    goto out;
  }

  if (!stream->hostname) {
    stream->hostname = silc_strdup(stream->ip);
    if (!stream->hostname) {
      lookup->status = SILC_ERR_OUT_OF_MEMORY;
      goto out;
    }
  }

  lookup->status = SILC_OK;

 out:
  silc_schedule_task_add_timeout(schedule, silc_socket_host_lookup_finish,
				 lookup, 0, 0);
  silc_schedule_wakeup(schedule);
  return NULL;
}

/* Abort callback for stream creation. */

static void silc_socket_host_lookup_abort(SilcAsyncOperation op,
					  void *context)
{
  SilcSocketHostLookup lookup = context;

  /* The host lookup is done in thread.  We'll let it finish in its own
     good time and handle the abortion after it finishes. */
  lookup->aborted = TRUE;
}


/******************************* Public API *********************************/

/* Creates TCP socket stream */

SilcAsyncOperation
silc_socket_tcp_stream_create(SilcSocket sock, SilcBool lookup,
			      SilcBool require_fqdn,
			      SilcSchedule schedule,
			      SilcSocketStreamCallback callback,
			      void *context)
{
  SilcSocketStream stream;
  SilcSocketHostLookup l;

  if (!schedule) {
    schedule = silc_schedule_get_global();
    if (!schedule) {
      silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
      if (callback)
	callback(silc_errno, NULL, context);
      return NULL;
    }
  }

  if (!sock) {
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
    if (callback)
      callback(silc_errno, NULL, context);
    return NULL;
  }

  stream = silc_calloc(1, sizeof(*stream));
  if (!stream) {
    if (callback)
      callback(silc_errno, NULL, context);
    return NULL;
  }

  SILC_LOG_DEBUG(("Creating TCP socket stream %p, sock %lu", stream, sock));

  stream->ops = &silc_socket_stream_ops;
  stream->sock = sock;
  stream->schedule = schedule;
  stream->connected = TRUE;

  l = silc_calloc(1, sizeof(*l));
  if (!l) {
    silc_free(stream);
    if (callback)
      callback(silc_errno, NULL, context);
    return NULL;
  }

  l->stream = stream;
  l->callback = callback;
  l->context = context;
  l->require_fqdn = require_fqdn;

  if (lookup) {
    /* Start asynchronous IP, hostname and port lookup process */
    l->op = silc_async_alloc(silc_socket_host_lookup_abort, NULL, l);
    if (!l->op) {
      silc_free(stream);
      silc_free(l);
      if (callback)
	callback(silc_errno, NULL, context);
      return NULL;
    }

    /* Lookup in thread */
    SILC_LOG_DEBUG(("Starting async host lookup"));
    silc_thread_create(silc_socket_host_lookup_start, l, FALSE);
    return l->op;
  } else {
    /* No lookup */
    l->status = SILC_OK;
    silc_socket_host_lookup_finish(schedule,
				   silc_schedule_get_context(schedule),
				   0, 0, l);
    return NULL;
  }
}

/* Creates UDP socket stream */

SilcStream silc_socket_udp_stream_create(SilcSocket sock, SilcBool ipv6,
					 SilcBool connected,
					 SilcSchedule schedule)
{
  SilcSocketStream stream;

  if (!schedule) {
    schedule = silc_schedule_get_global();
    if (!schedule) {
      silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
      return NULL;
    }
  }

  stream = silc_calloc(1, sizeof(*stream));
  if (!stream)
    return NULL;

  SILC_LOG_DEBUG(("Creating UDP socket stream %p", stream));

  stream->ops = &silc_socket_udp_stream_ops;
  stream->sock = sock;
  stream->schedule = schedule;
  stream->ipv6 = ipv6;
  stream->connected = connected;

  return (SilcStream)stream;
}

/* Returns TRUE if the stream is UDP stream */

SilcBool silc_socket_stream_is_udp(SilcStream stream, SilcBool *connected)
{
  SilcSocketStream socket_stream = stream;

  if (!SILC_IS_SOCKET_STREAM_UDP(socket_stream))
    return FALSE;

  if (connected)
    *connected = socket_stream->connected;

  return TRUE;
}

/* Returns socket stream information */

SilcBool silc_socket_stream_get_info(SilcStream stream,
				     SilcSocket *sock, const char **hostname,
				     const char **ip, SilcUInt16 *port)
{
  SilcSocketStream socket_stream = stream;

  if (!SILC_IS_SOCKET_STREAM(socket_stream) &&
      !SILC_IS_SOCKET_STREAM_UDP(socket_stream))
    return FALSE;

  if (sock)
    *sock = socket_stream->sock;
  if (port) {
    if (!socket_stream->port)
      return FALSE;
    *port = socket_stream->port;
  }
  if (ip) {
    if (!socket_stream->ip)
      return FALSE;
    *ip = socket_stream->ip;
  }
  if (hostname) {
    if (!socket_stream->hostname)
      return FALSE;
    *hostname = socket_stream->hostname;
  }

  return TRUE;
}

/* Set socket information */

SilcBool silc_socket_stream_set_info(SilcStream stream,
				     const char *hostname,
				     const char *ip, SilcUInt16 port)
{
  SilcSocketStream socket_stream = stream;

  if (!SILC_IS_SOCKET_STREAM(socket_stream) &&
      !SILC_IS_SOCKET_STREAM_UDP(socket_stream))
    return FALSE;

  if (hostname) {
    silc_free(socket_stream->hostname);
    socket_stream->hostname = silc_strdup(hostname);
    if (!socket_stream->hostname)
      return FALSE;
  }
  if (ip) {
    silc_free(socket_stream->ip);
    socket_stream->ip = silc_strdup(ip);
    if (!socket_stream->ip)
      return FALSE;
    if (!socket_stream->hostname) {
      socket_stream->hostname = silc_strdup(ip);
      if (!socket_stream->hostname)
	return FALSE;
    }
  }
  if (port)
    socket_stream->port = port;

  return TRUE;
}

/* Set QoS for socket stream */

SilcBool silc_socket_stream_set_qos(SilcStream stream,
				    SilcUInt32 read_rate,
				    SilcUInt32 read_limit_bytes,
				    SilcUInt32 limit_sec,
				    SilcUInt32 limit_usec)
{
  SilcSocketStream socket_stream = stream;

  if (!SILC_IS_SOCKET_STREAM(socket_stream) &&
      !SILC_IS_SOCKET_STREAM_UDP(socket_stream))
    return FALSE;

  SILC_LOG_DEBUG(("Setting QoS for socket stream"));

  if (socket_stream->qos && !read_rate && !read_limit_bytes &&
      !limit_sec && !limit_usec) {
    silc_schedule_task_del_by_context(socket_stream->schedule,
				      socket_stream->qos);
    silc_free(socket_stream->qos);
    socket_stream->qos = NULL;
    return TRUE;
  }

  if (!socket_stream->qos) {
    socket_stream->qos = silc_calloc(1, sizeof(*socket_stream->qos));
    if (!socket_stream->qos)
      return FALSE;
  }

  socket_stream->qos->read_rate = read_rate;
  socket_stream->qos->read_limit_bytes = read_limit_bytes;
  socket_stream->qos->limit_sec = limit_sec;
  socket_stream->qos->limit_usec = limit_usec;
  memset(&socket_stream->qos->next_limit, 0,
	 sizeof(socket_stream->qos->next_limit));
  socket_stream->qos->cur_rate = 0;
  socket_stream->qos->sock = socket_stream;

  socket_stream->qos->buffer = silc_malloc(read_limit_bytes);
  if (!socket_stream->qos->buffer)
    return FALSE;

  return TRUE;
}

/* Return associated scheduler */

SilcSchedule silc_socket_stream_get_schedule(SilcStream stream)
{
  SilcSocketStream socket_stream = stream;

  if (!SILC_IS_SOCKET_STREAM(socket_stream) &&
      !SILC_IS_SOCKET_STREAM_UDP(socket_stream))
    return NULL;

  return socket_stream->schedule;
}

/* SILC Socket Stream ops.  Functions are implemented under the
   platform specific subdirectories. */
const SilcStreamOps silc_socket_stream_ops =
{
  silc_socket_stream_read,
  silc_socket_stream_write,
  silc_socket_stream_close,
  silc_socket_stream_destroy,
  silc_socket_stream_notifier,
  silc_socket_stream_get_schedule,
};
const SilcStreamOps silc_socket_udp_stream_ops =
{
  silc_socket_udp_stream_read,
  silc_socket_udp_stream_write,
  silc_socket_stream_close,
  silc_socket_stream_destroy,
  silc_socket_stream_notifier,
  silc_socket_stream_get_schedule,
};
