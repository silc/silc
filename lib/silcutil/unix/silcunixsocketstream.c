/*

  silcunixsocketstream.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silc.h"

/************************ Static utility functions **************************/

/* The IO process callback that calls the notifier callback to upper layer. */

SILC_TASK_CALLBACK(silc_socket_stream_io)
{
  SilcSocketStream stream = context;

  if (silc_unlikely(!stream->notifier))
    return;

  switch (type) {
  case SILC_TASK_READ:
    stream->notifier(stream, SILC_STREAM_CAN_READ, stream->notifier_context);
    break;

  case SILC_TASK_WRITE:
    stream->notifier(stream, SILC_STREAM_CAN_WRITE, stream->notifier_context);
    break;

  default:
    break;
  }
}

/**************************** Stream Operations *****************************/

/* QoS read handler, this will call the read and write events to indicate
   that data is available again after a timeout. */

SILC_TASK_CALLBACK(silc_socket_read_qos)
{
  SilcSocketQos qos = context;
  qos->applied = TRUE;
  silc_schedule_set_listen_fd(qos->sock->schedule, qos->sock->sock,
			      (SILC_TASK_READ | SILC_TASK_WRITE), TRUE);
  qos->applied = FALSE;
  silc_schedule_set_listen_fd(qos->sock->schedule, qos->sock->sock,
			      SILC_TASK_READ, FALSE);
}

/* Stream read operation */

int silc_socket_stream_read(SilcStream stream, unsigned char *buf,
			    SilcUInt32 buf_len)
{
  SilcSocketStream sock = stream;
  int len = 0;
  struct timeval curtime;
  unsigned char *qosbuf;

  SILC_LOG_DEBUG(("Reading data from socket %d", sock->sock));

  /* Handle the simple non-QoS reading. */
  if (!sock->qos) {
    len = read(sock->sock, buf, buf_len);
    if (len < 0) {
      if (errno == EAGAIN || errno == EINTR) {
	SILC_LOG_DEBUG(("Could not read immediately, will do it later"));
	silc_schedule_set_listen_fd(sock->schedule, sock->sock,
				    SILC_TASK_READ, FALSE);
	return -1;
      }
      SILC_LOG_DEBUG(("Cannot read from socket: %d:%s",
		      sock->sock, strerror(errno)));
      silc_schedule_unset_listen_fd(sock->schedule, sock->sock);
      sock->sock_error = errno;
      return -2;
    }

    SILC_LOG_DEBUG(("Read %d bytes", len));

    if (!len)
      silc_schedule_unset_listen_fd(sock->schedule, sock->sock);

    return len;
  }

  /* We have QoS set, and reading is done via the QoS system. */
  qosbuf = sock->qos->buffer;

  /* If QoS was applied, return the data that was pending. */
  if (sock->qos->applied && sock->qos->data_len) {
    memcpy(buf, qosbuf, sock->qos->data_len);
    sock->qos->data_len = 0;
    return sock->qos->data_len;
  }

  /* If we have active QoS data pending, return with no data */
  if (sock->qos->data_len) {
    silc_schedule_unset_listen_fd(sock->schedule, sock->sock);
    return -1;
  }

  /* Read the data from the socket.  Never read more than the max limit. */
  len = (buf_len < sock->qos->read_limit_bytes ? buf_len :
	 sock->qos->read_limit_bytes);
  len = read(sock->sock, qosbuf, len);
  if (len < 0) {
    if (errno == EAGAIN || errno == EINTR) {
      SILC_LOG_DEBUG(("Could not read immediately, will do it later"));
      silc_schedule_set_listen_fd(sock->schedule, sock->sock,
				  SILC_TASK_READ, FALSE);
      return -1;
    }
    SILC_LOG_DEBUG(("Cannot read from socket: %d:%s",
		    sock->sock, strerror(errno)));
    silc_schedule_unset_listen_fd(sock->schedule, sock->sock);
    silc_schedule_task_del_by_context(sock->schedule, sock->qos);
    sock->qos->data_len = 0;
    sock->sock_error = errno;
    return -2;
  }

  SILC_LOG_DEBUG(("Read %d bytes", len));

  if (!len) {
    silc_schedule_unset_listen_fd(sock->schedule, sock->sock);
    silc_schedule_task_del_by_context(sock->schedule, sock->qos);
    sock->qos->data_len = 0;
    return 0;
  }

  /* If we have passed the rate time limit, set our new time limit,
     and zero the rate limit.  This limits reads per second. */
  silc_gettimeofday(&curtime);
  if (!silc_compare_timeval(&curtime, &sock->qos->next_limit)) {
    curtime.tv_sec++;
    sock->qos->next_limit = curtime;
    sock->qos->cur_rate = 0;
  }
  sock->qos->cur_rate++;

  /* If we are not within rate limit apply QoS for the read data */
  if (sock->qos->cur_rate > sock->qos->read_rate) {
    silc_schedule_task_add_timeout(sock->schedule, silc_socket_read_qos,
				   sock->qos, sock->qos->limit_sec,
				   sock->qos->limit_usec);
    sock->qos->data_len = len;

    /* Rate limit kicked in, do not return data yet */
    silc_schedule_unset_listen_fd(sock->schedule, sock->sock);
    return -1;
  }

  /* Return the data from the QoS buffer */
  memcpy(buf, qosbuf, len);
  return len;
}

/* Stream write operation */

int silc_socket_stream_write(SilcStream stream, const unsigned char *data,
			     SilcUInt32 data_len)
{
  SilcSocketStream sock = stream;
  int ret;

  SILC_LOG_DEBUG(("Writing data to socket %d", sock->sock));

  ret = write(sock->sock, data, data_len);
  if (ret < 0) {
    if (errno == EAGAIN || errno == EINTR) {
      SILC_LOG_DEBUG(("Could not write immediately, will do it later"));
      silc_schedule_set_listen_fd(sock->schedule, sock->sock,
				  SILC_TASK_READ | SILC_TASK_WRITE, FALSE);
      return -1;
    }
    SILC_LOG_DEBUG(("Cannot write to socket: %s", strerror(errno)));
    silc_schedule_unset_listen_fd(sock->schedule, sock->sock);
    sock->sock_error = errno;
    return -2;
  }

  SILC_LOG_DEBUG(("Wrote data %d bytes", ret));
  if (silc_schedule_get_fd_events(sock->schedule, sock->sock) &
      SILC_TASK_WRITE)
    silc_schedule_set_listen_fd(sock->schedule, sock->sock,
				SILC_TASK_READ, FALSE);

  return ret;
}

/* Receive UDP packet.  QoS is not supported. */

int silc_socket_udp_stream_read(SilcStream stream, unsigned char *buf,
				SilcUInt32 buf_len)
{
  return silc_net_udp_receive(stream, NULL, 0, NULL, buf, buf_len);
}

/* Send UDP packet.  This always succeeds. */

int silc_socket_udp_stream_write(SilcStream stream, const unsigned char *data,
				 SilcUInt32 data_len)
{
  SilcSocketStream sock = stream;

  /* In connectionless state check if remote IP and port is provided */
  if (!sock->connected && sock->ip && sock->port)
    return silc_net_udp_send(stream, sock->ip, sock->port, data, data_len);

  /* In connected state use normal writing to socket. */
  return silc_socket_stream_write(stream, data, data_len);
}

#if 0
/* Returns human readable socket error message */

SilcBool silc_socket_get_error(SilcStream sock, char *error,
			       SilcUInt32 error_len)
{
  char *err;

  if (!sock->sock_error)
    return FALSE;

  err = strerror(sock->sock_error);
  if (strlen(err) > error_len)
    return FALSE;

  memset(error, 0, error_len);
  memcpy(error, err, strlen(err));
  return TRUE;
}
#endif /* 0 */

/* Closes socket */

SilcBool silc_socket_stream_close(SilcStream stream)
{
  SilcSocketStream socket_stream = stream;

  if (!SILC_IS_SOCKET_STREAM(socket_stream) &&
      !SILC_IS_SOCKET_STREAM_UDP(socket_stream))
    return FALSE;

  silc_schedule_unset_listen_fd(socket_stream->schedule, socket_stream->sock);
  silc_net_close_connection(socket_stream->sock);

  return TRUE;
}

/* Destroys the stream */

void silc_socket_stream_destroy(SilcStream stream)
{
  SilcSocketStream socket_stream = stream;

  if (!SILC_IS_SOCKET_STREAM(socket_stream) &&
      !SILC_IS_SOCKET_STREAM_UDP(socket_stream))
    return;

  silc_socket_stream_close(socket_stream);
  silc_free(socket_stream->ip);
  silc_free(socket_stream->hostname);
  if (socket_stream->schedule)
    silc_schedule_task_del_by_fd(socket_stream->schedule, socket_stream->sock);

  if (socket_stream->qos) {
    silc_schedule_task_del_by_context(socket_stream->schedule,
				      socket_stream->qos);
    if (socket_stream->qos->buffer) {
      memset(socket_stream->qos->buffer, 0,
	     socket_stream->qos->read_limit_bytes);
      silc_free(socket_stream->qos->buffer);
    }
    silc_free(socket_stream->qos);
  }

  if (socket_stream->schedule)
    silc_schedule_wakeup(socket_stream->schedule);

  silc_free(socket_stream);
}

/* Sets stream notification callback for the stream */

void silc_socket_stream_notifier(SilcStream stream,
				 SilcSchedule schedule,
				 SilcStreamNotifier callback,
				 void *context)
{
  SilcSocketStream socket_stream = stream;

  if (!SILC_IS_SOCKET_STREAM(socket_stream) &&
      !SILC_IS_SOCKET_STREAM_UDP(socket_stream))
    return;

  SILC_LOG_DEBUG(("Setting stream notifier callback"));

  socket_stream->notifier = callback;
  socket_stream->notifier_context = context;
  socket_stream->schedule = schedule;

  if (socket_stream->notifier) {
    /* Add the socket to scheduler.  Safe to call if already added. */
    silc_schedule_task_add_fd(socket_stream->schedule, socket_stream->sock,
			      silc_socket_stream_io, socket_stream);

    /* Initially set socket for reading */
    silc_schedule_set_listen_fd(socket_stream->schedule, socket_stream->sock,
				SILC_TASK_READ, FALSE);
    silc_schedule_wakeup(socket_stream->schedule);
  } else {
    /* Unschedule the socket */
    silc_schedule_unset_listen_fd(socket_stream->schedule,
				  socket_stream->sock);
    silc_schedule_task_del_by_fd(socket_stream->schedule,
				 socket_stream->sock);
    silc_schedule_wakeup(socket_stream->schedule);
  }
}
