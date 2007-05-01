/*

  silcwin32socketstream.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"

/************************ Static utility functions **************************/

/* The IO process callback that calls the notifier callback to upper layer. */

SILC_TASK_CALLBACK(silc_socket_stream_io)
{
  SilcSocketStream stream = context;

  if (!stream->notifier)
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

/* Stream read operation */

int silc_socket_stream_read(SilcStream stream, unsigned char *buf,
			    SilcUInt32 buf_len)
{
  SilcSocketStream sock = stream;
  SOCKET fd = sock->sock;
  int len, argp;

  SILC_LOG_DEBUG(("Reading data from socket %d", fd));

  /* Check whether there is data available, without calling recv(). */
  ioctlsocket(fd, FIONREAD, (unsigned long *)&argp);
  if (argp == 0) {
    /* Is this kludge or what? Without this thing this contraption
       does not work at all!?. */
    SleepEx(1, TRUE);
    SILC_LOG_DEBUG(("Could not read immediately, will do it later"));
    silc_schedule_set_listen_fd(sock->schedule, sock->sock,
				silc_schedule_get_fd_events(sock->schedule,
							    sock->sock) |
				SILC_TASK_READ, FALSE);
    return -1;
  }

  /* Read the data from the socket. */
  len = recv(fd, buf, buf_len, 0);
  if (len == SOCKET_ERROR) {
    len = WSAGetLastError();
    if (len == WSAEWOULDBLOCK || len == WSAEINTR) {
      SILC_LOG_DEBUG(("Could not read immediately, will do it later"));
      silc_schedule_set_listen_fd(sock->schedule, sock->sock,
				  silc_schedule_get_fd_events(sock->schedule,
							      sock->sock) |
				  SILC_TASK_READ, FALSE);
      return -1;
    }
    SILC_LOG_DEBUG(("Cannot read from socket: %d", sock->sock));
    silc_schedule_unset_listen_fd(sock->schedule, sock->sock);
    sock->sock_error = len;
    return -2;
  }

  SILC_LOG_DEBUG(("Read %d bytes", len));

  if (!len)
    silc_schedule_unset_listen_fd(sock->schedule, sock->sock);

  return len;
}

/* Stream write operation */

int silc_socket_stream_write(SilcStream stream, const unsigned char *data,
			     SilcUInt32 data_len)
{
  SilcSocketStream sock = stream;
  SOCKET fd = sock->sock;
  int ret;

  SILC_LOG_DEBUG(("Writing data to socket %d", fd));

  ret = send(fd, data, data_len,  0);
  if (ret == SOCKET_ERROR) {
    ret = WSAGetLastError();
    if (ret == WSAEWOULDBLOCK) {
      SILC_LOG_DEBUG(("Could not write immediately, will do it later"));
      silc_schedule_set_listen_fd(sock->schedule, sock->sock,
				  SILC_TASK_READ | SILC_TASK_WRITE, FALSE);
      return -1;
    }
    SILC_LOG_DEBUG(("Cannot write to socket"));
    silc_schedule_unset_listen_fd(sock->schedule, sock->sock);
    sock->sock_error = ret;
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

/* Closes socket */

SilcBool silc_socket_stream_close(SilcStream stream)
{
  SilcSocketStream socket_stream = stream;

  if (socket_stream->schedule) {
    silc_schedule_unset_listen_fd(socket_stream->schedule,
				  socket_stream->sock);
    silc_schedule_task_del_by_fd(socket_stream->schedule,
				 socket_stream->sock);
  }
  silc_net_close_connection(socket_stream->sock);

  return TRUE;
}

/* Destroys the stream */

void silc_socket_stream_destroy(SilcStream stream)
{
  SilcSocketStream socket_stream = stream;

  silc_socket_stream_close(socket_stream);
  silc_free(socket_stream->ip);
  silc_free(socket_stream->hostname);
  if (socket_stream->schedule)
    silc_schedule_task_del_by_fd(socket_stream->schedule, socket_stream->sock);

  if (socket_stream->schedule)
    silc_schedule_wakeup(socket_stream->schedule);

  silc_free(socket_stream);
}

/* Sets stream notification callback for the stream */

SilcBool silc_socket_stream_notifier(SilcStream stream,
				     SilcSchedule schedule,
				     SilcStreamNotifier callback,
				     void *context)
{
  SilcSocketStream socket_stream = stream;

  SILC_LOG_DEBUG(("Setting stream notifier callback"));

  socket_stream->notifier = callback;
  socket_stream->notifier_context = context;
  socket_stream->schedule = schedule;

  if (socket_stream->notifier && socket_stream->schedule) {
    /* Add the socket to scheduler.  Safe to call if already added. */
    if (!silc_schedule_task_add_fd(socket_stream->schedule,
				   socket_stream->sock,
				   silc_socket_stream_io, socket_stream))
      return FALSE;

    /* Initially set socket for reading */
    if (!silc_schedule_set_listen_fd(socket_stream->schedule,
				     socket_stream->sock,
				     SILC_TASK_READ, FALSE))
      return FALSE;
  } else if (socket_stream->schedule) {
    /* Unschedule the socket */
    silc_schedule_unset_listen_fd(socket_stream->schedule,
				  socket_stream->sock);
    silc_schedule_task_del_by_fd(socket_stream->schedule,
				 socket_stream->sock);
  }

  if (socket_stream->schedule)
    silc_schedule_wakeup(socket_stream->schedule);

  return TRUE;
}
