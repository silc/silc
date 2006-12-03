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
