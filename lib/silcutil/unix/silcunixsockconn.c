/*

  silcunixsockconn.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2003 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"

/* Writes data from encrypted buffer to the socket connection. If the
   data cannot be written at once, it will be written later with a timeout.
   The data is written from the data section of the buffer, not from head
   or tail section. This automatically pulls the data section towards end
   after writing the data. */

int silc_socket_write(SilcSocketConnection sock)
{
  int ret = 0;
  int fd = sock->sock;
  SilcBuffer src = sock->outbuf;

  if (!src)
    return -2;
  if (SILC_IS_DISABLED(sock))
    return -1;

  SILC_LOG_DEBUG(("Writing data to socket %d", fd));

  if (src->len > 0) {
    ret = write(fd, src->data, src->len);
    if (ret < 0) {
      if (errno == EAGAIN || errno == EINTR) {
	SILC_LOG_DEBUG(("Could not write immediately, will do it later"));
	return -2;
      }
      SILC_LOG_DEBUG(("Cannot write to socket: %s", strerror(errno)));
      sock->sock_error = errno;
      return -1;
    }

    if (ret < src->len) {
      SILC_LOG_DEBUG(("Wrote data %d of %d bytes, will write rest later",
		      ret, src->len));
      silc_buffer_pull(src, ret);
      return -2;
    }

    silc_buffer_pull(src, ret);
  }

  SILC_LOG_DEBUG(("Wrote data %d bytes", ret));

  return ret;
}

/* QoS read handler, this will call the read and write events to indicate
   that data is available again after a timeout. */

SILC_TASK_CALLBACK(silc_socket_read_qos)
{
  SilcSocketConnectionQos qos = context;
  SilcSocketConnection sock = qos->sock;
  qos->applied = TRUE;
  if (sock->users > 1)
    silc_schedule_set_listen_fd(qos->schedule, sock->sock,
				(SILC_TASK_READ | SILC_TASK_WRITE), TRUE);
  else
    silc_schedule_unset_listen_fd(qos->schedule, sock->sock);
  qos->applied = FALSE;
  silc_socket_free(sock);
}

/* Reads data from the socket connection into the incoming data buffer.
   It reads as much as possible from the socket connection. This returns
   amount of bytes read or -1 on error or -2 on case where all of the
   data could not be read at once. */

int silc_socket_read(SilcSocketConnection sock)
{
  int len = 0;
  unsigned char buf[SILC_SOCKET_READ_SIZE];
  int fd = sock->sock;

  if (SILC_IS_DISABLED(sock))
    return -1;

  /* If QoS was applied to socket then return earlier read data but apply
     QoS to it too, if necessary. */
  if (sock->qos) {
    if (sock->qos->applied) {
      if (sock->qos->data_len) {
	/* Pull hidden data since we have it from earlier QoS apply */
	silc_buffer_pull_tail(sock->inbuf, sock->qos->data_len);
	len = sock->qos->data_len;
	sock->qos->data_len = 0;
      }

      if (sock->inbuf->len - len > sock->qos->read_limit_bytes) {
	/* Seems we need to apply QoS for the remaining data as well */
	silc_socket_dup(sock);
	silc_schedule_task_add(sock->qos->schedule, sock->sock,
			       silc_socket_read_qos, sock->qos,
			       sock->qos->limit_sec, sock->qos->limit_usec,
			       SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);
	silc_schedule_unset_listen_fd(sock->qos->schedule, sock->sock);

	/* Hide the rest of the data from the buffer. */
	sock->qos->data_len = (sock->inbuf->len - len -
			       sock->qos->read_limit_bytes);
	silc_buffer_push_tail(sock->inbuf, sock->qos->data_len);
      }

      if (sock->inbuf->len)
	return sock->inbuf->len;
    }

    /* If we were called and we have active QoS data pending, return
       with no data */
    if (sock->qos->data_len) {
      silc_schedule_unset_listen_fd(sock->qos->schedule, sock->sock);
      return -2;
    }
  }

  SILC_LOG_DEBUG(("Reading data from socket %d", fd));

  /* Read the data from the socket. */
  len = read(fd, buf, sizeof(buf));
  if (len < 0) {
    if (errno == EAGAIN || errno == EINTR) {
      SILC_LOG_DEBUG(("Could not read immediately, will do it later"));
      return -2;
    }
    SILC_LOG_DEBUG(("Cannot read from socket: %d:%s", fd, strerror(errno)));
    sock->sock_error = errno;
    return -1;
  }

  if (!len)
    return 0;

  /* Insert the data to the buffer. */

  if (!sock->inbuf)
    sock->inbuf = silc_buffer_alloc(SILC_SOCKET_BUF_SIZE);

  /* If the data does not fit to the buffer reallocate it */
  if ((sock->inbuf->end - sock->inbuf->tail) < len)
    sock->inbuf = silc_buffer_realloc(sock->inbuf, sock->inbuf->truelen +
				      (len * 2));
  silc_buffer_put_tail(sock->inbuf, buf, len);
  silc_buffer_pull_tail(sock->inbuf, len);

  SILC_LOG_DEBUG(("Read %d bytes", len));

  /* Apply QoS to the read data if necessary */
  if (sock->qos) {
    struct timeval curtime;
    silc_gettimeofday(&curtime);

    /* If we have passed the rate time limit, set our new time limit,
       and zero the rate limit. */
    if (!silc_compare_timeval(&curtime, &sock->qos->next_limit)) {
      curtime.tv_sec++;
      sock->qos->next_limit = curtime;
      sock->qos->cur_rate = 0;
    }
    sock->qos->cur_rate++;

    /* If we are not withing rate limit apply QoS for the read data */
    if (sock->qos->cur_rate > sock->qos->read_rate) {
      silc_socket_dup(sock);
      silc_schedule_task_add(sock->qos->schedule, sock->sock,
			     silc_socket_read_qos, sock->qos,
			     sock->qos->limit_sec, sock->qos->limit_usec,
			     SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);
      silc_schedule_unset_listen_fd(sock->qos->schedule, sock->sock);

      /* Check the byte limit as well, and do not return more than allowed */
      if (sock->inbuf->len > sock->qos->read_limit_bytes) {
	/* Hide the rest of the data from the buffer. */
	sock->qos->data_len = sock->inbuf->len - sock->qos->read_limit_bytes;
	silc_buffer_push_tail(sock->inbuf, sock->qos->data_len);
	len = sock->inbuf->len;
      } else {
	/* Rate limit kicked in, do not return data yet */
	return -2;
      }
    } else {
      /* Check the byte limit, and do not return more than allowed */
      if (sock->inbuf->len > sock->qos->read_limit_bytes) {
	silc_socket_dup(sock);
	silc_schedule_task_add(sock->qos->schedule, sock->sock,
			       silc_socket_read_qos, sock->qos,
			       sock->qos->limit_sec, sock->qos->limit_usec,
			       SILC_TASK_TIMEOUT, SILC_TASK_PRI_LOW);
	silc_schedule_unset_listen_fd(sock->qos->schedule, sock->sock);

	/* Hide the rest of the data from the buffer. */
	sock->qos->data_len = sock->inbuf->len - sock->qos->read_limit_bytes;
	silc_buffer_push_tail(sock->inbuf, sock->qos->data_len);
	len = sock->inbuf->len;
      }
    }
  }

  return len;
}

/* Returns human readable socket error message */

bool silc_socket_get_error(SilcSocketConnection sock, char *error,
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
