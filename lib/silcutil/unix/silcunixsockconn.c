/*

  silcunixsockconn.c

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

  if (SILC_IS_DISABLED(sock))
    return -1;

  SILC_LOG_DEBUG(("Writing data to socket %d", fd));

  if (src->len > 0) {
    ret = write(fd, src->data, src->len);
    if (ret < 0) {
      if (errno == EAGAIN) {
	SILC_LOG_DEBUG(("Could not write immediately, will do it later"));
	return -2;
      }
      SILC_LOG_DEBUG(("Cannot write to socket: %s", strerror(errno)));
      sock->sock_error = errno;
      return -1;
    }

    silc_buffer_pull(src, ret);
  }

  SILC_LOG_DEBUG(("Wrote data %d bytes", ret));

  return ret;
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

  return len;
}

/* Returns human readable socket error message */

bool silc_socket_get_error(SilcSocketConnection sock, char *error,
			   uint32 error_len)
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
