/*

  silcwin32sockconn.c

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
  int ret = 0, err;
  SOCKET fd = sock->sock;
  SilcBuffer src = sock->outbuf;

  if (SILC_IS_DISABLED(sock))
    return -1;

  SILC_LOG_DEBUG(("Writing data to socket %d", fd));

  if (src->len > 0) {
    ret = send(fd, src->data, src->len,  0);
    if (ret == SOCKET_ERROR) {
      err = WSAGetLastError();
      if (err == WSAEWOULDBLOCK) {
	SILC_LOG_DEBUG(("Could not write immediately, will do it later"));
	return -2;
      }
      SILC_LOG_ERROR(("Cannot write to socket: %d", (int)fd));
      sock->sock_error = err;
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
  int len = 0, err;
  unsigned char buf[SILC_SOCKET_READ_SIZE];
  SOCKET fd = sock->sock;
  int argp;

  if (SILC_IS_DISABLED(sock))
    return -1;

  SILC_LOG_DEBUG(("Reading data from socket %d", fd));

  /* Check whether there is data available, without calling recv(). */
  ioctlsocket(fd, FIONREAD, (unsigned long *)&argp);
  if (argp == 0) {
    /* Is this kludge or what? Without this thing this contraption
       does not work at all!?. */
    SleepEx(1, TRUE);
    SILC_LOG_DEBUG(("Could not read immediately, will do it later"));
    return -2;
  }

  /* Read the data from the socket. */
  len = recv(fd, buf, sizeof(buf), 0);
  if (len == SOCKET_ERROR) {
    err = WSAGetLastError();
    if (err == WSAEWOULDBLOCK || err == WSAEINTR) {
      SILC_LOG_DEBUG(("Could not read immediately, will do it later"));
      return -2;
    }
    SILC_LOG_ERROR(("Cannot read from socket: %d", (int)fd));
    sock->sock_error = err;
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
  /* XXX TODO */
  return FALSE;
}
