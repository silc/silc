/*

  silcsockconn.c

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
 * $Id$
 * $Log$
 * Revision 1.3  2001/02/11 14:09:34  priikone
 * 	Code auditing weekend results and fixes committing.
 *
 * Revision 1.2  2000/07/05 06:06:35  priikone
 * 	Global cosmetic change.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:55  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "silcincludes.h"

/* Allocates a new socket connection object. The allocated object is 
   returned to the new_socket argument. */

void silc_socket_alloc(int sock, SilcSocketType type, void *user_data, 
		       SilcSocketConnection *new_socket)
{
  SILC_LOG_DEBUG(("Allocating new socket connection object"));

  /* Set the pointers. Incoming and outgoing data buffers
     are allocated by the server when they are first used. */
  *new_socket = silc_calloc(1, sizeof(**new_socket));
  (*new_socket)->sock = sock;
  (*new_socket)->type = type;
  (*new_socket)->user_data = user_data;
  (*new_socket)->protocol = NULL;
  (*new_socket)->flags = 0;
  (*new_socket)->inbuf = NULL;
  (*new_socket)->outbuf = NULL;
}

/* Free's the Socket connection object. */

void silc_socket_free(SilcSocketConnection sock)
{
  if (sock) {
    silc_buffer_free(sock->inbuf);
    silc_buffer_free(sock->outbuf);
    silc_free(sock);
  }
}
