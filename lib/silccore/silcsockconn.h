/*

  silcsockconn.h

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

#ifndef SILCSOCKCONN_H
#define SILCSOCKCONN_H

/* Socket types. These identifies the socket connection. */
typedef enum {
  SILC_SOCKET_TYPE_UNKNOWN = 0,
  SILC_SOCKET_TYPE_CLIENT = 1,
  SILC_SOCKET_TYPE_SERVER = 2,
  SILC_SOCKET_TYPE_ROUTER = 3
} SilcSocketType;

/* Socket flags */
#define SILC_SF_NONE 0
#define SILC_SF_INBUF_PENDING 1
#define SILC_SF_OUTBUF_PENDING 2
#define SILC_SF_DISCONNECTING 3
#define SILC_SF_DISCONNECTED 4

/* 
   SILC Socket Connection object.

   This object holds information about the connected sockets to the server.
   This is quite important object since this is referenced by the server all
   the time when figuring out what the connection is supposed to be doing
   and to whom we should send a message.

   Following short description of the fields:

   int sock

       The actual connected socket. This is usually saved when accepting
       new connection to the server.

   SilcSocketType type

       Type of the socket. This identifies the type of the connection. This
       is mainly used to identify whether the connection is a client or a
       server connection.

   void *user_data

       This is a pointer to a data that is is saved here at the same
       time a new connection object is allocated. Usually this is a 
       back-pointer to some important data for fast referencing. For
       SILC server this is a pointer to the ID list and for SILC client
       to object holding active connections (windows).

   SilcProtocol protocol

       Protocol object for the socket. Currently only one protocol can be
       executing at a time for a particular socket.

   unsigned int flags

       Socket flags that indicate the status of the socket. This can
       indicate several different status that can affect the use of the
       socket object.

   SilcBuffer inbuf
   SilcBuffer outbuf

       Incoming and outgoing buffers for the particular socket connection.
       Incoming data from the socket is put after decryption in to the
       inbuf buffer and outgoing data after encryption is put to the outbuf
       buffer.

*/
typedef struct {
  int sock;
  SilcSocketType type;
  void *user_data;
  SilcProtocol protocol;
  unsigned int flags;

  char *hostname;
  char *ip;
  unsigned short port;

  SilcBuffer inbuf;
  SilcBuffer outbuf;
} SilcSocketConnectionObject;

typedef SilcSocketConnectionObject *SilcSocketConnection;

/* Macros */

/* Generic manipulation of flags */
#define SF_SET(x, f) (x)->flags |= (1L << (f))
#define SF_UNSET(x, f) (x)->flags &= ~(1L << (f))
#define SF_IS(x, f) (x)->flags & (1L << (f))

/* Setting/Unsetting flags */
#define SILC_SET_OUTBUF_PENDING(x) SF_SET((x), SILC_SF_OUTBUF_PENDING)
#define SILC_SET_INBUF_PENDING(x) SF_SET((x), SILC_SF_INBUF_PENDING)
#define SILC_SET_DISCONNECTING(x) SF_SET((x), SILC_SF_DISCONNECTING)
#define SILC_SET_DISCONNECTED(x) SF_SET((x), SILC_SF_DISCONNECTED)
#define SILC_UNSET_OUTBUF_PENDING(x) SF_UNSET((x), SILC_SF_OUTBUF_PENDING)
#define SILC_UNSET_INBUF_PENDING(x) SF_UNSET((x), SILC_SF_INBUF_PENDING)
#define SILC_UNSET_DISCONNECTING(x) SF_UNSET((x), SILC_SF_DISCONNECTING)
#define SILC_UNSET_DISCONNECTED(x) SF_UNSET((x), SILC_SF_DISCONNECTED)

/* Checking for flags */
#define SILC_IS_OUTBUF_PENDING(x) SF_IS((x), SILC_SF_OUTBUF_PENDING)
#define SILC_IS_INBUF_PENDING(x) SF_IS((x), SILC_SF_INBUF_PENDING)
#define SILC_IS_DISCONNECTING(x) SF_IS((x), SILC_SF_DISCONNECTING)
#define SILC_IS_DISCONNECTED(x) SF_IS((x), SILC_SF_DISCONNECTED)

/* Prototypes */
void silc_socket_alloc(int sock, SilcSocketType type, void *user_data,
		       SilcSocketConnection *new_socket);
void silc_socket_free(SilcSocketConnection sock);

#endif
