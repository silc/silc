/****h* silcutil/silcsockconn.h
 *
 * NAME
 *
 * silcsockconn.h
 *
 * COPYRIGHT
 *
 * Author: Pekka Riikonen <priikone@silnet.org>
 *
 * Copyright (C) 1997 - 2001 Pekka Riikonen
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * DESCRIPTION
 *
 * Implementation of the Socket Connection object. The SilcSocketConnection
 * is used by all applications to represent a socket based connection
 * to the network. The Socket Connection object handles inbound and outbound
 * data buffers, can perform keepalive actions for the connection and
 * supports connection based protocols as well.
 *
 ***/

#ifndef SILCSOCKCONN_H
#define SILCSOCKCONN_H

/****s* silcutil/SilcSocketConnectionAPI/SilcSocketConnection
 *
 * NAME
 * 
 *    typedef struct SilcSocketConnectionStruct *SilcSocketConnection;
 *
 * DESCRIPTION
 *
 *    This context is forward declaration for the SilcSocketConnectionStruct.
 *    This is allocated by the silc_socket_alloc and freed by the
 *    silc_socket_free function. The silc_socket_dup can be used to
 *    increase the reference counter of the context. The data is freed
 *    by the silc_socket_free function only after the reference counter
 *    hits zero.
 *
 ***/
typedef struct SilcSocketConnectionStruct *SilcSocketConnection;

/****s* silcutil/SilcSocketConnectionAPI/SilcSocketConnectionHB
 *
 * NAME
 * 
 *    typedef struct SilcSocketConnectionHB *SilcSocketConnectionHB;
 *
 * DESCRIPTION
 *
 *    This context is the heartbeat context for the SilcSockeConnection.
 *    It is meant to hold the keepalive information for the connection.
 *    This is allocated internally and freed internally by the 
 *    interface routines.
 *
 ***/
typedef struct SilcSocketConnectionHB *SilcSocketConnectionHB;

/****d* silcutil/SilcSocketConnectionAPI/SilcSocketType
 *
 * NAME
 * 
 *    typedef enum { ... } SilcSocketType;
 *
 * DESCRIPTION
 *
 *    Socket types. These identifies the socket connection. There
 *    are four different types; unknown, client, server and router.
 *    Unknown connections are connections that hasn't advanced long
 *    enough so that we might know which type of connection it is.
 *    It is the applications responsibility to update the type 
 *    information when it becomes available.
 *
 * SOURCE
 */
typedef enum {
  SILC_SOCKET_TYPE_UNKNOWN = 0,
  SILC_SOCKET_TYPE_CLIENT = 1,
  SILC_SOCKET_TYPE_SERVER = 2,
  SILC_SOCKET_TYPE_ROUTER = 3
} SilcSocketType;
/***/

/* Socket flags */
#define SILC_SF_NONE 0
#define SILC_SF_INBUF_PENDING 1
#define SILC_SF_OUTBUF_PENDING 2
#define SILC_SF_DISCONNECTING 3
#define SILC_SF_DISCONNECTED 4

/****f* silcutil/SilcSocketConnectionAPI/SilcSocketConnectionHBCb
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcSocketConnectionHBCb)(SilcSocketConnection sock,
 *                                             void *context);
 *
 * DESCRIPTION
 *
 *    Heartbeat callback function. This is the function in the application
 *    that this library will call when it is time to send the keepalive
 *    packet SILC_PACKET_HEARTBEAT.
 *
 ***/
typedef void (*SilcSocketConnectionHBCb)(SilcSocketConnection sock,
					 void *context);

/****s* silcutil/SilcSocketConnectionAPI/SilcSocketConnectionStruct
 *
 * NAME
 * 
 *    struct SilcSocketConnectionStruct { ... };
 *
 * DESCRIPTION
 *
 *    This object holds information about the connected sockets to the server.
 *    This is quite important object since this is referenced by the server all
 *    the time when figuring out what the connection is supposed to be doing
 *    and to whom we should send a message. This structure is the structure
 *    for the SilcSocketConnection forward declaration.
 *
 *    Following short description of the fields:
 *
 *    int sock
 *
 *      The actual connected socket. This is usually saved when accepting
 *      new connection to the server.
 *
 *    SilcSocketType type
 *
 *      Type of the socket. This identifies the type of the connection. This
 *      is mainly used to identify whether the connection is a client or a
 *      server connection.
 *
 *    void *user_data
 *
 *      This is a pointer to a data that is is saved here at the same
 *      time a new connection object is allocated. Usually this is a 
 *      back-pointer to some important data for fast referencing. For
 *      SILC server this is a pointer to the ID list and for SILC client
 *      to object holding active connections (windows).
 *
 *    SilcProtocol protocol
 *
 *      Protocol object for the socket. Currently only one protocol can be
 *      executing at a time for a particular socket.
 *
 *    uint32 flags
 *
 *      Socket flags that indicate the status of the socket. This can
 *      indicate several different status that can affect the use of the
 *      socket object.
 *
 *    int users
 *
 *      Reference counter. When allocated it is set to one (1) and it won't
 *      be freed until it hits zero (0).
 *
 *    char *hostname
 *    char *ip
 *    uint16 port
 *
 *      Resolved hostname, IP address and port of the connection who owns
 *      this object.
 *
 *    SilcBuffer inbuf
 *    SilcBuffer outbuf
 *
 *      Incoming and outgoing buffers for the particular socket connection.
 *      Incoming data from the socket is put after decryption in to the
 *      inbuf buffer and outgoing data after encryption is put to the outbuf
 *      buffer.
 *
 *    SilcSocketConnectionHB hb
 *
 *      The heartbeat context.  If NULL, heartbeat is not performed.
 *
 ***/
struct SilcSocketConnectionStruct {
  int sock;
  SilcSocketType type;
  void *user_data;
  SilcProtocol protocol;
  uint32 flags;
  int users;

  char *hostname;
  char *ip;
  uint16 port;

  SilcBuffer inbuf;
  SilcBuffer outbuf;

  SilcSocketConnectionHB hb;
};

/* Macros */

/* Amount of bytes to be read from the socket connection at once. */
#define SILC_SOCKET_READ_SIZE 16384

/* Default socket buffer size. */
#define SILC_SOCKET_BUF_SIZE 1024

/* Generic manipulation of flags */
#define SF_SET(x, f) (x)->flags |= (1L << (f))
#define SF_UNSET(x, f) (x)->flags &= ~(1L << (f))
#define SF_IS(x, f) ((x)->flags & (1L << (f)))

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

/****f* silcutil/SilcSocketConnectionAPI/silc_socket_alloc
 *
 * SYNOPSIS
 *
 *    void silc_socket_alloc(int sock, SilcSocketType type, void *user_data,
 *                           SilcSocketConnection *new_socket);
 *
 * DESCRIPTION
 *
 *    Allocates a new socket connection object. The allocated object is 
 *    returned to the new_socket argument. The `sock' is the socket
 *    for the connection, the `type' the initial type of the connection and
 *    the `user_data' a application specific pointer.
 *
 ***/
void silc_socket_alloc(int sock, SilcSocketType type, void *user_data,
		       SilcSocketConnection *new_socket);

/****f* silcutil/SilcSocketConnectionAPI/silc_socket_free
 *
 * SYNOPSIS
 *
 *    void silc_socket_free(SilcSocketConnection sock);
 *
 * DESCRIPTION
 *
 *    Frees the socket connection context. This frees it only if the
 *    reference counter of the socket is zero, otherwise it decreases the
 *    reference counter.
 *
 ***/
void silc_socket_free(SilcSocketConnection sock);

/****f* silcutil/SilcSocketConnectionAPI/silc_socket_dup
 *
 * SYNOPSIS
 *
 *    SilcSocketConnection silc_socket_dup(SilcSocketConnection sock);
 *
 * DESCRIPTION
 *
 *    Duplicates the socket context. This actually does not duplicate
 *    any data, instead this increases the reference counter of the
 *    context. The reference counter is decreased by calling the
 *    silc_socket_free function and it frees the data when the counter
 *    hits zero.
 *
 ***/
SilcSocketConnection silc_socket_dup(SilcSocketConnection sock);

/****f* silcutil/SilcSocketConnectionAPI/silc_socket_read
 *
 * SYNOPSIS
 *
 *    int silc_socket_read(SilcSocketConnection sock);
 *
 * DESCRIPTION
 *
 *    Reads data from the socket connection into the incoming data buffer.
 *    It reads as much as possible from the socket connection. This returns
 *    amount of bytes read or -1 on error or -2 on case where all of the
 *    data could not be read at once. Implementation of this function
 *    may be platform specific.
 *
 ***/
int silc_socket_read(SilcSocketConnection sock);

/****f* silcutil/SilcSocketConnectionAPI/silc_socket_write
 *
 * SYNOPSIS
 *
 *    int silc_socket_read(SilcSocketConnection sock);
 *
 * DESCRIPTION
 *
 *    Writes data from the outgoing buffer to the socket connection. If the
 *    data cannot be written at once, it must be written at later time. 
 *    The data is written from the data section of the buffer, not from head
 *    or tail section. This automatically pulls the data section towards end
 *    after writing the data. Implementation of this function may be
 *    platform specific.
 *
 ***/
int silc_socket_write(SilcSocketConnection sock);

/****f* silcutil/SilcSocketConnectionAPI/silc_socket_set_heartbeat
 *
 * SYNOPSIS
 *
 *    void silc_socket_set_heartbeat(SilcSocketConnection sock, 
 *                                   uint32 heartbeat,
 *                                   void *hb_context,
 *                                   SilcSocketConnectionHBCb hb_callback,
 *                                   void *timeout_queue);
 *
 * DESCRIPTION
 *
 *    Sets the heartbeat timeout and prepares the socket for performing
 *    heartbeat in `heartbeat' intervals (seconds). The `hb_context' is
 *    allocated by the application and will be sent as argument to the
 *    `hb_callback' function that is called when the `heartbeat' timeout
 *    expires.  The callback `hb_context' won't be touched by the library
 *    but will be freed automatically when calling silc_socket_free.  The
 *    `timeout_queue' is the application's scheduler timeout queue.
 *
 ***/
void silc_socket_set_heartbeat(SilcSocketConnection sock, 
			       uint32 heartbeat,
			       void *hb_context,
			       SilcSocketConnectionHBCb hb_callback,
			       void *timeout_queue);

#endif
