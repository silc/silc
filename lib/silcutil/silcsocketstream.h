/*

  silcsocketstream.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Socket Stream Interface
 *
 * DESCRIPTION
 *
 * Implementation of SILC Socket Stream.  SILC Socket Stream can be used
 * read data from and write data to a socket connection.  The SILC Socket
 * Stream provides also Quality of Service (QoS) support that can be used
 * to control the throughput of the stream.  It also supports both TCP and
 * UDP, and IPv4 and IPv6.
 *
 * SILC Socket Stream is not thread-safe.  If the same socket stream must be
 * used in multithreaded environment concurrency control must be employed.
 *
 ***/

#ifndef SILCSOCKETSTREAM_H
#define SILCSOCKETSTREAM_H

/****d* silcutil/SilcSocketStreamAPI/SilcSocketStreamStatus
 *
 * NAME
 *
 *    typedef enum { ... } SilcStreamStatus;
 *
 * DESCRIPTION
 *
 *    Socket Stream status.  This status is returned into the
 *    SilcSocketStreamCallback function after the socket stream is
 *    created.
 *
 * SOURCE
 */
typedef enum {
  SILC_SOCKET_OK,		/* Normal status */
  SILC_SOCKET_UNKNOWN_IP,	/* Remote does not have IP address */
  SILC_SOCKET_UNKNOWN_HOST,	/* Remote does not have host name */
  SILC_SOCKET_NO_MEMORY,	/* System out of memory */
  SILC_SOCKET_ERROR,		/* Unknown error */
} SilcSocketStreamStatus;
/***/

/****f* silcutil/SilcSocketStreamAPI/SilcSocketStreamCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcSocketStreamCallback)(SilcSocketStreamStatus status,
 *                                             SilcStream stream,
 *                                             void *context);
 *
 * DESCRIPTION
 *
 *    Callback function of this type is called after the socket stream
 *    creation is completed.  If the `stream' is NULL the socket stream could
 *    not be created or the socket connection is not otherwise allowed.  The
 *    `status' will indicate the error status.  The `stream' is socket stream
 *    representing the socket connection and silc_socket_stream_* functions
 *    can be used to access the stream.  All other silc_stream_* functions
 *    can also be used to read data, send data, and otherwise handle the
 *    stream.
 *
 ***/
typedef void (*SilcSocketStreamCallback)(SilcSocketStreamStatus status,
					 SilcStream stream, void *context);

/****f* silcutil/SilcSocketStreamAPI/silc_socket_tcp_stream_create
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation
 *    silc_socket_tcp_stream_create(int sock, SilcBool lookup,
 *                                  SilcBool require_fqdn,
 *                                  SilcSchedule schedule,
 *                                  SilcSocketStreamCallback callback,
 *                                  void *context);
 *
 * DESCRIPTION
 *
 *    Creates TCP socket stream of the TCP connection indicated by `sock'.
 *    The stream can be destroyed by calling the silc_stream_destroy.  Data
 *    can be sent and received from the stream by calling silc_stream_write
 *    and silc_stream_read.  The creation process is asynchronous since
 *    socket connection information, such as hostname and IP address are
 *    resolved, so SilcAsyncOperation is returned which can be used to cancel
 *    the creation process.  The `callback' will be called to return the
 *    created socket stream.  To destroy the stream call silc_stream_destroy.
 *
 *    If the `lookup' is TRUE then this will perform IP and hostname lookup
 *    for the socket.  If the `require_fqdn' is TRUE then the socket must
 *    have valid hostname and IP address, otherwise the stream creation will
 *    fail.  If it is FALSE then only valid IP address is required.  Note that,
 *    if the `lookup' is FALSE then the hostname, IP and port information
 *    will not be available from the socket stream.  In that case this will
 *    also return NULL as the `callback' is called immediately.
 *
 ***/
SilcAsyncOperation
silc_socket_tcp_stream_create(int sock, SilcBool lookup,
			      SilcBool require_fqdn,
			      SilcSchedule schedule,
			      SilcSocketStreamCallback callback,
			      void *context);

/****f* silcutil/SilcSocketStreamAPI/silc_socket_udp_stream_create
 *
 * SYNOPSIS
 *
 *    SilcStream silc_socket_udp_stream_create(int sock, SilcBool ipv6,
 *                                             SilcSchedule schedule);
 *
 * DESCRIPTION
 *
 *    Creates UDP socket stream of the UDP connection indicated by `sock'.
 *    The stream can be destroyed by calling the silc_stream_destroy.
 *
 *    Note that, UDP packets may be read only through the notifier
 *    callback (see silc_stream_set_notifier), when SILC_STREAM_CAN_READ
 *    is returned to the callback.  Because of this the notifier callback
 *    must be set.
 *
 *    Note that, UDP packet sending using silc_stream_write and receiving
 *    with silc_stream_read works only if the `sock' is a UDP socket in a
 *    connected state.  If it is not the silc_net_udp_send function and
 *    silc_net_udp_receive functions must be used.  The SILC_STREAM_CAN_WRITE
 *    is never returned to the notifier callback.
 *
 *    This function returns the created SilcStream or NULL on error.
 *
 ***/
SilcStream silc_socket_udp_stream_create(int sock, SilcBool ipv6,
					 SilcSchedule schedule);

/****f* silcutil/SilcSocketStreamAPI/silc_socket_stream_get_info
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_socket_stream_get_info(SilcStream stream,
 *                                int *sock, const char **hostname,
 *                                const char **ip, SilcUInt16 *port);
 *
 * DESCRIPTION
 *
 *    Returns socket stream information such as the socket number, hostname,
 *    IP address and the port of the remote socket connection.  Return FALSE
 *    if these informations are not available.
 *
 ***/
SilcBool silc_socket_stream_get_info(SilcStream stream,
				     int *sock, const char **hostname,
				     const char **ip, SilcUInt16 *port);

/****f* silcutil/SilcSocketStreamAPI/silc_socket_stream_set_info
 *
 * SYNOPSIS
 *
 *    SilcBool
 *    silc_socket_stream_set_info(SilcStream stream,
 *                                const char *hostname,
 *                                const char *ip, SilcUInt16 port);
 *
 * DESCRIPTION
 *
 *    Use this function to set the hostname, IP address and remote port
 *    information to the socket stream indicated by `stream' if you did not
 *    perform lookup in the silc_socket_tcp_stream_create.  This is not
 *    mandatory but if you would like to associate the information with the
 *    stream use this function.  If the lookup was performed when creating
 *    the stream then calling this function is not necessary.  Use the
 *    function silc_socket_stream_get_info to get the information from the
 *    stream.
 *
 ***/
SilcBool silc_socket_stream_set_info(SilcStream stream,
				     const char *hostname,
				     const char *ip, SilcUInt16 port);

/****f* silcutil/SilcSocketStreamAPI/silc_socket_stream_get_error
 *
 * SYNOPSIS
 *
 *    int silc_socket_stream_get_error(SilcStream stream);
 *
 * DESCRIPTION
 *
 *    If error occurred during socket stream operations, this function
 *    can be used to retrieve the error number that occurred.
 *
 ***/
int silc_socket_stream_get_error(SilcStream stream);

/****f* silcutil/SilcSocketStreamAPI/silc_socket_stream_set_qos
 *
 * SYNOPSIS
 *
 *    SilcBool silc_socket_stream_set_qos(SilcStream stream,
 *                                        SilcUInt32 read_rate,
 *                                        SilcUInt32 read_limit_bytes,
 *                                        SilcUInt32 limit_sec,
 *                                        SilcUInt32 limit_usec)
 *
 * DESCRIPTION
 *
 *    Sets a "Quality of Service" settings for socket stream `stream'.
 *    The `read_rate' specifies the maximum read operations per second.
 *    If more read operations are executed the limit will be applied for
 *    the reading.  The `read_limit_bytes' specifies the maximum data
 *    that is read.  It is guaranteed that silc_stream_read  never returns
 *    more than `read_limit_bytes' of data.  The `limit_sec' and `limit_usec'
 *    specifies the time limit that is applied if `read_rate' and/or
 *    `read_limit_bytes' is reached.  If all arguments except `stream'
 *    are zero this resets the QoS from the socket stream, all QoS for
 *    this socket stream that may be pending will be cancelled.
 *
 ***/
SilcBool silc_socket_stream_set_qos(SilcStream stream,
				    SilcUInt32 read_rate,
				    SilcUInt32 read_limit_bytes,
				    SilcUInt32 limit_sec,
				    SilcUInt32 limit_usec);

#include "silcsocketstream_i.h"

#endif /* SILCSOCKETSTREAM_H */
