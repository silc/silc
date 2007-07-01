/*

  silcnet.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Net Interface
 *
 * DESCRIPTION
 *
 * SILC Net API provides various network routines for applications. It
 * can be used to create TCP/IP and UDP/IP connections and listeners.
 * Various utility functions for resolving various information is also
 * provided.
 *
 * On WIN32 systems the SILC Net API must initialized by calling the
 * silc_net_win32_init and uninitialized when the application ends by
 * calling the silc_net_win32_uninit function. The initializing must be
 * done in order to assure that the SILC Net API works correctly.
 *
 ***/

#ifndef SILCNET_H
#define SILCNET_H

/* Prototypes */

/****s* silcutil/SilcNetAPI/SilcNetListener
 *
 * NAME
 *
 *    typedef struct SilcNetListenerStruct *SilcNetListener;
 *
 * DESCRIPTION
 *
 *    The network listenr context.  This context is created with the
 *    silc_net_create_listener function and destroyed with
 *    silc_net_close_listener function.
 *
 ***/
typedef struct SilcNetListenerStruct *SilcNetListener;

/****d* silcutil/SilcNetAPI/SilcNetStatus
 *
 * NAME
 *
 *    typedef enum { ... } SilcNetStatus;
 *
 * DESCRIPTION
 *
 *    Status to indicate the result of the network operation creation.  This
 *    type is returned in the SilcNetCallback callback function.
 *
 * SOURCE
 */
typedef enum {
  SILC_NET_OK,			       /* Everything Ok */
  SILC_NET_UNKNOWN_IP,		       /* Unknown IP address */
  SILC_NET_UNKNOWN_HOST,	       /* Unknown hostname */
  SILC_NET_HOST_UNREACHABLE,	       /* Destination unreachable */
  SILC_NET_CONNECTION_REFUSED,	       /* Connection refused */
  SILC_NET_CONNECTION_TIMEOUT,	       /* Connection timedout */
  SILC_NET_NO_MEMORY,		       /* System out of memory */
  SILC_NET_ERROR,		       /* Unknown error */
} SilcNetStatus;
/***/

/****f* silcutil/SilcNetAPI/SilcNetCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcNetCallback)(SilcNetStatus status,
 *                                    SilcStream stream, void *context);
 *
 * DESCRIPTION
 *
 *    A callback of this type is returned by silc_net_tcp_create_listener
 *    and silc_net_tcp_connect functions.  For silc_net_tcp_create_listener
 *    this callback means that new incoming connection was accepted, and the
 *    `stream' is the socket stream representing the socket connection.
 *
 *    For silc_net_tcp_connect this means that we have connected to the
 *    remote host and the `stream' is the socket stream for the socket
 *    connection.  The SILC Stream API (such as silc_stream_read, etc.) can
 *    be used to read and write to the stream.  The created stream is socket
 *    stream so various SilcSocketStream API functions can be used with
 *    the `stream'.
 *
 ***/
typedef void (*SilcNetCallback)(SilcNetStatus status,
				SilcStream stream, void *context);

/****f* silcutil/SilcNetAPI/silc_net_tcp_create_listener
 *
 * SYNOPSIS
 *
 *    SilcNetListener
 *    silc_net_tcp_create_listener(const char **local_ip_addr,
 *                                 SilcUInt32 local_ip_count, int port,
 *                                 SilcBool lookup, SilcBool require_fqdn,
 *                                 SilcSchedule schedule,
 *                                 SilcNetCallback callback, void *context);
 *
 * DESCRIPTION
 *
 *    This function creates TCP listener.  This is used to create network
 *    listener for incoming connections, and `callback' will be called
 *    everytime new connection is received.  If `local_ip_addr' is NULL 'any'
 *    address is used.  If provided it can be used bind the listener to
 *    `local_ip_count' many IP addresses provided in `local_ip_addr' table.
 *    On success returns the SilcNetListener context, or NULL on error.
 *    If `require_fqdn' is TRUE the listener will require that the incoming
 *    connection has FQDN to be able to connect.  If the `lookup' is TRUE
 *    then the incoming connection hostname will be resolved.  If the `port'
 *    is zero (0), operating system will define it automatically.
 *
 *    The `callback' always delivers valid new stream.  It is not called
 *    with an error status.
 *
 ***/
SilcNetListener
silc_net_tcp_create_listener(const char **local_ip_addr,
			     SilcUInt32 local_ip_count, int port,
			     SilcBool lookup, SilcBool require_fqdn,
			     SilcSchedule schedule,
			     SilcNetCallback callback, void *context);

/****f* silcutil/SilcNetAPI/silc_net_listener_get_port
 *
 * SYNOPSIS
 *
 *    SilcUInt16 silc_net_listener_get_port(SilcNetListener listener);
 *
 * DESCRIPTION
 *
 *    Returns the ports to where the `listener' is bound.  This can be used
 *    to get the port if none was specified in silc_net_tcp_create_listener.
 *    Returns an array of ports of size of `port_count'.  The caller must
 *    free the array with silc_free.  There are as many ports in the array
 *    as there were IP addresses provided in silc_net_tcp_create_listener.
 *
 ***/
SilcUInt16 *silc_net_listener_get_port(SilcNetListener listener,
				       SilcUInt32 *port_count);

/****f* silcutil/SilcNetAPI/silc_net_listener_get_ip
 *
 * SYNOPSIS
 *
 *    char **silc_net_listener_get_ip(SilcNetListener listener,
 *                                    SilcUInt32 *ip_count);
 *
 * DESCRIPTION
 *
 *    Returns the IP's to where the `listener' is bound.  Returns an array
 *    of IP addresses of size of `port_count'.  The caller must free the
 *    array and its strings with silc_free.
 *
 ***/
char **silc_net_listener_get_ip(SilcNetListener listener,
				SilcUInt32 *ip_count);

/****f* silcutil/SilcNetAPI/silc_net_listener_get_hostname
 *
 * SYNOPSIS
 *
 *    char **silc_net_listener_get_hostname(SilcNetListener listener,
 *                                          SilcUInt32 *hostname_count);
 *
 * DESCRIPTION
 *
 *    Returns the hostnames to where the `listener' is bound.  Returns an
 *    array of hostnames of size of `port_count'.  The caller must free the
 *    array and its strings with silc_free.
 *
 ***/
char **silc_net_listener_get_hostname(SilcNetListener listener,
				      SilcUInt32 *hostname_count);

/****f* silcutil/SilcNetAPI/silc_net_close_listener
 *
 * SYNOPSIS
 *
 *    void silc_net_close_listener(SilcNetListener listener);
 *
 * DESCRIPTION
 *
 *    Closes the network listener indicated by `listener'.
 *
 ***/
void silc_net_close_listener(SilcNetListener listener);

/****f* silcutil/SilcNetAPI/silc_net_tcp_connect
 *
 * SYNOPSIS
 *
 *    SilcAsyncOperation silc_net_tcp_connect(const char *local_ip_addr,
 *                                            const char *remote_ip_addr,
 *                                            int remote_port,
 *                                            SilcSchedule schedule,
 *                                            SilcNetCallback callback,
 *                                            void *context);
 *
 * DESCRIPTION
 *
 *    Creates TCP/IP connection to the remote host indicated by `remote_host'
 *    which may be hostname or IP address, on the port indicated by
 *    `remote_port'.  If the `local_ip_addr' is provided the local host is
 *    bound to that address before creating the connection.  This is
 *    asynchronous call, and this function returns before the connection is
 *    actually established.  The `callback' will be called after the
 *    connection is created to deliver the SilcStream for the created
 *    connection.  This function supports IPv6 if the platform supports it.
 *
 *    The returned SilcAsyncOperation context can be used to control the
 *    asynchronous connecting, such as to abort it.  If it is aborted
 *    using silc_async_abort the `callback' will not be called.  If NULL
 *    is returned the operation cannot be aborted.
 *
 ***/
SilcAsyncOperation silc_net_tcp_connect(const char *local_ip_addr,
					const char *remote_ip_addr,
					int remote_port,
					SilcSchedule schedule,
					SilcNetCallback callback,
					void *context);

/****f* silcutil/SilcNetAPI/silc_net_udp_connect
 *
 * SYNOPSIS
 *
 *    SilcStream
 *    silc_net_udp_connect(const char *local_ip_addr, int local_port,
 *                         const char *remote_ip_addr, int remote_port,
 *                         SilcSchedule schedule);
 *
 * DESCRIPTION
 *
 *    This function creates UDP stream.  The UDP stream is bound to the
 *    `local_ip_addr' if it is specified.  If `local_port' is non-zero the
 *    stream is bound to that port.  If the `remote_ip_addr' and `remote_port'
 *    is also provided, packets may be sent to that address using
 *    silc_stream_write function and packets may be received using
 *    silc_stream_read function.
 *
 *    If the remote address is not provided the stream is in connectionless
 *    state.  This means that packets can be received only by using
 *    silc_net_udp_receive and sent only by using the function
 *    silc_net_udp_send.
 *
 *    To receive packets the silc_stream_set_notifier must be called for the
 *    returned SilcStream.  The packets are always received in the notifier
 *    callback when the SILC_STREAM_CAN_READ is returned to the callback
 *    To read the packet use silc_stream_read if the remote address was
 *    provided, and silc_net_udp_receive if it was not.
 *
 *    Supports IPv6 if the platform supports it.
 *
 * EXAMPLE
 *
 *    SilcStream udpstream;
 *
 *    // Create UDP stream and prepare to receive packets
 *    udpstream = silc_net_udp_connect("10.2.1.7", 5000,
 *                                     "10.2.1.100, 5000, schedule);
 *    silc_stream_set_notifier(udpstream, schedule, receive_callback, context);
 *
 *    // Send packet to remote host
 *    silc_stream_write(udpstream, data, data_len);
 *
 *    Create UDP listener:
 *
 *    udpstream = silc_net_udp_connect("0.0.0.0", 500, NULL, 0, schedule);
 *    silc_stream_set_notifier(udpstream, schedule, receive_callback, context);
 *
 ***/
SilcStream silc_net_udp_connect(const char *local_ip_addr, int local_port,
				const char *remote_ip_addr, int remote_port,
				SilcSchedule schedule);

/****f* silcutil/SilcNetAPI/silc_net_udp_receive
 *
 * SYNOPSIS
 *
 *    int
 *    silc_net_udp_receive(SilcStream stream, char *remote_ip_addr,
 *                         SilcUInt32 remote_ip_addr_size, int *remote_port,
 *                         unsigned char *ret_data, SilcUInt32 data_size)
 *
 * DESCRIPTION
 *
 *    Receive a UDP packet from the `stream'.  The IP address and port of
 *    the sender is returned into `remote_ip_addr' buffer and `remote_port'
 *    pointer.  The packet data is returned into the `ret_data' buffer.
 *
 *    Returns the length of the packet, or -1 on error or 0 in case of EOF.
 *
 ***/
int silc_net_udp_receive(SilcStream stream, char *remote_ip_addr,
			 SilcUInt32 remote_ip_addr_size, int *remote_port,
			 unsigned char *ret_data, SilcUInt32 data_size);

/****f* silcutil/SilcNetAPI/silc_net_udp_send
 *
 * SYNOPSIS
 *
 *    int silc_net_udp_send(SilcStream stream,
 *                          const char *remote_ip_addr, int remote_port,
 *                          const unsigned char *data, SilcUInt32 data_len);
 *
 * DESCRIPTION
 *
 *    Sends an UDP packet to remote host `remote_ip_addr' on `remote_port'.
 *    This may be used with UDP streams that are not connected to any
 *    specific remote host.  With those stream silc_stream_write cannot be
 *    used.  In those cases, this function must be used.  This may also be
 *    used even if the stream is connected.
 *
 *    Returns the amount of data written, -1 if data could not be written
 *    at this moment, or -2 if error occurred.  If -1 is returned the
 *    notifier callback will later be called with SILC_STREAM_CAN_WRITE
 *    status when stream is again ready for writing.
 *
 ***/
int silc_net_udp_send(SilcStream stream,
		      const char *remote_ip_addr, int remote_port,
		      const unsigned char *data, SilcUInt32 data_len);

/****f* silcutil/SilcNetAPI/silc_net_get_error_string
 *
 * SYNOPSIS
 *
 *    const char silc_net_get_error_string(SilcNetStatus error);
 *
 * DESCRIPTION
 *
 *    Return `error' as a string.
 *
 ***/
const char *silc_net_get_error_string(SilcNetStatus error);

/****f* silcutil/SilcNetAPI/silc_net_close_connection
 *
 * SYNOPSIS
 *
 *    void silc_net_close_connection(int sock);
 *
 * DESCRIPTION
 *
 *    Closes the connection by closing the socket connection.  This routine
 *    can only be used with POSIX compliant systems.
 *
 ***/
void silc_net_close_connection(int sock);

/****f* silcutil/SilcNetAPI/silc_net_accept_connection
 *
 * SYNOPSIS
 *
 *    int silc_net_accept_connection(int sock);
 *
 * DESCRIPTION
 *
 *    Accepts a connection from a particular socket.  This routine can only
 *    be used with POSIX compliant systems.  This call is equivalent to
 *    accept(2).
 *
 ***/
int silc_net_accept_connection(int sock);

/****f* silcutil/SilcNetAPI/silc_net_set_socket_opt
 *
 * SYNOPSIS
 *
 *    int silc_net_set_socket_opt(int sock, int level, int option, int on);
 *
 * DESCRIPTION
 *
 *    Sets a option for a socket.  This function can be used to set
 *    various options for the socket.  Some of the options might be
 *    system specific.  This routine can only be used with POSIX compliant
 *    systems.  This call is equivalent to setsockopt(2);
 *
 ***/
int silc_net_set_socket_opt(int sock, int level, int option, int on);

/****f* silcutil/SilcNetAPI/silc_net_get_socket_opt
 *
 * SYNOPSIS
 *
 *    int silc_net_get_socket_opt(int sock, int level, int option,
 *                                void *optval, int *opt_len);
 *
 * DESCRIPTION
 *
 *    Return socket options to the `optval' and `opt_len'.  This routine
 *    can only be used with POSIX compliant systems.  This call is
 *    equivalent to getsockopt(2).
 *
 ***/
int silc_net_get_socket_opt(int sock, int level, int option,
			    void *optval, int *opt_len);

/****f* silcutil/SilcNetAPI/silc_net_set_socket_nonblock
 *
 * SYNOPSIS
 *
 *    int silc_net_set_socket_nonblock(SilcSocket sock);
 *
 * DESCRIPTION
 *
 *    Sets the socket `sock' to non-blocking mode.
 *
 ***/
int silc_net_set_socket_nonblock(SilcSocket sock);

/****f* silcutil/SilcNetAPI/silc_net_is_ip4
 *
 * SYNOPSIS
 *
 *    SilcBool silc_net_is_ip4(const char *addr);
 *
 * DESCRIPTION
 *
 *    Checks whether IP address sent as argument is valid IPv4 address.
 *
 ***/
SilcBool silc_net_is_ip4(const char *addr);

/****f* silcutil/SilcNetAPI/silc_net_is_ip6
 *
 * SYNOPSIS
 *
 *    SilcBool silc_net_is_ip6(const char *addr);
 *
 * DESCRIPTION
 *
 *    Checks whether IP address sent as argument is valid IPv6 address.
 *
 ***/
SilcBool silc_net_is_ip6(const char *addr);

/****f* silcutil/SilcNetAPI/silc_net_is_ip
 *
 * SYNOPSIS
 *
 *    SilcBool silc_net_is_ip(const char *addr);
 *
 * DESCRIPTION
 *
 *    Checks whether IP address sent as argument is valid IP address.
 *    This supports both IPv4 and IPv6 addresses.
 *
 ***/
SilcBool silc_net_is_ip(const char *addr);

/****f* silcutil/SilcNetAPI/silc_net_addr2bin
 *
 * SYNOPSIS
 *
 *    SilcBool silc_net_addr2bin(const char *addr, void *bin,
 *                               SilcUInt32 bin_len);
 *
 * DESCRIPTION
 *
 *    Converts the IP number string from numbers-and-dots notation to
 *    binary form in network byte order.  The address can be either
 *    IPv4 or IPv6 address.
 *
 ***/
SilcBool silc_net_addr2bin(const char *addr, void *bin, SilcUInt32 bin_len);

/****f* silcutil/SilcNetAPI/SilcNetResolveCallback
 *
 * SYNOPSIS
 *
 *    typedef void (*SilcNetResolveCallback)(const char *result,
 *                                           void *context);
 *
 * DESCRIPTION
 *
 *    A callback function of this type is called after the asynchronous
 *    resolving operation has been completed.  This callback is used
 *    when asynchronously resolving IP addresses and hostnames.
 *
 ***/
typedef void (*SilcNetResolveCallback)(const char *result, void *context);

/****f* silcutil/SilcNetAPI/silc_net_gethostbyname
 *
 * SYNOPSIS
 *
 *    SilcBool silc_net_gethostbyname(const char *name, SilcBool prefer_ipv6,
 *                                    char *address, SilcUInt32 address_len);
 *
 * DESCRIPTION
 *
 *    Resolves the IP address of the hostname indicated by the `name'.
 *    This returns TRUE and the IP address of the host to the `address'
 *    buffer, or FALSE if the address could not be resolved.  This is
 *    synchronous function and will block the calling process.  If the
 *    `prefer_ipv6' is TRUE then this will return IPv6 address if it
 *    finds.  If FALSE if returns IPv4 address even if it found IPv6
 *    address also.
 *
 ***/
SilcBool silc_net_gethostbyname(const char *name, SilcBool prefer_ipv6,
				char *address, SilcUInt32 address_len);

/****f* silcutil/SilcNetAPI/silc_net_gethostbyname_async
 *
 * SYNOPSIS
 *
 *    void silc_net_gethostbyname_async(const char *name,
 *                                      SilcBool prefer_ipv6,
 *                                      SilcSchedule schedule,
 *                                      SilcNetResolveCallback completion,
 *                                      void *context)
 *
 * DESCRIPTION
 *
 *    Asynchronously resolves the IP address of the hostname indicated
 *    by the `name'.  This function returns immediately, and the
 *    `completion' callback will be called after the resolving is
 *    completed.
 *
 *    If the `prefer_ipv6' is TRUE then this will return IPv6 address if it
 *    finds.  If FALSE if returns IPv4 address even if it found IPv6
 *    address also.
 *
 ***/
void silc_net_gethostbyname_async(const char *name,
				  SilcBool prefer_ipv6,
				  SilcSchedule schedule,
				  SilcNetResolveCallback completion,
				  void *context);

/****f* silcutil/SilcNetAPI/silc_net_gethostbyaddr
 *
 * SYNOPSIS
 *
 *   SilcBool silc_net_gethostbyaddr(const char *addr, char *name,
 *                                   SilcUInt32 name_len);
 *
x * DESCRIPTION
 *
 *    Resolves the hostname for the IP address indicated by the `addr'
 *    This returns TRUE and the resolved hostname to the `name' buffer,
 *    or FALSE on error. The `addr' may be either IPv4 or IPv6 address.
 *    This is synchronous function and will block the calling process.
 *
 ***/
SilcBool silc_net_gethostbyaddr(const char *addr, char *name,
				SilcUInt32 name_len);

/****f* silcutil/SilcNetAPI/silc_net_gethostbyaddr_async
 *
 * SYNOPSIS
 *
 *    void silc_net_gethostbyaddr_async(const char *addr,
 *                                      SilcSchedule schedule,
 *                                      SilcNetResolveCallback completion,
 *                                      void *context)
 *
 * DESCRIPTION
 *
 *    Asynchronously resolves the hostname for the IP address indicated
 *    by the `addr'.  This function returns immediately, and the
 *    `completion' callback will be called after the resolving is
 *    completed.
 *
 ***/
void silc_net_gethostbyaddr_async(const char *addr,
				  SilcSchedule schedule,
				  SilcNetResolveCallback completion,
				  void *context);

/****f* silcutil/SilcNetAPI/silc_net_check_host_by_sock
 *
 * SYNOPSIS
 *
 *    SilcBool silc_net_check_host_by_sock(SilcSocket sock, char **hostname,
 *                                         char **ip);
 *
 * DESCRIPTION
 *
 *    Performs lookups for remote name and IP address. This peforms reverse
 *    lookup as well to verify that the IP has FQDN.
 *
 ***/
SilcBool silc_net_check_host_by_sock(SilcSocket sock, char **hostname,
				     char **ip);

/****f* silcutil/SilcNetAPI/silc_net_check_local_by_sock
 *
 * SYNOPSIS
 *
 *    SilcBool silc_net_check_local_by_sock(SilcSocket sock, char **hostname,
 *                                          char **ip);
 *
 * DESCRIPTION
 *
 *    Performs lookups for local name and IP address. This peforms reverse
 *    lookup as well to verify that the IP has FQDN.
 *
 ***/
SilcBool silc_net_check_local_by_sock(SilcSocket sock, char **hostname,
				      char **ip);

/****f* silcutil/SilcNetAPI/silc_net_get_remote_port
 *
 * SYNOPSIS
 *
 *    SilcUInt16 silc_net_get_remote_port(SilcSocket sock);
 *
 * DESCRIPTION
 *
 *    Return remote port by socket.
 *
 ***/
SilcUInt16 silc_net_get_remote_port(SilcSocket sock);

/****f* silcutil/SilcNetAPI/silc_net_get_local_port
 *
 * SYNOPSIS
 *
 *    SilcUInt16 silc_net_get_local_port(SilcSocket sock);
 *
 * DESCRIPTION
 *
 *    Return local port by socket.
 *
 ***/
SilcUInt16 silc_net_get_local_port(SilcSocket sock);

/****f* silcutil/SilcNetAPI/silc_net_localhost
 *
 * SYNOPSIS
 *
 *    char *silc_net_localhost(void);
 *
 * DESCRIPTION
 *
 *    Return name of localhost.  This will also attempt to resolve
 *    the real hostname by the local host's IP address.  If unsuccessful
 *    the first found hostname is returned.  The caller must free
 *    returned hostname.
 *
 ***/
char *silc_net_localhost(void);

/****f* silcutil/SilcNetAPI/silc_net_localip
 *
 * SYNOPSIS
 *
 *    char *silc_net_localip(void)
 *
 * DESCRIPTION
 *
 *    Return IP of localhost.  The caller must free the returned IP.
 *
 ***/
char *silc_net_localip(void);

#include "silcnet_i.h"

#endif /* SILCNET_H */
