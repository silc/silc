/*

  silcnet.h
 
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

/****h* silcutil/SILC Net Interface
 *
 * DESCRIPTION
 *
 * SILC Net API provides various network routines for applications. It
 * can be used to create TCP/IP connections and servers. Various utility
 * functions for resolving various information is also provided.
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

/****f* silcutil/SilcNetAPI/silc_net_create_server
 *
 * SYNOPSIS
 *
 *    int silc_net_create_server(int port, char *ip_addr);
 *
 * DESCRIPTION
 *
 *    This function creates server or daemon or listener or what ever. This
 *    does not fork a new process, it must be done by the caller if caller
 *    wants to create a child process. This is used by the SILC server. 
 *    If argument `ip_addr' is NULL `any' address will be used. Returns 
 *    the created socket or -1 on error.
 *
 ***/
int silc_net_create_server(int port, const char *ip_addr);

/****f* silcutil/SilcNetAPI/silc_net_close_server
 *
 * SYNOPSIS
 *
 *    void silc_net_close_server(int sock);
 *
 * DESCRIPTION
 *
 *    Closes the server by closing the socket connection.
 *
 ***/
void silc_net_close_server(int sock);

/****f* silcutil/SilcNetAPI/silc_net_create_connection
 *
 * SYNOPSIS
 *
 *    int silc_net_create_connection(const char *local_ip, int port, 
 *                                   const char *host);
 *
 * DESCRIPTION
 *
 *    Creates a connection (TCP/IP) to a remote host. Returns the connection
 *    socket or -1 on error. This blocks the process while trying to create
 *    the connection. If the `local_ip' is not NULL then this will bind
 *    the `local_ip' address to a port before creating the connection.  If
 *    it is NULL then this will directly create the connection.
 *
 ***/
int silc_net_create_connection(const char *localhost, int port, 
			       const char *host);

/****f* silcutil/SilcNetAPI/silc_net_create_connection_async
 *
 * SYNOPSIS
 *
 *    int silc_net_create_connection_async(const char *local_ip, int port, 
 *                                         const char *host);
 *
 * DESCRIPTION
 *
 *    Creates a connection (TCP/IP) to a remote host. Returns the connection
 *    socket or -1 on error. This creates non-blocking socket hence the
 *    connection returns directly. To get the result of the connect() one
 *    must select() the socket and read the result after it's ready. If the
 *    `local_ip' is not NULL then this will bind the `local_ip' address to
 *    a port before creating the connection.  If it is NULL then this will
 *    directly create the connection.
 *
 ***/
int silc_net_create_connection_async(const char *local_ip, int port, 
				     const char *host);

/****f* silcutil/SilcNetAPI/silc_net_close_connection
 *
 * SYNOPSIS
 *
 *    void silc_net_close_connection(int sock);
 *
 * DESCRIPTION
 *
 *    Closes the connection by closing the socket connection.
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
 *    Accepts a connection from a particular socket.
 *
 ***/
int silc_net_accept_connection(int sock);

/****f* silcutil/SilcNetAPI/silc_net_set_socket_nonblock
 *
 * SYNOPSIS
 *
 *    int silc_net_set_socket_nonblock(int sock);
 *
 * DESCRIPTION
 *
 *    Sets the socket to non-blocking mode.
 *
 ***/
int silc_net_set_socket_nonblock(int sock);

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
 *    system specific.
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
 *    Return socket options to the `optval' and `opt_len'.
 *
 ***/
int silc_net_get_socket_opt(int sock, int level, int option, 
			    void *optval, int *opt_len);

/****f* silcutil/SilcNetAPI/silc_net_is_ip4
 *
 * SYNOPSIS
 *
 *    bool silc_net_is_ip4(const char *addr);
 *
 * DESCRIPTION
 *
 *    Checks whether IP address sent as argument is valid IPv4 address.
 *
 ***/
bool silc_net_is_ip4(const char *addr);

/****f* silcutil/SilcNetAPI/silc_net_is_ip6
 *
 * SYNOPSIS
 *
 *    bool silc_net_is_ip6(const char *addr);
 *
 * DESCRIPTION
 *
 *    Checks whether IP address sent as argument is valid IPv6 address.
 *
 ***/
bool silc_net_is_ip6(const char *addr);

/****f* silcutil/SilcNetAPI/silc_net_is_ip
 *
 * SYNOPSIS
 *
 *    bool silc_net_is_ip(const char *addr);
 *
 * DESCRIPTION
 *
 *    Checks whether IP address sent as argument is valid IP address.
 *    This supports both IPv4 and IPv6 addresses.
 *
 ***/
bool silc_net_is_ip(const char *addr);

/****f* silcutil/SilcNetAPI/silc_net_addr2bin
 *
 * SYNOPSIS
 *
 *    bool silc_net_addr2bin(const char *addr, void *bin, SilcUInt32 bin_len);
 *
 * DESCRIPTION
 *
 *    Converts the IP number string from numbers-and-dots notation to
 *    binary form in network byte order.  The address can be either
 *    IPv4 or IPv6 address.
 *
 ***/
bool silc_net_addr2bin(const char *addr, void *bin, SilcUInt32 bin_len);

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
 *    bool silc_net_gethostbyname(const char *name, bool prefer_ipv6, 
 *                                char *address, SilcUInt32 address_len);
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
bool silc_net_gethostbyname(const char *name, bool prefer_ipv6, char *address, 
			    SilcUInt32 address_len);

/****f* silcutil/SilcNetAPI/silc_net_gethostbyname_async
 *
 * SYNOPSIS
 *
 *    void silc_net_gethostbyname_async(const char *name, 
 *                                      bool prefer_ipv6,
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
				  bool prefer_ipv6,
				  SilcSchedule schedule,
				  SilcNetResolveCallback completion,
				  void *context);

/****f* silcutil/SilcNetAPI/silc_net_gethostbyaddr
 *
 * SYNOPSIS
 *
 *   bool silc_net_gethostbyaddr(const char *addr, char *name, 
 *                               SilcUInt32 name_len);
 *
 * DESCRIPTION
 *
 *    Resolves the hostname for the IP address indicated by the `addr'
 *    This returns TRUE and the resolved hostname to the `name' buffer, 
 *    or FALSE on error. The `addr' may be either IPv4 or IPv6 address.
 *    This is synchronous function and will block the calling process.
 *
 ***/
bool silc_net_gethostbyaddr(const char *addr, char *name, SilcUInt32 name_len);

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
 *    bool silc_net_check_host_by_sock(int sock, char **hostname, char **ip);
 *
 * DESCRIPTION
 *
 *    Performs lookups for remote name and IP address. This peforms reverse
 *    lookup as well to verify that the IP has FQDN.
 *
 ***/
bool silc_net_check_host_by_sock(int sock, char **hostname, char **ip);

/****f* silcutil/SilcNetAPI/silc_net_check_local_by_sock
 *
 * SYNOPSIS
 *
 *    bool silc_net_check_local_by_sock(int sock, char **hostname, char **ip);
 *
 * DESCRIPTION
 *
 *    Performs lookups for local name and IP address. This peforms reverse
 *    lookup as well to verify that the IP has FQDN.
 *
 ***/
bool silc_net_check_local_by_sock(int sock, char **hostname, char **ip);

/****f* silcutil/SilcNetAPI/silc_net_get_remote_port
 *
 * SYNOPSIS
 *
 *    SilcUInt16 silc_net_get_remote_port(int sock);
 *
 * DESCRIPTION
 *
 *    Return remote port by socket.
 *
 ***/
SilcUInt16 silc_net_get_remote_port(int sock);

/****f* silcutil/SilcNetAPI/silc_net_get_local_port
 *
 * SYNOPSIS
 *
 *    SilcUInt16 silc_net_get_local_port(int sock);
 *
 * DESCRIPTION
 *
 *    Return local port by socket.
 *
 ***/
SilcUInt16 silc_net_get_local_port(int sock);

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

/****f* silcutil/SilcNetAPI/silc_net_win32_init
 *
 * SYNOPSIS
 *
 *    bool silc_net_win32_init(void);
 *
 * DESCRIPTION
 *
 *    This is WIN32 system specific function and is used to initialize
 *    the network.  This must be called by all WIN32 applications.  It
 *    is usually called at the application's main() or WinMain() before
 *    calling any other SILC routine.  The application must also call
 *    the silc_net_win32_uninit when exiting the application.  Returns
 *    FALSE on error.  The network will not work if this function returns
 *    FALSE.
 *
 * NOTES
 *
 *    This routines is available only on Win32 platform.
 *
 ***/
bool silc_net_win32_init(void);

/****f* silcutil/SilcNetAPI/silc_net_win32_uninit
 *
 * SYNOPSIS
 *
 *    void silc_net_win32_init(void);
 *
 * DESCRIPTION
 *
 *    This is WIN32 system specific function and is used to uninitialize
 *    the network.  This must be called by all WIN32 applications.  It
 *    is usually called when the application is exiting.  After calling
 *    this function the SILC Net API routines will not work anymore.
 *
 * NOTES
 *
 *    This routines is available only on Win32 platform.
 *
 ***/
void silc_net_win32_uninit(void);

#endif
