/*

  silcunixnet.c

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
#include "silcnet.h"

#ifdef HAVE_IPV6
#define SIZEOF_SOCKADDR(so) ((so).sa.sa_family == AF_INET6 ?	\
  sizeof(so.sin6) : sizeof(so.sin))
#else
#define SIZEOF_SOCKADDR(so) (sizeof(so.sin))
#endif

typedef union {
  struct sockaddr sa;
  struct sockaddr_in sin;
#ifdef HAVE_IPV6
  struct sockaddr_in6 sin6;
#endif
} SilcSockaddr;

static bool silc_net_set_sockaddr(SilcSockaddr *addr, const char *ip_addr,
				  int port)
{
  int len;

  memset(addr, 0, sizeof(*addr));

  /* Check for IPv4 and IPv6 addresses */
  if (ip_addr) {
    if (!silc_net_is_ip(ip_addr)) {
      SILC_LOG_ERROR(("%s is not IP address", ip_addr));
      return FALSE;
    }

    if (silc_net_is_ip4(ip_addr)) {
      /* IPv4 address */
      len = sizeof(addr->sin.sin_addr);
      silc_net_addr2bin(ip_addr, 
			(unsigned char *)&addr->sin.sin_addr.s_addr, len);
      addr->sin.sin_family = AF_INET;
      addr->sin.sin_port = port ? htons(port) : 0;
    } else {
#ifdef HAVE_IPV6
      /* IPv6 address */
      len = sizeof(addr->sin6.sin6_addr);
      silc_net_addr2bin(ip_addr, 
			(unsigned char *)&addr->sin6.sin6_addr, len);
      addr->sin6.sin6_family = AF_INET6;
      addr->sin6.sin6_port = port ? htons(port) : 0;
#else
      SILC_LOG_ERROR(("IPv6 support is not compiled in"));
      return FALSE;
#endif
    }
  } else {
    /* Any address */
    addr->sin.sin_family = AF_INET;
    addr->sin.sin_addr.s_addr = INADDR_ANY;
    if (port)
      addr->sin.sin_port = htons(port);
  }

  return TRUE;
}

/* This function creates server or daemon or listener or what ever. This
   does not fork a new process, it must be done by the caller if caller
   wants to create a child process. This is used by the SILC server. 
   If argument `ip_addr' is NULL `any' address will be used. Returns 
   the created socket or -1 on error. */

int silc_net_create_server(int port, const char *ip_addr)
{
  int sock, rval;
  SilcSockaddr server;

  SILC_LOG_DEBUG(("Creating a new server listener"));

  /* Set sockaddr for server */
  if (!silc_net_set_sockaddr(&server, ip_addr, port))
    return -1;

  /* Create the socket */
  sock = socket(server.sin.sin_family, SOCK_STREAM, 0);
  if (sock < 0) {
    SILC_LOG_ERROR(("Cannot create socket: %s", strerror(errno)));
    return -1;
  }

  /* Set the socket options */
  rval = silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
  if (rval < 0) {
    SILC_LOG_ERROR(("Cannot set socket options: %s", strerror(errno)));
    return -1;
  }

  /* Bind the server socket */
  rval = bind(sock, &server.sa, SIZEOF_SOCKADDR(server));
  if (rval < 0) {
    SILC_LOG_DEBUG(("Cannot bind socket: %s", strerror(errno)));
    return -1;
  }

  /* Specify that we are listenning */
  rval = listen(sock, 5);
  if (rval < 0) {
    SILC_LOG_ERROR(("Cannot set socket listenning: %s", strerror(errno)));
    return -1;
  }

  /* Set the server socket to non-blocking mode */
  silc_net_set_socket_nonblock(sock);

  SILC_LOG_DEBUG(("Server listener created, fd=%d", sock));

  return sock;
}

/* Closes the server by closing the socket connection. */

void silc_net_close_server(int sock)
{
  shutdown(sock, 2);
  close(sock);

  SILC_LOG_DEBUG(("Server socket closed"));
}

/* Creates a connection (TCP/IP) to a remote host. Returns the connection
   socket or -1 on error. This blocks the process while trying to create
   the connection. */

int silc_net_create_connection(const char *local_ip, int port, 
			       const char *host)
{
  int sock, rval;
  char ip_addr[64];
  SilcSockaddr desthost;
  bool prefer_ipv6 = TRUE;

  SILC_LOG_DEBUG(("Creating connection to host %s port %d", host, port));

  /* Do host lookup */
 retry:
  if (!silc_net_gethostbyname(host, prefer_ipv6, ip_addr, sizeof(ip_addr))) {
    SILC_LOG_ERROR(("Network (%s) unreachable: could not resolve the "
		    "IP address", host));
    return -1;
  }

  /* Set sockaddr for this connection */
  if (!silc_net_set_sockaddr(&desthost, ip_addr, port))
    return -1;

  /* Create the connection socket */
  sock = socket(desthost.sin.sin_family, SOCK_STREAM, 0);
  if (sock < 0) {
    /* If address is IPv6, then fallback to IPv4 and see whether we can do
       better with that on socket creation. */
    if (prefer_ipv6 && silc_net_is_ip6(ip_addr)) {
      prefer_ipv6 = FALSE;
      goto retry;
    }

    SILC_LOG_ERROR(("Cannot create socket: %s", strerror(errno)));
    return -1;
  }

  /* Bind to the local address if provided */
  if (local_ip) {
    SilcSockaddr local;

    /* Set sockaddr for local listener, and try to bind it. */
    if (silc_net_set_sockaddr(&local, local_ip, 0))
      bind(sock, &local.sa, sizeof(local));
  }

  /* Connect to the host */
  rval = connect(sock, &desthost.sa, sizeof(desthost));
  if (rval < 0) {
    SILC_LOG_ERROR(("Cannot connect to remote host: %s", strerror(errno)));
    shutdown(sock, 2);
    close(sock);
    return -1;
  }

  /* Set appropriate options */
#if defined(TCP_NODELAY)
  silc_net_set_socket_opt(sock, IPPROTO_TCP, TCP_NODELAY, 1);
#endif
  silc_net_set_socket_opt(sock, SOL_SOCKET, SO_KEEPALIVE, 1);

  SILC_LOG_DEBUG(("Connection created"));

  return sock;
}

/* Creates a connection (TCP/IP) to a remote host. Returns the connection
   socket or -1 on error. This creates non-blocking socket hence the
   connection returns directly. To get the result of the connect() one
   must select() the socket and read the result after it's ready. */

int silc_net_create_connection_async(const char *local_ip, int port, 
				     const char *host)
{
  int sock, rval;
  char ip_addr[64];
  SilcSockaddr desthost;
  bool prefer_ipv6 = TRUE;

  SILC_LOG_DEBUG(("Creating connection (async) to host %s port %d", 
		  host, port));

  /* Do host lookup */
 retry:
  if (!silc_net_gethostbyname(host, prefer_ipv6, ip_addr, sizeof(ip_addr))) {
    SILC_LOG_ERROR(("Network (%s) unreachable: could not resolve the "
		    "IP address", host));
    return -1;
  }

  /* Set sockaddr for this connection */
  if (!silc_net_set_sockaddr(&desthost, ip_addr, port))
    return -1;

  /* Create the connection socket */
  sock = socket(desthost.sin.sin_family, SOCK_STREAM, 0);
  if (sock < 0) {
    /* If address is IPv6, then fallback to IPv4 and see whether we can do
       better with that on socket creation. */
    if (prefer_ipv6 && silc_net_is_ip6(ip_addr)) {
      prefer_ipv6 = FALSE;
      goto retry;
    }

    SILC_LOG_ERROR(("Cannot create socket: %s", strerror(errno)));
    return -1;
  }

  /* Bind to the local address if provided */
  if (local_ip) {
    SilcSockaddr local;

    /* Set sockaddr for local listener, and try to bind it. */
    if (silc_net_set_sockaddr(&local, local_ip, 0))
      bind(sock, &local.sa, sizeof(local));
  }

  /* Set the socket to non-blocking mode */
  silc_net_set_socket_nonblock(sock);

  /* Connect to the host */
  rval = connect(sock, &desthost.sa, sizeof(desthost));
  if (rval < 0) {
    if (errno !=  EINPROGRESS) {
      SILC_LOG_ERROR(("Cannot connect to remote host: %s", strerror(errno)));
      shutdown(sock, 2);
      close(sock);
      return -1;
    }
  }

  /* Set appropriate options */
#if defined(TCP_NODELAY)
  silc_net_set_socket_opt(sock, IPPROTO_TCP, TCP_NODELAY, 1);
#endif
  silc_net_set_socket_opt(sock, SOL_SOCKET, SO_KEEPALIVE, 1);

  SILC_LOG_DEBUG(("Connection operation in progress"));

  return sock;
}

/* Closes the connection by closing the socket connection. */

void silc_net_close_connection(int sock)
{
  close(sock);
}

/* Set's the socket to non-blocking mode. */

int silc_net_set_socket_nonblock(int sock)
{
  return fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
}

/* Converts the IP number string from numbers-and-dots notation to
   binary form. */

bool silc_net_addr2bin(const char *addr, void *bin, uint32 bin_len)
{
  int ret = 0;

  if (silc_net_is_ip4(addr)) {
    /* IPv4 address */
    struct in_addr tmp;
    ret = inet_aton(addr, &tmp);
    if (bin_len < 4)
      return FALSE;
    
    memcpy(bin, (unsigned char *)&tmp.s_addr, 4);
#ifdef HAVE_IPV6
  } else {
    /* IPv6 address */
    if (bin_len < 16)
      return FALSE;

    ret = inet_pton(AF_INET6, addr, &bin);
#endif /* HAVE_IPV6 */
  }

  return ret != 0;
}
