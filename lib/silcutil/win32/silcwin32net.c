/*

  silcwin32net.c

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

/* XXX IPv6 support missing */

#include "silcincludes.h"
#include "silcnet.h"

/* This function creates server or daemon or listener or what ever. This
   does not fork a new process, it must be done by the caller if caller
   wants to create a child process. This is used by the SILC server. 
   If argument `ip_addr' is NULL `any' address will be used. Returns 
   the created socket or -1 on error. */

int silc_net_create_server(int port, const char *ip_addr)
{
  SOCKET sock;
  int rval;
  struct sockaddr_in server;
  int len = sizeof(server.sin_addr);

  SILC_LOG_DEBUG(("Creating a new server listener"));

  /* Create the socket */
  sock = socket(PF_INET, SOCK_STREAM, 0);
  if (sock == INVALID_SOCKET) {
    SILC_LOG_ERROR(("Cannot create socket"));
    return -1;
  }

  /* Set the socket options */
  rval = silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
  if (rval != 0) {
    SILC_LOG_ERROR(("Cannot set socket options"));
    closesocket(sock);
    return -1;
  }

  /* Set the socket information for bind() */
  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  if (port)
    server.sin_port = htons(port);

  /* Convert IP address to network byte order */
  if (ip_addr)
    silc_net_addr2bin(ip_addr, (unsigned char *)&server.sin_addr.s_addr, len);
  else
    server.sin_addr.s_addr = INADDR_ANY;

  /* Bind the server socket */
  rval = bind(sock, (struct sockaddr *)&server, sizeof(server));
  if (rval != 0) {
    SILC_LOG_ERROR(("Cannot bind socket"));
    closesocket(sock);
    return -1;
  }

  /* Specify that we are listenning */
  rval = listen(sock, 5);
  if (rval != 0) {
    SILC_LOG_ERROR(("Cannot set socket listenning"));
    closesocket(sock);
    return -1;
  }

  SILC_LOG_DEBUG(("Server listener created, fd=%d", sock));

  return sock;
}

/* Closes the server by closing the socket connection. */

void silc_net_close_server(int sock)
{
  shutdown(sock, 2);
  closesocket(sock);

  SILC_LOG_DEBUG(("Server socket closed"));
}

/* Creates a connection (TCP/IP) to a remote host. Returns the connection
   socket or -1 on error. This blocks the process while trying to create
   the connection. */

int silc_net_create_connection(const char *local_ip, int port, 
			       const char *host)
{
  SOCKET sock;
  int rval, err;
  struct hostent *dest;
  struct sockaddr_in desthost;

  SILC_LOG_DEBUG(("Creating connection to host %s port %d", host, port));

  /* Do host lookup */
  dest = gethostbyname(host);
  if (!dest) {
    SILC_LOG_ERROR(("Network (%s) unreachable: could not resolve the "
		    "IP address", host));
    return -1;
  }

  /* Set socket information */
  memset(&desthost, 0, sizeof(desthost));
  desthost.sin_port = htons(port);
  desthost.sin_family = AF_INET;
  memcpy(&desthost.sin_addr, dest->h_addr_list[0], sizeof(desthost.sin_addr));

  /* Create the connection socket */
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == INVALID_SOCKET) {
    SILC_LOG_ERROR(("Cannot create socket"));
    return -1;
  }

  /* Connect to the host */
  rval = connect(sock, (struct sockaddr *)&desthost, sizeof(desthost));
  err = WSAGetLastError();
  if (rval == SOCKET_ERROR && err != WSAEWOULDBLOCK) {
    SILC_LOG_ERROR(("Cannot connect to remote host"));
    shutdown(sock, 2);
    closesocket(sock);
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
  SOCKET sock;
  int rval, err;
  struct hostent *dest;
  struct sockaddr_in desthost;

  SILC_LOG_DEBUG(("Creating connection (async) to host %s port %d", 
		  host, port));

  /* Do host lookup */
  dest = gethostbyname(host);
  if (!dest) {
    SILC_LOG_ERROR(("Network (%s) unreachable: could not resolve the "
		    "IP address", host));
    return -1;
  }

  /* Set socket information */
  memset(&desthost, 0, sizeof(desthost));
  desthost.sin_port = htons(port);
  desthost.sin_family = AF_INET;
  memcpy(&desthost.sin_addr, dest->h_addr_list[0], sizeof(desthost.sin_addr));

  /* Create the connection socket */
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == INVALID_SOCKET) {
    SILC_LOG_ERROR(("Cannot create socket"));
    return -1;
  }

  /* Connect to the host */
  rval = connect(sock, (struct sockaddr *)&desthost, sizeof(desthost));
  err = WSAGetLastError();
  if (rval == SOCKET_ERROR && err != WSAEWOULDBLOCK) {
    SILC_LOG_ERROR(("Cannot connect to remote host"));
    shutdown(sock, 2);
    closesocket(sock);
    return -1;
  }

  /* Set socket to nonblocking mode */
  silc_net_set_socket_nonblock(sock);

  /* Set appropriate options */
#if defined(TCP_NODELAY)
  silc_net_set_socket_opt(sock, IPPROTO_TCP, TCP_NODELAY, 1);
#endif
  silc_net_set_socket_opt(sock, SOL_SOCKET, SO_KEEPALIVE, 1);

  SILC_LOG_DEBUG(("Connection created"));

  return sock;
}

/* Closes the connection by closing the socket connection. */

void silc_net_close_connection(int sock)
{
  closesocket(sock);
}

/* Converts the IP number string from numbers-and-dots notation to
   binary form. */

bool silc_net_addr2bin(const char *addr, void *bin, SilcUInt32 bin_len)
{
  unsigned long ret;

  ret = inet_addr(addr);

  if (bin_len < 4)
    return FALSE;

  memcpy(bin, (unsigned char *)&ret, 4);
  return ret != INADDR_NONE;
}

/* Set socket to non-blocking mode. */

int silc_net_set_socket_nonblock(int sock)
{
  unsigned long on = 1;
  return ioctlsocket(sock, FIONBIO, &on);
}

/* Init Winsock2. */

bool silc_net_win32_init(void)
{
  int ret, sopt = SO_SYNCHRONOUS_NONALERT;
  WSADATA wdata;
  WORD ver = MAKEWORD(1, 1);

  ret = WSAStartup(ver, &wdata);
  if (ret)
    return FALSE;

  /* Allow using the SOCKET's as file descriptors so that we can poll
     them with SILC Scheduler. */
  ret = setsockopt(INVALID_SOCKET, SOL_SOCKET, SO_OPENTYPE, (char *)&sopt,
		   sizeof(sopt));
  if (ret)
    return FALSE;

  return TRUE;
}

/* Uninit Winsock2 */

void silc_net_win32_uninit(void)
{
  WSACleanup();
}
