/*

  silcnet.c

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
 * Revision 1.2  2000/06/30 10:49:48  priikone
 * 	Added SOCKS4 and SOCKS5 support for SILC client.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:55  priikone
 * 	Importet from internal CVS/Added Log headers.
 *
 *
 */

#include "silcincludes.h"
#include "silcnet.h"

/* This function creates server or daemon or listener or what ever. This
   does not fork a new process, it must be done by the caller if caller
   wants to create a child process. This is used by the SILC server. 
   If argument `ip_addr' is NULL `any' address will be used. Returns 
   the created socket or -1 on error. */

int silc_net_create_server(int port, char *ip_addr)
{
  int sock, rval;
  struct sockaddr_in server;

  SILC_LOG_DEBUG(("Creating a new server listener"));

  /* Create the socket */
  sock = socket(PF_INET, SOCK_STREAM, 0);
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

  /* Set the socket information for bind() */
  memset(&server, 0, sizeof(server));
  server.sin_family = PF_INET;
  server.sin_port = htons(port);

  /* Convert IP address to network byte order */
  if (ip_addr)
    inet_aton(ip_addr, &server.sin_addr);
  else
    server.sin_addr.s_addr = INADDR_ANY;

  /* Bind the server socket */
  rval = bind(sock, (struct sockaddr *)&server, sizeof(server));
  if (rval < 0) {
    SILC_LOG_ERROR(("Cannot bind socket: %s", strerror(errno)));
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

void silc_net_close_server(int sock)
{
  shutdown(sock, 2);
  close(sock);

  SILC_LOG_DEBUG(("Server socket closed"));
}

/* Creates a connection (TCP/IP) to a remote host. Returns the connection
   socket or -1 on error. This blocks the process while trying to create
   the connection. */

int silc_net_create_connection(int port, char *host)
{
  int sock, rval;
  struct hostent *dest;
  struct sockaddr_in desthost;

  SILC_LOG_DEBUG(("Creating connection to host %s port %d", host, port));

  /* Do host lookup */
  dest = gethostbyname(host);
  if (!dest) {
    SILC_LOG_ERROR(("Network (%s) unreachable", host));
    return -1;
  }

  /* Set socket information */
  memset(&desthost, 0, sizeof(desthost));
  desthost.sin_port = htons(port);
  desthost.sin_family = PF_INET;
  memcpy(&desthost.sin_addr, dest->h_addr_list[0], sizeof(desthost.sin_addr));

  /* Create the connection socket */
  sock = socket(PF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    SILC_LOG_ERROR(("Cannot create socket: %s", strerror(errno)));
    return -1;
  }

  /* Connect to the host */
  rval = connect(sock, (struct sockaddr *)&desthost, sizeof(desthost));
  if (rval < 0) {
    SILC_LOG_ERROR(("Cannot connect to remote host: %s", strerror(errno)));
    shutdown(sock, 2);
    close(sock);
    return -1;
  }

  /* Set appropriate option */
  silc_net_set_socket_opt(sock, IPPROTO_TCP, TCP_NODELAY, 1);

  SILC_LOG_DEBUG(("Connection created"));

  return sock;
}

/* Creates a connection (TCP/IP) to a remote host. Returns the connection
   socket or -1 on error. This creates non-blocking socket hence the
   connection returns directly. To get the result of the connect() one
   must select() the socket and read the result after it's ready. */

int silc_net_create_connection_async(int port, char *host)
{
  int sock, rval;
  struct hostent *dest;
  struct sockaddr_in desthost;

  SILC_LOG_DEBUG(("Creating connection (async) to host %s port %d", 
		  host, port));

  /* Do host lookup */
  dest = gethostbyname(host);
  if (!dest) {
    SILC_LOG_ERROR(("Network (%s) unreachable", host));
    return -1;
  }

  /* Set socket information */
  memset(&desthost, 0, sizeof(desthost));
  desthost.sin_port = htons(port);
  desthost.sin_family = PF_INET;
  memcpy(&desthost.sin_addr, dest->h_addr_list[0], sizeof(desthost.sin_addr));

  /* Create the connection socket */
  sock = socket(PF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    SILC_LOG_ERROR(("Cannot create socket: %s", strerror(errno)));
    return -1;
  }

  /* Set the socket to non-blocking mode */
  silc_net_set_socket_nonblock(sock);

  /* Connect to the host */
  rval = connect(sock, (struct sockaddr *)&desthost, sizeof(desthost));
  if (rval < 0) {
    if (errno !=  EINPROGRESS) {
      SILC_LOG_ERROR(("Cannot connect to remote host: %s", strerror(errno)));
      shutdown(sock, 2);
      close(sock);
      return -1;
    }
  }

  /* Set appropriate option */
  silc_net_set_socket_opt(sock, IPPROTO_TCP, TCP_NODELAY, 1);

  SILC_LOG_DEBUG(("Connection operation in progress"));

  return sock;
}

/* Closes the connection */

void silc_net_close_connection(int sock)
{
  close(sock);
}

/* Accepts a connection from a particular socket */

int silc_net_accept_connection(int sock)
{
  return accept(sock, 0, 0);
}

/* Set's the socket to non-blocking mode. */

int silc_net_set_socket_nonblock(int sock)
{
  return fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
}

/* Sets a option for a socket. */

int silc_net_set_socket_opt(int sock, int level, int option, int on)
{
  return setsockopt(sock, level, option, (void *)&on, sizeof(on));
}

/* Checks whether IP address sent as argument is valid IP address. */

int silc_net_is_ip(const char *addr)
{
  struct in_addr tmp;
  return inet_aton(addr, &tmp);
}

/* Performs lookups for remote name and IP address. */

void silc_net_check_host_by_sock(int sock, char **hostname, char **ip)
{
  struct sockaddr_in remote;
  struct hostent *dest;
  char *host_ip = NULL;
  char host_name[1024];
  int rval, len;
  int i;

  *hostname = NULL;
  *ip = NULL;

  SILC_LOG_DEBUG(("Resolving remote hostname and IP address"));

  memset(&remote, 0, sizeof(remote));
  len = sizeof(remote);
  rval = getpeername(sock, (struct sockaddr *)&remote, &len);
  if (rval < 0)
    return;

  /* Get host by address */
  dest = gethostbyaddr((char *)&remote.sin_addr, 
		       sizeof(struct in_addr), AF_INET);
  if (!dest)
    return;

  /* Get same hsot by name to see that the remote host really is
     the who it says it is */
  memset(host_name, 0, sizeof(host_name));
  memcpy(host_name, dest->h_name, strlen(dest->h_name));
  dest = gethostbyname(host_name);
  if (!dest)
    return;

  /* Find the address from list */
  for (i = 0; dest->h_addr_list[i]; i++)
    if (!memcmp(dest->h_addr_list[i], &remote.sin_addr, 
	       sizeof(struct in_addr)))
      break;
  if (!dest->h_addr_list[i])
    return;

  host_ip = inet_ntoa(remote.sin_addr);
  if (!host_ip)
    return;

  *hostname = silc_calloc(strlen(host_name) + 1, sizeof(char));
  memcpy(*hostname, host_name, strlen(host_name));
  SILC_LOG_DEBUG(("Resolved hostname `%s'", *hostname));
  *ip = silc_calloc(strlen(host_ip) + 1, sizeof(char));
  memcpy(*ip, host_ip, strlen(host_ip));
  SILC_LOG_DEBUG(("Resolved IP address `%s'", *ip));
}
