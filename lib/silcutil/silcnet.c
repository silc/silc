/*

  silcnet.c

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

/* Accepts a connection from a particular socket */

int silc_net_accept_connection(int sock)
{
  return accept(sock, 0, 0);
}

/* Sets a option for a socket. */

int silc_net_set_socket_opt(int sock, int level, int option, int on)
{
  return setsockopt(sock, level, option, (void *)&on, sizeof(on));
}

/* Get socket options */

int silc_net_get_socket_opt(int sock, int level, int option, 
			    void *optval, int *opt_len)
{
  return getsockopt(sock, level, option, optval, opt_len);
}

/* Checks whether IP address sent as argument is valid IP address. */

bool silc_net_is_ip(const char *addr)
{
  struct in_addr tmp;
  int len = sizeof(tmp);
  return silc_net_addr2bin(addr, (unsigned char *)&tmp.s_addr, len);
}

/* Performs lookups for remote name and IP address. This peforms reverse
   lookup as well to verify that the IP has FQDN. */

bool silc_net_check_host_by_sock(int sock, char **hostname, char **ip)
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
    return FALSE;

  host_ip = inet_ntoa(remote.sin_addr);
  if (!host_ip)
    return FALSE;

  *ip = silc_calloc(strlen(host_ip) + 1, sizeof(char));
  memcpy(*ip, host_ip, strlen(host_ip));

  /* Get host by address */
  dest = gethostbyaddr((char *)&remote.sin_addr, 
		       sizeof(struct in_addr), AF_INET);
  if (!dest)
    return FALSE;

  /* Get same host by name to see that the remote host really is
     the who it says it is */
  memset(host_name, 0, sizeof(host_name));
  memcpy(host_name, dest->h_name, strlen(dest->h_name));

  *hostname = silc_calloc(strlen(host_name) + 1, sizeof(char));
  memcpy(*hostname, host_name, strlen(host_name));
  SILC_LOG_DEBUG(("Resolved hostname `%s'", *hostname));

  dest = gethostbyname(host_name);
  if (!dest)
    return FALSE;

  /* Find the address from list */
  for (i = 0; dest->h_addr_list[i]; i++)
    if (!memcmp(dest->h_addr_list[i], &remote.sin_addr, 
		sizeof(struct in_addr)))
      break;
  if (!dest->h_addr_list[i])
    return FALSE;

  silc_free(*ip);
  *ip = silc_calloc(strlen(host_ip) + 1, sizeof(char));
  memcpy(*ip, host_ip, strlen(host_ip));
  SILC_LOG_DEBUG(("Resolved IP address `%s'", *ip));

  return TRUE;
}

/* Performs lookups for local name and IP address. This peforms reverse
   lookup as well to verify that the IP has FQDN. */

bool silc_net_check_local_by_sock(int sock, char **hostname, char **ip)
{
  struct sockaddr_in local;
  struct hostent *dest;
  char *host_ip = NULL;
  char host_name[1024];
  int rval, len;
  int i;

  *hostname = NULL;
  *ip = NULL;

  SILC_LOG_DEBUG(("Resolving local hostname and IP address"));

  memset(&local, 0, sizeof(local));
  len = sizeof(local);
  rval = getsockname(sock, (struct sockaddr *)&local, &len);
  if (rval < 0)
    return FALSE;

  host_ip = inet_ntoa(local.sin_addr);
  if (!host_ip)
    return FALSE;

  *ip = silc_calloc(strlen(host_ip) + 1, sizeof(char));
  memcpy(*ip, host_ip, strlen(host_ip));

  /* Get host by address */
  dest = gethostbyaddr((char *)&local.sin_addr, 
		       sizeof(struct in_addr), AF_INET);
  if (!dest)
    return FALSE;

  /* Get same host by name to see that the local host really is
     the who it says it is */
  memset(host_name, 0, sizeof(host_name));
  memcpy(host_name, dest->h_name, strlen(dest->h_name));

  *hostname = silc_calloc(strlen(host_name) + 1, sizeof(char));
  memcpy(*hostname, host_name, strlen(host_name));
  SILC_LOG_DEBUG(("Resolved hostname `%s'", *hostname));

  dest = gethostbyname(host_name);
  if (!dest)
    return FALSE;

  /* Find the address from list */
  for (i = 0; dest->h_addr_list[i]; i++)
    if (!memcmp(dest->h_addr_list[i], &local.sin_addr, 
	       sizeof(struct in_addr)))
      break;
  if (!dest->h_addr_list[i])
    return FALSE;

  silc_free(*ip);
  *ip = silc_calloc(strlen(host_ip) + 1, sizeof(char));
  memcpy(*ip, host_ip, strlen(host_ip));
  SILC_LOG_DEBUG(("Resolved IP address `%s'", *ip));

  return TRUE;
}

/* Return remote port by socket. */

uint16 silc_net_get_remote_port(int sock)
{
  struct sockaddr_in remote;
  int len;

  memset(&remote, 0, sizeof(remote));
  len = sizeof(remote);
  if (getpeername(sock, (struct sockaddr *)&remote, &len) < 0)
    return 0;

  return ntohs(remote.sin_port);
}

/* Return local port by socket. */

uint16 silc_net_get_local_port(int sock)
{
  struct sockaddr_in local;
  int len;

  memset(&local, 0, sizeof(local));
  len = sizeof(local);
  if (getsockname(sock, (struct sockaddr *)&local, &len) < 0)
    return 0;

  return ntohs(local.sin_port);
}

/* Return name of localhost. */

char *silc_net_localhost(void)
{
  char hostname[256];
  struct hostent *dest;

  if (gethostname(hostname, sizeof(hostname)))
    return NULL;

  dest = gethostbyname(hostname);
  if (!dest)
    return strdup(hostname);

  return strdup(dest->h_name);
}
