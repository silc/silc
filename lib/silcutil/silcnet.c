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

/* Checks whether IP address sent as argument is valid IPv4 address. */

bool silc_net_is_ip4(const char *addr)
{
  int count = 0;

  while (*addr) {
    if (*addr != '.' && !isdigit(*addr))
      return FALSE;
    if (*addr == '.')
      count++;
    addr++;
  }

  if (count != 3)
    return FALSE;
  
  return TRUE;
}

/* Checks whether IP address sent as argument is valid IPv6 address. */

bool silc_net_is_ip6(const char *addr)
{
  /* XXX does this work with all kinds of IPv6 addresses? */
  while (*addr) {
    if (*addr != ':' && !isxdigit(*addr))
      return FALSE;
    addr++;
  }
  
  return TRUE;
}

/* Checks whether IP address sent as argument is valid IP address. */

bool silc_net_is_ip(const char *addr)
{
  if (silc_net_is_ip4(addr))
    return TRUE;
  return silc_net_is_ip6(addr);
}

/* Internal context for async resolving */
typedef struct {
  SilcNetResolveCallback completion;
  void *context;
  SilcSchedule schedule;
  char *input;
  char *result;
} *SilcNetResolveContext;

SILC_TASK_CALLBACK(silc_net_resolve_completion)
{
  SilcNetResolveContext r = (SilcNetResolveContext)context;

  /* Call the completion callback */
  if (r->completion)
    (*r->completion)(r->result, r->context);

  silc_free(r->input);
  silc_free(r->result);
  silc_free(r);
}

/* Thread function to resolve the address for hostname. */

static void *silc_net_gethostbyname_thread(void *context)
{
  SilcNetResolveContext r = (SilcNetResolveContext)context;
  char tmp[64];

  if (silc_net_gethostbyname(r->input, tmp, sizeof(tmp)))
    r->result = strdup(tmp);

  silc_schedule_task_add(r->schedule, 0, silc_net_resolve_completion, r, 0, 1,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
  silc_schedule_wakeup(r->schedule);
  return NULL;
}

/* Thread function to resolve the hostname for address. */

static void *silc_net_gethostbyaddr_thread(void *context)
{
  SilcNetResolveContext r = (SilcNetResolveContext)context;
  char tmp[256];

  if (silc_net_gethostbyaddr(r->input, tmp, sizeof(tmp)))
    r->result = strdup(tmp);

  silc_schedule_task_add(r->schedule, 0, silc_net_resolve_completion, r, 0, 1,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
  silc_schedule_wakeup(r->schedule);
  return NULL;
}

/* Resolves IP address for hostname. */

bool silc_net_gethostbyname(const char *name, char *address,
			    uint32 address_len)
{
#ifdef HAVE_IPV6
  struct addrinfo hints, *ai;
  char hbuf[NI_MAXHOST];

  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(name, NULL, &hints, &ai))
    return FALSE;

  if (getnameinfo(ai->ai_addr, ai->ai_addrlen, hbuf,
		  sizeof(hbuf), NULL, 0, NI_NUMERICHOST))
    return FALSE;

  if (ai->ai_family == AF_INET) {
    if (!inet_ntop(ai->ai_family, 
		   &((struct sockaddr_in *)ai->ai_addr)->sin_addr,
		   address, address_len))
      return FALSE;
  } else {
    if (!inet_ntop(ai->ai_family, 
		   &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
		   address, address_len))
      return FALSE;
  }

  freeaddrinfo(ai);
#else
  struct hostent *hp;
  struct in_addr ip;
  char *tmp;

  hp = gethostbyname(name);
  if (!hp)
    return FALSE;

  memcpy(&ip.s_addr, hp->h_addr_list[0], 4);
  tmp = inet_ntoa(ip);
  if (!tmp)
    return FALSE;
  if (address_len < strlen(tmp))
    return FALSE;
  memset(address, 0, address_len);
  strncpy(address, tmp, strlen(tmp));
#endif
  
  return TRUE;
}

/* Resolves IP address for hostname async. */

void silc_net_gethostbyname_async(const char *name, 
				  SilcSchedule schedule,
				  SilcNetResolveCallback completion,
				  void *context)
{
  SilcNetResolveContext r = silc_calloc(1, sizeof(*r));

  r->completion = completion;
  r->context = context;
  r->schedule = schedule;
  r->input = strdup(name);

  silc_thread_create(silc_net_gethostbyname_thread, r, FALSE);
}

/* Resolves hostname by IP address. */

bool silc_net_gethostbyaddr(const char *addr, char *name, uint32 name_len)
{
#ifdef HAVE_IPV6
  struct addrinfo req, *ai;
  
  memset(&req, 0, sizeof(req));
  req.ai_socktype = SOCK_STREAM;
  req.ai_flags = AI_CANONNAME;
  
  if (getaddrinfo(addr, NULL, &req, &ai))
    return FALSE;
  if (name_len < strlen(ai->ai_canonname))
    return FALSE;
  memset(name, 0, name_len);
  strncpy(name, ai->ai_canonname, strlen(ai->ai_canonname));

  freeaddrinfo(ai);
#else
  struct hostent *hp;

  hp = gethostbyaddr(addr, strlen(addr), AF_INET);
  if (!hp)
    return FALSE;
  if (name_len < strlen(hp->h_name))
    return FALSE;
  memset(name, 0, name_len);
  strncpy(name, hp->h_name, strlen(hp->h_name));
#endif
  
  return TRUE;
}

/* Resolves hostname by IP address async. */

void silc_net_gethostbyaddr_async(const char *addr, 
				  SilcSchedule schedule,
				  SilcNetResolveCallback completion,
				  void *context)
{
  SilcNetResolveContext r = silc_calloc(1, sizeof(*r));

  r->completion = completion;
  r->context = context;
  r->schedule = schedule;
  r->input = strdup(addr);

  silc_thread_create(silc_net_gethostbyaddr_thread, r, FALSE);
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
  char hostname[256], ip_addr[64];

  if (gethostname(hostname, sizeof(hostname)))
    return NULL;

  if (!silc_net_gethostbyname(hostname, ip_addr, sizeof(ip_addr)))
    return strdup(hostname);

  silc_net_gethostbyaddr(ip_addr, hostname, sizeof(hostname));
  return strdup(hostname);
}

/* Returns local IP address */

char *silc_net_localip(void)
{
  char hostname[256], ip_addr[64];

  if (gethostname(hostname, sizeof(hostname)))
    return NULL;

  if (!silc_net_gethostbyname(hostname, ip_addr, sizeof(ip_addr)))
    return NULL;

  return strdup(ip_addr);
}
