/*

  silcwin32net.c

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
/* $Id$ */

#include "silc.h"

/************************** Types and definitions ***************************/

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


/************************ Static utility functions **************************/

static SilcBool silc_net_set_sockaddr(SilcSockaddr *addr, const char *ip_addr,
				      int port)
{
  int len;

  memset(addr, 0, sizeof(*addr));

  /* Check for IPv4 and IPv6 addresses */
  if (ip_addr) {
    if (!silc_net_is_ip(ip_addr)) {
      SILC_LOG_ERROR(("%s is not IP address", ip_addr));
      silc_set_errno_reason(SILC_ERR_BAD_IP, "%s is not an IP address",
			    ip_addr);
      return FALSE;
    }

    if (silc_net_is_ip4(ip_addr)) {
      /* IPv4 address */
      len = sizeof(addr->sin.sin_addr);
      if (!silc_net_addr2bin(ip_addr,
			     (unsigned char *)&addr->sin.sin_addr.s_addr,
			     len))
	return FALSE;
      addr->sin.sin_family = AF_INET;
      addr->sin.sin_port = port ? htons(port) : 0;
    } else {
#ifdef HAVE_IPV6
      /* IPv6 address */
      len = sizeof(addr->sin6.sin6_addr);
      if (!silc_net_addr2bin(ip_addr,
			     (unsigned char *)&addr->sin6.sin6_addr, len))
	return FALSE;
      addr->sin6.sin6_family = AF_INET6;
      addr->sin6.sin6_port = port ? htons(port) : 0;
#else
      SILC_LOG_ERROR(("Operating System does not support IPv6"));
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


/****************************** TCP Listener ********************************/

/* Deliver new stream to upper layer */

static void silc_net_accept_stream(SilcResult status,
				   SilcStream stream, void *context)
{
  SilcNetListener listener = context;

  if (status != SILC_OK)
    return;

  listener->callback(SILC_OK, stream, listener->context);
}

/* Accept incoming connection and notify upper layer */

SILC_TASK_CALLBACK(silc_net_accept)
{
  SilcNetListener listener = context;
  int sock;

  SILC_LOG_DEBUG(("Accepting new connection"));

  sock = silc_net_accept_connection(fd);
  if (sock == INVALID_SOCKET)
    return;

  /* Set socket options */
  silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);

  /* Create socket stream */
  silc_socket_tcp_stream_create(sock, listener->lookup,
				listener->require_fqdn, schedule,
				silc_net_accept_stream, listener);
}

/* Create TCP network listener */

SilcNetListener
silc_net_tcp_create_listener(const char **local_ip_addr,
			     SilcUInt32 local_ip_count, int port,
			     SilcBool lookup, SilcBool require_fqdn,
			     SilcSchedule schedule,
			     SilcNetCallback callback, void *context)
{
  SilcNetListener listener = NULL;
  SOCKET sock;
  SilcSockaddr server;
  int i, rval;
  const char *ipany = "0.0.0.0";

  SILC_LOG_DEBUG(("Creating TCP listener"));

  if (port < 0 || !schedule || !callback) {
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
    goto err;
  }

  listener = silc_calloc(1, sizeof(*listener));
  if (!listener)
    return NULL;
  listener->schedule = schedule;
  listener->callback = callback;
  listener->context = context;
  listener->require_fqdn = require_fqdn;
  listener->lookup = lookup;

  if (local_ip_count > 0) {
    listener->socks = silc_calloc(local_ip_count, sizeof(*listener->socks));
    if (!listener->socks)
      return NULL;
  } else {
    listener->socks = silc_calloc(1, sizeof(*listener->socks));
    if (!listener->socks)
      return NULL;

    local_ip_count = 1;
  }

  /* Bind to local addresses */
  for (i = 0; i < local_ip_count; i++) {
    SILC_LOG_DEBUG(("Binding to local address %s",
		    local_ip_addr ? local_ip_addr[i] : ipany));

    /* Set sockaddr for server */
    if (!silc_net_set_sockaddr(&server,
			       local_ip_addr ? local_ip_addr[i] : ipany,
			       port))
      goto err;

    /* Create the socket */
    sock = socket(server.sin.sin_family, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
      silc_set_errno_posix(WSAGetLastError());
      SILC_LOG_ERROR(("Cannot create socket, error %s",
		      silc_errno_string(silc_errno)));
      goto err;
    }

    /* Set the socket options */
    rval = silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
    if (rval == SOCKET_ERROR) {
      SILC_LOG_ERROR(("Cannot set socket options, error %s",
		      silc_errno_string(silc_errno)));
      closesocket(sock);
      goto err;
    }

    /* Bind the listener socket */
    rval = bind(sock, &server.sa, SIZEOF_SOCKADDR(server));
    if (rval == SOCKET_ERROR) {
      silc_set_errno_posix(WSAGetLastError());
      SILC_LOG_ERROR(("Cannot bind socket, error %s",
		      silc_errno_string(silc_errno)));
      closesocket(sock);
      goto err;
    }

    /* Specify that we are listenning */
    rval = listen(sock, SOMAXCONN);
    if (rval == SOCKET_ERROR) {
      silc_set_errno_posix(WSAGetLastError());
      SILC_LOG_ERROR(("Cannot set socket listenning, error %s",
		      silc_errno_string(silc_errno)));
      closesocket(sock);
      goto err;
    }

    /* Schedule for incoming connections */
    silc_schedule_task_add_fd(schedule, sock, silc_net_accept, listener);

    SILC_LOG_DEBUG(("TCP listener created, fd=%d", sock));
    listener->socks[i] = sock;
    listener->socks_count++;
  }

  return listener;

 err:
  if (listener)
    silc_net_close_listener(listener);
  return NULL;
}

/* Create TCP network, multiple ports */

SilcNetListener
silc_net_tcp_create_listener2(const char *local_ip_addr, int *ports,
			      SilcUInt32 port_count,
			      SilcBool ignore_port_error,
			      SilcBool lookup, SilcBool require_fqdn,
			      SilcSchedule schedule,
			      SilcNetCallback callback, void *context)
{
  SilcNetListener listener = NULL;
  SOCKET sock;
  SilcSockaddr server;
  int i, rval;
  const char *ipany = "0.0.0.0";

  SILC_LOG_DEBUG(("Creating TCP listener"));

  if (!schedule || !callback) {
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
    goto err;
  }

  listener = silc_calloc(1, sizeof(*listener));
  if (!listener)
    return NULL;
  listener->schedule = schedule;
  listener->callback = callback;
  listener->context = context;
  listener->require_fqdn = require_fqdn;
  listener->lookup = lookup;

  if (port_count > 0) {
    listener->socks = silc_calloc(port_count, sizeof(*listener->socks));
    if (!listener->socks)
      return NULL;
  } else {
    listener->socks = silc_calloc(1, sizeof(*listener->socks));
    if (!listener->socks)
      return NULL;

    port_count = 1;
  }

  /* Bind to local addresses */
  for (i = 0; i < local_ip_count; i++) {
    SILC_LOG_DEBUG(("Binding to local address %s:%d",
		    local_ip_addr ? local_ip_addr : ipany,
		    ports ? ports[i] : 0));

    /* Set sockaddr for server */
    if (!silc_net_set_sockaddr(&server,
			       local_ip_addr ? local_ip_addr : ipany,
			       ports ? ports[i] : 0)) {
      if (ignore_port_error)
	continue;
      goto err;
    }

    /* Create the socket */
    sock = socket(server.sin.sin_family, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
      if (ignore_port_error)
	continue;
      silc_set_errno_posix(WSAGetLastError());
      SILC_LOG_ERROR(("Cannot create socket, error %s",
		      silc_errno_string(silc_errno)));
      goto err;
    }

    /* Set the socket options */
    rval = silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
    if (rval == SOCKET_ERROR) {
      closesocket(sock);
      if (ignore_port_error)
	continue;
      SILC_LOG_ERROR(("Cannot set socket options, error %s",
		      silc_errno_string(silc_errno)));
      goto err;
    }

    /* Bind the listener socket */
    rval = bind(sock, &server.sa, SIZEOF_SOCKADDR(server));
    if (rval == SOCKET_ERROR) {
      closesocket(sock);
      if (ignore_port_error)
	continue;
      silc_set_errno_posix(WSAGetLastError());
      SILC_LOG_ERROR(("Cannot bind socket, error %s",
		      silc_errno_string(silc_errno)));
      goto err;
    }

    /* Specify that we are listenning */
    rval = listen(sock, SOMAXCONN);
    if (rval == SOCKET_ERROR) {
      closesocket(sock);
      if (ignore_port_error)
	continue;
      silc_set_errno_posix(WSAGetLastError());
      SILC_LOG_ERROR(("Cannot set socket listenning, error %s",
		      silc_errno_string(silc_errno)));
      goto err;
    }

    /* Schedule for incoming connections */
    silc_schedule_task_add_fd(schedule, sock, silc_net_accept, listener);

    SILC_LOG_DEBUG(("TCP listener created, fd=%d", sock));
    listener->socks[i] = sock;
    listener->socks_count++;
  }

  if (ignore_port_error && !listener->socks_count)
    goto err;

  return listener;

 err:
  if (listener)
    silc_net_close_listener(listener);
  return NULL;
}

/* Close network listener */

void silc_net_close_listener(SilcNetListener listener)
{
  int i;

  SILC_LOG_DEBUG(("Closing network listener"));

  if (!listener)
    return;

  for (i = 0; i < listener->socks_count; i++) {
    silc_schedule_task_del_by_fd(listener->schedule, listener->socks[i]);
    shutdown(listener->socks[i], 2);
    closesocket(listener->socks[i]);
  }

  silc_free(listener->socks);
  silc_free(listener);
}

/******************************* UDP Stream *********************************/

/* Create UDP stream */

SilcStream
silc_net_udp_connect(const char *local_ip_addr, int local_port,
		     const char *remote_ip_addr, int remote_port,
		     SilcSchedule schedule)
{
  SilcStream stream;
  SilcSockaddr server;
  SOCKET sock;
  int rval;
  const char *ipany = "0.0.0.0";

  SILC_LOG_DEBUG(("Creating UDP stream"));

  if (!schedule)
    goto err;

  /* Bind to local addresses */
  SILC_LOG_DEBUG(("Binding to local address %s",
		  local_ip_addr ? local_ip_addr : ipany));

  /* Set sockaddr for server */
  if (!silc_net_set_sockaddr(&server, local_ip_addr ? local_ip_addr : ipany,
			     local_port))
    goto err;

  /* Create the socket */
  sock = socket(server.sin.sin_family, SOCK_DGRAM, 0);
  if (sock == INVALID_SOCKET) {
    SILC_LOG_ERROR(("Cannot create socket"));
    silc_set_errno_posix(WSAGetLastError());
    goto err;
  }

  /* Set the socket options */
  rval = silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
  if (rval == SOCKET_ERROR) {
    SILC_LOG_ERROR(("Cannot set socket options"));
    goto err;
  }
#ifdef SO_REUSEPORT
  rval = silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEPORT, 1);
  if (rval == SOCKET_ERROR) {
    SILC_LOG_ERROR(("Cannot set socket options"));
    goto err;
  }
#endif /* SO_REUSEPORT */

  /* Bind the listener socket */
  rval = bind(sock, &server.sa, SIZEOF_SOCKADDR(server));
  if (rval == SOCKET_ERROR) {
    SILC_LOG_DEBUG(("Cannot bind socket"));
    silc_set_errno_posix(WSAGetLastError());
    goto err;
  }

  /* Set to connected state if remote address is provided. */
  if (remote_ip_addr && remote_port) {
    if (!silc_net_set_sockaddr(&server, remote_ip_addr, remote_port))
      goto err;

    rval = connect(sock, &server.sa, SIZEOF_SOCKADDR(server));
    if (rval == SOCKET_ERROR) {
      SILC_LOG_DEBUG(("Cannot connect UDP stream"));
      silc_set_errno_posix(WSAGetLastError());
      goto err;
    }
  }

  /* Encapsulate into socket stream */
  stream =
    silc_socket_udp_stream_create(sock, local_ip_addr ?
				  silc_net_is_ip6(local_ip_addr) : FALSE,
				  remote_ip_addr ? TRUE : FALSE, schedule);
  if (!stream)
    goto err;

  SILC_LOG_DEBUG(("UDP stream created, fd=%d", sock));
  return stream;

 err:
  if (sock != -1)
    close(sock);
  return NULL;
}

/* Receive UDP packet */

int silc_net_udp_receive(SilcStream stream, char *remote_ip_addr,
			 SilcUInt32 remote_ip_addr_size, int *remote_port,
			 unsigned char *ret_data, SilcUInt32 data_size)
{
  SilcSocketStream sock = stream;
  SilcSockaddr s;
  struct sockaddr *from;
  int len, flen, err;

  SILC_LOG_DEBUG(("Reading data from UDP socket %d", sock->sock));

  if (remote_ip_addr && remote_port) {
    if (sock->ipv6) {
#ifdef HAVE_IPV6
      from = (struct sockaddr *)&s.sin6;
      flen = sizeof(s.sin6);
#endif /* HAVE_IPV6 */
    } else {
      from = (struct sockaddr *)&s.sin;
      flen = sizeof(s.sin);
    }
    len = recvfrom(sock->sock, ret_data, data_size, 0, from, &flen);
  } else
    len = recv(sock->sock, ret_data, data_size, 0);

  if (len == SOCKET_ERROR) {
    err = WSAGetLastError();
    silc_set_errno_posix(err);
    if (err == WSAEWOULDBLOCK) {
      SILC_LOG_DEBUG(("Could not read immediately, will do it later"));
      silc_schedule_set_listen_fd(sock->schedule, sock->sock,
				  SILC_TASK_READ, FALSE);
      return -1;
    }
    SILC_LOG_DEBUG(("Cannot read from UDP socket: %d: %s", sock->sock,
		    silc_errno_string(silc_errno)));
    silc_schedule_unset_listen_fd(sock->schedule, sock->sock);
    return -2;
  }

  SILC_LOG_DEBUG(("Read %d bytes", len));

  if (!len)
    silc_schedule_unset_listen_fd(sock->schedule, sock->sock);

  /* Return remote address */
  if (remote_ip_addr && remote_port) {
    if (sock->ipv6) {
#ifdef HAVE_IPV6
      *remote_port = ntohs(s.sin6.sin6_port);
      inet_ntop(AF_INET6, &s.sin6.sin6_addr, remote_ip_addr,
		remote_ip_addr_size);
#endif /* HAVE_IPV6 */
    } else {
      const char *ip = inet_ntoa(s.sin.sin_addr);
      if (ip)
	silc_snprintf(remote_ip_addr, remote_ip_addr_size, ip);
      *remote_port = ntohs(s.sin.sin_port);
    }

    SILC_LOG_DEBUG(("UDP packet from %s:%d", remote_ip_addr, *remote_port));
  }

  return len;
}

/* Send UDP packet */

int silc_net_udp_send(SilcStream stream,
		      const char *remote_ip_addr, int remote_port,
		      const unsigned char *data, SilcUInt32 data_len)
{
  SilcSocketStream sock = stream;
  SilcSockaddr remote;
  int ret, err;

  SILC_LOG_DEBUG(("Sending data to UDP socket %d", sock->sock));

  /* Set sockaddr */
  if (!silc_net_set_sockaddr(&remote, remote_ip_addr, remote_port))
    return -2;

  /* Send */
  ret = sendto(sock->sock, data, data_len, 0, &remote.sa,
	       SIZEOF_SOCKADDR(remote));
  if (ret == SOCKET_ERROR) {
    err = WSAGetLastError();
    silc_set_errno_posix(err);
    if (err == WSAEWOULDBLOCK) {
      SILC_LOG_DEBUG(("Could not send immediately, will do it later"));
      silc_schedule_set_listen_fd(sock->schedule, sock->sock,
				  SILC_TASK_READ | SILC_TASK_WRITE, FALSE);
      return -1;
    }
    SILC_LOG_DEBUG(("Cannot send to UDP socket: %s",
		    silc_errno_string(silc_errno)));
    silc_schedule_unset_listen_fd(sock->schedule, sock->sock);
    return -2;
  }

  SILC_LOG_DEBUG(("Sent data %d bytes", ret));
  if (silc_schedule_get_fd_events(sock->schedule, sock->sock) &
      SILC_TASK_WRITE)
    silc_schedule_set_listen_fd(sock->schedule, sock->sock,
				SILC_TASK_READ, FALSE);

  return ret;
}


/******************************* TCP Stream *********************************/

typedef struct {
  SilcResult status;
  SilcStream stream;
  SilcFSMStruct fsm;
  SilcFSMThreadStruct thread;
  SilcAsyncOperation op;
  SilcAsyncOperation sop;
  char *local_ip;
  char *remote;
  char ip_addr[64];
  int sock;
  SilcNetCallback callback;
  void *context;
  unsigned int port     : 24;
  unsigned int retry    : 7;
  unsigned int aborted  : 1;
} *SilcNetConnect;

SILC_FSM_STATE(silc_net_connect_st_start);
SILC_FSM_STATE(silc_net_connect_st_stream);
SILC_FSM_STATE(silc_net_connect_st_finish);

static void silc_net_connect_wait_stream(SilcResult status,
					 SilcStream stream, void *context)
{
  SilcNetConnect conn = context;
  conn->sop = NULL;
  conn->status = status;
  conn->stream = stream;
  SILC_FSM_CALL_CONTINUE(&conn->thread);
}

/* Start connecting.  Create a real thread where we connect. */

SILC_FSM_STATE(silc_net_connect_st_thread)
{
  SilcNetConnect conn = fsm_context;

  /* Connect in real thread so as to not block the application. */
  silc_fsm_thread_init(&conn->thread, fsm, conn, NULL, NULL, TRUE);
  silc_fsm_start(&conn->thread, silc_net_connect_st_start);

  /* Wait for the thread to finish */
  silc_fsm_next(fsm, silc_net_connect_st_finish);
  SILC_FSM_THREAD_WAIT(&conn->thread);
}

/* Connecting thread */

SILC_FSM_STATE(silc_net_connect_st_start)
{
  SilcNetConnect conn = fsm_context;
  SOCKET sock;
  int rval, err;
  SilcSockaddr desthost;
  SilcBool prefer_ipv6 = TRUE;

  if (conn->aborted)
    return SILC_FSM_FINISH;

  /* Do host lookup */
 retry:
  if (!silc_net_gethostbyname(conn->remote, prefer_ipv6,
			      conn->ip_addr, sizeof(conn->ip_addr))) {
    SILC_LOG_ERROR(("Network (%s) unreachable: could not resolve the "
		    "host, error %d", conn->remote, WSAGetLastError()));

    /** Network unreachable */
    conn->status = SILC_ERR_UNREACHABLE;
    return SILC_FSM_FINISH;
  }

  /* Set sockaddr for this connection */
  if (!silc_net_set_sockaddr(&desthost, conn->ip_addr, conn->port))
    return SILC_FSM_FINISH;

  /* Create the connection socket */
  sock = socket(desthost.sin.sin_family, SOCK_STREAM, 0);
  if (sock == INVALID_SOCKET) {
    /* If address is IPv6, then fallback to IPv4 and see whether we can do
       better with that on socket creation. */
    if (prefer_ipv6 && silc_net_is_ip6(conn->ip_addr)) {
      prefer_ipv6 = FALSE;
      goto retry;
    }

    /** Cannot create socket */
    silc_set_errno_posix(err);
    SILC_LOG_ERROR(("Cannot create socket, error %d",
		    silc_errno_string(silc_errno)));
    return SILC_FSM_FINISH;
  }

  /* Bind to the local address if provided */
  if (conn->local_ip) {
    SilcSockaddr local;

    /* Set sockaddr for local listener, and try to bind it. */
    if (silc_net_set_sockaddr(&local, conn->local_ip, 0))
      bind(sock, &local.sa, SIZEOF_SOCKADDR(local));
  }

  /* Connect to the host */
  rval = connect(sock, &desthost.sa, SIZEOF_SOCKADDR(desthost));
  err = WSAGetLastError();
  if (rval == SOCKET_ERROR) {
    if (err != WSAEWOULDBLOCK) {
      shutdown(sock, 2);
      closesocket(sock);

      /* Retry using an IPv4 address, if IPv6 didn't work */
      if (prefer_ipv6 && silc_net_is_ip6(conn->ip_addr)) {
	prefer_ipv6 = FALSE;
	goto retry;
      }

      /* Set error */
      silc_set_errno_posix(err);
      conn->status = silc_errno;

      SILC_LOG_ERROR(("Cannot connect to remote host: %s",
		      silc_errno_string(silc_errno)));
      return SILC_FSM_FINISH;
    }
  }

  /* Set the socket to non-blocking mode */
  silc_net_set_socket_nonblock(sock);

  /* Set appropriate options */
#if defined(TCP_NODELAY)
  silc_net_set_socket_opt(sock, IPPROTO_TCP, TCP_NODELAY, 1);
#endif
  silc_net_set_socket_opt(sock, SOL_SOCKET, SO_KEEPALIVE, 1);

  SILC_LOG_DEBUG(("TCP connection established"));

  conn->sock = sock;

  /** Connection created */
  silc_fsm_next(fsm, silc_net_connect_st_stream);
  SILC_FSM_CALL((conn->sop = silc_socket_tcp_stream_create(
				     conn->sock, TRUE, FALSE,
				     silc_fsm_get_schedule(&conn->fsm),
				     silc_net_connect_wait_stream, conn)));
}

/* TCP socket stream created */

SILC_FSM_STATE(silc_net_connect_st_stream)
{
  SilcNetConnect conn = fsm_context;

  if (conn->aborted)
    return SILC_FSM_FINISH;

  if (conn->status != SILC_OK) {
    /** Stream creation failed */
    return SILC_FSM_FINISH;
  }

  /** Stream created successfully */
  SILC_LOG_DEBUG(("Connected successfully, sock %d", conn->sock));
  conn->status = SILC_OK;
  return SILC_FSM_FINISH;
}

SILC_FSM_STATE(silc_net_connect_st_finish)
{
  SilcNetConnect conn = fsm_context;

  /* Deliver error or new stream */
  if (!conn->aborted) {
    conn->callback(conn->status, conn->stream, conn->context);
    if (conn->op)
      silc_async_free(conn->op);
  }

  return SILC_FSM_FINISH;
}

static void silc_net_connect_abort(SilcAsyncOperation op, void *context)
{
  SilcNetConnect conn = context;
  conn->aborted = TRUE;

  /* Abort underlaying stream creation too */
  if (conn->sop) {
    silc_async_abort(conn->sop, NULL, NULL);
    conn->sop = NULL;
  }
}

static void silc_net_connect_destructor(SilcFSM fsm, void *fsm_context,
					void *destructor_context)
{
  SilcNetConnect conn = fsm_context;
  silc_free(conn->local_ip);
  silc_free(conn->remote);
  silc_free(conn);
}

/* Create asynchronous TCP/IP connection. */

SilcAsyncOperation silc_net_tcp_connect(const char *local_ip_addr,
					const char *remote_ip_addr,
					int remote_port,
					SilcSchedule schedule,
					SilcNetCallback callback,
					void *context)
{
  SilcNetConnect conn;

  if (!remote_ip_addr || remote_port < 1 || !schedule || !callback) {
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
    return NULL;
  }

  SILC_LOG_DEBUG(("Creating connection to host %s port %d",
		  remote_ip_addr, remote_port));

  conn = silc_calloc(1, sizeof(*conn));
  if (!conn) {
    callback(SILC_ERR_OUT_OF_MEMORY, NULL, context);
    return NULL;
  }

  /* Start async operation */
  conn->op = silc_async_alloc(silc_net_connect_abort, NULL, conn);
  if (!conn->op) {
    silc_free(conn);
    callback(SILC_ERR_OUT_OF_MEMORY, NULL, context);
    return NULL;
  }

  if (local_ip_addr)
    conn->local_ip = silc_strdup(local_ip_addr);
  conn->remote = silc_strdup(remote_ip_addr);
  if (!conn->remote) {
    silc_async_free(conn->op);
    silc_free(conn->local_ip);
    silc_free(conn);
    callback(SILC_ERR_OUT_OF_MEMORY, NULL, context);
    return NULL;
  }
  conn->port = remote_port;
  conn->callback = callback;
  conn->context = context;
  conn->retry = 1;
  conn->status = SILC_ERR;

  silc_fsm_init(&conn->fsm, conn, silc_net_connect_destructor, NULL, schedule);
  silc_fsm_start(&conn->fsm, silc_net_connect_st_thread);

  return conn->op;
}

/* Closes the connection by closing the socket connection. */

void silc_net_close_connection(int sock)
{
  SILC_LOG_DEBUG(("Closing sock %d", sock));
  closesocket(sock);
}

/* Converts the IP number string from numbers-and-dots notation to
   binary form. */

SilcBool silc_net_addr2bin(const char *addr, void *bin, SilcUInt32 bin_len)
{
  if (silc_net_is_ip4(addr)) {
    /* IPv4 address */
    int i = 0, c = 0, d = 0, len = strlen(addr);
    unsigned char ret[4];

    memset(ret, 0, sizeof(ret));
    while (len-- > 0) {
      if (addr[i++] == '.') {
	ret[c++] = d;
	d = 0;
	if (c > 3)
	  goto err;
	continue;
      }

      if (!isdigit((int)addr[i - 1]))
	goto err;

      d = 10 * d + addr[i - 1] - '0';
      if (d > 255)
	goto err;
    }
    if (c != 3)
      goto err;
    ret[c] = d;

    if (bin_len < sizeof(ret)) {
      silc_set_errno(SILC_ERR_OVERFLOW);
      return FALSE;
    }

    memcpy(bin, ret, sizeof(ret));
    return TRUE;

    err:
    return FALSE;
  } else {
#ifdef HAVE_IPV6
    struct addrinfo hints, *ai;
    SilcSockaddr *s;

    /* IPv6 address */
    if (bin_len < 16) {
      silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
      return FALSE;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    if (getaddrinfo(addr, NULL, &hints, &ai))
      return FALSE;

    if (ai) {
      s = (SilcSockaddr *)ai->ai_addr;
      memcpy(bin, &s->sin6.sin6_addr, sizeof(s->sin6.sin6_addr));
      freeaddrinfo(ai);
    }

    return TRUE;
#else
    return FALSE;
#endif /* HAVE_IPV6 */
  }
}

/* Set socket to non-blocking mode. */

int silc_net_set_socket_nonblock(SilcSocket sock)
{
  unsigned long on = 1;
  return ioctlsocket(sock, FIONBIO, &on);
}
