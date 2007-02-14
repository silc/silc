/*

  silcunixnet.c

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

static SilcBool silc_net_set_sockaddr(SilcSockaddr *addr, const char *ip_addr,
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

/* Deliver new stream to upper layer */

static void silc_net_accept_stream(SilcSocketStreamStatus status,
				   SilcStream stream, void *context)
{
  SilcNetListener listener = context;

  if (status != SILC_SOCKET_OK)
    return;

  listener->callback(SILC_NET_OK, stream, listener->context);
}

/* Accept incoming connection and notify upper layer */

SILC_TASK_CALLBACK(silc_net_accept)
{
  SilcNetListener listener = context;
  int sock;

  SILC_LOG_DEBUG(("Accepting new connection"));

  sock = silc_net_accept_connection(fd);
  if (sock < 0)
    return;

  /* Set socket options */
  silc_net_set_socket_nonblock(sock);
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
  SilcSockaddr server;
  int i, sock, rval;
  const char *ipany = "0.0.0.0";

  SILC_LOG_DEBUG(("Creating TCP listener"));

  if (port < 0 || !schedule || !callback)
    goto err;

  listener = silc_calloc(1, sizeof(*listener));
  if (!listener) {
    callback(SILC_NET_NO_MEMORY, NULL, context);
    return NULL;
  }
  listener->schedule = schedule;
  listener->callback = callback;
  listener->context = context;
  listener->require_fqdn = require_fqdn;
  listener->lookup = lookup;

  if (local_ip_count > 0) {
    listener->socks = silc_calloc(local_ip_count, sizeof(*listener->socks));
    if (!listener->socks) {
      callback(SILC_NET_NO_MEMORY, NULL, context);
      return NULL;
    }
  } else {
    listener->socks = silc_calloc(1, sizeof(*listener->socks));
    if (!listener->socks) {
      callback(SILC_NET_NO_MEMORY, NULL, context);
      return NULL;
    }

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
    if (sock < 0) {
      SILC_LOG_ERROR(("Cannot create socket: %s", strerror(errno)));
      goto err;
    }

    /* Set the socket options */
    rval = silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
    if (rval < 0) {
      SILC_LOG_ERROR(("Cannot set socket options: %s", strerror(errno)));
      goto err;
    }

    /* Bind the listener socket */
    rval = bind(sock, &server.sa, SIZEOF_SOCKADDR(server));
    if (rval < 0) {
      SILC_LOG_DEBUG(("Cannot bind socket: %s", strerror(errno)));
      goto err;
    }

    /* Specify that we are listenning */
    rval = listen(sock, 64);
    if (rval < 0) {
      SILC_LOG_ERROR(("Cannot set socket listenning: %s", strerror(errno)));
      goto err;
    }

    /* Set the server socket to non-blocking mode */
    silc_net_set_socket_nonblock(sock);

    /* Schedule for incoming connections */
    silc_schedule_task_add_fd(schedule, sock, silc_net_accept, listener);

    SILC_LOG_DEBUG(("TCP listener created, fd=%d", sock));
    listener->socks[i] = sock;
    listener->socks_count++;
  }

  return listener;

 err:
  if (callback)
    callback(SILC_NET_ERROR, NULL, context);
  if (listener)
    silc_net_close_listener(listener);
  return NULL;
}

/* Close network listener */

void silc_net_close_listener(SilcNetListener listener)
{
  int i;

  SILC_LOG_DEBUG(("Closing network listener"));

  for (i = 0; i < listener->socks_count; i++) {
    silc_schedule_task_del_by_fd(listener->schedule, listener->socks[i]);
    shutdown(listener->socks[i], 2);
    close(listener->socks[i]);
  }

  silc_free(listener->socks);
  silc_free(listener);
}

/* Create UDP stream */

SilcStream
silc_net_udp_connect(const char *local_ip_addr, int local_port,
		     const char *remote_ip_addr, int remote_port,
		     SilcSchedule schedule)
{
  SilcStream stream;
  SilcSockaddr server;
  int sock = -1, rval;
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
  if (sock < 0) {
    SILC_LOG_ERROR(("Cannot create socket: %s", strerror(errno)));
    goto err;
  }

  /* Set the socket options */
  rval = silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
  if (rval < 0) {
    SILC_LOG_ERROR(("Cannot set socket options: %s", strerror(errno)));
    goto err;
  }
#ifdef SO_REUSEPORT
  rval = silc_net_set_socket_opt(sock, SOL_SOCKET, SO_REUSEPORT, 1);
  if (rval < 0) {
    SILC_LOG_ERROR(("Cannot set socket options: %s", strerror(errno)));
    goto err;
  }
#endif /* SO_REUSEPORT */

  /* Bind the listener socket */
  rval = bind(sock, &server.sa, SIZEOF_SOCKADDR(server));
  if (rval < 0) {
    SILC_LOG_DEBUG(("Cannot bind socket: %s", strerror(errno)));
    goto err;
  }

  /* Set socket to non-blocking mode */
  silc_net_set_socket_nonblock(sock);

  /* Set to connected state if remote address is provided. */
  if (remote_ip_addr && remote_port) {
    if (!silc_net_set_sockaddr(&server, remote_ip_addr, remote_port))
      goto err;

    rval = connect(sock, &server.sa, SIZEOF_SOCKADDR(server));
    if (rval < 0) {
      SILC_LOG_DEBUG(("Cannot connect UDP stream: %s", strerror(errno)));
      goto err;
    }
  }

  /* Set send and receive buffer size */
#ifdef SO_SNDBUF
  rval = silc_net_set_socket_opt(sock, SOL_SOCKET, SO_SNDBUF, 65535);
  if (rval < 0) {
    SILC_LOG_ERROR(("Cannot set socket options: %s", strerror(errno)));
    goto err;
  }
#endif /* SO_SNDBUF */
#ifdef SO_RCVBUF
  rval = silc_net_set_socket_opt(sock, SOL_SOCKET, SO_RCVBUF, 65535);
  if (rval < 0) {
    SILC_LOG_ERROR(("Cannot set socket options: %s", strerror(errno)));
    goto err;
  }
#endif /* SO_RCVBUF */

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
  int len, flen;

  SILC_LOG_DEBUG(("Reading data from UDP socket %d", sock->sock));

  if (remote_ip_addr && remote_port) {
    if (sock->ipv6) {
      from = (struct sockaddr *)&s.sin6;
      flen = sizeof(s.sin6);
    } else {
      from = (struct sockaddr *)&s.sin;
      flen = sizeof(s.sin);
    }
    len = recvfrom(sock->sock, ret_data, data_size, 0, from, &flen);
  } else
    len = recv(sock->sock, ret_data, data_size, 0);

  if (len < 0) {
    if (errno == EAGAIN || errno == EINTR) {
      SILC_LOG_DEBUG(("Could not read immediately, will do it later"));
      silc_schedule_set_listen_fd(sock->schedule, sock->sock,
				  SILC_TASK_READ, FALSE);
      return -1;
    }
    SILC_LOG_DEBUG(("Cannot read from UDP socket: %d:%s",
		    sock->sock, strerror(errno)));
    silc_schedule_unset_listen_fd(sock->schedule, sock->sock);
    sock->sock_error = errno;
    return -2;
  }

  SILC_LOG_DEBUG(("Read %d bytes", len));

  if (!len)
    silc_schedule_unset_listen_fd(sock->schedule, sock->sock);

  /* Return remote address */
  if (remote_ip_addr && remote_port) {
    if (sock->ipv6) {
      *remote_port = ntohs(s.sin6.sin6_port);
      inet_ntop(AF_INET6, &s.sin6.sin6_addr, remote_ip_addr,
		remote_ip_addr_size);
    } else {
      *remote_port = ntohs(s.sin.sin_port);
      inet_ntop(AF_INET, &s.sin.sin_addr, remote_ip_addr,
		remote_ip_addr_size);
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
  int ret;

  SILC_LOG_DEBUG(("Sending data to UDP socket %d", sock->sock));

  /* Set sockaddr */
  if (!silc_net_set_sockaddr(&remote, remote_ip_addr, remote_port))
    return -2;

  /* Send */
  ret = sendto(sock->sock, data, data_len, 0, &remote.sa,
	       SIZEOF_SOCKADDR(remote));
  if (ret < 0) {
    if (errno == EAGAIN || errno == EINTR) {
      SILC_LOG_DEBUG(("Could not send immediately, will do it later"));
      silc_schedule_set_listen_fd(sock->schedule, sock->sock,
				  SILC_TASK_READ | SILC_TASK_WRITE, FALSE);
      return -1;
    }
    SILC_LOG_DEBUG(("Cannot send to UDP socket: %s", strerror(errno)));
    silc_schedule_unset_listen_fd(sock->schedule, sock->sock);
    sock->sock_error = errno;
    return -2;
  }

  SILC_LOG_DEBUG(("Sent data %d bytes", ret));
  if (silc_schedule_get_fd_events(sock->schedule, sock->sock) &
      SILC_TASK_WRITE)
    silc_schedule_set_listen_fd(sock->schedule, sock->sock,
				SILC_TASK_READ, FALSE);

  return ret;
}

/* Asynchronous TCP/IP connecting */

typedef struct {
  SilcNetStatus status;
  SilcSocketStreamStatus stream_status;
  SilcStream stream;
  SilcFSMStruct fsm;
  SilcFSMEventStruct event;
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
SILC_FSM_STATE(silc_net_connect_st_connected);
SILC_FSM_STATE(silc_net_connect_st_stream);
SILC_FSM_STATE(silc_net_connect_st_finish);

SILC_TASK_CALLBACK(silc_net_connect_wait)
{
  SilcNetConnect conn = context;
  SILC_FSM_EVENT_SIGNAL(&conn->event);
}

SILC_FSM_STATE(silc_net_connect_st_start)
{
  SilcNetConnect conn = fsm_context;
  int sock, rval;
  SilcSockaddr desthost;
  SilcBool prefer_ipv6 = TRUE;

  if (conn->aborted) {
    /** Aborted */
    silc_fsm_next(fsm, silc_net_connect_st_finish);
    return SILC_FSM_CONTINUE;
  }

  /* Do host lookup */
 retry:
  if (!silc_net_gethostbyname(conn->remote, prefer_ipv6,
			      conn->ip_addr, sizeof(conn->ip_addr))) {
    SILC_LOG_ERROR(("Network (%s) unreachable: could not resolve the "
		    "host", conn->remote));

    /** Network unreachable */
    conn->status = SILC_NET_HOST_UNREACHABLE;
    silc_fsm_next(fsm, silc_net_connect_st_finish);
    return SILC_FSM_CONTINUE;
  }

  /* Set sockaddr for this connection */
  if (!silc_net_set_sockaddr(&desthost, conn->ip_addr, conn->port)) {
    /** Sockaddr failed */
    silc_fsm_next(fsm, silc_net_connect_st_finish);
    return SILC_FSM_CONTINUE;
  }

  /* Create the connection socket */
  sock = socket(desthost.sin.sin_family, SOCK_STREAM, 0);
  if (sock < 0) {
    /* If address is IPv6, then fallback to IPv4 and see whether we can do
       better with that on socket creation. */
    if (prefer_ipv6 && silc_net_is_ip6(conn->ip_addr)) {
      prefer_ipv6 = FALSE;
      goto retry;
    }

    /** Cannot create socket */
    SILC_LOG_ERROR(("Cannot create socket: %s", strerror(errno)));
    silc_fsm_next(fsm, silc_net_connect_st_finish);
    return SILC_FSM_CONTINUE;
  }

  /* Bind to the local address if provided */
  if (conn->local_ip) {
    SilcSockaddr local;

    /* Set sockaddr for local listener, and try to bind it. */
    if (silc_net_set_sockaddr(&local, conn->local_ip, 0))
      bind(sock, &local.sa, SIZEOF_SOCKADDR(local));
  }

  /* Set the socket to non-blocking mode */
  silc_net_set_socket_nonblock(sock);

  /* Connect to the host */
  rval = connect(sock, &desthost.sa, SIZEOF_SOCKADDR(desthost));
  if (rval < 0) {
    if (errno != EINPROGRESS) {
      /* retry using an IPv4 adress, if IPv6 didn't work */
      if (prefer_ipv6 && silc_net_is_ip6(conn->ip_addr)) {
        shutdown(sock, 2);
        close(sock);

        prefer_ipv6 = FALSE;
        goto retry;
      }

      shutdown(sock, 2);
      close(sock);

      /** Cannot connect to remote host */
      SILC_LOG_ERROR(("Cannot connect to remote host: %s", strerror(errno)));
      silc_fsm_next(fsm, silc_net_connect_st_finish);
      return SILC_FSM_CONTINUE;
    }
  }

  /* Set appropriate options */
#if defined(TCP_NODELAY)
  silc_net_set_socket_opt(sock, IPPROTO_TCP, TCP_NODELAY, 1);
#endif
  silc_net_set_socket_opt(sock, SOL_SOCKET, SO_KEEPALIVE, 1);

  SILC_LOG_DEBUG(("Connection operation in progress"));

  conn->sock = sock;

  /** Wait for connection */
  silc_fsm_next(fsm, silc_net_connect_st_connected);
  silc_fsm_event_init(&conn->event, fsm);
  silc_schedule_task_add_fd(silc_fsm_get_schedule(fsm), sock,
			    silc_net_connect_wait, conn);
  silc_schedule_set_listen_fd(silc_fsm_get_schedule(fsm), sock,
			      SILC_TASK_WRITE, FALSE);
  SILC_FSM_EVENT_WAIT(&conn->event);
  return SILC_FSM_CONTINUE;
}

static void silc_net_connect_wait_stream(SilcSocketStreamStatus status,
					 SilcStream stream, void *context)
{
  SilcNetConnect conn = context;
  conn->stream_status = status;
  conn->stream = stream;
  SILC_FSM_CALL_CONTINUE(&conn->fsm);
}

SILC_FSM_STATE(silc_net_connect_st_connected)
{
  SilcNetConnect conn = fsm_context;
  SilcSchedule schedule = silc_fsm_get_schedule(fsm);
  int opt = EINVAL, optlen = sizeof(opt), ret;

  if (conn->aborted) {
    /** Aborted */
    silc_schedule_unset_listen_fd(schedule, conn->sock);
    silc_schedule_task_del_by_fd(schedule, conn->sock);
    silc_fsm_next(fsm, silc_net_connect_st_finish);
    return SILC_FSM_CONTINUE;
  }

  ret = silc_net_get_socket_opt(conn->sock, SOL_SOCKET, SO_ERROR,
				&opt, &optlen);

  silc_schedule_unset_listen_fd(schedule, conn->sock);
  silc_schedule_task_del_by_fd(schedule, conn->sock);

  if (ret != 0 || opt != 0) {
    if (conn->retry) {
      /** Retry connecting */
      SILC_LOG_DEBUG(("Retry connecting"));
      conn->retry--;
      silc_net_close_connection(conn->sock);
      silc_fsm_next(fsm, silc_net_connect_st_start);
      return SILC_FSM_CONTINUE;
    }

#if defined(ECONNREFUSED)
    if (errno == ECONNREFUSED)
      conn->status = SILC_NET_CONNECTION_REFUSED;
#endif /* ECONNREFUSED */
#if defined(ETIMEDOUT)
    if (errno == ETIMEDOUT)
      conn->status = SILC_NET_CONNECTION_TIMEOUT;
#endif /* ETIMEDOUT */
#if defined(ENETUNREACH)
    if (errno == ENETUNREACH)
      conn->status = SILC_NET_HOST_UNREACHABLE;
#endif /* ENETUNREACH */

    /** Connecting failed */
    SILC_LOG_DEBUG(("Connecting failed"));
    silc_fsm_next(fsm, silc_net_connect_st_finish);
    return SILC_FSM_CONTINUE;
  }

  /** Connection created */
  silc_fsm_next(fsm, silc_net_connect_st_stream);
  SILC_FSM_CALL((conn->sop = silc_socket_tcp_stream_create(
				     conn->sock, FALSE, FALSE,
				     schedule,
				     silc_net_connect_wait_stream, conn)));
}

SILC_FSM_STATE(silc_net_connect_st_stream)
{
  SilcNetConnect conn = fsm_context;

  if (conn->aborted) {
    /** Aborted */
    silc_fsm_next(fsm, silc_net_connect_st_finish);
    return SILC_FSM_CONTINUE;
  }

  if (conn->stream_status != SILC_SOCKET_OK) {
    /** Stream creation failed */
    if (conn->stream_status == SILC_SOCKET_UNKNOWN_IP)
      conn->status = SILC_NET_UNKNOWN_IP;
    else if (conn->stream_status == SILC_SOCKET_UNKNOWN_HOST)
      conn->status = SILC_NET_UNKNOWN_HOST;
    else
      conn->status = SILC_NET_ERROR;
    silc_fsm_next(fsm, silc_net_connect_st_finish);
    return SILC_FSM_CONTINUE;
  }

  /* Set stream information */
  silc_socket_stream_set_info(conn->stream,
			      !silc_net_is_ip(conn->remote) ? conn->remote :
			      conn->ip_addr, conn->ip_addr, conn->port);

  /** Stream created successfully */
  SILC_LOG_DEBUG(("Connected successfully, sock %d", conn->sock));
  conn->status = SILC_NET_OK;
  silc_fsm_next(fsm, silc_net_connect_st_finish);
  return SILC_FSM_CONTINUE;
}

SILC_FSM_STATE(silc_net_connect_st_finish)
{
  SilcNetConnect conn = fsm_context;

  /* Deliver error or new stream */
  if (!conn->aborted) {
    conn->callback(conn->status, conn->stream, conn->context);
    if (conn->op)
      silc_async_free(conn->op);
    if (conn->sop)
      silc_async_free(conn->sop);
  }

  return SILC_FSM_FINISH;
}

static void silc_net_connect_abort(SilcAsyncOperation op, void *context)
{
  SilcNetConnect conn = context;
  conn->aborted = TRUE;

  /* Abort underlaying stream creation too */
  if (conn->sop)
    silc_async_abort(conn->op, NULL, NULL);
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

  if (!remote_ip_addr || remote_port < 1 || !schedule || !callback)
    return NULL;

  SILC_LOG_DEBUG(("Creating connection to host %s port %d",
		  remote_ip_addr, remote_port));

  conn = silc_calloc(1, sizeof(*conn));
  if (!conn) {
    callback(SILC_NET_NO_MEMORY, NULL, context);
    return NULL;
  }

  /* Start async operation */
  conn->op = silc_async_alloc(silc_net_connect_abort, NULL, conn);
  if (!conn->op) {
    silc_free(conn);
    callback(SILC_NET_NO_MEMORY, NULL, context);
    return NULL;
  }

  if (local_ip_addr)
    conn->local_ip = strdup(local_ip_addr);
  conn->remote = strdup(remote_ip_addr);
  if (!conn->remote) {
    silc_async_free(conn->op);
    silc_free(conn->local_ip);
    silc_free(conn);
    callback(SILC_NET_NO_MEMORY, NULL, context);
    return NULL;
  }
  conn->port = remote_port;
  conn->callback = callback;
  conn->context = context;
  conn->retry = 1;
  conn->status = SILC_NET_ERROR;

  silc_fsm_init(&conn->fsm, conn, silc_net_connect_destructor, NULL, schedule);
  silc_fsm_start(&conn->fsm, silc_net_connect_st_start);

  return conn->op;
}

/* Closes the connection by closing the socket connection. */

void silc_net_close_connection(int sock)
{
  SILC_LOG_DEBUG(("Closing sock %d", sock));
  close(sock);
}

/* Set's the socket to non-blocking mode. */

int silc_net_set_socket_nonblock(SilcSocket sock)
{
  return fcntl((int)sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
}

/* Converts the IP number string from numbers-and-dots notation to
   binary form. */

SilcBool silc_net_addr2bin(const char *addr, void *bin, SilcUInt32 bin_len)
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
    struct addrinfo hints, *ai;
    SilcSockaddr *s;

    /* IPv6 address */
    if (bin_len < 16)
      return FALSE;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    if (getaddrinfo(addr, NULL, &hints, &ai))
      return FALSE;

    if (ai) {
      s = (SilcSockaddr *)ai->ai_addr;
      memcpy(bin, &s->sin6.sin6_addr, sizeof(s->sin6.sin6_addr));
      freeaddrinfo(ai);
    }

    ret = TRUE;
#endif /* HAVE_IPV6 */
  }

  return ret != 0;
}
