/*

  silcsymbiannet.cpp

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"
#include "silcsymbiansocketstream.h"

/****************************** TCP Listener ********************************/

class SilcSymbianTCPListener;

/* Deliver new stream to upper layer */

static void silc_net_accept_stream(SilcSocketStreamStatus status,
				   SilcStream stream, void *context)
{
  SilcNetListener listener = (SilcNetListener)context;

  /* In case of error, the socket has been destroyed already */
  if (status != SILC_SOCKET_OK)
    return;

  listener->callback(SILC_NET_OK, stream, listener->context);
}

/* TCP Listener class */

class SilcSymbianTCPListener : public CActive {
public:
  /* Constructor */
  SilcSymbianTCPListener() : CActive(CActive::EPriorityStandard)
  {
    CActiveScheduler::Add(this);
  }

  /* Destructor */
  ~SilcSymbianTCPListener()
  {
    Cancel();
  }

  /* Listen for connection */
  void Listen()
  {
    new_conn = new RSocket;
    if (!new_conn)
      return;
    User::LeaveIfError(new_conn->Open(ss));

    /* Start listenning */
    sock.Accept(*new_conn, iStatus);
    SetActive();
  }

  /* Listener callback */
  void RunL()
  {
    if (iStatus != KErrNone) {
      if (new_conn)
	delete new_conn;
      new_conn = NULL;
      Listen();
      return;
    }

    /* Set socket options */
    new_conn->SetOpt(KSoReuseAddr, KSolInetIp, 1);

    /* Create socket stream */
    silc_socket_tcp_stream_create(
		        (SilcSocket)silc_create_symbian_socket(new_conn, NULL),
			listener->lookup, listener->require_fqdn,
			listener->schedule, silc_net_accept_stream,
			(void *)listener);

    /* Continue listenning */
    Listen();
  }

  /* Cancel */
  void DoCancel()
  {
    sock.CancelAll();
    ss.Close();
    if (new_conn)
      delete new_conn;
  }

  RSocket *new_conn;
  RSocket sock;
  RSocketServ ss;
  SilcNetListener listener;
};

/* Create TCP listener */

SilcNetListener
silc_net_tcp_create_listener(const char **local_ip_addr,
			     SilcUInt32 local_ip_count, int port,
			     SilcBool lookup, SilcBool require_fqdn,
			     SilcSchedule schedule,
			     SilcNetCallback callback, void *context)
{
  SilcNetListener listener = NULL;
  SilcSymbianTCPListener *l = NULL;
  TInetAddr server;
  TInt ret;
  TBuf<64> tmp;
  int i;

  SILC_LOG_DEBUG(("Creating TCP listener"));

  if (port < 0 || !schedule || !callback)
    goto err;

  listener = (SilcNetListener)silc_calloc(1, sizeof(*listener));
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
    listener->socks = (SilcSocket *)silc_calloc(local_ip_count,
					      sizeof(*listener->socks));
    if (!listener->socks) {
      callback(SILC_NET_NO_MEMORY, NULL, context);
      return NULL;
    }
  } else {
    listener->socks = (SilcSocket *)silc_calloc(1, sizeof(*listener->socks));
    if (!listener->socks) {
      callback(SILC_NET_NO_MEMORY, NULL, context);
      return NULL;
    }

    local_ip_count = 1;
  }

  /* Bind to local addresses */
  for (i = 0; i < local_ip_count; i++) {
    SILC_LOG_DEBUG(("Binding to local address %s",
		    local_ip_addr ? local_ip_addr[i] : "0.0.0.0"));

    l = new SilcSymbianTCPListener;
    if (!l)
      goto err;

    /* Connect to socket server */
    ret = l->ss.Connect();
    if (ret != KErrNone)
      goto err;

    /* Set listener address */
    if (local_ip_addr) {
      server = TInetAddr(port);
	  tmp = (TText *)local_ip_addr[i];
      ret = server.Input(tmp);
      if (ret != KErrNone)
	goto err;
    } else {
      server = TInetAddr(KInetAddrAny, port);
    }

    /* Create the socket */
    ret = l->sock.Open(l->ss, KAfInet, KSockStream, KProtocolInetTcp);
    if (ret != KErrNone) {
      SILC_LOG_ERROR(("Cannot create socket"));
      goto err;
    }

    /* Set the socket options */
    ret = l->sock.SetOpt(KSoReuseAddr, KSolInetIp, 1);
    if (ret != KErrNone) {
      SILC_LOG_ERROR(("Cannot set socket options"));
      goto err;
    }

    /* Bind the listener socket */
    ret = l->sock.Bind(server);
    if (ret != KErrNone) {
      SILC_LOG_DEBUG(("Cannot bind socket"));
      goto err;
    }

    /* Specify that we are listenning */
    ret = l->sock.Listen(5);
    if (ret != KErrNone) {
      SILC_LOG_ERROR(("Cannot set socket listenning"));
      goto err;
    }
    l->Listen();

    l->listener = listener;
    listener->socks[i] = (SilcSocket)l;
    listener->socks_count++;
  }

  SILC_LOG_DEBUG(("TCP listener created"));

  return listener;

 err:
  if (l)
    delete l;
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
    SilcSymbianTCPListener *l = (SilcSymbianTCPListener *)listener->socks[i];
    l->sock.CancelAll();
    l->sock.Close();
    l->ss.Close();
    if (l->new_conn)
      delete l->new_conn;
    delete l;
  }

  silc_free(listener->socks);
  silc_free(listener);
}

/**************************** TCP/IP connecting *****************************/

static void silc_net_connect_stream(SilcSocketStreamStatus status,
				    SilcStream stream, void *context);

/* TCP connecting class */

class SilcSymbianTCPConnect : public CActive {
public:
  /* Constructor */
  SilcSymbianTCPConnect() : CActive(CActive::EPriorityStandard)
  {
    CActiveScheduler::Add(this);
  }

  /* Destructor */
  ~SilcSymbianTCPConnect()
  {
    silc_free(remote);
    if (op)
      silc_async_free(op);
    Cancel();
  }

  /* Connect to remote host */
  void Connect(TSockAddr &addr)
  {
    sock->Connect(addr, iStatus);
    SetActive();
  }

  /* Connection callback */
  void RunL()
  {
    if (iStatus != KErrNone) {
      if (callback)
	callback(SILC_NET_ERROR, NULL, context);
      sock->CancelConnect();
      delete sock;
      ss->Close();
      delete ss;
      delete this;
    }

    /* Create stream */
    if (callback) {
      silc_socket_tcp_stream_create(
			     (SilcSocket)silc_create_symbian_socket(sock, ss),
			     FALSE, FALSE, schedule, silc_net_connect_stream,
			     (void *)this);
    } else {
      sock->Close();
      delete sock;
      ss->Close();
      delete ss;
    }

    delete this;
  }

  /* Cancel */
  void DoCancel()
  {
    sock->CancelConnect();
    ss->Close();
    delete ss;
    delete sock;
    delete this;
  }

  RSocket *sock;
  RSocketServ *ss;
  char *remote;
  char remote_ip[64];
  int port;
  SilcAsyncOperation op;
  SilcSchedule schedule;
  SilcNetCallback callback;
  void *context;
};

/* Stream creation callback */

static void silc_net_connect_stream(SilcSocketStreamStatus status,
				    SilcStream stream, void *context)
{
  SilcSymbianTCPConnect *conn = (SilcSymbianTCPConnect *)context;
  SilcNetStatus net_status = SILC_NET_OK;

  if (status != SILC_SOCKET_OK) {
    /* In case of error, the socket has been destroyed already */
    if (status == SILC_SOCKET_UNKNOWN_IP)
      net_status = SILC_NET_UNKNOWN_IP;
    else if (status == SILC_SOCKET_UNKNOWN_HOST)
      net_status = SILC_NET_UNKNOWN_HOST;
    else
      net_status = SILC_NET_ERROR;
  }

  /* Set stream information */
  if (stream && conn->callback)
    silc_socket_stream_set_info(stream,
				!silc_net_is_ip(conn->remote) ? conn->remote :
				conn->remote_ip, conn->remote_ip, conn->port);

  /* Call connection callback */
  if (conn->callback)
    conn->callback(net_status, stream, conn->context);
  else if (stream)
    silc_stream_destroy(stream);

  delete conn;
}

/* Connecting abort callback */

static void silc_net_connect_abort(SilcAsyncOperation op, void *context)
{
  SilcSymbianTCPConnect *conn = (SilcSymbianTCPConnect *)context;

  /* Abort */
  conn->callback = NULL;
  conn->op = NULL;
  conn->DoCancel();
}

/* Create TCP/IP connection */

SilcAsyncOperation silc_net_tcp_connect(const char *local_ip_addr,
					const char *remote_ip_addr,
					int remote_port,
					SilcSchedule schedule,
					SilcNetCallback callback,
					void *context)
{
  SilcSymbianTCPConnect *conn;
  TInetAddr local, remote;
  SilcNetStatus status;
  TBuf<64> tmp;
  TInt ret;

  if (!remote_ip_addr || remote_port < 1 || !schedule || !callback)
    return NULL;

  SILC_LOG_DEBUG(("Creating connection to host %s port %d",
		  remote_ip_addr, remote_port));

  conn = new SilcSymbianTCPConnect;
  if (!conn) {
    callback(SILC_NET_NO_MEMORY, NULL, context);
    return NULL;
  }
  conn->schedule = schedule;
  conn->callback = callback;
  conn->context = context;
  conn->port = remote_port;
  conn->remote = strdup(remote_ip_addr);
  if (!conn->remote) {
    status = SILC_NET_NO_MEMORY;
    goto err;
  }

  /* Allocate socket */
  conn->sock = new RSocket;
  if (!conn->sock) {
    status = SILC_NET_NO_MEMORY;
    goto err;
  }

  /* Allocate socket server */
  conn->ss = new RSocketServ;
  if (!conn->ss) {
    status = SILC_NET_NO_MEMORY;
    goto err;
  }

  /* Connect to socket server */
  ret = conn->ss->Connect();
  if (ret != KErrNone) {
    status = SILC_NET_ERROR;
    goto err;
  }

  /* Start async operation */
  conn->op = silc_async_alloc(silc_net_connect_abort, NULL, (void *)conn);
  if (!conn->op) {
    status = SILC_NET_NO_MEMORY;
    goto err;
  }

  /* Do host lookup */
  if (!silc_net_is_ip(remote_ip_addr)) {
    if (!silc_net_gethostbyname(remote_ip_addr, FALSE, conn->remote_ip,
				sizeof(conn->remote_ip))) {
      SILC_LOG_ERROR(("Network (%s) unreachable: could not resolve the "
		      "host", conn->remote));
      status = SILC_NET_HOST_UNREACHABLE;
      goto err;
    }
  } else {
    strcpy(conn->remote_ip, remote_ip_addr);
  }

  /* Create the connection socket */
  ret = conn->sock->Open(*conn->ss, KAfInet, KSockStream, KProtocolInetTcp);
  if (ret != KErrNone) {
    SILC_LOG_ERROR(("Cannot create socket"));
    status = SILC_NET_ERROR;
    goto err;
  }

  /* Set appropriate options */
  conn->sock->SetOpt(KSoTcpNoDelay, KSolInetTcp, 1);
  conn->sock->SetOpt(KSoTcpKeepAlive, KSolInetTcp, 1);

  /* Bind to the local address if provided */
  if (local_ip_addr) {
    local = TInetAddr(0);
	tmp = (TText *)local_ip_addr;
    ret = local.Input(tmp);
    if (ret == KErrNone)
      ret = conn->sock->Bind(local);
  }

  /* Connect to the host */
  remote = TInetAddr(remote_port);
  tmp = (TText *)conn->remote_ip;
  ret = remote.Input(tmp);
  if (ret != KErrNone) {
    SILC_LOG_ERROR(("Cannot connect (cannot set address)"));
    status = SILC_NET_ERROR;
    goto err;
  }
  conn->Connect(remote);

  SILC_LOG_DEBUG(("Connection operation in progress"));

  return conn->op;

 err:
  if (conn->ss) {
    conn->ss->Close();
    delete conn->ss;
  }
  if (conn->sock)
    delete conn->sock;
  if (conn->remote)
    silc_free(conn->remote);
  if (conn->op)
    silc_async_free(conn->op);
  callback(status, NULL, context);
  delete conn;
  return NULL;
}

/****************************** UDP routines ********************************/

/* Create UDP/IP connection */

SilcStream silc_net_udp_connect(const char *local_ip_addr, int local_port,
				const char *remote_ip_addr, int remote_port,
				SilcSchedule schedule)
{
  SilcSymbianSocket *s;
  SilcStream stream;
  TInetAddr local, remote;
  TRequestStatus status;
  RSocket *sock = NULL;
  RSocketServ *ss = NULL;
  TBuf<64> tmp;
  TInt ret;

  SILC_LOG_DEBUG(("Creating UDP stream"));

  if (!schedule)
    goto err;

  SILC_LOG_DEBUG(("Binding to local address %s",
		  local_ip_addr ? local_ip_addr : "0.0.0.0"));

  sock = new RSocket;
  if (!sock)
    goto err;

  ss = new RSocketServ;
  if (!ss)
    goto err;

  /* Open socket server */
  ret = ss->Connect();
  if (ret != KErrNone)
    goto err;

  /* Get local bind address */
  if (local_ip_addr) {
    local = TInetAddr(local_port);
	tmp = (TText *)local_ip_addr;
    ret = local.Input(tmp);
    if (ret != KErrNone)
      goto err;
  } else {
    local = TInetAddr(KInetAddrAny, local_port);
  }

  /* Create the socket */
  ret = sock->Open(*ss, KAfInet, KSockDatagram, KProtocolInetUdp);
  if (ret != KErrNone) {
    SILC_LOG_ERROR(("Cannot create socket"));
    goto err;
  }

  /* Set the socket options */
  sock->SetOpt(KSoReuseAddr, KSolInetIp, 1);

  /* Bind the listener socket */
  ret = sock->Bind(local);
  if (ret != KErrNone) {
    SILC_LOG_DEBUG(("Cannot bind socket"));
    goto err;
  }

  /* Set to connected state if remote address is provided. */
  if (remote_ip_addr && remote_port) {
    remote = TInetAddr(remote_port);
	tmp = (TText *)remote_ip_addr;
    ret = remote.Input(tmp);
    if (ret != KErrNone)
      goto err;

    sock->Connect(remote, status);
    if (status != KErrNone) {
      SILC_LOG_DEBUG(("Cannot connect UDP stream"));
      goto err;
    }
  }

  /* Encapsulate into socket stream */
  s = silc_create_symbian_socket(sock, ss);
  if (!s)
    goto err;
  stream =
    silc_socket_udp_stream_create((SilcSocket)s, local_ip_addr ?
				  silc_net_is_ip6(local_ip_addr) : FALSE,
				  remote_ip_addr ? TRUE : FALSE, schedule);
  if (!stream)
    goto err;

  SILC_LOG_DEBUG(("UDP stream created, fd=%d", sock));
  return stream;

 err:
  if (sock)
    delete sock;
  if (ss) {
    ss->Close();
    delete ss;
  }
  return NULL;
}

/* Sets socket to non-blocking mode */

int silc_net_set_socket_nonblock(SilcSocket sock)
{
  /* Nothing to do in Symbian where blocking socket mode is asynchronous
     already (ie. non-blocking). */
  return 0;
}

/* Converts the IP number string from numbers-and-dots notation to
   binary form. */

SilcBool silc_net_addr2bin(const char *addr, void *bin, SilcUInt32 bin_len)
{
  int ret = 0;

  struct in_addr tmp;
  ret = inet_aton(addr, &tmp);
  if (bin_len < 4)
    return FALSE;

  memcpy(bin, (unsigned char *)&tmp.s_addr, 4);

  return ret != 0;
}

/* Get remote host and IP from socket */

SilcBool silc_net_check_host_by_sock(SilcSocket sock, char **hostname,
				     char **ip)
{
  SilcSymbianSocket *s = (SilcSymbianSocket *)sock;
  TInetAddr addr;
  char host[256];
  TBuf<64> tmp;

  if (hostname)
    *hostname = NULL;
  *ip = NULL;

  s->sock->RemoteName(addr);
  addr.Output(tmp);

  *ip = (char *)silc_memdup(tmp.Ptr(), tmp.Length());
  if (*ip == NULL)
    return FALSE;

  /* Do reverse lookup if we want hostname too. */
  if (hostname) {
    /* Get host by address */
    if (!silc_net_gethostbyaddr(*ip, host, sizeof(host)))
      return FALSE;

    *hostname = (char *)silc_memdup(host, strlen(host));
    SILC_LOG_DEBUG(("Resolved hostname `%s'", *hostname));

    /* Reverse */
    if (!silc_net_gethostbyname(*hostname, TRUE, host, sizeof(host)))
      return FALSE;

    if (strcmp(*ip, host))
      return FALSE;
  }

  SILC_LOG_DEBUG(("Resolved IP address `%s'", *ip));
  return TRUE;
}

/* Get local host and IP from socket */

SilcBool silc_net_check_local_by_sock(SilcSocket sock, char **hostname,
				      char **ip)
{
  SilcSymbianSocket *s = (SilcSymbianSocket *)sock;
  TInetAddr addr;
  char host[256];
  TBuf<64> tmp;

  if (hostname)
    *hostname = NULL;
  *ip = NULL;

  s->sock->LocalName(addr);
  addr.Output(tmp);

  *ip = (char *)silc_memdup(tmp.Ptr(), tmp.Length());
  if (*ip == NULL)
    return FALSE;

  /* Do reverse lookup if we want hostname too. */
  if (hostname) {
    /* Get host by address */
    if (!silc_net_gethostbyaddr(*ip, host, sizeof(host)))
      return FALSE;

    *hostname = (char *)silc_memdup(host, strlen(host));
    SILC_LOG_DEBUG(("Resolved hostname `%s'", *hostname));

    /* Reverse */
    if (!silc_net_gethostbyname(*hostname, TRUE, host, sizeof(host)))
      return FALSE;

    if (strcmp(*ip, host))
      return FALSE;
  }

  SILC_LOG_DEBUG(("Resolved IP address `%s'", *ip));
  return TRUE;
}

/* Get remote port from socket */

SilcUInt16 silc_net_get_remote_port(SilcSocket sock)
{
  SilcSymbianSocket *s = (SilcSymbianSocket *)sock;
  TInetAddr addr;

  s->sock->RemoteName(addr);
  return (SilcUInt16)addr.Port();
}

/* Get local port from socket */

SilcUInt16 silc_net_get_local_port(SilcSocket sock)
{
  SilcSymbianSocket *s = (SilcSymbianSocket *)sock;
  TInetAddr addr;

  s->sock->LocalName(addr);
  return (SilcUInt16)addr.Port();
}
