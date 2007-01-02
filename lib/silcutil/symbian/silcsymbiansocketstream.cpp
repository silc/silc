/*

  silcsymbiansocketstream.cpp

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/* In this implementation the sockets are in blocking mode, except that
   on Symbian the blocking mode is actually asynchronous, which semantically
   translates into non-blocking mode.  The non-blocking mode just is not
   explicitly set because it would require us also to explicitly poll for the
   socket, which is done automatically by the Active Scheduler in blocking
   mode. */

#include "silc.h"
#include "silcsymbiansocketstream.h"

/***************************** Socket Classes *******************************/

/* Socket stream sender */

class SilcSymbianSocketSend : public CActive {
public:
  /* Constructor */
  SilcSymbianSocketSend() : CActive(CActive::EPriorityStandard)
  {
    CActiveScheduler::Add(this);
  }

  /* Destructor */
  ~SilcSymbianSocketSend()
  {
    Cancel();
  }

  /* Send data */
  void Send(const TDesC8& buf, TSockXfrLength& ret_len)
  {
    s->sock->Send(buf, 0, iStatus, ret_len);
    SetActive();
  }

  /* Send data */
  void Send(const TDesC8& buf, TSockXfrLength& ret_len,
	    const char *remote_ip, int remote_port)
  {
    TInetAddr remote;
    TBuf<64> tmp;

    remote = TInetAddr(remote_port);
    tmp = (TText *)remote_ip;
    if (remote.Input(tmp) == KErrNone) {
      s->sock->SendTo(buf, remote, 0, iStatus, ret_len);
      SetActive();
    }
  }

  /* Sending callback */
  virtual void RunL()
  {
    if (iStatus != KErrNone) {
      if (iStatus == KErrEof)
	s->eof = 1;
      else
	s->error = 1;
      return;
    }

    /* Call stream callback */
    if (s->stream && s->stream->notifier)
      s->stream->notifier(s->stream, SILC_STREAM_CAN_WRITE,
			  s->stream->notifier_context);
  }

  /* Cancel */
  virtual void DoCancel()
  {
    s->sock->CancelWrite();
  }

  SilcSymbianSocket *s;
};

/* Socket stream receiver */

class SilcSymbianSocketReceive : public CActive {
public:
  /* Constructor */
  SilcSymbianSocketReceive() : CActive(CActive::EPriorityStandard)
  {
    CActiveScheduler::Add(this);
  }

  /* Destructor */
  ~SilcSymbianSocketReceive()
  {
    Cancel();
  }

  /* Read data */
  void Read()
  {
    if (!s->stream || s->stream->connected)
      s->sock->RecvOneOrMore(inbuf, 0, iStatus, inbuf_len);
    else
      s->sock->RecvFrom(inbuf, remote, 0, iStatus);
    SetActive();
  }

  /* Reading callback */
  virtual void RunL()
  {
    if (iStatus != KErrNone) {
      if (iStatus == KErrEof)
	s->eof = 1;
      else
	s->error = 1;
      return;
    }

    if (!inbuf_ptr)
      inbuf_ptr = inbuf.Ptr();
    inbuf_len = inbuf.Length();

    /* Call stream callback */
    if (s->stream && s->stream->notifier)
      s->stream->notifier(s->stream, SILC_STREAM_CAN_READ,
			  s->stream->notifier_context);

    /* Read more */
    Read();
  }

  /* Cancel */
  virtual void DoCancel()
  {
    s->sock->CancelRecv();
  }

  TBuf8<8192> inbuf;
  const unsigned char *inbuf_ptr;
  TSockXfrLength inbuf_len;
  SilcSymbianSocket *s;
  TInetAddr remote;
};

/* Creates symbian socket stream context */

SilcSymbianSocket *silc_create_symbian_socket(RSocket *sock,
					      RSocketServ *ss)
{
  SilcSymbianSocket *stream;

  stream = (SilcSymbianSocket *)silc_calloc(1, sizeof(*stream));
  if (!stream)
    return NULL;
  stream->sock = sock;
  stream->ss = ss;

  stream->send = new SilcSymbianSocketSend;
  if (!stream->send) {
    silc_free(stream);
    return NULL;
  }

  stream->receive = new SilcSymbianSocketReceive;
  if (!stream->receive) {
    delete stream->send;
    silc_free(stream);
    return NULL;
  }

  return stream;
}

/***************************** SILC Stream API ******************************/

/* Stream read operation */

int silc_socket_stream_read(SilcStream stream, unsigned char *buf,
			    SilcUInt32 buf_len)
{
  SilcSocketStream socket_stream = (SilcSocketStream)stream;
  SilcSymbianSocket *s = (SilcSymbianSocket *)socket_stream->sock;
  SilcSymbianSocketReceive *recv = s->receive;
  int len;

  if (s->error || !s->stream)
    return -2;
  if (s->eof)
    return 0;
  if (!recv->inbuf_len() || !recv->inbuf_ptr)
    return -1;

  len = recv->inbuf_len();
  if (buf_len < len)
    len = buf_len;

  /* Copy the read data */
  memcpy(buf, recv->inbuf_ptr, len);

  recv->inbuf_ptr = NULL;
  if (len < recv->inbuf_len())
    recv->inbuf_ptr += len;

  return len;
}

/* Stream write operation */

int silc_socket_stream_write(SilcStream stream, const unsigned char *data,
			     SilcUInt32 data_len)
{
  SilcSocketStream socket_stream = (SilcSocketStream)stream;
  SilcSymbianSocket *s = (SilcSymbianSocket *)socket_stream->sock;
  SilcSymbianSocketSend *send = s->send;
  TSockXfrLength ret_len;
  TPtrC8 write_buf(data, data_len);

  if (s->would_block)
    return -1;
  if (s->error || !s->stream)
    return -2;
  if (s->eof)
    return 0;

  /* Send data */
  send->Send(write_buf, ret_len);
  if (send->iStatus.Int() != KErrNone) {
    if (send->iStatus.Int() == KErrEof)
      return 0;
    return -2;
  }

  if (!ret_len())
    return -1;

  s->would_block = 0;
  if (ret_len() < data_len)
    s->would_block = 1;

  return ret_len();
}

/* Receive UDP packet, connected socket. */

int silc_socket_udp_stream_read(SilcStream stream, unsigned char *buf,
				SilcUInt32 buf_len)
{
  return silc_net_udp_receive(stream, NULL, 0, NULL, buf, buf_len);
}

/* Send UDP packet, connected socket. */

int silc_socket_udp_stream_write(SilcStream stream, const unsigned char *data,
				 SilcUInt32 data_len)
{
  SilcSocketStream sock = (SilcSocketStream)stream;

  /* In connectionless state check if remote IP and port is provided */
  if (!sock->connected && sock->ip && sock->port)
    return silc_net_udp_send(stream, sock->ip, sock->port, data, data_len);

  /* In connected state use normal writing to socket. */
  return silc_socket_stream_write(stream, data, data_len);
}

/* Receive UDP packet, connectionless socket */

int silc_net_udp_receive(SilcStream stream, char *remote_ip_addr,
			 SilcUInt32 remote_ip_addr_size, int *remote_port,
			 unsigned char *buf, SilcUInt32 buf_len)
{
  SilcSocketStream socket_stream = (SilcSocketStream)stream;
  SilcSymbianSocket *s = (SilcSymbianSocket *)socket_stream->sock;
  SilcSymbianSocketReceive *recv = s->receive;
  int len;

  if (s->eof)
    return 0;
  if (!recv->inbuf_len() || !recv->inbuf_ptr)
    return -1;

  len = recv->inbuf_len();
  if (buf_len < len)
    len = buf_len;

  /* Copy the read data */
  memcpy(buf, recv->inbuf_ptr, len);

  recv->inbuf_ptr = NULL;
  if (len < recv->inbuf_len())
    recv->inbuf_ptr += len;

  if (remote_ip_addr && remote_ip_addr_size && remote_port) {
    TBuf<64> ip;
    recv->remote.Output(ip);
    silc_strncat(remote_ip_addr, remote_ip_addr_size, (const char *)ip.Ptr(),
		 ip.Length());
    *remote_port = recv->remote.Port();
  }

  return len;
}

/* Send UDP packet, connectionless socket  */

int silc_net_udp_send(SilcStream stream,
		      const char *remote_ip_addr, int remote_port,
		      const unsigned char *data, SilcUInt32 data_len)
{
  SilcSocketStream socket_stream = (SilcSocketStream)stream;
  SilcSymbianSocket *s = (SilcSymbianSocket *)socket_stream->sock;
  SilcSymbianSocketSend *send = s->send;
  TSockXfrLength ret_len;
  TPtrC8 write_buf(data, data_len);

  if (s->would_block)
    return -1;
  if (s->eof)
    return 0;

  /* Send data */
  send->Send(write_buf, ret_len, remote_ip_addr, remote_port);
  if (send->iStatus.Int() != KErrNone) {
    if (send->iStatus.Int() == KErrEof)
      return 0;
    return -2;
  }

  if (!ret_len())
    return -1;

  s->would_block = 0;
  if (ret_len() < data_len)
    s->would_block = 1;

  return ret_len();
}

/* Closes socket */

SilcBool silc_socket_stream_close(SilcStream stream)
{
  SilcSocketStream socket_stream = (SilcSocketStream)stream;
  SilcSymbianSocket *s;

  if (!SILC_IS_SOCKET_STREAM(socket_stream) &&
      !SILC_IS_SOCKET_STREAM_UDP(socket_stream))
    return FALSE;

  s = (SilcSymbianSocket *)socket_stream->sock;
  s->sock->Close();

  return TRUE;
}

/* Destroys the stream */

void silc_socket_stream_destroy(SilcStream stream)
{
  SilcSocketStream socket_stream = (SilcSocketStream)stream;
  SilcSymbianSocket *s;

  if (!SILC_IS_SOCKET_STREAM(socket_stream) &&
      !SILC_IS_SOCKET_STREAM_UDP(socket_stream))
    return;

  s = (SilcSymbianSocket *)socket_stream->sock;

  silc_socket_stream_close(stream);
  silc_free(socket_stream->ip);
  silc_free(socket_stream->hostname);
  silc_free(socket_stream);
  delete s->send;
  delete s->receive;
  delete s->sock;
  if (s->ss) {
    s->ss->Close();
    delete s->ss;
  }
  silc_free(s);
}

/* Sets stream notification callback for the stream */

void silc_socket_stream_notifier(SilcStream stream,
				 SilcSchedule schedule,
				 SilcStreamNotifier callback,
				 void *context)
{
  SilcSocketStream socket_stream = (SilcSocketStream)stream;
  SilcSymbianSocket *s;

  if (!SILC_IS_SOCKET_STREAM(socket_stream) &&
      !SILC_IS_SOCKET_STREAM_UDP(socket_stream))
    return;

  s = (SilcSymbianSocket *)socket_stream->sock;
  if (callback)
    s->stream = socket_stream;
  else
    s->stream = NULL;

  socket_stream->notifier = callback;
  socket_stream->notifier_context = context;
  socket_stream->schedule = schedule;
}
