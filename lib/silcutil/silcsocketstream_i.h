/*

  silcsocketstream_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 - 2008 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCSOCKETSTREAM_I_H
#define SILCSOCKETSTREAM_I_H

#ifndef SILCSOCKETSTREAM_H
#error "Do not include this header directly"
#endif

typedef struct SilcSocketStreamStruct *SilcSocketStream;

/* Qos context */
typedef struct SilcSocketQosStruct {
  SilcUInt16 read_limit_bytes;	    /* Max read bytes */
  SilcUInt16 read_rate;		    /* Max read rate/second */
  SilcUInt16 limit_sec;		    /* Limit seconds */
  SilcUInt32 limit_usec;	    /* Limit microseconds */
  struct timeval next_limit;
  unsigned int cur_rate : 31;
  unsigned int applied  : 1;
  SilcUInt32 data_len;
  unsigned char *buffer;
  SilcSocketStream sock;
} *SilcSocketQos;

/* SILC Socket Stream context */
struct SilcSocketStreamStruct {
  const SilcStreamOps *ops;
  SilcSchedule schedule;
  SilcSocket sock;
  char *hostname;
  char *ip;
  SilcUInt16 port;
  SilcUInt16 sock_error;
  SilcSocketQos qos;
  SilcStreamNotifier notifier;
  void *notifier_context;
  void *user_context;
  unsigned int ipv6      : 1;       /* UDP IPv6 */
  unsigned int connected : 1;	    /* UDP connected state */
};

#define SILC_IS_SOCKET_STREAM(s) (s && s->ops == &silc_socket_stream_ops)
#define SILC_IS_SOCKET_STREAM_UDP(s) (s && s->ops == &silc_socket_udp_stream_ops)

extern const SilcStreamOps silc_socket_stream_ops;
extern const SilcStreamOps silc_socket_udp_stream_ops;

#endif /* SILCSOCKETSTREAM_I_H */
