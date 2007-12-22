/*

  silcsocketstream_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 - 2007 Pekka Riikonen

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
  SilcSocketQos qos;
  SilcStreamNotifier notifier;
  void *notifier_context;
  SilcUInt16 port;
  unsigned int ipv6      : 1;       /* UDP IPv6 */
  unsigned int connected : 1;	    /* UDP connected state */
};

#define SILC_IS_SOCKET_STREAM(s) (s->ops == &silc_socket_stream_ops)
#define SILC_IS_SOCKET_STREAM_UDP(s) (s->ops == &silc_socket_udp_stream_ops)

extern const SilcStreamOps silc_socket_stream_ops;
extern const SilcStreamOps silc_socket_udp_stream_ops;

/* Backwards support */
#define silc_socket_stream_get_error(stream) silc_errno
#define SILC_SOCKET_OK SILC_OK
#define SILC_SOCKET_UNKNOWN_IP SILC_ERR_UNKNOWN_IP
#define SILC_SOCKET_UNKNOWN_HOST SILC_ERR_UNKNOWN_HOST
#define SILC_SOCKET_NO_MEMORY SILC_ERR_OUT_OF_MEMORY
#define SILC_SOCKET_ERROR SILC_ERR

#endif /* SILCSOCKETSTREAM_I_H */
