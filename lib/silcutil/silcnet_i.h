/*

  silcnet_i.h

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

#ifndef SILCNET_I_H
#define SILCNET_I_H

#ifndef SILCNET_H
#error "Do not include this header directly"
#endif

/* Net listener context */
struct SilcNetListenerStruct {
  SilcSchedule schedule;
  SilcNetCallback callback;
  void *context;
  SilcSocket *socks;
  unsigned int socks_count   : 30;
  unsigned int require_fqdn  : 1;
  unsigned int lookup        : 1;
};

/* Backwards support */
#define SilcNetStatus SilcResult
#define silc_net_get_error_string silc_errno_string
#define SILC_NET_OK SILC_OK
#define SILC_NET_UNKNOWN_IP SILC_ERR_UNKNOWN_IP
#define SILC_NET_UNKNOWN_HOST SILC_ERR_UNKNOWN_HOST
#define SILC_NET_HOST_UNREACHABLE SILC_ERR_UNREACHABLE
#define SILC_NET_CONNECTION_REFUSED SILC_ERR_REFUSED
#define SILC_NET_CONNECTION_TIMEOUT SILC_ERR_TIMEOUT
#define SILC_NET_NO_MEMORY SILC_ERR_OUT_OF_MEMORY
#define SILC_NET_ERROR SILC_ERR

#endif /* SILCNET_I_H */
