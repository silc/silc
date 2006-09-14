/*

  silcnet_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 - 2006 Pekka Riikonen

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

/* Net listenrr context */
struct SilcNetListenerStruct {
  SilcSchedule schedule;
  SilcNetCallback callback;
  void *context;
  int *socks;
  unsigned int socks_count   : 30;
  unsigned int require_fqdn  : 1;
  unsigned int lookup        : 1;
};

#endif /* SILCNET_I_H */
