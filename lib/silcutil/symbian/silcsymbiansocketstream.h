/*

  silcsymbiansocketstream.h

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

#ifndef SILCSYMBIANSOCKETSTREAM_H
#define SILCSYMBIANSOCKETSTREAM_H

#include <e32std.h>
#include <es_sock.h>
#include <in_sock.h>

class SilcSymbianSocketSend;
class SilcSymbianSocketReceive;

/* Symbian Socket context */
typedef struct {
  SilcSymbianSocketSend *send;
  SilcSymbianSocketReceive *receive;
  RSocket *sock;
  RSocketServ *ss;
  SilcSocketStream stream;
  unsigned int eof          : 1;
  unsigned int error        : 1;
  unsigned int would_block  : 1;
} SilcSymbianSocket;

/* Creates symbian socket context.  This will steal the `sock' and `ss'. */
SilcSymbianSocket *silc_create_symbian_socket(RSocket *sock,
					      RSocketServ *ss);

#endif /* SILCSYMBIANSOCKETSTREAM_H */
