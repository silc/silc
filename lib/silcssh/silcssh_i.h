/*

  silcssh_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCSSH_I_H
#define SILCSSH_I_H

#ifndef SILCSSH_H
#error "Do not include this header directly"
#endif

SilcHashTable silc_ssh_allocate_fields(void);
SilcBool silc_ssh_parse_line(SilcBuffer key, SilcBuffer line,
			     SilcBool cont);
SilcHashTable silc_ssh_parse_headers(SilcBuffer key);

#endif /* SILCSSH_I_H */
