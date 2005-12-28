/*

  silcmime_i.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SILCMIME_I_H
#define SILCMIME_I_H

#ifndef SILCMIME_H
#error "Do not include this header directly"
#endif

/* MIME context */
struct SilcMimeStruct {
  SilcHashTable fields;
  unsigned char *data;
  SilcUInt32 data_len;
  SilcDList multiparts;
  char *boundary;
  char *multitype;
};

/* MIME assembler */
struct SilcMimeAssemblerStruct {
  SilcHashTable fragments;
};

#endif /* SILCMIME_I_H */
