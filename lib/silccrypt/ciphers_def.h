/*

  ciphers_def.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1999 - 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef CIPHERS_DEF_H
#define CIPHERS_DEF_H

/* General definitions for algorithms */
typedef unsigned char u1byte;
typedef uint32 u4byte;
typedef uint32 u32;

#define rotr(x, nr) (((x) >> ((int)(nr))) | ((x) << (32 - (int)(nr))))
#define rotl(x, nr) (((x) << ((int)(nr))) | ((x) >> (32 - (int)(nr))))
#define byte(x, nr) ((x) >> (nr * 8) & 255)

#endif
