/*

  data.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef DATA_H
#define DATA_H

/* Bitmap context */
typedef struct {
  char width;
  char height;
  unsigned char data[32 * 32];
} MapBitmap;

/* Circle */
const MapBitmap silc_map_circle =
{
  6, 7,
  {  0,  1,  1,  1,  1,  0,
     1,  0,  0,  0,  0,  1,
     1,  0,  0,  0,  0,  1,
     1,  0,  0,  0,  0,  1,
     1,  0,  0,  0,  0,  1,
     1,  0,  0,  0,  0,  1,
     0,  1,  1,  1,  1,  0
  }
};

/* Rectangle */
const MapBitmap silc_map_rectangle =
{
  6, 7,
  {  1,  1,  1,  1,  1,  1,
     1,  0,  0,  0,  0,  1,
     1,  0,  0,  0,  0,  1,
     1,  0,  0,  0,  0,  1,
     1,  0,  0,  0,  0,  1,
     1,  0,  0,  0,  0,  1,
     1,  1,  1,  1,  1,  1
  }
};

#endif /* DATA_H */
