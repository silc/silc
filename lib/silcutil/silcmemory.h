/*

  silcmemory.h

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

#ifndef SILCMEMORY_H
#define SILCMEMORY_H

/* Prototypes */
void *silc_malloc(size_t size);
void *silc_calloc(size_t items, size_t size);
void *silc_realloc(void *ptr, size_t size);
void silc_free(void *ptr);

#endif
