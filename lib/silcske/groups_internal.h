/*

  groups_internal.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2000 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef GROUPS_INTERNAL_H
#define GROUPS_INTERNAL_H

/* Diffie Hellman Group. Defines the group name, prime, largest prime 
   factor (group order) and generator. */
struct SilcSKEDiffieHellmanGroupDefStruct {
  int number;
  char *name;
  char *group;
  char *group_order;
  char *generator;
};

struct SilcSKEDiffieHellmanGroupStruct {
  int number;
  char *name;
  SilcMPInt group;
  SilcMPInt group_order;
  SilcMPInt generator;
};

#endif
