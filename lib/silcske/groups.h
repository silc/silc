/*

  groups.h

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef GROUPS_H
#define GROUPS_H

#include "silcske_status.h"
#include "groups_internal.h"

/* Forward declaration */
typedef struct SilcSKEDiffieHellmanGroupStruct *SilcSKEDiffieHellmanGroup;

/* List of defined groups. */
extern const struct SilcSKEDiffieHellmanGroupDefStruct silc_ske_groups[];

/* Prototypes */
SilcSKEStatus silc_ske_get_group_by_number(int number,
					   SilcSKEDiffieHellmanGroup *ret);
SilcSKEStatus silc_ske_get_group_by_name(const char *name,
					 SilcSKEDiffieHellmanGroup *ret);
char *silc_ske_get_supported_groups();

#endif
