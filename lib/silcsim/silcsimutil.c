/*

  silcsimutil.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2000 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"

#ifdef SILC_SIM			/* SIM support enabled */

static char symname[256];

/* This is used to produce the function names that are then get from
   SIM's. */

char *silc_sim_symname(char *symbol, char *function)
{
  int len1, len2, len3;

  len1 = strlen(symbol);
  len2 = strlen(function);
  len3 = strlen(SILC_SIM_SYMBOL_PREFIX);
  memset(symname, 0, sizeof(symname));
  silc_strncat(symname, sizeof(symname), SILC_SIM_SYMBOL_PREFIX, len3);
  silc_strncat(symname, sizeof(symname), "_", 1);
  silc_strncat(symname, sizeof(symname), symbol, len1);
  silc_strncat(symname, sizeof(symname), "_", 1);
  silc_strncat(symname, sizeof(symname), function, len2);

  return symname;
}

#endif /* SILC_SIM */
