/*

  silcsimutil.c

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

#include "silcincludes.h"

#ifdef SILC_SIM			/* SIM support enabled */

/* This puts two arguments together and returns a new allocated string.
   This is used to produce the function names that are then get from
   SIM's. */

char *silc_sim_symname(char *symbol, char *function)
{
  char *ret;
  int len1, len2, len3;

  len1 = strlen(symbol);
  len2 = strlen(function);
  len3 = strlen(SILC_SIM_SYMBOL_PREFIX);
  ret = silc_calloc(len1 + len2 + len3 + 2 + 1, sizeof(char));

  strncpy(ret, SILC_SIM_SYMBOL_PREFIX, len3);
  strncat(ret, "_", 1);
  strncat(ret, symbol, len1);
  strncat(ret, "_", 1);
  strncat(ret, function, len2);

  return ret;
}

#endif /* SILC_SIM */
