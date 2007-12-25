/*

  silcgetopt.c

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

#include "silc.h"

/* Getopt, like getopt(3). */

int silc_getopt(int argc, char **argv, const char *optstring, SilcGetOpt op)
{
  register int c;
  register char *cp;
  SilcBool optional = FALSE, optional_found = FALSE;

  SILC_VERIFY(op);

  op->opt_arg = NULL;

  if (op->opt_sp == 1) {
    if (op->opt_index >= argc ||
	argv[op->opt_index][0] != '-' || argv[op->opt_index][1] == '\0') {
      return -1;
    } else if (strcmp(argv[op->opt_index], "--") == 0) {
      op->opt_index++;
      return -1;
    }
  }
  op->opt_option = c = argv[op->opt_index][op->opt_sp];

  if (c == ':' || (cp = strchr(optstring, c)) == NULL) {
    if (op->opt_error)
      fprintf(stderr, "%s: illegal option -- %c\n", argv[0], c);
    if (argv[op->opt_index][++op->opt_sp] == '\0') {
      op->opt_index++;
      op->opt_sp = 1;
    }
    return '?';
  }

  if (*++cp == ':') {
    /* Check for optional argument (::), must be written -oarg, not -o arg. */
    if (strlen(cp) && *(cp + 1) == ':') {
      optional = TRUE;
      if (argv[op->opt_index][op->opt_sp + 1] != '\0')
	optional_found = TRUE;
    }

    if (argv[op->opt_index][op->opt_sp + 1] != '\0')
      op->opt_arg = &argv[op->opt_index++][op->opt_sp + 1];
    else if (++op->opt_index >= argc) {
      if (!optional && !optional_found) {
	if (op->opt_error)
	  fprintf(stderr, "%s: option requires an argument -- %c\n",
		  argv[0], c);
	op->opt_sp = 1;
	return ':';
      }
    } else if (!optional || optional_found)
      op->opt_arg = argv[op->opt_index++];
    op->opt_sp = 1;
  } else {
    if (argv[op->opt_index][++op->opt_sp] == '\0') {
      op->opt_sp = 1;
      op->opt_index++;
    }
    op->opt_arg = NULL;
  }

  return c;
}
