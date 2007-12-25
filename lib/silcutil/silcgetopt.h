/*

  silcgetopt.h

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

#ifndef SILCGETOPT_H
#define SILCGETOPT_H

/****s* silcutil/SilcGetOptAPI/SilcGetOpt
 *
 * NAME
 *
 *    typedef struct SilcGetOptObject { ... } *SilcGetOpt, SilcGetOptStruct;
 *
 * DESCRIPTION
 *
 *    Command line option parsers structure given to silc_getopt as argument.
 *    It contains the current parsed command line option data.
 *
 * SOURCE
 */
typedef struct SilcGetOptObject {
  int opt_index;		/* Current option index in argv[] array */
  int opt_option;		/* Current option character */
  char *opt_arg;		/* Current parsed option argument */
  SilcBool opt_error;		/* Set this to TRUE to make silc_getopt print
				   errors or FALSE to suppress them. */

  SilcUInt16 opt_sp;		/* Internal parser index */
} *SilcGetOpt, SilcGetOptStruct;
/***/

/****d* silcutil/SilcGetOptAPI/SILC_GETOPT_INIT
 *
 * NAME
 *
 *    #define SILC_GETOPT_INIT ...
 *
 * DESCRIPTION
 *
 *    Macro used to initialize SilcGetOptStruct before calling silc_getopt.
 *
 * EXAMPLE
 *
 *    SilcGetOptStruct op = SILC_GETOPT_INIT;
 *
 ***/
#define SILC_GETOPT_INIT { 1, 0, NULL, TRUE, 1 }

/****f* silcutil/SilcGetOptAPI/silc_getopt
 *
 * SYNOPSIS
 *
 *    int silc_getopt(int argc, char **argv, const char *optstring,
 *                    SilcGetOpt op)
 *
 * DESCRIPTION
 *
 *    Parses comand line options.  This function is equivalent to getopt(3).
 *    Returns the current parsed option, '?' if option was unknown, ':' if
 *    required argument was missing or -1 after all options have been parsed.
 *    If options require arguments they are available from the `op' structure,
 *    to where the options are parsed.  The parsing is stopped immediately
 *    when first non-option character, which is not an argument for an option,
 *    is encountered.
 *
 *    The `optstring' contains the supported option characters.  One character
 *    per option is required.  If colon (':') follows option character the
 *    option requires an argument.  If two colons ('::') follows option
 *    character the argument is optional.  In that case the argument must
 *    follow the option in command line, for example -oarg, instead of -o arg.
 *
 * EXAMPLE
 *
 *    int main(int argc, char **argv)
 *    {
 *      SilcGetOptStruct op = SILC_GETOPT_INIT;
 *
 *      while ((option = silc_getopt(argc, argv, "ab:t::", &op)) != -1) {
 *        switch (option) {
 *          case 'a':
 *            ...
 *            break;
 *          case 'b':
 *            argument = silc_strdup(op.opt_arg);
 *            break;
 *          case 't':
 *            if (op.opt_arg)
 *              optional_argument = silc_strdup(op.opt_arg);
 *            break;
 *          default:
 *            exit(1);
 *            break;
 *        }
 *      }
 *    }
 *
 ***/
int silc_getopt(int argc, char **argv, const char *optstring, SilcGetOpt op);

#endif /* SILCGETOPT_H */
