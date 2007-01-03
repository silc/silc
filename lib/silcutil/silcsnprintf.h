/*

  silcsnprintf.h

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

/****h* silcutil/Snprintf
 *
 * DESCRIPTION
 *
 * Platform independent version of snprintf and other similar string
 * formatting routines.
 *
 ***/

#ifndef SILCSNPRINTF_H
#define SILCSNPRINTF_H

/****f* silcutil/SilcSnprintf/silc_snprintf
 *
 * SYNOPSIS
 *
 *    int silc_snprintf(char *str, size_t count, const char *fmt, ...);
 *
 * DESCRIPTION
 *
 *    Outputs string into `str' of maximum of size `count' including the
 *    trailing '\0' according to the `fmt'.  The `fmt' is equivalent to
 *    snprintf(3) and printf(3) formatting.  Returns the number of character
 *    in `str' or negative value on error.
 *
 ***/
int silc_snprintf(char *str, size_t count, const char *fmt, ...);

/****f* silcutil/SilcSnprintf/silc_vsnprintf
 *
 * SYNOPSIS
 *
 *    int silc_vsnprintf(char *str, size_t count, const char *fmt,
 *                       va_list args)
 *
 * DESCRIPTION
 *
 *    Same as silc_snprintf but takes the argument for the formatting from
 *    the `args' variable argument list.
 *
 ***/
int silc_vsnprintf(char *str, size_t count, const char *fmt, va_list args);

/****f* silcutil/SilcSnprintf/silc_asprintf
 *
 * SYNOPSIS
 *
 *    int silc_asprintf(char **ptr, const char *format, ...)
 *
 * DESCRIPTION
 *
 *    Same as silc_snprintf but allocates a string large enough to hold the
 *    output including the trailing '\0'.  The caller must free the `ptr'.
 *
 ***/
int silc_asprintf(char **ptr, const char *format, ...);

/****f* silcutil/SilcSnprintf/silc_vasprintf
 *
 * SYNOPSIS
 *
 *    int silc_vasprintf(char **ptr, const char *format, va_list ap)
 *
 * DESCRIPTION
 *
 *    Same as silc_asprintf but takes the argument from the `ap' variable
 *    argument list.
 *
 ***/
int silc_vasprintf(char **ptr, const char *format, va_list ap);

#endif /* SILCSNPRINTF_H */
