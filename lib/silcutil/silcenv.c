/*

  silcenv.c

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

/* Set environment variable with value */

SilcBool silc_setenv(const char *variable, const char *value)
{
  SILC_LOG_DEBUG(("Set %s=%s", variable, value));
#if defined(HAVE_SETENV)
  return setenv(variable, value, TRUE) == 0;
#elif defined (HAVE_PUTENV)
  char tmp[1024];
  silc_snprintf(tmp, sizeof(tmp), "%s=%s", variable, value);
  return putenv(tmp) == 0;
#endif /* HAVE_SETENV */
  return FALSE;
}

/* Get environment variable value */

const char *silc_getenv(const char *variable)
{
  SILC_LOG_DEBUG(("Get %s value", variable));
#if defined(HAVE_GETENV)
  return (const char *)getenv(variable);
#endif /* HAVE_GETENV */
  return NULL;
}

/* Unset environment variable */

SilcBool silc_unsetenv(const char *variable)
{
  SILC_LOG_DEBUG(("Unset %s value", variable));
#if defined(HAVE_UNSETENV)
  return unsetenv(variable) == 0;
#endif /* HAVE_GETENV */
  return FALSE;
}

/* Clear environment */

SilcBool silc_clearenv(void)
{
  SILC_LOG_DEBUG(("Clear allenvironment variables"));
#if defined(HAVE_CLEARENV)
  return clearenv() == 0;
#endif /* HAVE_GETENV */
  return FALSE;
}
