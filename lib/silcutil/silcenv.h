/*

  silcenv.h

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

/****h* silcutil/Environment Manipulation Interface
 *
 * DESCRIPTION
 *
 * This interface provides utility functions for manipulating environment
 * variables.  On platforms that do not support environment variables this
 * interfaces does nothing.
 *
 ***/

#ifndef SILCENV_H
#define SILCENV_H

/****f* silcutil/SilcEnvAPI/silc_setenv
 *
 * SYNOPSIS
 *
 *    SilcBool silc_setenv(const char *variable, const char *value);
 *
 * DESCRIPTION
 *
 *    Sets the environment variable named `variable' with value `value'
 *    to the environment.  If the `variable' already exists in the
 *    environment its value is changed to `value'.  Returns FALSE if the
 *    value could not be set or if environment variables are not supported.
 *
 ***/
SilcBool silc_setenv(const char *variable, const char *value);

/****f* silcutil/SilcEnvAPI/silc_getenv
 *
 * SYNOPSIS
 *
 *    const char *silc_getenv(const char *variable);
 *
 * DESCRIPTION
 *
 *    Returns the value of the environment variable `variable' or NULL if
 *    such variable does not exist in the environment.
 *
 ***/
const char *silc_getenv(const char *variable);

/****f* silcutil/SilcEnvAPI/silc_unsetenv
 *
 * SYNOPSIS
 *
 *    SilcBool silc_unsetenv(const char *variable);
 *
 * DESCRIPTION
 *
 *    Clears the value of the environment variable `variable'.  Returns FALSE
 *    if the value could not be cleared or if environment variables are not
 *    supported.
 *
 ***/
SilcBool silc_unsetenv(const char *variable);

/****f* silcutil/SilcEnvAPI/silc_clearenv
 *
 * SYNOPSIS
 *
 *    SilcBool silc_clearenv(void);
 *
 * DESCRIPTION
 *
 *    Clears the environment of all environment variables.  Returns FALSE
 *    if the environment could not be cleared or if environment variables are
 *    not supported.
 *
 ***/
SilcBool silc_clearenv(void);


#endif /* SILCENV_H */
