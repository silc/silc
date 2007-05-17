/*

  silcsymbianutil.cpp

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2006 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"
#include <e32std.h>
#include <e32svr.h>

extern "C" {

/* Returns the username of the user. */

char *silc_get_username()
{
#if 0
  char *logname = NULL;

  logname = getlogin();
  if (!logname) {
    struct passwd *pw;

    pw = getpwuid(getuid());
    if (!pw)
      return strdup("User");

    logname = pw->pw_name;
  }

  return strdup(logname);
#else
  return strdup("Symbian");
#endif /* 0 */
}

/* Returns the real name of ther user. */

char *silc_get_real_name()
{
#if 0
  char *realname = NULL;
  struct passwd *pw;

  pw = getpwuid(getuid());
  if (!pw)
    return strdup("No Name");

  if (strchr(pw->pw_gecos, ','))
    *strchr(pw->pw_gecos, ',') = 0;

  if (!strlen(pw->pw_gecos))
    return strdup("No Name");

  realname = strdup(pw->pw_gecos);

  return realname;
#else
  return strdup("Lastname");
#endif /* 0 */
}

/* Return current time to struct timeval. */

int silc_gettimeofday(struct timeval *p)
{
  return gettimeofday(p, NULL);
}

int silc_file_set_nonblock(int fd)
{
  return 0;
}

void silc_symbian_usleep(long microseconds)
{
  User::After(microseconds / 1000);
}

void silc_symbian_debug(const char *function, int line, char *string)
{
  fprintf(stderr, "%s:%d: %s\n", function, line, string);
  // RDebug::Print(_L("%s:%d: %s"), function, line, string);
}

} /* extern "C" */
