/*

  silcunixutil.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"

/* Returns the username of the user. If the global variable LOGNAME
   does not exists we will get the name from the password file. */

char *silc_get_username()
{
  char *logname = NULL;

  logname = getenv("LOGNAME");
  if (!logname) {
    logname = getlogin();
    if (!logname) {
      struct passwd *pw;

      pw = getpwuid(getuid());
      if (!pw)
	return strdup("foo");

      logname = pw->pw_name;
    }
  }

  return strdup(logname);
}

/* Returns the real name of ther user. */

char *silc_get_real_name()
{
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
}

/* Return current time to struct timeval. */

int silc_gettimeofday(struct timeval *p)
{
#if defined(HAVE_CLOCK_GETTIME)
  struct timespec tp;
  clock_gettime(CLOCK_REALTIME, &tp);
  p->tv_sec = tp.tv_sec;
  p->tv_usec = tp.tv_nsec / 1000;
  return 0;
#else
  return gettimeofday(p, NULL);
#endif /* HAVE_CLOCK_GETTIME */
}

int silc_file_set_nonblock(int fd)
{
  return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
}
