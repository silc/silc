/*

  silctimer_i.h

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

#ifndef SILCTIMER_I_H
#define SILCTIMER_I_H

#ifndef SILCTIMER_H
#error "Do not include this header directly"
#endif

struct SilcTimerObject {
  SilcUInt64 start_sec;		/* Start seconds */
  SilcUInt64 timer_sec;		/* Timer seconds */
  SilcUInt32 start_usec;	/* Start microseconds */
  SilcUInt32 timer_usec;	/* Timer microseconds */
  unsigned int running    : 1;	/* Set when timer is running */
  unsigned int sync_diff  : 15;	/* Synchronization delta */
  unsigned int sync_tdiff : 16;	/* Synchronization tick delta */
};

#endif /* SILCTIMER_I_H */
