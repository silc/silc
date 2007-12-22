/*

  silctimer.c

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

/* Start timer */

void silc_timer_start(SilcTimer timer)
{
  struct timeval curtime;

  silc_gettimeofday(&curtime);
  timer->start_sec = curtime.tv_sec;
  timer->start_usec = curtime.tv_usec;
  timer->timer_sec = 0;
  timer->timer_usec = 0;
  timer->sync_diff = 0;
  timer->sync_tdiff = 0;
  timer->running = TRUE;
}

/* Stop timer */

void silc_timer_stop(SilcTimer timer)
{
  struct timeval curtime;

  silc_gettimeofday(&curtime);

  if (curtime.tv_usec < timer->start_usec) {
    curtime.tv_sec--;
    curtime.tv_usec += 1000000L;
  }
  timer->timer_sec = curtime.tv_sec - timer->start_sec;
  timer->timer_usec = curtime.tv_usec - timer->start_usec;
  timer->timer_usec -= timer->sync_diff;

  timer->running = FALSE;
}

/* Continue stopped timer */

void silc_timer_continue(SilcTimer timer)
{
  struct timeval curtime;

  if (timer->running)
    return;

  silc_gettimeofday(&curtime);

  if (curtime.tv_usec < timer->timer_usec) {
    curtime.tv_sec--;
    curtime.tv_usec += 1000000L;
  }
  timer->start_sec = curtime.tv_sec - timer->timer_sec;
  timer->start_usec = curtime.tv_usec - timer->timer_usec;

  timer->running = TRUE;
}

/* Return timer value */

void silc_timer_value(SilcTimer timer,
		      SilcUInt64 *elapsed_time_seconds,
		      SilcUInt32 *elapsed_time_microseconds)
{
  if (timer->running) {
    struct timeval curtime;

    silc_gettimeofday(&curtime);

    if (curtime.tv_usec < timer->start_usec) {
      curtime.tv_sec--;
      curtime.tv_usec += 1000000L;
    }
    timer->timer_sec = curtime.tv_sec - timer->start_sec;
    timer->timer_usec = curtime.tv_usec - timer->start_usec;
    timer->timer_usec -= timer->sync_diff;
  }

  if (elapsed_time_seconds)
    *elapsed_time_seconds = timer->timer_sec;
  if (elapsed_time_microseconds)
    *elapsed_time_microseconds = timer->timer_usec;
}

/* Return timer value */

void silc_timer_value_time(SilcTimer timer, SilcTime ret_time)
{
  SilcUInt64 sec;
  SilcUInt32 usec;

  silc_timer_value(timer, &sec, &usec);
  sec = ((timer->start_sec + sec) * (SilcUInt64)1000);
  sec += ((timer->start_usec + usec) / 1000);
  silc_time_value(sec, ret_time);
}

/* Return start time */

void silc_timer_start_time(SilcTimer timer, SilcTime ret_start_time)
{
  silc_time_value(((timer->start_sec * (SilcUInt64)1000) +
		   (timer->start_usec / 1000)), ret_start_time);
}

/* Return TRUE if timer is running */

SilcBool silc_timer_is_running(SilcTimer timer)
{
  return timer->running;
}
