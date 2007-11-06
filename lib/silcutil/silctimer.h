/*

  silctimer.h

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

/****h* silcutil/SILC Timer Interface
 *
 * DESCRIPTION
 *
 * SILC Timer interface provides a simple way to measure time intervals.
 * The SILC Timer works with microsecond resolution, depending on platform.
 *
 * EXAMPLE
 *
 * SilcTimerStruct timer;
 *
 * silc_timer_start(&timer);
 * ... time passes ...
 * silc_timer_stop(&timer);
 * silc_timer_value(&timer, &elapsed_sec, &elapsed_usec);
 *
 ***/

#ifndef SILCTIMER_H
#define SILCTIMER_H

/****s* silcutil/SilcTimerAPI/SilcTimer
 *
 * NAME
 *
 *    typedef struct SilcTimerObject *SilcTimer, SilcTimerStruct;
 *
 * DESCRIPTION
 *
 *    The timer context.  The context is given as argument to all
 *    silc_timer_* functions.
 *
 ***/
typedef struct SilcTimerObject *SilcTimer, SilcTimerStruct;

/****f* silcutil/SilcTimerAPI/silc_timer_start
 *
 * SYNOPSIS
 *
 *    SilcBool silc_timer_start(SilcTimer timer);
 *
 * DESCRIPTION
 *
 *    Starts the timer.  If the timer is already running this will reset
 *    the timer and continue.
 *
 * EXAMPLE
 *
 *    SilcTimerStruct timer;
 *
 *    silc_timer_start(&timer);
 *    ... time passes ...
 *    silc_timer_stop(&timer);
 *    silc_timer_value(&timer, &elapsed_sec, &elapsed_usec);
 *
 ***/
void silc_timer_start(SilcTimer timer);

/****f* silcutil/SilcTimerAPI/silc_timer_stop
 *
 * SYNOPSIS
 *
 *    void silc_timer_stop(SilcTimer timer);
 *
 * DESCRIPTION
 *
 *    Stop the timer.  The elapsed time can be retrieved by calling the
 *    silc_timer_value function.
 *
 ***/
void silc_timer_stop(SilcTimer timer);

/****f* silcutil/SilcTimerAPI/silc_timer_continue
 *
 * SYNOPSIS
 *
 *    void silc_timer_continue(SilcTimer timer);
 *
 * DESCRIPTION
 *
 *    Continue stopped timer.  If timer is running already this does nothing.
 *
 ***/
void silc_timer_continue(SilcTimer timer);

/****f* silcutil/SilcTimerAPI/silc_timer_value
 *
 * SYNOPSIS
 *
 *    void silc_timer_value(SilcTimer timer,
 *                          SilcUInt64 *elapsed_time_seconds,
 *                          SilcUInt32 *elapsed_time_microseconds);
 *
 * DESCRIPTION
 *
 *    Returns either the current value or the end value of the timer.  If the
 *    timer is currently running this returns the currently elapsed time.  If
 *    the timer is stopped this returns the cumulative elapsed time.
 *
 ***/
void silc_timer_value(SilcTimer timer,
		      SilcUInt64 *elapsed_time_seconds,
		      SilcUInt32 *elapsed_time_microseconds);

/****f* silcutil/SilcTimerAPI/silc_timer_value_time
 *
 * SYNOPSIS
 *
 *    void silc_timer_value_time(SilcTimer timer, SilcTime ret_time);
 *
 * DESCRIPTION
 *
 *    Same as silc_timer_value but returns the elapsed time to `ret_time'
 *    SilcTime structure as absolute date and time.  This is useful if the
 *    returned time needs to be converted into some other format such as
 *    time and date strings.
 *
 ***/
void silc_timer_value_time(SilcTimer timer, SilcTime ret_time);

/****f* silcutil/SilcTimerAPI/silc_timer_start_time
 *
 * SYNOPSIS
 *
 *    void silc_timer_start_time(SilcTimer timer, SilcTime ret_start_time);
 *
 * DESCRIPTION
 *
 *    Returns the timer's start time into `ret_start_time' SilcTime structure.
 *
 ***/
void silc_timer_start_time(SilcTimer timer, SilcTime ret_start_time);

/****f* silcutil/SilcTimerAPI/silc_timer_is_running
 *
 * SYNOPSIS
 *
 *    SilcBool silc_timer_is_running(SilcTimer timer);
 *
 * DESCRIPTION
 *
 *    Returns TRUE if the timer is currently running, FALSE otherwise.
 *
 ***/
SilcBool silc_timer_is_running(SilcTimer timer);

#include "silctimer_i.h"

/****f* silcutil/SilcTimerAPI/silc_timer_tick
 *
 * SYNOPSIS
 *
 *    SilcUInt64 silc_timer_tick(SilcTimer &timer, SilcBool adjust)
 *
 * DESCRIPTION
 *
 *    Returns the current CPU tick count.  You should call the
 *    silc_timer_synchronize before using this function to make sure the
 *    overhead of measuring the CPU tick count is not included in the
 *    tick count.  If the `adjust' is TRUE and the silc_timer_synchronize
 *    has been called the returned value is adjusted to be more accurate.
 *
 * EXAMPLES
 *
 *    // Synchronize timer for more accurate CPU tick counts
 *    silc_timer_synchronize(&timer);
 *    start = silc_timer_tick(&timer, FALSE);
 *    do_something();
 *    stop = silc_timer_tick(&timer, TRUE);
 *
 ***/

static inline
SilcUInt64 silc_timer_tick(SilcTimer timer, SilcBool adjust)
{
#if defined(__GNUC__) || defined(__ICC)
#ifdef SILC_I486
  SilcUInt64 x;
  asm volatile ("rdtsc" : "=A" (x));
  return adjust ? x - timer->sync_tdiff : x;

#elif SILC_X86_64
  SilcUInt64 x;
  SilcUInt32 hi, lo;
  asm volatile ("rdtsc" : "=a" (lo), "=d" (hi));
  x = ((SilcUInt64)lo | ((SilcUInt64)hi << 32));
  return adjust ? x - timer->sync_tdiff : x;

#elif SILC_POWERPC
  SilcUInt32 hi, lo, tmp;
  asm volatile ("0:            \n\t"
                "mftbu   %0    \n\t"
                "mftb    %1    \n\t"
                "mftbu   %2    \n\t"
                "cmpw    %2,%0 \n\t"
                "bne     0b    \n"
                : "=r" (hi), "=r" (lo), "=r" (tmp));
  x = ((SilcUInt64)lo | ((SilcUInt64)hi << 32));
  return adjust ? x - timer->sync_tdiff : x;
#endif /* SILC_I486 */

#elif defined(SILC_WIN32)
  __asm rdtsc

#else
  return 0;
#endif /* __GNUC__ || __ICC */
}

/****f* silcutil/SilcTimerAPI/silc_timer_synchronize
 *
 * SYNOPSIS
 *
 *    void silc_timer_synchronize(SilcTimer timer);
 *
 * DESCRIPTION
 *
 *    Synchronizes the `timer'.  This call will attempt to synchronize the
 *    timer for more accurate results with high resolution timing.  Call
 *    this before you start using time `timer'.
 *
 * EXAMPLE
 *
 *    // Synchronized timer
 *    silc_timer_synchronize(&timer);
 *    silc_timer_start(&timer);
 *    ... time passes ...
 *    silc_timer_stop(&timer);
 *    silc_timer_value(&timer, &elapsed_sec, &elapsed_usec);
 *
 ***/

static inline
void silc_timer_synchronize(SilcTimer timer)
{
  SilcUInt32 tdiff, cumu, i;
  SilcUInt64 t1, t2;

  /* Sync normal timer */
  for (i = 0, cumu = 0; i < 5; i++) {
    silc_timer_start(timer);
    silc_timer_stop(timer);
    silc_timer_value(timer, NULL, &tdiff);
    cumu += (int)tdiff;
  }

  timer->sync_diff = cumu;
  if (timer->sync_diff > 5)
    timer->sync_diff /= 5;

  /* Sync CPU tick count */
  cumu = 0;
  t1 = silc_timer_tick(timer, FALSE);
  t2 = silc_timer_tick(timer, FALSE);
  cumu += (t2 - t1);
  t1 = silc_timer_tick(timer, FALSE);
  t2 = silc_timer_tick(timer, FALSE);
  cumu += (t2 - t1);
  t1 = silc_timer_tick(timer, FALSE);
  t2 = silc_timer_tick(timer, FALSE);
  cumu += (t2 - t1);

  timer->sync_tdiff = cumu / 3;

  t1 = silc_timer_tick(timer, FALSE);
  t2 = silc_timer_tick(timer, TRUE);
  timer->sync_tdiff += (int)(t2 - t1);
}

#endif /* SILCTIMER_H */
