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

#endif /* SILCTIMER_H */
