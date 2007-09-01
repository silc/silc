/*

  silctime.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Time Interface
 *
 * DESCRIPTION
 *
 * This interface provides various utility functions for getting current
 * time and converting different time representations into the SilcTime
 * representation.
 *
 ***/

#ifndef SILCTIME_H
#define SILCTIME_H

/****s* silcutil/SilcTimeAPI/SilcTime
 *
 * NAME
 *
 *    typedef struct { ... } *SilcTime, SilcTimeStruct;
 *
 * DESCRIPTION
 *
 *    This context represents time value.  It includes date and time
 *    down to millisecond precision.  The structure size is 64 bits.
 *
 * SOURCE
 *
 ***/
typedef struct SilcTimeObject {
  unsigned int year       : 15;	   /* Year,     0 - 32768 */
  unsigned int month      : 4;	   /* Month,    1 - 12 */
  unsigned int day        : 5;	   /* Day,      1 - 31 */
  unsigned int hour       : 5;	   /* Hour,     0 - 23 */
  unsigned int minute     : 6;	   /* Minute,   0 - 59 */
  unsigned int second     : 6;	   /* Second,   0 - 61 */
  unsigned int msecond    : 10;	   /* Millisec, 0 - 1000 */
  unsigned int utc_hour   : 5;	   /* Offset to Zulu (UTC) hours */
  unsigned int utc_minute : 6;	   /* Offset to Zulu (UTC) minutes */
  unsigned int utc_east   : 1;	   /* Offset, 1 east (+), 0 west (-) */
  unsigned int dst        : 1;	   /* Set if daylight saving time */
} *SilcTime, SilcTimeStruct;
/***/

/****f* silcutil/SilcTimeAPI/silc_time
 *
 * SYNOPSIS
 *
 *    SilcInt64 silc_time(void);
 *
 * DESCRIPTION
 *
 *    Returns the current time of the system since Epoch.  The returned
 *    value is seconds since Epoch (1.1.1970).  Returns -1 on error.
 *
 ***/
SilcInt64 silc_time(void);

/****f* silcutil/SilcTimeAPI/silc_time_msec
 *
 * SYNOPSIS
 *
 *    SilcInt64 silc_time_msec(void);
 *
 * DESCRIPTION
 *
 *    Returns the current time of the system since Epoch in millisecond
 *    resolution.  Returns - 1 on error.
 *
 ***/
SilcInt64 silc_time_msec(void);

/****f* silcutil/SilcTimeAPI/silc_time_usec
 *
 * SYNOPSIS
 *
 *    SilcInt64 silc_time_usec(void);
 *
 * DESCRIPTION
 *
 *    Returns the current time of the system since Epoch in microsecond
 *    resolution.  Returns - 1 on error.
 *
 ***/
SilcInt64 silc_time_usec(void);

/****f* silcutil/SilcTimeAPI/silc_time_string
 *
 * SYNOPSIS
 *
 *    const char *silc_time_string(SilcInt64 time_val_sec);
 *
 * DESCRIPTION
 *
 *    Returns time and date as string.  The caller must not free the string
 *    and next call to this function will delete the old string.  If the
 *    `time_val_sec' is zero (0) returns current time as string, otherwise the
 *    `time_val_sec' as string.  The `time_val_sec' is in seconds since Epoch.
 *    Returns NULL on error.
 *
 ***/
const char *silc_time_string(SilcInt64 time_val_sec);

/****f* silcutil/SilcTimeAPI/silc_time_value
 *
 * SYNOPSIS
 *
 *   SilcBool silc_time_value(SilcInt64 time_val_msec, SilcTime ret_time);
 *
 * DESCRIPTION
 *
 *    Returns time and date as SilcTime.  If the `time_val_msec' is zero (0)
 *    returns current time as SilcTime, otherwise the `time_val_msec' as
 *    SilcTime.  The `time_val_msec' is in milliseconds since Epoch.  Returns
 *    FALSE on error, TRUE otherwise.
 *
 ***/
SilcBool silc_time_value(SilcInt64 time_val_msec, SilcTime ret_time);

/****f* silcutil/SilcTimeAPI/silc_timezone
 *
 * SYNOPSIS
 *
 *    SilcBool silc_timezone(char *timezone, SilcUInt32 timezone_size);
 *
 * DESCRIPTION
 *
 *    Returns current timezone in Universal time format into the `timezone'
 *    buffer of size of `timezone_size'.  The possible values this function
 *    returns are: Z (For UTC timezone), +hh (UTC + hours) -hh (UTC - hours),
 *    +hh:mm (UTC + hours:minutes) or -hh:mm (UTC - hours:minutes).  The
 *    returned values are always offsets to UTC.
 *
 *    Returns FALSE on error, TRUE otherwise.
 *
 ***/
SilcBool silc_timezone(char *timezone, SilcUInt32 timezone_size);

/****f* silcutil/SilcTimeAPI/silc_time_universal
 *
 * SYNOPSIS
 *
 *    SilcBool silc_time_universal(const char *universal_time,
 *                                 SilcTime ret_time);
 *
 * DESCRIPTION
 *
 *    Returns time and date as SilcTime from `universal_time' string which
 *    format is "YYMMDDhhmmssZ", where YY is year, MM is month, DD is day,
 *    hh is hour, mm is minutes, ss is seconds and Z is timezone, which
 *    by default is Zulu (UTC).  Universal time is defined in ISO/EIC 8824-1.
 *
 *    Returns FALSE on error, TRUE otherwise.
 *
 * EXAMPLE
 *
 *    SilcTimeStruct ret_time;
 *
 *    time is 03/02/19 19:04:03 Zulu (UTC)
 *    silc_time_universal("030219190403Z", &ret_time);
 *
 ***/
SilcBool silc_time_universal(const char *universal_time, SilcTime ret_time);

/****f* silcutil/SilcTimeAPI/silc_time_universal_string
 *
 * SYNOPSIS
 *
 *    SilcBool silc_time_universal_string(SilcTime time_val, char *ret_string,
 *                                        SilcUInt32 ret_string_size);
 *
 * DESCRIPTION
 *
 *    Encodes the SilcTime `time' into the universal time format into the
 *    `ret_string' buffer.  Returns FALSE if the buffer is too small.
 *
 ***/
SilcBool silc_time_universal_string(SilcTime time_val, char *ret_string,
				    SilcUInt32 ret_string_size);

/****f* silcutil/SilcTimeAPI/silc_time_generalized
 *
 * SYNOPSIS
 *
 *    SilcBool silc_time_generalized(const char *generalized_time,
 *                                   SilcTime ret_time);
 *
 * DESCRIPTION
 *
 *    Returns time and date as SilcTime from `generalized_time' string which
 *    format is "YYYYMMDDhhmmss.ppZ", where YYYY is year, MM is month, DD
 *    is day, hh is hour, mm is minutes, ss is seconds which may have optional
 *    precision pp, and Z is timezone, which by default is Zulu (UTC).
 *    Generalized time is defined in ISO/EIC 8824-1.
 *
 *    Returns FALSE on error, TRUE otherwise.
 *
 * EXAMPLE
 *
 *    SilcTimeStruct ret_time;
 *
 *    time is 2003/02/19 19:04:03 Zulu (UTC)
 *    silc_time_generalized("20030219190403Z", &ret_time);
 *
 *    time is 2003/02/19 19:05:10.212 Zulu (UTC)
 *    silc_time_generalized("20030219190510.212Z", &ret_time);
 *
 ***/
SilcBool
silc_time_generalized(const char *generalized_time, SilcTime ret_time);

/****f* silcutil/SilcTimeAPI/silc_time_generalized_string
 *
 * SYNOPSIS
 *
 *    SilcBool silc_time_generalized_string(SilcTime time_val,
 *                                          char *ret_string,
 *                                          SilcUInt32 ret_string_size);
 *
 * DESCRIPTION
 *
 *    Encodes the SilcTime `time' into the generalized time format into the
 *    `ret_string' buffer.  Returns FALSE if the buffer is too small.
 *
 ***/
SilcBool silc_time_generalized_string(SilcTime time_val, char *ret_string,
				      SilcUInt32 ret_string_size);

/****f* silcutil/SilcTimeAPI/silc_compare_timeval
 *
 * SYNOPSIS
 *
 *    int silc_compare_timeval(struct time_val *t1, struct time_val *t2);
 *
 * DESCRIPTION
 *
 *    Compares `t1' and `t2' time structures and returns less than zero,
 *    zero or more than zero when `t1' is smaller, equal or bigger than
 *    `t2', respectively.
 *
 ***/
int silc_compare_timeval(struct timeval *t1, struct timeval *t2);

/****f* silcutil/SilcTimeAPI/silc_gettimeofday
 *
 * SYNOPSIS
 *
 *    int silc_gettimeofday(struct timeval *p);
 *
 * DESCRIPTION
 *
 *    Return current time to struct timeval.  This function is system
 *    dependant.  Returns 0 on success and -1 on error.
 *
 ***/
int silc_gettimeofday(struct timeval *p);

/****f* silcutil/SilcTimeAPI/silc_usleep
 *
 * SYNOPSIS
 *
 *    void silc_usleep(unsigned long microseconds);
 *
 * DESCRIPTION
 *
 *    Delays the execution of process/thread for the specified amount of
 *    time, which is in microseconds.
 *
 * NOTES
 *
 *    The delay is only approximate and on some platforms the resolution is
 *    in fact milliseconds.
 *
 ***/
static inline
void silc_usleep(unsigned long microseconds)
{
#ifdef SILC_UNIX
#ifdef HAVE_NANOSLEEP
  struct timespec tv;
  tv.tv_sec = 0;
  tv.tv_nsec = microseconds * 1000;
#endif /* HAVE_NANOSLEEP */
#endif /* SILC_UNIX */

#ifdef SILC_UNIX
#ifdef HAVE_NANOSLEEP
  nanosleep(&tv, NULL);
#else
  usleep(microseconds);
#endif /* HAVE_NANOSLEEP */
#endif /* SILC_UNIX */
#ifdef SILC_WIN32
  Sleep(microseconds / 1000);
#endif /* SILC_WIN32 */
#ifdef SILC_SYMBIAN
  silc_symbian_usleep(microseconds);
#endif /* SILC_SYMBIAN */
}

#endif /* SILCTIME_H */
