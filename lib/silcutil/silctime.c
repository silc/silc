/*

  silctime.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"

/* Fills the SilcTime structure with correct values */

static SilcBool silc_time_fill(SilcTime time,
			       unsigned int year,
			       unsigned int month,
			       unsigned int day,
			       unsigned int hour,
			       unsigned int minute,
			       unsigned int second,
			       unsigned int msec)
{
  if (year > (1 << 15))
    return FALSE;
  if (month < 1 || month > 12)
    return FALSE;
  if (day < 1 || day > 31)
    return FALSE;
  if (hour > 23)
    return FALSE;
  if (minute > 60)
    return FALSE;
  if (second > 61)
    return FALSE;
  if (msec > 1000)
    return FALSE;

  time->year = year;
  time->month = month;
  time->day = day;
  time->hour = hour;
  time->minute = minute;
  time->second = second;
  time->msecond = msec;

  return TRUE;
}

/* Return time since Epoch */

SilcInt64 silc_time(void)
{
  return (SilcInt64)time(NULL);
}

/* Return time since Epoch in milliseconds */

SilcInt64 silc_time_msec(void)
{
  struct timeval curtime;
  silc_gettimeofday(&curtime);
  return (curtime.tv_sec * 1000) + (curtime.tv_usec / 1000);
}

/* Return time since Epoch in microseconds */

SilcInt64 silc_time_usec(void)
{
  struct timeval curtime;
  silc_gettimeofday(&curtime);
  return (curtime.tv_sec * 1000000) + curtime.tv_usec;
}

/* Returns time as string */

const char *silc_time_string(SilcInt64 time_val)
{
  time_t curtime;
  char *return_time;

  if (!time_val)
    curtime = silc_time();
  else
    curtime = (time_t)time_val;
  return_time = ctime(&curtime);
  if (!return_time)
    return NULL;
  return_time[strlen(return_time) - 1] = '\0';

  return (const char *)return_time;
}

/* Returns time as SilcTime structure */

SilcBool silc_time_value(SilcInt64 time_val, SilcTime ret_time)
{
  struct tm *time;
  unsigned int msec = 0;

  if (!ret_time)
    return TRUE;

  if (!time_val)
    time_val = silc_time_msec();

  msec = time_val % 1000;
  time_val /= 1000;

  time = localtime((time_t *)&time_val);
  if (!time)
    return FALSE;

  memset(ret_time, 0, sizeof(*ret_time));
  if (!silc_time_fill(ret_time, time->tm_year + 1900, time->tm_mon + 1,
		      time->tm_mday, time->tm_hour, time->tm_min,
		      time->tm_sec, msec))
    return FALSE;

  ret_time->dst        = time->tm_isdst ? 1 : 0;
#ifdef SILC_WIN32
  ret_time->utc_east   = _timezone < 0 ? 1 : 0;
  ret_time->utc_hour   = (ret_time->utc_east ? (-(_timezone)) / 3600 :
			  _timezone / 3600);
  ret_time->utc_minute = (ret_time->utc_east ? (-(_timezone)) % 3600 :
			  _timezone % 3600);
#else
#if defined(HAVE_TZSET)
  ret_time->utc_east   = timezone < 0 ? 1 : 0;
  ret_time->utc_hour   = (ret_time->utc_east ? (-(timezone)) / 3600 :
			  timezone / 3600);
  ret_time->utc_minute = (ret_time->utc_east ? (-(timezone)) % 3600 :
			  timezone % 3600);
#endif /* HAVE_TZSET */
#endif /* SILC_WIN32 */

  return TRUE;
}

/* Returns time from universal time string into SilcTime */

SilcBool silc_time_universal(const char *universal_time, SilcTime ret_time)
{
  int ret;
  unsigned int year, month, day, hour = 0, minute = 0, second = 0;
  unsigned char z = 0;

  if (!ret_time)
    return TRUE;
  memset(ret_time, 0, sizeof(*ret_time));

  /* Parse the time string */
  ret = sscanf(universal_time, "%02u%02u%02u%02u%02u%02u%c", &year, &month,
	       &day, &hour, &minute, &second, &z);
  if (ret < 3) {
    SILC_LOG_DEBUG(("Invalid UTC time string"));
    return FALSE;
  }

  /* Fill the SilcTime structure */
  ret = silc_time_fill(ret_time, year, month, day, hour, minute, second, 0);
  if (!ret) {
    SILC_LOG_DEBUG(("Incorrect values in UTC time string"));
    return FALSE;
  }

  /* Check timezone */
  if (z == '-' || z == '+') {
    ret = sscanf(universal_time + (ret * 2) + 1, "%02u%02u", &hour, &minute);
    if (ret != 2) {
      SILC_LOG_DEBUG(("Malformed UTC time string"));
      return FALSE;
    }

    if (hour < 0 || hour > 23)
      return FALSE;
    if (minute < 0 || minute > 60)
      return FALSE;

    ret_time->utc_hour   = hour;
    ret_time->utc_minute = minute;
    ret_time->utc_east   = (z == '-') ? 0 : 1;
  } else if (z != 'Z') {
    SILC_LOG_DEBUG(("Invalid timezone"));
    return FALSE;
  }

  /* UTC year must be fixed since it's represented only as YY not YYYY. */
  ret_time->year += 1900;
  if (ret_time->year < 1950)
    ret_time->year += 100;

  return TRUE;
}

/* Encode universal time string. */

SilcBool silc_time_universal_string(SilcTime time_val, char *ret_string,
				    SilcUInt32 ret_string_size)
{
  int ret, len = 0;
  memset(ret_string, 0, ret_string_size);
  ret = silc_silc_snprintf(ret_string, ret_string_size - 1,
		 "%02u%02u%02u%02u%02u%02u",
		 time_val->year % 100, time_val->month, time_val->day,
		 time_val->hour, time_val->minute, time_val->second);
  if (ret < 0)
    return FALSE;
  len += ret;

  if (!time_val->utc_hour && !time_val->utc_minute) {
    ret = silc_silc_snprintf(ret_string + len, ret_string_size - 1 - len, "Z");
    if (ret < 0)
      return FALSE;
    len += ret;
  } else {
    ret = silc_silc_snprintf(ret_string + len, ret_string_size - 1 - len,
		   "%c%02u%02u", time_val->utc_east ? '+' : '-',
		   time_val->utc_hour, time_val->utc_minute);
    if (ret < 0)
      return FALSE;
    len += ret;
  }

  return TRUE;
}

/* Returns time from generalized time string into SilcTime */

SilcBool silc_time_generalized(const char *generalized_time, SilcTime ret_time)
{
  int ret, i;
  unsigned int year, month, day, hour = 0, minute = 0, second = 0;
  unsigned int msecond = 0;
  unsigned char z = 0;

  if (!ret_time)
    return TRUE;
  memset(ret_time, 0, sizeof(*ret_time));

  /* Parse the time string */
  ret = sscanf(generalized_time, "%04u%02u%02u%02u%02u%02u", &year, &month,
	       &day, &hour, &minute, &second);
  if (ret < 3) {
    SILC_LOG_DEBUG(("Invalid generalized time string"));
    return FALSE;
  }

  /* Fill the SilcTime structure */
  ret = silc_time_fill(ret_time, year, month, day, hour, minute, second, 0);
  if (!ret) {
    SILC_LOG_DEBUG(("Incorrect values in generalized time string"));
    return FALSE;
  }

  /* Check fractions of second and/or timezone */
  i = ret * 4;
  ret = sscanf(generalized_time + i, "%c", &z);
  if (ret != 1) {
    SILC_LOG_DEBUG(("Malformed generalized time string"));
    return FALSE;
  }

  if (z == '.') {
    /* Take fractions of second */
    int l;
    i++;
    ret = sscanf(generalized_time + i, "%u%n", &msecond, &l);
    if (ret != 1) {
      SILC_LOG_DEBUG(("Malformed generalized time string"));
      return FALSE;
    }
    while (l > 4) {
      msecond /= 10;
      l--;
    }
    ret_time->msecond = msecond;
    i += l;

    /* Read optional timezone */
    if (strlen(generalized_time) < i)
      sscanf(generalized_time + i, "%c", &z);
  }

  /* Check timezone if present */
  if (z == '-' || z == '+') {
    ret = sscanf(generalized_time + i + 1, "%02u%02u", &hour, &minute);
    if (ret != 2) {
      SILC_LOG_DEBUG(("Malformed UTC time string"));
      return FALSE;
    }

    if (hour < 0 || hour > 23)
      return FALSE;
    if (minute < 0 || minute > 60)
      return FALSE;

    ret_time->utc_hour   = hour;
    ret_time->utc_minute = minute;
    ret_time->utc_east   = (z == '-') ? 0 : 1;
  }

  return TRUE;
}

/* Encode generalized time string */

SilcBool silc_time_generalized_string(SilcTime time_val, char *ret_string,
				      SilcUInt32 ret_string_size)
{
  int len = 0, ret;
  memset(ret_string, 0, ret_string_size);
  ret = silc_silc_snprintf(ret_string, ret_string_size - 1,
		 "%04u%02u%02u%02u%02u%02u",
		 time_val->year, time_val->month, time_val->day, time_val->hour,
		 time_val->minute, time_val->second);
  if (ret < 0)
    return FALSE;
  len += ret;

  if (time_val->msecond) {
    ret = silc_silc_snprintf(ret_string + len, ret_string_size - 1 - len,
		   ".%lu", (unsigned long)time_val->msecond);
    if (ret < 0)
      return FALSE;
    len += ret;
  }

  if (!time_val->utc_hour && !time_val->utc_minute) {
    ret = silc_silc_snprintf(ret_string + len, ret_string_size - 1 - len, "Z");
    if (ret < 0)
      return FALSE;
    len += ret;
  } else {
    ret = silc_silc_snprintf(ret_string + len, ret_string_size - 1 - len,
		   "%c%02u%02u", time_val->utc_east ? '+' : '-',
		   time_val->utc_hour, time_val->utc_minute);
    if (ret < 0)
      return FALSE;
    len += ret;
  }

  return TRUE;
}

/* Return TRUE if `smaller' is smaller than `bigger'. */

SilcBool silc_compare_timeval(struct timeval *smaller,
			      struct timeval *bigger)
{
  if ((smaller->tv_sec < bigger->tv_sec) ||
      ((smaller->tv_sec == bigger->tv_sec) &&
       (smaller->tv_usec < bigger->tv_usec)))
    return TRUE;

  return FALSE;
}
