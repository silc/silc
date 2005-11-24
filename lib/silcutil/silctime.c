/*

  silctime.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2003 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silcincludes.h"

/* Return time since Epoch */

SilcInt64 silc_time(void)
{
  return (SilcInt64)time(NULL);
}

/* Returns time as string */

const char *silc_time_string(SilcInt64 timeval)
{
  time_t curtime;
  char *return_time;

  if (!timeval)
    curtime = time(NULL);
  else
    curtime = (time_t)timeval;
  return_time = ctime(&curtime);
  if (!return_time)
    return NULL;
  return_time[strlen(return_time) - 1] = '\0';

  return (const char *)return_time;
}

/* Returns time as SilcTime structure */

bool silc_time_value(SilcInt64 timeval, SilcTime ret_time)
{
  struct tm *time;

  if (!ret_time)
    return TRUE;

  if (!timeval)
    timeval = silc_time();

  time = localtime((time_t *)&timeval);
  if (!time)
    return FALSE;

  memset(ret_time, 0, sizeof(*ret_time));
  ret_time->year    = time->tm_year + 1900;
  ret_time->month   = time->tm_mon + 1;
  ret_time->day     = time->tm_mday;
  ret_time->hour    = time->tm_hour;
  ret_time->minute  = time->tm_min;
  ret_time->second  = time->tm_sec;
  ret_time->dst     = time->tm_isdst ? 1 : 0;

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

/* Fills the SilcTime structure with correct values */

static bool silc_time_fill(SilcTime time,
			   unsigned int year,
			   unsigned int month,
			   unsigned int day,
			   unsigned int hour,
			   unsigned int minute,
			   unsigned int second)
{
  if (year > 8191)
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

  time->year = year;
  time->month = month;
  time->day = day;
  time->hour = hour;
  time->minute = minute;
  time->second = second;

  return TRUE;
}

/* Returns time from universal time string into SilcTime */

bool silc_time_universal(const char *universal_time, SilcTime ret_time)
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
  ret = silc_time_fill(ret_time, year, month, day, hour, minute, second);
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

bool silc_time_universal_string(SilcTime timeval, char *ret_string,
				SilcUInt32 ret_string_size)
{
  int ret, len = 0;
  memset(ret_string, 0, ret_string_size);
  ret = snprintf(ret_string, ret_string_size - 1,
		 "%02u%02u%02u%02u%02u%02u",
		 timeval->year % 100, timeval->month, timeval->day,
		 timeval->hour, timeval->minute, timeval->second);
  if (ret < 0)
    return FALSE;
  len += ret;

  if (!timeval->utc_hour && !timeval->utc_minute) {
    ret = snprintf(ret_string + len, ret_string_size - 1 - len, "Z");
    if (ret < 0)
      return FALSE;
    len += ret;
  } else {
    ret = snprintf(ret_string + len, ret_string_size - 1 - len,
		   "%c%02u%02u", timeval->utc_east ? '+' : '-',
		   timeval->utc_hour, timeval->utc_minute);
    if (ret < 0)
      return FALSE;
    len += ret;
  }

  return TRUE;
}

/* Returns time from generalized time string into SilcTime */

bool silc_time_generalized(const char *generalized_time, SilcTime ret_time)
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
  ret = silc_time_fill(ret_time, year, month, day, hour, minute, second);
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

bool silc_time_generalized_string(SilcTime timeval, char *ret_string,
				  SilcUInt32 ret_string_size)
{
  int len = 0, ret;
  memset(ret_string, 0, ret_string_size);
  ret = snprintf(ret_string, ret_string_size - 1,
		 "%04u%02u%02u%02u%02u%02u",
		 timeval->year, timeval->month, timeval->day, timeval->hour,
		 timeval->minute, timeval->second);
  if (ret < 0)
    return FALSE;
  len += ret;

  if (timeval->msecond) {
    ret = snprintf(ret_string + len, ret_string_size - 1 - len,
		   ".%lu", (unsigned long)timeval->msecond);
    if (ret < 0)
      return FALSE;
    len += ret;
  }

  if (!timeval->utc_hour && !timeval->utc_minute) {
    ret = snprintf(ret_string + len, ret_string_size - 1 - len, "Z");
    if (ret < 0)
      return FALSE;
    len += ret;
  } else {
    ret = snprintf(ret_string + len, ret_string_size - 1 - len,
		   "%c%02u%02u", timeval->utc_east ? '+' : '-',
		   timeval->utc_hour, timeval->utc_minute);
    if (ret < 0)
      return FALSE;
    len += ret;
  }

  return TRUE;
}
