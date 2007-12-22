/*

  silctime.c

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
    goto err;
  if (month < 1 || month > 12)
    goto err;
  if (day < 1 || day > 31)
    goto err;
  if (hour > 23)
    goto err;
  if (minute > 60)
    goto err;
  if (second > 61)
    goto err;
  if (msec > 1000)
    goto err;

  time->year = year;
  time->month = month;
  time->day = day;
  time->hour = hour;
  time->minute = minute;
  time->second = second;
  time->msecond = msec;

  return TRUE;

 err:
  silc_set_errno(SILC_ERR_BAD_TIME);
  return FALSE;
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
  return (curtime.tv_sec * (SilcUInt64)1000) +
    (curtime.tv_usec / (SilcUInt64)1000);
}

/* Return time since Epoch in microseconds */

SilcInt64 silc_time_usec(void)
{
  struct timeval curtime;
  if (silc_gettimeofday(&curtime))
    silc_set_errno_posix(errno);
  return (curtime.tv_sec * (SilcUInt64)1000000) + curtime.tv_usec;
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
  if (!return_time) {
    silc_set_errno(SILC_ERR_BAD_TIME);
    return NULL;
  }
  return_time[strlen(return_time) - 1] = '\0';

  return (const char *)return_time;
}

/* Returns time as SilcTime structure */

SilcBool silc_time_value(SilcInt64 time_val, SilcTime ret_time)
{
  struct tm *t;
  unsigned int msec = 0;
  time_t timeval;
  SilcInt32 ctz = 0;

  if (!ret_time)
    return TRUE;

  if (!time_val)
    time_val = silc_time_msec();

  msec = (SilcUInt64)time_val % (SilcUInt64)1000;
  timeval = (time_t)((SilcUInt64)time_val / (SilcUInt64)1000);

  t = localtime(&timeval);
  if (!t) {
    silc_set_errno(SILC_ERR_BAD_TIME);
    return FALSE;
  }

  memset(ret_time, 0, sizeof(*ret_time));
  if (!silc_time_fill(ret_time, t->tm_year + 1900, t->tm_mon + 1,
		      t->tm_mday, t->tm_hour, t->tm_min,
		      t->tm_sec, msec))
    return FALSE;

  ret_time->dst        = t->tm_isdst ? 1 : 0;

#ifdef SILC_WIN32
  ret_time->utc_east   = _timezone < 0 ? 1 : 0;
  ret_time->utc_hour   = (ret_time->utc_east ? (-(_timezone)) / 3600 :
			  _timezone / 3600);
  ret_time->utc_minute = (ret_time->utc_east ? (-(_timezone)) % 3600 :
			  _timezone % 3600);
#else
#if defined(HAVE_TIMEZONE)
  ret_time->utc_east   = timezone < 0 ? 1 : 0;
  ctz = timezone;
  if (ret_time->dst)
    ctz -= 3600;
#elif defined(HAVE_TM_GMTOFF)
  ret_time->utc_east   = t->tm_gmtoff > 0 ? 1 : 0;
  ctz = -t->tm_gmtoff;
#elif defined(HAVE___TM_GMTOFF)
  ret_time->utc_east   = t->__tm_gmtoff > 0 ? 1 : 0;
  ctz = -t->__tm_gmtoff;
#elif defined(HAVE___TM_GMTOFF__)
  ret_time->utc_east   = t->__tm_gmtoff__ > 0 ? 1 : 0;
  ctz = -t->__tm_gmtoff__;
#endif /* HAVE_TIMEZONE */

  ret_time->utc_hour   = (ret_time->utc_east ? (-(ctz)) / 3600 : ctz / 3600);
  ret_time->utc_minute = (ret_time->utc_east ? (-(ctz)) % 3600 : ctz % 3600);
#endif /* SILC_WIN32 */

  if (ret_time->utc_minute)
    ret_time->utc_minute /= 60;

  return TRUE;
}

/* Returns timezone */

SilcBool silc_timezone(char *timezone, SilcUInt32 timezone_size)
{
  SilcTimeStruct curtime;

  if (timezone_size < 6) {
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
    return FALSE;
  }

  if (!silc_time_value(0, &curtime))
    return FALSE;

  if (!curtime.utc_hour && curtime.utc_minute)
    silc_snprintf(timezone, timezone_size, "Z");
  else if (curtime.utc_minute)
    silc_snprintf(timezone, timezone_size, "%c%02d:%02d",
		  curtime.utc_east ? '+' : '-', curtime.utc_hour,
		  curtime.utc_minute);
  else
    silc_snprintf(timezone, timezone_size, "%c%02d",
		  curtime.utc_east ? '+' : '-', curtime.utc_hour);

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
    silc_set_errno_reason(SILC_ERR_BAD_TIME, "Invalid UTC time string");
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
      silc_set_errno_reason(SILC_ERR_BAD_TIME, "Malformed UTC time string");
      return FALSE;
    }

    if (hour > 23 || minute > 60) {
      silc_set_errno(SILC_ERR_BAD_TIME);
      return FALSE;
    }

    ret_time->utc_hour   = hour;
    ret_time->utc_minute = minute;
    ret_time->utc_east   = (z == '-') ? 0 : 1;
  } else if (z != 'Z') {
    SILC_LOG_DEBUG(("Invalid timezone"));
    silc_set_errno_reason(SILC_ERR_BAD_TIME, "Invalid timezone");
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
  ret = silc_snprintf(ret_string, ret_string_size - 1,
		      "%02u%02u%02u%02u%02u%02u",
		      time_val->year % 100, time_val->month, time_val->day,
		      time_val->hour, time_val->minute, time_val->second);
  if (ret < 0)
    return FALSE;
  len += ret;

  if (!time_val->utc_hour && !time_val->utc_minute) {
    ret = silc_snprintf(ret_string + len, ret_string_size - 1 - len, "Z");
    if (ret < 0)
      return FALSE;
    len += ret;
  } else {
    ret = silc_snprintf(ret_string + len, ret_string_size - 1 - len,
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
    silc_set_errno_reason(SILC_ERR_BAD_TIME, "Invalid generalized time string");
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
    silc_set_errno_reason(SILC_ERR_BAD_TIME,
			  "Malformed generalized time string");
    return FALSE;
  }

  if (z == '.') {
    /* Take fractions of second */
    int l;
    i++;
    ret = sscanf(generalized_time + i, "%u%n", &msecond, &l);
    if (ret != 1) {
      SILC_LOG_DEBUG(("Malformed generalized time string"));
      silc_set_errno_reason(SILC_ERR_BAD_TIME,
			    "Malformed generalized time string");
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
      SILC_LOG_DEBUG(("Malformed generalized time string"));
      silc_set_errno_reason(SILC_ERR_BAD_TIME,
			    "Malformed generalized time string");
      return FALSE;
    }

    if (hour > 23 || minute > 60) {
      silc_set_errno(SILC_ERR_BAD_TIME);
      return FALSE;
    }

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
  ret = silc_snprintf(ret_string, ret_string_size - 1,
		      "%04u%02u%02u%02u%02u%02u",
		      time_val->year, time_val->month,
		      time_val->day, time_val->hour,
		      time_val->minute, time_val->second);
  if (ret < 0)
    return FALSE;
  len += ret;

  if (time_val->msecond) {
    ret = silc_snprintf(ret_string + len, ret_string_size - 1 - len,
			".%lu", (unsigned long)time_val->msecond);
    if (ret < 0)
      return FALSE;
    len += ret;
  }

  if (!time_val->utc_hour && !time_val->utc_minute) {
    ret = silc_snprintf(ret_string + len, ret_string_size - 1 - len, "Z");
    if (ret < 0)
      return FALSE;
    len += ret;
  } else {
    ret = silc_snprintf(ret_string + len, ret_string_size - 1 - len,
			"%c%02u%02u", time_val->utc_east ? '+' : '-',
			time_val->utc_hour, time_val->utc_minute);
    if (ret < 0)
      return FALSE;
    len += ret;
  }

  return TRUE;
}

/* Return TRUE if `smaller' is smaller than `bigger'. */

int silc_compare_timeval(struct timeval *t1, struct timeval *t2)
{
  SilcInt32 s = t1->tv_sec - t2->tv_sec;
  if (!s)
    return t1->tv_usec - t2->tv_usec;
  return s;
}
