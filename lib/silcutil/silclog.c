/*

  silclog.c

  Author: Giovanni Giacobbi <giovanni@giacobbi.net>

  Copyright (C) 1997 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"

/* Minimum time delay for log flushing calls (in seconds) */
#define SILC_LOG_FLUSH_MIN_DELAY 2

/* nice macro for looping through all logs -- makes the code more readable */
#define SILC_FOREACH_LOG(__x__) for (__x__ = 0; __x__ < SILC_LOG_MAX; __x__++)

/* Our working struct -- at the moment we keep it private, but this could
 * change in the future */
struct SilcLogStruct {
  char filename[256];
  FILE *fp;
  SilcUInt32 maxsize;
  const char *typename;
  SilcLogType type;
  SilcLogCb cb;
  void *context;
};
typedef struct SilcLogStruct *SilcLog;

/* These are the known logging channels.  We initialize this struct with most
 * of the fields set to NULL, because we'll fill in those values at runtime. */
static struct SilcLogStruct silclogs[SILC_LOG_MAX] = {
  {"", NULL, 0, "Info", SILC_LOG_INFO, NULL, NULL},
  {"", NULL, 0, "Warning", SILC_LOG_WARNING, NULL, NULL},
  {"", NULL, 0, "Error", SILC_LOG_ERROR, NULL, NULL},
  {"", NULL, 0, "Fatal", SILC_LOG_FATAL, NULL, NULL},
};

/* Causes logging output to contain timestamps */
bool silc_log_timestamp = TRUE;

/* If TRUE, log files will be flushed for each log input */
bool silc_log_quick = FALSE;

/* Set TRUE/FALSE to enable/disable debugging */
bool silc_debug = FALSE;
bool silc_debug_hexdump = FALSE;

/* Flush delay (in seconds) */
long silc_log_flushdelay = 300;

/* Regular pattern matching expression for the debug output */
char silc_log_debug_string[128];

/* Debug callbacks. If set, these are triggered for each specific output. */
static SilcLogDebugCb silc_log_debug_cb = NULL;
static void *silc_log_debug_context = NULL;
static SilcLogHexdumpCb silc_log_hexdump_cb = NULL;
static void *silc_log_hexdump_context = NULL;

/* Did we register already our functions to the scheduler? */
static bool silc_log_scheduled = FALSE;
static bool silc_log_no_init = FALSE;

/* This is only needed during starting up -- don't lose any logging message */
static bool silc_log_starting = TRUE;

/* The type wrapper utility. Translates a SilcLogType id to the corresponding
 * logfile, or NULL if not found. */
static SilcLog silc_log_find_by_type(SilcLogType type)
{
  /* this is not really needed, but i think it's more secure */
  switch (type) {
    case SILC_LOG_INFO:
      return &silclogs[SILC_LOG_INFO];
    case SILC_LOG_WARNING:
      return &silclogs[SILC_LOG_WARNING];
    case SILC_LOG_ERROR:
      return &silclogs[SILC_LOG_ERROR];
    case SILC_LOG_FATAL:
      return &silclogs[SILC_LOG_FATAL];
    default:
      return NULL;
  }
  return NULL;
}

/* Given an open log file, checks the size and rotates it if there is a
 * max size set lower then the current size */
static void silc_log_checksize(SilcLog log)
{
  char newname[127];
  long size;

  if (!log || !log->fp || !log->maxsize)
    return; /* we are not interested */

  if ((size = ftell(log->fp)) < 0) {
    /* OMG, EBADF is here.. we'll try our best.. */
    FILE *oldfp = log->fp;
    fclose(oldfp); /* we can discard the error */
    log->fp = NULL; /* make sure we don't get here recursively */
    SILC_LOG_ERROR(("Error while checking size of the log file %s, fp=%p",
		    log->filename, oldfp));
    return;
  }
  if (size < log->maxsize)
    return;

  /* It's too big */
  fprintf(log->fp, "[%s] [%s] Cycling log file, over max "
	  "logsize (%lu kilobytes)\n",
	  silc_get_time(0), log->typename, (unsigned long)log->maxsize / 1024);
  fflush(log->fp);
  fclose(log->fp);
  memset(newname, 0, sizeof(newname));
  snprintf(newname, sizeof(newname) - 1, "%s.old", log->filename);
  unlink(newname);

  /* I heard the following syscall may cause portability issues, but I don't
   * have any other solution since SILC library doesn't provide any other
   * function like this. -Johnny */
  rename(log->filename, newname);
  if (!(log->fp = fopen(log->filename, "w")))
    SILC_LOG_WARNING(("Couldn't reopen logfile %s for type \"%s\": %s",
		      log->filename, log->typename, strerror(errno)));
#ifdef HAVE_CHMOD
  chmod(log->filename, 0600);
#endif /* HAVE_CHMOD */
}

/* Reset a logging channel (close and reopen) */

static bool silc_log_reset(SilcLog log)
{
  if (!log) return FALSE;
  if (log->fp) {
    fflush(log->fp);
    fclose(log->fp);
  }
  if (!log->filename[0]) return FALSE;
  if (!(log->fp = fopen(log->filename, "a+"))) {
    SILC_LOG_WARNING(("Couldn't reset logfile %s for type \"%s\": %s",
		      log->filename, log->typename, strerror(errno)));
    return FALSE;
  }

  return TRUE;
}

/* Internal timeout callback to flush log channels and check file sizes */

SILC_TASK_CALLBACK(silc_log_fflush_callback)
{
  unsigned int u;
  if (!silc_log_quick) {
    silc_log_flush_all();
    SILC_FOREACH_LOG(u)
      silc_log_checksize(&silclogs[u]);
  }
  silc_log_starting = FALSE;
  if (silc_log_flushdelay < SILC_LOG_FLUSH_MIN_DELAY)
    silc_log_flushdelay = SILC_LOG_FLUSH_MIN_DELAY;
  silc_schedule_task_add((SilcSchedule) context, 0, silc_log_fflush_callback,
			 context, silc_log_flushdelay, 0, SILC_TASK_TIMEOUT,
			 SILC_TASK_PRI_NORMAL);
}

/* Outputs the log message to the first available channel. Channels are
 * ordered by importance (see SilcLogType documentation).
 * More important channels can be printed on less important ones, but not
 * vice-versa. */

void silc_log_output(SilcLogType type, char *string)
{
  const char *typename = NULL;
  FILE *fp;
  SilcLog log;

  if ((type > SILC_LOG_MAX) || !(log = silc_log_find_by_type(type)))
    goto end;

  /* Save the original typename, because even if we redirect the message
   * to another channel we'll keep however the original channel name */
  typename = log->typename;

  /* If there is a custom callback set, use it and return. */
  if (log->cb) {
    if ((*log->cb)(type, string, log->context))
      goto end;
  }

  if (!silc_log_scheduled) {
    if (silc_log_no_init == FALSE) {
      fprintf(stderr,
	      "Warning, trying to output without log files initialization, "
	      "log output is going to stderr\n");
      silc_log_no_init = TRUE;
    }
    /* redirect output */
    fp = stderr;
    log = NULL;
    goto found;
  }

  /* ok, now we have to find an open stream */
  while (TRUE) {
    if (log && (fp = log->fp)) goto found;
    if (type == 0) break;
    log = silc_log_find_by_type(--type);
  }

  /* Couldn't find any open stream.. sorry :( */
  SILC_LOG_DEBUG(("Warning! couldn't find any available log channel!"));
  goto end;

 found:
  /* writes the logging string to the selected channel */
  if (silc_log_timestamp)
    fprintf(fp, "[%s] [%s] %s\n", silc_get_time(0), typename, string);
  else
    fprintf(fp, "[%s] %s\n", typename, string);

  if (silc_log_quick || silc_log_starting) {
    fflush(fp);
    if (log) /* we may have been redirected to stderr */
      silc_log_checksize(log);
  }

 end:
  /* If debugging, also output the logging message to the console */
  if (typename && silc_debug) {
    fprintf(stderr, "[Logging] [%s] %s\n", typename, string);
    fflush(stderr);
  }
  silc_free(string);
}

/* returns an internally allocated pointer to a logging channel file */
char *silc_log_get_file(SilcLogType type)
{
  SilcLog log;

  if (!(log = silc_log_find_by_type(type)))
    return NULL;
  if (log->fp)
    return log->filename;
  return NULL;
}

/* Set and initialize the specified logging channel. See the API reference */
bool silc_log_set_file(SilcLogType type, char *filename, SilcUInt32 maxsize,
		       SilcSchedule scheduler)
{
  FILE *fp = NULL;
  SilcLog log;

  log = silc_log_find_by_type(type);
  if (!log)
    return FALSE;

  SILC_LOG_DEBUG(("Setting \"%s\" file to %s (max size=%d)",
		  log->typename, filename, maxsize));

  /* before assuming the new file, make sure we can open it */
  if (filename) {
    if (!(fp = fopen(filename, "a+"))) {
      fprintf(stderr, "warning: couldn't open log file %s: %s\n",
	      filename, strerror(errno));
      return FALSE;
    }
#ifdef HAVE_CHMOD
    chmod(filename, 0600);
#endif /* HAVE_CHMOD */
  }

  /* clean the logging channel */
  if (strlen(log->filename)) {
    if (log->fp)
      fclose(log->fp);
    memset(log->filename, 0, sizeof(log->filename));
    log->fp = NULL;
  }

  if (fp) {
    memset(log->filename, 0, sizeof(log->filename));
    strncpy(log->filename, filename,
	    strlen(filename) < sizeof(log->filename) ? strlen(filename) :
	    sizeof(log->filename) - 1);
    log->fp = fp;
    log->maxsize = maxsize;
  }

  if (scheduler) {
    if (silc_log_scheduled)
      return TRUE;

    /* Add schedule hook with a short delay to make sure we'll use
       right delay */
    silc_schedule_task_add(scheduler, 0, silc_log_fflush_callback,
			   (void *) scheduler, 10, 0,
			   SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);
    silc_log_scheduled = TRUE;
  }

  return TRUE;
}

/* Sets a log callback, set callback to NULL to return to default behaviour */

void silc_log_set_callback(SilcLogType type, SilcLogCb cb, void *context)
{
  SilcLog log;

  if (!(log = silc_log_find_by_type(type)))
    return;

  log->cb = cb;
  log->context = context;
}

/* Resets log callbacks */

void silc_log_reset_callbacks()
{
  unsigned int u;
  SILC_FOREACH_LOG(u) {
    silclogs[u].cb = NULL;
    silclogs[u].context = NULL;
  }
}

/* Flushes all opened logging channels */

void silc_log_flush_all() {
  unsigned int u;
  SILC_LOG_DEBUG(("Flushing all logs"));
  SILC_FOREACH_LOG(u) {
    if (silclogs[u].fp)
      fflush(silclogs[u].fp);
  }
}

/* Resets all known logging channels */

void silc_log_reset_all() {
  unsigned int u;
  SILC_LOG_DEBUG(("Resetting all logs"));
  SILC_FOREACH_LOG(u)
    silc_log_reset(&silclogs[u]);
  /* Immediately flush any possible warning message */
  silc_log_flush_all();
}

/* Outputs the debug message to stderr. */

void silc_log_output_debug(char *file, const char *function,
			   int line, char *string)
{
  if (!silc_debug)
    goto end;

  if (silc_log_debug_string &&
      !silc_string_regex_match(silc_log_debug_string, file) &&
      !silc_string_regex_match(silc_log_debug_string, function))
    goto end;

  if (silc_log_debug_cb) {
    if ((*silc_log_debug_cb)(file, (char *)function, line, string,
			     silc_log_debug_context))
      goto end;
  }

  fprintf(stderr, "%s:%d: %s\n", function, line, string);
  fflush(stderr);

 end:
  silc_free(string);
}

/* Hexdumps a message */

void silc_log_output_hexdump(char *file, const char *function,
			     int line, void *data_in,
			     SilcUInt32 len, char *string)
{
  int i, k;
  int off, pos, count;
  unsigned char *data = (unsigned char *)data_in;

  if (!silc_debug_hexdump)
    goto end;

  if (silc_log_debug_string &&
      !silc_string_regex_match(silc_log_debug_string, file) &&
      !silc_string_regex_match(silc_log_debug_string, function))
    goto end;

  if (silc_log_hexdump_cb) {
    if ((*silc_log_hexdump_cb)(file, (char *)function, line,
			       data_in, len, string,
			       silc_log_hexdump_context))
      goto end;
  }

  fprintf(stderr, "%s:%d: %s\n", function, line, string);

  k = 0;
  pos = 0;
  count = 16;
  off = len % 16;
  while (1) {
    if (off) {
      if ((len - pos) < 16 && (len - pos <= len - off))
	count = off;
    } else {
      if (pos == len)
	count = 0;
    }
    if (off == len)
      count = len;

    if (count)
      fprintf(stderr, "%08X  ", k++ * 16);

    for (i = 0; i < count; i++) {
      fprintf(stderr, "%02X ", data[pos + i]);

      if ((i + 1) % 4 == 0)
	fprintf(stderr, " ");
    }

    if (count && count < 16) {
      int j;

      for (j = 0; j < 16 - count; j++) {
	fprintf(stderr, "   ");

	if ((j + count + 1) % 4 == 0)
	  fprintf(stderr, " ");
      }
    }

    for (i = 0; i < count; i++) {
      char ch;

      if (data[pos] < 32 || data[pos] >= 127)
	ch = '.';
      else
	ch = data[pos];

      fprintf(stderr, "%c", ch);
      pos++;
    }

    if (count)
      fprintf(stderr, "\n");

    if (count < 16)
      break;
  }

 end:
  silc_free(string);
}

/* Sets debug callbacks */

void silc_log_set_debug_callbacks(SilcLogDebugCb debug_cb,
				  void *debug_context,
				  SilcLogHexdumpCb hexdump_cb,
				  void *hexdump_context)
{
  silc_log_debug_cb = debug_cb;
  silc_log_debug_context = debug_context;
  silc_log_hexdump_cb = hexdump_cb;
  silc_log_hexdump_context = hexdump_context;
}

/* Resets debug callbacks */

void silc_log_reset_debug_callbacks()
{
  silc_log_debug_cb = NULL;
  silc_log_debug_context = NULL;
  silc_log_hexdump_cb = NULL;
  silc_log_hexdump_context = NULL;
}

/* Set current debug string */

void silc_log_set_debug_string(const char *debug_string)
{
  char *string;
  int len;
  if ((strchr(debug_string, '(') && strchr(debug_string, ')')) ||
      strchr(debug_string, '$'))
    string = strdup(debug_string);
  else
    string = silc_string_regexify(debug_string);
  len = strlen(string);
  if (len >= sizeof(silc_log_debug_string))
    len = sizeof(silc_log_debug_string) - 1;
  memset(silc_log_debug_string, 0, sizeof(silc_log_debug_string));
  strncpy(silc_log_debug_string, string, len);
  silc_free(string);
}
