/*

  silclog.c

  Author: Johnny Mnemonic <johnny@themnemonic.org>

  Copyright (C) 1997 - 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"

/* default flush time (5 minutes) */
#define SILC_LOG_TIMEOUT 300

/* nice macro for looping through all logs -- makes the code more readable */
#define SILC_FOREACH_LOG(__x__) for (__x__ = 0; __x__ < SILC_LOG_MAX; __x__++)

/* Our working struct -- at the moment we keep it private, but this could
 * change in the future */
struct SilcLogStruct {
  char *filename;
  FILE *fp;
  uint32 maxsize;
  char *typename;
  SilcLogType type;
  SilcLogCb cb;
  void *context;
};
typedef struct SilcLogStruct *SilcLog;

/* These are the known logging channels */
static struct SilcLogStruct silclogs[SILC_LOG_MAX] = {
  {NULL, NULL, 0, "Info", SILC_LOG_INFO, NULL, NULL},
  {NULL, NULL, 0, "Error", SILC_LOG_ERROR, NULL, NULL},
  {NULL, NULL, 0, "Warning", SILC_LOG_WARNING, NULL, NULL},
  {NULL, NULL, 0, "Fatal", SILC_LOG_FATAL, NULL, NULL},
};

/* If TRUE, log files will be flushed for each log input */
bool silc_log_quick = FALSE;

/* Set TRUE/FALSE to enable/disable debugging */
bool silc_debug = FALSE;
bool silc_debug_hexdump = FALSE;

/* Regular pattern matching expression for the debug output */
static char *silc_log_debug_string = NULL;

/* Debug callbacks. If set these are used instead of default ones. */
static SilcLogDebugCb silc_log_debug_cb = NULL;
static void *silc_log_debug_context = NULL;
static SilcLogHexdumpCb silc_log_hexdump_cb = NULL;
static void *silc_log_hexdump_context = NULL;

/* Did we register already our functions to the scheduler? */
static bool silc_log_scheduled = FALSE;
static bool silc_log_no_init = FALSE;

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
 * max size set less then the current size */
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
    SILC_LOG_ERROR(("Error while checking size of the log file %s, fp=%d",
		    log->filename, oldfp));
    return;
  }
  if (size < log->maxsize) return;

  /* It's too big */
  fprintf(log->fp, "[%s] [%s] Cycling log file, over max "
	  "logsize (%lu kilobytes)\n",
	  silc_get_time(), log->typename, log->maxsize / 1024);
  fflush(log->fp);
  fclose(log->fp);
  snprintf(newname, sizeof(newname), "%s.old", log->filename);
  unlink(newname);

  /* I heard the following syscall may cause portability issues, but I don't
   * have any other solution since SILC library doesn't provide any other
   * function like this. -Johnny */
  rename(log->filename, newname);
  if (!(log->fp = fopen(log->filename, "w")))
    SILC_LOG_WARNING(("Couldn't reopen logfile %s for type \"%s\": %s",
		      log->filename, log->typename, strerror(errno)));
}

/* Reset a logging channel (close and reopen) */

static bool silc_log_reset(SilcLog log)
{
  if (!log) return FALSE;
  if (log->fp) {
    fflush(log->fp);
    fclose(log->fp);
  }
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
  silc_schedule_task_add((SilcSchedule) context, 0, silc_log_fflush_callback,
			 context, SILC_LOG_TIMEOUT, 0, SILC_TASK_TIMEOUT,
			 SILC_TASK_PRI_NORMAL);
}

/* Outputs the log message to the first available channel. Channels are
 * ordered by importance (see SilcLogType documentation).
 * More importants channels can be printed on less important ones, but not
 * vice-versa. */

void silc_log_output(SilcLogType type, char *string)
{
  char *typename;
  SilcLog log;

  if ((type > SILC_LOG_MAX) || !(log = silc_log_find_by_type(type)))
    goto end;

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

    fprintf(stderr, "%s\n", string);
    goto end;
  }

  /* save the original typename, because if we redirect the channel we
   * keep however the original destination channel name */
  typename = log->typename;

  /* ok, now we have to find an open stream */
  while (TRUE) {
    if (log && log->fp) goto found;
    if (type == 0) break;
    log = silc_log_find_by_type(--type);
  }

  /* Couldn't find any open stream.. sorry :( */
  SILC_LOG_DEBUG(("Warning! couldn't find any available log channel!"));
  goto end;

 found:
  fprintf(log->fp, "[%s] [%s] %s\n", silc_get_time(), typename, string);
  if (silc_log_quick) {
    fflush(log->fp);
    silc_log_checksize(log);
  }

 end:
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
bool silc_log_set_file(SilcLogType type, char *filename, uint32 maxsize,
		       SilcSchedule scheduler)
{
  FILE *fp = NULL;
  SilcLog log;

  log = silc_log_find_by_type(type);
  if (!log || !scheduler)
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
  }

  /* remove old file */
  if (log->filename) {
    if (log->fp) {
      fflush(fp);
      fclose(fp);
    }
    silc_free(log->filename);
    log->filename = NULL;
    log->fp = NULL;
  }

  if (fp) {
    log->filename = strdup(filename);
    log->fp = fp;
    log->maxsize = maxsize;
  }

  if (silc_log_scheduled)
    return TRUE;

  /* make sure we write to the disk sometimes */
  silc_schedule_task_add(scheduler, 0, silc_log_fflush_callback,
			 (void *) scheduler, SILC_LOG_TIMEOUT, 0,
			 SILC_TASK_TIMEOUT, SILC_TASK_PRI_NORMAL);

  silc_log_scheduled = TRUE;

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
}

/* Outputs the debug message to stderr. */

void silc_log_output_debug(char *file, char *function,
			   int line, char *string)
{
  if (!silc_debug)
    goto end;
  if (silc_log_debug_string &&
	!silc_string_regex_match(silc_log_debug_string, file) &&
	!silc_string_regex_match(silc_log_debug_string, function))
    goto end;
  if (silc_log_debug_cb) {
    if ((*silc_log_debug_cb)(file, function, line, string,
			     silc_log_debug_context))
      goto end;
  }
  fprintf(stderr, "%s:%d: %s\n", function, line, string);
  fflush(stderr);
end:
  silc_free(string);
}

/* Hexdumps a message */

void silc_log_output_hexdump(char *file, char *function,
			     int line, void *data_in,
			     uint32 len, char *string)
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
    if ((*silc_log_hexdump_cb)(file, function, line, data_in, len, string,
			       silc_log_hexdump_context))
      goto end;
  }

  fprintf(stderr, "%s:%d: %s\n", function, line, string);
  silc_free(string);

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
  return;

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
  silc_free(silc_log_debug_string);
  if ((strchr(debug_string, '(') &&
	strchr(debug_string, ')')) ||
	strchr(debug_string, '$'))
    silc_log_debug_string = strdup(debug_string);
  else
    silc_log_debug_string = silc_string_regexify(debug_string);
}
