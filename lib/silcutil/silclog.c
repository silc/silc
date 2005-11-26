/*

  silclog.c

  Author: Pekka Riikonen <priikone@silcnet.org>

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

/* SilcLogSettings context */
typedef struct {
  SilcUInt32 flushdelay;

  char debug_string[128];
  SilcLogDebugCb debug_cb;
  void *debug_context;
  SilcLogHexdumpCb hexdump_cb;
  void *hexdump_context;

  unsigned int timestamp       : 1;
  unsigned int quick           : 1;
  unsigned int debug           : 1;
  unsigned int debug_hexdump   : 1;
  unsigned int scheduled       : 1;
  unsigned int no_init         : 1;
  unsigned int starting        : 1;
} *SilcLogSettings, SilcLogSettingsStruct;

/* SilcLog context */
typedef struct {
  char filename[256];
  FILE *fp;
  SilcUInt64 maxsize;
  const char *typename;
  SilcLogType type;
  SilcLogCb cb;
  void *context;
} *SilcLog, SilcLogStruct;

/* Default settings */
static SilcLogSettingsStruct silclog =
{
  300,
  { 0 },
  NULL, NULL,
  NULL, NULL,
  TRUE,
  FALSE,
  FALSE,
  FALSE,
  FALSE,
  FALSE,
  TRUE,
};

/* Default log contexts */
static SilcLogStruct silclogs[4] =
{
  {"", NULL, 0, "Info", SILC_LOG_INFO, NULL, NULL},
  {"", NULL, 0, "Warning", SILC_LOG_WARNING, NULL, NULL},
  {"", NULL, 0, "Error", SILC_LOG_ERROR, NULL, NULL},
  {"", NULL, 0, "Fatal", SILC_LOG_FATAL, NULL, NULL},
};

/* Return log context by type */

static SilcLog silc_log_get_context(SilcLogType type)
{
  if (type < 1 || type > 4)
    return NULL;
  return &silclogs[(int)type - 1];
}

/* Check log file site and cycle log file if it is over max size. */

static void silc_log_checksize(SilcLog log)
{
  char newname[256];
  SilcUInt64 size;

  if (!log || !log->fp || !log->maxsize)
    return;

  size = silc_file_size(log->filename);
  if (!size) {
    fclose(log->fp);
    log->fp = NULL;
  }

  if (size < log->maxsize)
    return;

  /* Cycle log file */
  fprintf(log->fp,
	  "[%s] [%s] Cycling log file, over max log size (%lu kilobytes)\n",
	  silc_get_time(0), log->typename, (unsigned long)log->maxsize / 1024);
  fflush(log->fp);
  fclose(log->fp);

  memset(newname, 0, sizeof(newname));
  snprintf(newname, sizeof(newname) - 1, "%s.old", log->filename);
  unlink(newname);
  rename(log->filename, newname);

  log->fp = fopen(log->filename, "w");
  if (!log->fp)
    SILC_LOG_WARNING(("Couldn't reopen log file '%s' for type '%s': %s",
		      log->filename, log->typename, strerror(errno)));
#ifdef HAVE_CHMOD
  chmod(log->filename, 0600);
#endif /* HAVE_CHMOD */
}

/* Internal timeout callback to flush log channels and check file sizes */

SILC_TASK_CALLBACK(silc_log_fflush_callback)
{
  SilcLog log;

  if (!silclog.quick) {
    silc_log_flush_all();
    log = silc_log_get_context(SILC_LOG_INFO);
    silc_log_checksize(log);
    log = silc_log_get_context(SILC_LOG_WARNING);
    silc_log_checksize(log);
    log = silc_log_get_context(SILC_LOG_ERROR);
    silc_log_checksize(log);
    log = silc_log_get_context(SILC_LOG_FATAL);
    silc_log_checksize(log);
  }

  silclog.starting = FALSE;

  if (silclog.flushdelay < 2)
    silclog.flushdelay = 2;
  silc_schedule_task_add_timeout(context, silc_log_fflush_callback, context,
				 silclog.flushdelay, 0);
}

/* Output log message to log file */

void silc_log_output(SilcLogType type, char *string)
{
  const char *typename = NULL;
  SilcLog log = silc_log_get_context(type);
  FILE *fp;

  if (!log)
    goto end;

  /* Forward to callback if set */
  if (log->cb)
    if ((*log->cb)(type, string, log->context))
      goto end;

  typename = log->typename;

  if (!silclog.scheduled) {
    if (silclog.no_init == FALSE) {
      fprintf(stderr,
	      "Warning, trying to output without log files initialization, "
	      "log output is going to stderr\n");
      silclog.no_init = TRUE;
    }

    fp = stderr;
    log = NULL;
    goto found;
  }

  /* Find open log file */
  while (log) {
    if (log->fp) {
      fp = log->fp;
      break;
    }

    log = silc_log_get_context(--type);
  }
  if (!log || !log->fp)
    goto end;

 found:
  if (silclog.timestamp)
    fprintf(fp, "[%s] [%s] %s\n", silc_get_time(0), typename, string);
  else
    fprintf(fp, "[%s] %s\n", typename, string);

  if (silclog.quick || silclog.starting) {
    fflush(fp);
    if (log)
      silc_log_checksize(log);
  }

 end:
  /* Output log to stderr if debugging */
  if (typename && silclog.debug) {
    fprintf(stderr, "[Logging] [%s] %s\n", typename, string);
    fflush(stderr);
  }
  silc_free(string);
}

/* Set and initialize the specified log file. */

SilcBool silc_log_set_file(SilcLogType type, char *filename, SilcUInt32 maxsize,
		       SilcSchedule scheduler)
{
  FILE *fp = NULL;
  SilcLog log;

  log = silc_log_get_context(type);
  if (!log)
    return FALSE;

  SILC_LOG_DEBUG(("Setting '%s' file to %s (max size=%d)",
		  log->typename, filename, maxsize));

  /* Open log file */
  if (filename) {
    fp = fopen(filename, "a+");
    if (!fp) {
      fprintf(stderr, "warning: couldn't open log file '%s': %s\n",
	      filename, strerror(errno));
      return FALSE;
    }
#ifdef HAVE_CHMOD
    chmod(filename, 0600);
#endif /* HAVE_CHMOD */
  }

  /* Close previous log file if it exists */
  if (strlen(log->filename)) {
    if (log->fp)
      fclose(log->fp);
    memset(log->filename, 0, sizeof(log->filename));
    log->fp = NULL;
  }

  /* Set new log file */
  if (fp) {
    log->fp = fp;
    log->maxsize = maxsize;

    memset(log->filename, 0, sizeof(log->filename));
    silc_strncat(log->filename, sizeof(log->filename), filename,
		 strlen(filename));
  }

  /* Add flush timeout */
  if (scheduler) {
    silc_schedule_task_del_by_callback(scheduler, silc_log_fflush_callback);
    silc_schedule_task_add_timeout(scheduler, silc_log_fflush_callback,
				   scheduler, 10, 0);
    silclog.scheduled = TRUE;
  }

  return TRUE;
}

/* Return log filename */

char *silc_log_get_file(SilcLogType type)
{
  SilcLog log = silc_log_get_context(type);
  return log && log->fp ? log->filename : NULL;
}

/* Sets a log callback, set callback to NULL to return to default behaviour */

void silc_log_set_callback(SilcLogType type, SilcLogCb cb, void *context)
{
  SilcLog log = silc_log_get_context(type);
  if (log) {
    log->cb = cb;
    log->context = context;
  }
}

/* Reset log callbacks */

void silc_log_reset_callbacks(void)
{
  SilcLog log;
  log = silc_log_get_context(SILC_LOG_INFO);
  log->cb = log->context = NULL;
  log = silc_log_get_context(SILC_LOG_WARNING);
  log->cb = log->context = NULL;
  log = silc_log_get_context(SILC_LOG_ERROR);
  log->cb = log->context = NULL;
  log = silc_log_get_context(SILC_LOG_FATAL);
  log->cb = log->context = NULL;
}

/* Flush all log files */

void silc_log_flush_all(void)
{
  SilcLog log;
  log = silc_log_get_context(SILC_LOG_INFO);
  if (log->fp)
    fflush(log->fp);
  log = silc_log_get_context(SILC_LOG_WARNING);
  if (log->fp)
    fflush(log->fp);
  log = silc_log_get_context(SILC_LOG_ERROR);
  if (log->fp)
    fflush(log->fp);
  log = silc_log_get_context(SILC_LOG_FATAL);
  if (log->fp)
    fflush(log->fp);
}

/* Reset a log file */

static void silc_log_reset(SilcLog log)
{
  if (log->fp) {
    fflush(log->fp);
    fclose(log->fp);
  }

  if (!strlen(log->filename))
    return;

  log->fp = fopen(log->filename, "a+");
  if (!log->fp)
    SILC_LOG_WARNING(("Couldn't reset log file '%s' for type '%s': %s",
		      log->filename, log->typename, strerror(errno)));
}

/* Reset all log files */

void silc_log_reset_all(void)
{
  SilcLog log;
  log = silc_log_get_context(SILC_LOG_INFO);
  if (log->fp)
    silc_log_reset(log);
  log = silc_log_get_context(SILC_LOG_WARNING);
  if (log->fp)
    silc_log_reset(log);
  log = silc_log_get_context(SILC_LOG_ERROR);
  if (log->fp)
    silc_log_reset(log);
  log = silc_log_get_context(SILC_LOG_FATAL);
  if (log->fp)
    silc_log_reset(log);
  silc_log_flush_all();
}

/* Sets debug callbacks */

void silc_log_set_debug_callbacks(SilcLogDebugCb debug_cb,
				  void *debug_context,
				  SilcLogHexdumpCb hexdump_cb,
				  void *hexdump_context)
{
  silclog.debug_cb = debug_cb;
  silclog.debug_context = debug_context;
  silclog.hexdump_cb = hexdump_cb;
  silclog.hexdump_context = hexdump_context;
}

/* Resets debug callbacks */

void silc_log_reset_debug_callbacks()
{
  silclog.debug_cb = NULL;
  silclog.debug_context = NULL;
  silclog.hexdump_cb = NULL;
  silclog.hexdump_context = NULL;
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
  if (len >= sizeof(silclog.debug_string))
    len = sizeof(silclog.debug_string) - 1;
  memset(silclog.debug_string, 0, sizeof(silclog.debug_string));
  strncpy(silclog.debug_string, string, len);
  silc_free(string);
}

/* Set timestamp */

void silc_log_timestamp(SilcBool enable)
{
  silclog.timestamp = enable;
}

/* Set flushdelay */

void silc_log_flushdelay(SilcUInt32 flushdelay)
{
  silclog.flushdelay = flushdelay;
}

/* Set quick logging */

void silc_log_quick(SilcBool enable)
{
  silclog.quick = enable;
}

/* Set debugging */

void silc_log_debug(SilcBool enable)
{
  silclog.debug = enable;
}

/* Set debug hexdump */

void silc_log_debug_hexdump(SilcBool enable)
{
  silclog.debug_hexdump = enable;
}

/* Outputs the debug message to stderr. */

void silc_log_output_debug(char *file, const char *function,
			   int line, char *string)
{
  if (!silclog.debug)
    goto end;

  if (!silc_string_regex_match(silclog.debug_string, file) &&
      !silc_string_regex_match(silclog.debug_string, function))
    goto end;

  if (silclog.debug_cb) {
    if ((*silclog.debug_cb)(file, (char *)function, line, string,
			    silclog.debug_context))
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

  if (!silclog.debug_hexdump)
    goto end;

  if (!silc_string_regex_match(silclog.debug_string, file) &&
      !silc_string_regex_match(silclog.debug_string, function))
    goto end;

  if (silclog.hexdump_cb) {
    if ((*silclog.hexdump_cb)(file, (char *)function, line,
			      data_in, len, string, silclog.hexdump_context))
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
