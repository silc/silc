/*

  silclog.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

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

/* Set TRUE/FALSE to enable/disable debugging */
bool silc_debug = FALSE;
bool silc_debug_hexdump = FALSE;
char *silc_debug_string = NULL;

/* SILC Log name strings. These strings are printed to the log file. */
const SilcLogTypeName silc_log_types[] =
{
  { "Info", SILC_LOG_INFO },
  { "Warning", SILC_LOG_WARNING },
  { "Error", SILC_LOG_ERROR },
  { "Fatal", SILC_LOG_FATAL },

  { NULL, -1 },
};

char *log_info_file;
char *log_warning_file;
char *log_error_file;
char *log_fatal_file;
uint32 log_info_size;
uint32 log_warning_size;
uint32 log_error_size;
uint32 log_fatal_size;

/* Log callbacks. If these are set by the application these are used
   instead of the default functions in this file. */
static SilcLogCb info_cb = NULL;
static SilcLogCb warning_cb = NULL;
static SilcLogCb error_cb = NULL;
static SilcLogCb fatal_cb = NULL;

/* Debug callbacks. If set these are used instead of default ones. */
static SilcDebugCb debug_cb = NULL;
static SilcDebugHexdumpCb debug_hexdump_cb = NULL;

/* Outputs the log message to what ever log file selected. */

void silc_log_output(const char *filename, uint32 maxsize,
                     SilcLogType type, char *string)
{
  FILE *fp;
  const SilcLogTypeName *np;

  switch(type)
    {
    case SILC_LOG_INFO:
      if (info_cb) {
	(*info_cb)(string);
	silc_free(string);
	return;
      }
      break;
    case SILC_LOG_WARNING:
      if (warning_cb) {
	(*warning_cb)(string);
	silc_free(string);
	return;
      }
      break;
    case SILC_LOG_ERROR:
      if (error_cb) {
	(*error_cb)(string);
	silc_free(string);
	return;
      }
      break;
    case SILC_LOG_FATAL:
      if (fatal_cb) {
	(*fatal_cb)(string);
	silc_free(string);
	return;
      }
      break;
    }

  if (!filename)
    fp = stderr;
  else {
    /* Purge the log file if the max size is defined. */
    if (maxsize) {
      fp = fopen(filename, "r");
      if (fp) {
	int filelen;
	
	filelen = fseek(fp, (off_t)0L, SEEK_END);
	fseek(fp, (off_t)0L, SEEK_SET);  
	
	/* Purge? */
	if (filelen >= maxsize)
	  unlink(filename);
	
	fclose(fp);
      }
    }
    
    /* Open the log file */
    if ((fp = fopen(filename, "a+")) == NULL) {
      fprintf(stderr, "warning: could not open log file "
	      "%s: %s\n", filename, strerror(errno));
      fprintf(stderr, "warning: log messages will be displayed on "
	      "the screen\n");
      fp = stderr;
    }
  }

  /* Get the log type name */
  for (np = silc_log_types; np->name; np++) {
    if (np->type == type)
      break;
  }

  fprintf(fp, "[%s] [%s] %s\n", silc_get_time(), np->name, string);
  fflush(fp);
  if (fp != stderr)
    fclose(fp);
  silc_free(string);
}

/* Outputs the debug message to stderr. */

void silc_log_output_debug(char *file, char *function, 
			   int line, char *string)
{
  if (!silc_debug) {
    silc_free(string);
    return;
  }

  if (silc_debug_string && 
      (!silc_string_regex_match(silc_debug_string, file) &&
       !silc_string_regex_match(silc_debug_string, function))) {
    silc_free(string);
    return;
  }

  if (debug_cb) {
    (*debug_cb)(file, function, line, string);
    silc_free(string);
    return;
  }

  fprintf(stderr, "%s:%d: %s\n", function, line, string);
  fflush(stderr);
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

  if (!silc_debug_hexdump) {
    silc_free(string);
    return;
  }

  if (silc_debug_string && 
      (!silc_string_regex_match(silc_debug_string, file) &&
       !silc_string_regex_match(silc_debug_string, function))) {
    silc_free(string);
    return;
  }

  if (debug_hexdump_cb) {
    (*debug_hexdump_cb)(file, function, line, data_in, len, string);
    silc_free(string);
    return;
  }

  fprintf(stderr, "%s:%d: %s\n", function, line, string);
  silc_free(string);

  k = 0;
  off = len % 16;
  pos = 0;
  count = 16;
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
}

/* Sets log files */

void silc_log_set_files(char *info, uint32 info_size, 
			char *warning, uint32 warning_size,
			char *error, uint32 error_size,
			char *fatal, uint32 fatal_size)
{
  log_info_file = info;
  log_warning_file = warning;
  log_error_file = error;
  log_fatal_file = fatal;

  log_info_size = info_size;
  log_warning_size = warning_size;
  log_error_size = error_size;
  log_fatal_size = fatal_size;
}

/* Sets log callbacks */

void silc_log_set_callbacks(SilcLogCb info, SilcLogCb warning,
			    SilcLogCb error, SilcLogCb fatal)
{
  info_cb = info;
  warning_cb = warning;
  error_cb = error;
  fatal_cb = fatal;
}

/* Resets log callbacks */

void silc_log_reset_callbacks()
{
  info_cb = warning_cb = error_cb = fatal_cb = NULL;
}

/* Sets debug callbacks */

void silc_log_set_debug_callbacks(SilcDebugCb debug, 
				  SilcDebugHexdumpCb debug_hexdump)
{
  debug_cb = debug;
  debug_hexdump_cb = debug_hexdump;
}

/* Resets debug callbacks */

void silc_log_reset_debug_callbacks()
{
  debug_cb = NULL;
  debug_hexdump_cb = NULL;
}

/* Set current debug string */

void silc_log_set_debug_string(const char *debug_string)
{
  silc_free(silc_debug_string);
  if ((strchr(debug_string, '(') &&
       strchr(debug_string, ')')) ||
      strchr(debug_string, '$'))
    silc_debug_string = strdup(debug_string);
  else
    silc_debug_string = silc_string_regexify(debug_string);
}
