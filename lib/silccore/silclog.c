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
/*
 * $Id$
 * $Log$
 * Revision 1.5  2000/07/17 16:46:37  priikone
 * 	Still bug fix in silc_log_format :)
 *
 * Revision 1.4  2000/07/17 16:44:57  priikone
 * 	Buffer overflow bug fixe in silc_log_format.
 *
 * Revision 1.3  2000/07/05 06:06:35  priikone
 * 	Global cosmetic change.
 *
 * Revision 1.2  2000/07/03 05:53:58  priikone
 * 	Fixed file purging bug.  The purging should work now ok.
 *
 * Revision 1.1.1.1  2000/06/27 11:36:55  priikone
 * 	Imported from internal CVS/Added Log headers.
 *
 *
 */

#include "silcincludes.h"

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
unsigned int log_info_size;
unsigned int log_warning_size;
unsigned int log_error_size;
unsigned int log_fatal_size;

/* Formats arguments to a string and returns it after allocating memory
   for it. It must be remembered to free it later. */

char *silc_log_format(char *fmt, ...)
{
  va_list args;
  static char buf[8192];

  memset(buf, 0, sizeof(buf));
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf) - 1, fmt, args);
  va_end(args);

  return strdup(buf);
}

/* Outputs the log message to what ever log file selected. */

void silc_log_output(const char *filename, unsigned int maxsize,
                     SilcLogType type, char *string)
{
  FILE *fp;
  const SilcLogTypeName *np;

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
    }
  }

  /* Open the log file */
  if ((fp = fopen(filename, "a+")) == NULL) {
    fprintf(stderr, "warning: could not open log file "
	    "%s: %s\n", filename, strerror(errno));
    fprintf(stderr, "warning: log messages will be displayed on the screen\n");
    fp = stderr;
  }
 
  /* Get the log type name */
  for(np = silc_log_types; np->name; np++) {
    if (np->type == type)
      break;
  }

  fprintf(fp, "[%s] [%s] %s\n", silc_get_time(), np->name, string);
  fflush(fp);
  fclose(fp);
  silc_free(string);
}

/* Outputs the debug message to stderr. */

void silc_log_output_debug(char *file, char *function, 
			   int line, char *string)
{
  /* fprintf(stderr, "%s:%s:%d: %s\n", file, function, line, string); */
  fprintf(stderr, "%s:%d: %s\n", function, line, string);
  fflush(stderr);
  silc_free(string);
}

/* Hexdumps a message */

void silc_log_output_hexdump(char *file, char *function, 
			     int line, void *data_in,
			     unsigned int len, char *string)
{
  int i, k;
  int off, pos, count;
  unsigned char *data = (unsigned char *)data_in;

  /* fprintf(stderr, "%s:%s:%d: %s\n", file, function, line, string); */
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

void silc_log_set_files(char *info, unsigned int info_size, 
			char *warning, unsigned int warning_size,
			char *error, unsigned int error_size,
			char *fatal, unsigned int fatal_size)
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
