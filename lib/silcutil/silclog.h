/*

  silclog.h

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

#ifndef SILCLOG_H
#define SILCLOG_H

/* Set TRUE/FALSE to enable/disable debugging */
extern int silc_debug;

/* SILC Log types */
typedef enum {
  SILC_LOG_INFO,
  SILC_LOG_WARNING,
  SILC_LOG_ERROR,
  SILC_LOG_FATAL
} SilcLogType;

/* Log type name structure. */
typedef struct {
  char *name;
  SilcLogType type;
} SilcLogTypeName;

/* Log function callback. */
typedef void (*SilcLogCb)(char *message);

/* Debug function callback. */
typedef void (*SilcDebugCb)(char *file, char *function, 
			    int line, char *message);

/* Debug hexdump function callback. */
typedef void (*SilcDebugHexdumpCb)(char *file, char *function, 
				   int line, unsigned char *data,
				   unsigned int data_len, char *message);

/* Default log filenames */
#define SILC_LOG_FILE_INFO "silcd.log"
#define SILC_LOG_FILE_WARNING "silcd_error.log"
#define SILC_LOG_FILE_ERROR SILC_LOG_FILE_WARNING
#define SILC_LOG_FILE_FATAL SILC_LOG_FILE_WARNING

/* Log files. Set by silc_log_set_logfiles. */
extern char *log_info_file;
extern char *log_warning_file;
extern char *log_error_file;
extern char *log_fatal_file;
extern unsigned int log_info_size;
extern unsigned int log_warning_size;
extern unsigned int log_error_size;
extern unsigned int log_fatal_size;

/* Log macros. */
#define SILC_LOG_INFO(fmt) (silc_log_output(log_info_file, \
                                           log_info_size, \
					   SILC_LOG_INFO, \
					   silc_log_format fmt))
#define SILC_LOG_WARNING(fmt) (silc_log_output(log_warning_file, \
                                               log_warning_size, \
					       SILC_LOG_WARNING, \
					       silc_log_format fmt))
#define SILC_LOG_ERROR(fmt) (silc_log_output(log_error_file, \
                                             log_error_size, \
					     SILC_LOG_ERROR, \
					     silc_log_format fmt))
#define SILC_LOG_FATAL(fmt) (silc_log_output(log_fatal_file, \
                                             log_fatal_size, \
					     SILC_LOG_FATAL, \
					     silc_log_format fmt))

/* Debug macro is a bit different from other logging macros and it
   is compiled in only if debugging is enabled. */
#ifdef SILC_DEBUG
#define SILC_LOG_DEBUG(fmt) (silc_log_output_debug(__FILE__, \
						   __FUNCTION__, \
						   __LINE__, \
						   silc_log_format fmt))
#define SILC_LOG_HEXDUMP(fmt, data, len) \
  (silc_log_output_hexdump(__FILE__, \
			   __FUNCTION__, \
			   __LINE__, \
                           (data), (len), \
			   silc_log_format fmt))
#else
#define SILC_LOG_DEBUG(fmt)
#define SILC_LOG_HEXDUMP(fmt, data, len)
#endif

/* Prototypes */
char *silc_log_format(char *fmt, ...);
void silc_log_output_debug(char *file, char *function, 
                           int line, char *string);
void silc_log_output(const char *filename, unsigned int maxsize,
                     SilcLogType type, char *string);
void silc_log_output_hexdump(char *file, char *function, 
			     int line, void *data_in,
                             unsigned int len, char *string);
void silc_log_set_files(char *info, unsigned int info_size, 
			char *warning, unsigned int warning_size,
			char *error, unsigned int error_size,
                        char *fatal, unsigned int fatal_size);
void silc_log_set_callbacks(SilcLogCb info, SilcLogCb warning,
			    SilcLogCb error, SilcLogCb fatal);
void silc_log_reset_callbacks();
void silc_log_set_debug_callbacks(SilcDebugCb debug, 
				  SilcDebugHexdumpCb debug_hexdump);
void silc_log_reset_debug_callbacks();

#endif
