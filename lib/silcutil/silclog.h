/*

  silclog.h

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

/****h* silcutil/SILC Logging Interface
 *
 * DESCRIPTION
 *
 * The SILC logging APIs provide a powerful and easy-to-use interface to
 * the logging system and debugging output.
 *
 ***/

#ifndef SILCLOG_H
#define SILCLOG_H

/****d* silcutil/SilcLogAPI/SilcLogType
 *
 * NAME
 *
 *    typedef enum { ... } SilcLogType;
 *
 * DESCRIPTION
 *
 *    This is the main logging channel id. There are currently four known
 *    logging channels (plus the debugging output channel), and they are
 *    ordered by importance.
 *    See the source code for SILC coding conventions about how to choose
 *    the right output channel.
 *
 * SOURCE
 */
typedef enum {
  /* Generic info channel file */
  SILC_LOG_INFO,

  /* This should be used for warnings and non critical failures */
  SILC_LOG_WARNING,

  /* Generic error and critical failure messages */
  SILC_LOG_ERROR,

  /* Fatal messages (usually situations that will lead to a program crash */
  SILC_LOG_FATAL,

  /* Total number logging channels */
  SILC_LOG_MAX
} SilcLogType;
/***/

/****f* silcutil/SilcLogAPI/SilcLogCb
 *
 * SYNOPSIS
 *
 *    typedef bool (*SilcLogCb)(SilcLogType type, char *message,
 *                              void *context);
 *
 * DESCRIPTION
 *
 *    The logging custom callback function.  The `type' is the channel ID
 *    that triggered the event, which allows you to use the same callback
 *    function for multiple logging channels.
 *    The `message' parameter points to a null-terminated buffer containing
 *    the received message, while `context' is the caller-specified context.
 *    The message must not be modified or freed by the callback function.
 *
 * SEE ALSO
 *    silc_log_set_callback
 *
 ***/
typedef bool (*SilcLogCb)(SilcLogType type, char *message, void *context);

/****f* silcutil/SilcLogAPI/SilcLogDebugCb
 *
 * SYNOPSIS
 *
 *    typedef bool (*SilcLogDebugCb)(char *file, char *function, int line,
 *                                   char *message, void *context);
 *
 * DESCRIPTION
 *
 *    The debug logging callback function.  The default behaviour is to
 *    output messages to stderr.  `file', `function', and `line' are the
 *    corresponding offsets in the source files.  `message' points to a
 *    null-terminated buffer containing the debugging message, and `context'
 *    is the caller-specified context.
 *    The message must not be modified or freed by the callback function.
 *    If the function returns TRUE, SilcLog will assume the message as handled
 *    and won't run its default handler.
 *
 * SEE ALSO
 *    silc_debug, silc_log_set_debug_callbacks
 *
 ***/
typedef bool (*SilcLogDebugCb)(char *file, char *function, int line,
			       char *message, void *context);

/****f* silcutil/SilcLogAPI/SilcLogHexdumpCb
 *
 * SYNOPSIS
 *
 *    typedef bool (*SilcDebugHexdumpCb)(char *file, char *function, int line,
 *                                       unsigned char *data, SilcUInt32 data_len,
 *                                       char *message, void *context;
 *
 * DESCRIPTION
 *
 *    The hexdump logging callback function.  The default behaviour is to
 *    print a formatted hexdump to stderr, and is commonly what you would
 *    like it to be.  `file', `function', and `line' are the corresponding
 *    offsets in the source files.  `data' is the begin of the buffer that
 *    should be hexdumped, which is `data_len' bytes long.
 *    The `message' parameter points to a null-terminated buffer containing
 *    the received message, while `context' is the caller-specified context.
 *    The message must not be modified or freed by the callback function.
 *    If the function returns TRUE, SilcLog will assume the message as handled
 *    and won't run its default handler.
 *
 * SEE ALSO
 *    silc_debug_hexdump, silc_log_set_debug_callbacks
 *
 ***/
typedef bool (*SilcLogHexdumpCb)(char *file, char *function, int line,
				 unsigned char *data, SilcUInt32 data_len,
				 char *message, void *context);

/* Global Variables */

/****v* silcutil/SilcLogAPI/silc_log_timestamp
 *
 * NAME
 *
 *    bool silc_log_timestamp -- enable/disable fast logging timestamp
 *
 * DESCRIPTION
 *
 *    Causes SilcLog to add a timestamp as returned by silc_get_time().
 *    This may be useful for example if you run your application under a
 *    daemon helper like watchdog that adds its own timestamp.  Defaults to
 *    true.
 *
 ***/
extern DLLAPI bool silc_log_timestamp;

/****v* silcutil/SilcLogAPI/silc_log_quick
 *
 * NAME
 *
 *    bool silc_log_quick -- enable/disable fast logging output
 *
 * DESCRIPTION
 *
 *    SilcLog makes use of libc stream buffering output, which means that it
 *    saves HD activity by buffering the logging messages and writing them
 *    all together every some minutes (default is 5 minutes).
 *    Setting this variable to TRUE will force SilcLog to write messages to the
 *    filesystem as soon as they are received. This increases the CPU activity
 *    notably on bigger servers, but reduces memory usage.
 *    If you want to change the logging style on-the-fly, make sure to call
 *    silc_log_flush_all() after setting this variable to TRUE.
 *
 ***/
extern DLLAPI bool silc_log_quick;

/****v* silcutil/SilcLogAPI/silc_log_flushdelay
 *
 * NAME
 *
 *    long silc_log_flushdelay -- flushing time delay
 *
 * DESCRIPTION
 *
 *    Sets the logfiles flushing delay in seconds.  As for now, changing this
 *    value AFTER logfiles initialization won't take effect until previous
 *    delay time will expire; for example if you change from 300 seconds to
 *    60 seconds you will have to wait up to 300 seconds for this change to
 *    take effect.
 *    This value must be greater than 2 seconds.
 *
 ***/
extern DLLAPI long silc_log_flushdelay;

/****v* silcutil/SilcLogAPI/silc_debug
 *
 * NAME
 *
 *    bool silc_debug -- enable/disable debugging output
 *
 * DESCRIPTION
 *
 *    If silc_debug is set to FALSE, debugging functions won't procude any
 *    output.  This is useful when for example you compile in the debugging
 *    support but at a certain point you want to send the program in the
 *    background.
 *
 * SEE ALSO
 *    SILC_LOG_DEBUG
 *
 ***/
extern DLLAPI bool silc_debug;

/****v* silcutil/SilcLogAPI/silc_debug_hexdump
 *
 * NAME
 *
 *    bool silc_debug_hexdump -- enable/disable debugging output
 *
 * DESCRIPTION
 *
 *    If silc_debug_hexdump is set to FALSE, debugging functions won't produce
 *    any output.  This is useful when for example you compile in the debugging
 *    support but at a certain point you want to send the program in the
 *    background.
 *
 * SEE ALSO
 *    SILC_LOG_HEXDUMP
 *
 ***/
extern DLLAPI bool silc_debug_hexdump;

/* Macros */

#if defined(WIN32)
#ifndef __FUNCTION__
#define __FUNCTION__ ""
#endif
#endif

/****d* silcutil/SilcLogAPI/SILC_ENABLE_DEBUG
 *
 * NAME
 *
 *    #define SILC_ENABLE_DEBUG
 *
 * DESCRIPTION
 *
 *    Use this macro to enable the debugging in your application.  If
 *    SILC was compiled with debugging enabled, this macro enables it.
 *    Use this macro in your application's main header, or in place where
 *    you need to enable the debugging.
 *
 * NOTES
 *
 *    You still can control the debugging with silc_debug variable, on
 *    whether to actually print the debugging or not.  This macro is
 *    used to enable debugging, not to say it is printed or not.
 *
 * SOURCE
 */
#define SILC_ENABLE_DEBUG	\
  #ifndef SILC_DEBUG		\
  #define SILC_DEBUG 1		\
  #endif SILC_DEBUG		\
/***/

/****d* silcutil/SilcLogAPI/SILC_LOG_INFO
 *
 * NAME
 *
 *    #define SILC_LOG_INFO(...)
 *
 * DESCRIPTION
 *
 *    This macro is a wrapper to the main logging function.
 *    It supports variable argument list formatting, and *automatically*
 *    appends newline at the end of the string.
 *
 * NOTES
 *
 *    This macro requires double parenthesis to ensure that the VA list
 *    formatting would work correctly.
 *
 * EXAMPLE
 *
 *    SILC_LOG_INFO(("Today i feel %s", core->mood));
 *
 * SOURCE
 */
#define SILC_LOG_INFO(fmt) silc_log_output(SILC_LOG_INFO, silc_format fmt)
/***/

/****d* silcutil/SilcLogAPI/SILC_LOG_WARNING
 *
 * NAME
 *
 *    #define SILC_LOG_WARNING(...)
 *
 * DESCRIPTION
 *
 *    Wrapper to the WARNING logging channel.
 *    Please see the SILC_LOG_INFO macro.
 *
 * SEE ALSO
 *    SILC_LOG_INFO
 *
 * SOURCE
 */
#define SILC_LOG_WARNING(fmt) silc_log_output(SILC_LOG_WARNING, silc_format fmt)
/***/

/****d* silcutil/SilcLogAPI/SILC_LOG_ERROR
 *
 * NAME
 *
 *    #define SILC_LOG_ERROR(...)
 *
 * DESCRIPTION
 *
 *    Wrapper to the ERROR logging channel.
 *    Please see the SILC_LOG_INFO macro.
 *
 * SEE ALSO
 *    SILC_LOG_INFO
 *
 * SOURCE
 */
#define SILC_LOG_ERROR(fmt) silc_log_output(SILC_LOG_ERROR, silc_format fmt)
/***/

/****d* silcutil/SilcLogAPI/SILC_LOG_FATAL
 *
 * NAME
 *
 *    #define SILC_LOG_FATAL(...)
 *
 * DESCRIPTION
 *
 *    Wrapper to the FATAL logging channel.
 *    Please see the SILC_LOG_INFO macro.
 *
 * SEE ALSO
 *    SILC_LOG_INFO
 *
 * SOURCE
 */
#define SILC_LOG_FATAL(fmt) silc_log_output(SILC_LOG_FATAL, silc_format fmt)
/***/

/****d* silcutil/SilcLogAPI/SILC_LOG_DEBUG
 *
 * NAME
 *
 *    #define SILC_LOG_DEBUG(...)
 *
 * DESCRIPTION
 *
 *    This is a special wrapper to the debugging output (usually stderr).
 *    The standard behaviour is the same as SILC_LOG_INFO, with the difference
 *    that this macro also depends on the global define SILC_DEBUG.
 *    Undefining SILC_DEBUG causes these functions to be defined to an empty
 *    value, thus removing all debug logging calls from the compiled
 *    application.
 *    This macro is also affected by the global variable silc_debug.
 *
 * SOURCE
 */
#if defined(SILC_DEBUG)
#define SILC_LOG_DEBUG(fmt) silc_log_output_debug(__FILE__, \
				__FUNCTION__, \
				__LINE__, \
				silc_format fmt)
#define SILC_NOT_IMPLEMENTED(string) \
  SILC_LOG_INFO(("*********** %s: NOT IMPLEMENTED YET", string));
#else
#define SILC_LOG_DEBUG(fmt)
#define SILC_NOT_IMPLEMENTED(string)
#endif	/* SILC_DEBUG */
/***/

/****d* silcutil/SilcLogAPI/SILC_LOG_HEXDUMP
 *
 * NAME
 *
 *    #define SILC_LOG_HEXDUMP(...)
 *
 * DESCRIPTION
 *
 *    This is a special wrapper to the hexdump output function.  This macro
 *    behaves slightly differently from other logging wrappers.
 *    The first parameter, is composed by a group of parameters delimited by
 *    parenthesis.
 *    The second parameter is a `char *' pointer pointing to the beginning
 *    of the memory section that should be hexdumped, and the third parameter
 *    is the length of this memory section.
 *    Undefining the global SILC_DEBUG define causes these functions to be
 *    defined to an empty value, thus removing all debug logging calls from
 *    the compiled application.
 *    This macro is also affected by the global variable silc_debug_hexdump.
 *
 * EXAMPLE
 *
 *    SILC_LOG_HEXDUMP(("Outgoing packet [%d], len %d", pckt->seq, pckt->len),
 *                     pckt->data, pckt->datalen);
 *
 * SOURCE
 */
#if defined(SILC_DEBUG)
#define SILC_LOG_HEXDUMP(fmt, data, len) silc_log_output_hexdump(__FILE__, \
				__FUNCTION__, \
				__LINE__, \
				(data), (len), \
				silc_format fmt)
#else
#define SILC_LOG_HEXDUMP(fmt, data, len)
#endif	/* SILC_DEBUG */
/***/

/* Prototypes */

/****f* silcutil/SilcLogAPI/silc_log_output
 *
 * SYNOPSIS
 *
 *    void silc_log_output(SilcLogType type, char *string);
 *
 * DESCRIPTION
 *
 *    This is the main function for logging output. Please note that you
 *    should rather use one of the logging wrapper macros.
 *    If you really want to use this function, its usage is quite simple.
 *    The `type' parameter identifies the channel to use, while the `string'
 *    parameter must be a dynamic allocated (null-terminated) buffer, because
 *    it will be freed at the end of this function, for internal reasons.
 *    If there are registered callbacks for the specified type, this function
 *    will first trigger those callbacks.  The callback functions must NOT
 *    free or modify the original buffer.
 *
 * SEE ALSO
 *    SILC_LOG_INFO, SILC_LOG_WARNING, SILC_LOG_ERROR, SILC_LOG_FATAL
 *
 ***/
void silc_log_output(SilcLogType type, char *string);

/****f* silcutil/SilcLogAPI/silc_log_get_file
 *
 * SYNOPSIS
 *
 *    char *silc_log_get_file(SilcLogType type);
 *
 * DESCRIPTION
 *
 *    Returns the current logging file for the channel `type'.
 *    If there has been an error during the opening of this channel, NULL
 *    is returned, even if the file has been previously set with
 *    silc_log_set_file().
 *    The returned pointer points to internally allocated storage and must
 *    not be freed, modified or stored.
 *
 ***/
char *silc_log_get_file(SilcLogType type);

/****f* silcutil/SilcLogAPI/silc_log_set_file
 *
 * SYNOPSIS
 *
 *    bool silc_log_set_file(SilcLogType type, char *filename, 
 *                           SilcUInt32 maxsize,
 *                           SilcSchedule scheduler);
 *
 * DESCRIPTION
 *
 *    Sets `filename', which can be maximum `maxsize' bytes long, as the new
 *    logging file for the channel `type'.  If you specify an illegal filename
 *    a warning message is printed and FALSE is returned.  In this case
 *    logging settings are not changed.
 *    You can disable logging for a channel by specifying NULL filename, the
 *    maxsize in this case is not important.
 *    The `scheduler' parameter is needed by the internal logging to allow
 *    buffered output and thus to save HD activity.
 *
 ***/
bool silc_log_set_file(SilcLogType type, char *filename, SilcUInt32 maxsize,
		       SilcSchedule scheduler);

/****f* silcutil/SilcLogAPI/silc_log_set_callback
 *
 * SYNOPSIS
 *
 *    void silc_log_set_callback(SilcLogType type, SilcLogCb cb,
 *                               void *context);
 *
 * DESCRIPTION
 *
 *    Set `cb' as the default callback function for the logging channel
 *    `type'.  When SilcLog receives a message for this channel, it will
 *    trigger the callback function.  If the callback function returns TRUE
 *    SilcLog will assume the input as handled and won't run its default
 *    handler.
 *    You can disable/remove a callback by setting it to NULL or calling the
 *    function silc_log_reset_callbacks.
 *    If set, the callback function must be in the form described by
 *    SilcLogCb.
 *
 * SEE ALSO
 *    silc_log_reset_callbacks
 *
 ***/
void silc_log_set_callback(SilcLogType type, SilcLogCb cb, void *context);

/****f* silcutil/SilcLogAPI/silc_log_reset_callbacks
 *
 * SYNOPSIS
 *
 *    void silc_log_reset_callbacks();
 *
 * DESCRIPTION
 *
 *    Removes all logging callbacks for normal channels.  This function does
 *    NOT remove callbacks for debugging channels (debug and hexdump), you
 *    rather need to call silc_log_set_debug_callbacks() with NULL callbacks.
 *
 ***/
void silc_log_reset_callbacks();

/****f* silcutil/SilcLogAPI/silc_log_flush_all
 *
 * SYNOPSIS
 *
 *    void silc_log_flush_all();
 *
 * DESCRIPTION
 *
 *    Forces flushing for all logging channels.  This should be called for
 *    example after receiving special signals.
 *
 * SEE ALSO
 *    silc_log_quick
 *
 ***/
void silc_log_flush_all();

/****f* silcutil/SilcLogAPI/silc_log_reset_all
 *
 * SYNOPSIS
 *
 *    void silc_log_reset_all();
 *
 * DESCRIPTION
 *
 *    Forces all logging channels to close and reopen their streams.  Useful
 *    for example after a SIGHUP signal.
 *    Please note that this function could generate some warning messages if
 *    one or more logging channels point to an illegal filename.
 *
 ***/
void silc_log_reset_all();

/****f* silcutil/SilcLogAPI/silc_log_output_debug
 *
 * SYNOPSIS
 *
 *    void silc_log_output_debug(char *file, char *function,
 *                               int line, char *string);
 *
 * DESCRIPTION
 *
 *    This is the main function for debug output.  Please note that you should
 *    rather use the wrapper macro SILC_LOG_DEBUG.
 *    If you want to use it anyway, the `file', `function', and `line' are the
 *    corresponding offsets in the source files, while `string' must be a
 *    dynamic allocated (null-terminated) buffer.
 *
 ***/
void silc_log_output_debug(char *file, char *function,
			   int line, char *string);

/****f* silcutil/SilcLogAPI/silc_log_output_hexdump
 *
 * SYNOPSIS
 *
 *    void silc_log_output_hexdump(char *file, char *function,
 *                                 int line, void *data_in,
 *                                 SilcUInt32 len, char *string);
 *
 * DESCRIPTION
 *
 *    This is the main function for hexdump output.  Please note that you
 *    should rather use the wrapper macro SILC_LOG_HEXDUMP.
 *    If you want to use it anyway, the `file', `function', and `line' are the
 *    corresponding offsets in the source files, `data_in' is the beginning
 *    of the buffer you wish to hexdump, which is `len' bytes long.
 *    `string' must be a dynamic allocated (null-terminated) buffer.
 *
 ***/
void silc_log_output_hexdump(char *file, char *function,
			     int line, void *data_in,
			     SilcUInt32 len, char *string);

/****f* silcutil/SilcLogAPI/silc_log_set_debug_callbacks
 *
 * SYNOPSIS
 *
 *    void silc_log_set_debug_callbacks(SilcLogDebugCb debug_cb,
 *                                      void *debug_context,
 *                                      SilcLogHexdumpCb hexdump_cb,
 *                                      void *hexdump_context);
 *
 * DESCRIPTION
 *
 *    Sets `debug_cb' as the the default callback function for the debug
 *    output, that will be called with the `debug_context' parameter.
 *    When SilcLog receives a debug message, it will trigger the callback
 *    function.  If the callback function returns TRUE SilcLog will assume
 *    the input as handled and won't run its default handler.
 *    `hexdump_cb' and `hexdump_context' works the same way, except that they
 *    are referred to SILC_LOG_HEXDUMP requests.
 *    You can disable/remove a callback by setting it to NULL.
 *    If set, each callback function must be either in the form described by
 *    SilcLogDebugCb or SilcLogHexdumpCb.
 *
 * SEE ALSO
 *    SilcLogDebugCb,  SilcLogHexdumpCb
 *
 ***/
void silc_log_set_debug_callbacks(SilcLogDebugCb debug_cb,
				  void *debug_context,
				  SilcLogHexdumpCb hexdump_cb,
				  void *hexdump_context);

/****f* silcutil/SilcLogAPI/silc_log_set_debug_string
 *
 * SYNOPSIS
 *
 *    void silc_log_set_debug_string(const char *debug_string);
 *
 * DESCRIPTION
 *
 *    Sets `debug_string' as the regexp string for filtering debugging
 *    output.  The string is copied and it can be modified/destroyed after
 *    this function call.
 *
 ***/
void silc_log_set_debug_string(const char *debug_string);

#endif	/* !SILCLOG_H */
