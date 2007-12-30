/*

  silcerrno.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

/****h* silcutil/SILC Errno
 *
 * DESCRIPTION
 *
 * Error codes and routines for accessing the error codes in case of
 * error condition.  SILC Runtime toolkit contains a global silc_errno
 * that contains the error code that occurred.  Each thread has their own
 * silc_errno.
 *
 * Each silc_errno error code can be mapped to a string that can be used
 * to display the error for user.  Some routines may also provide detailed
 * reason why the error occurred.  The reason string can be retrieved for
 * the last error by using silc_errno_reason.
 *
 * EXAMPLE
 *
 * // Use silc_errno
 * buf = silc_file_readfile(filename, &buf_len, NULL);
 * if (buf == NULL) {
 *   fprintf(stderr, "Error reading file %s: %s (%d)", filename,
 *           silc_errno_string(silc_errno), silc_errno);
 *   exit(1);
 * }
 *
 * // Get the detailed reason for the error too
 * if (silc_some_routine() == FALSE) {
 *   fprintf(stderr, "%s (%d) (%s)", silc_errno_string(silc_errno),
 *          silc_errno, silc_errno_reason);
 *   exit(1);
 * }
 *
 ***/

#ifndef SILCERRNO_H
#define SILCERRNO_H

/****d* silcutil/SilcErrnoAPI/SilcResult
 *
 * NAME
 *
 *    typedef enum { ... } SilcResult;
 *
 * DESCRIPTION
 *
 *    Error codes.
 *
 * SOURCE
 */
typedef enum {
  SILC_OK                              = 0,   /* Ok, no error */

  /* General errors */
  SILC_ERR                             = 1,   /* General error */
  SILC_ERR_OUT_OF_MEMORY               = 2,   /* Out of memory */
  SILC_ERR_ZERO_ALLOCATION             = 3,   /* Allocation by zero */
  SILC_ERR_TOO_LARGE_ALLOCATION        = 4,   /* Too large allocation */
  SILC_ERR_OVERFLOW                    = 5,   /* Would overflow */
  SILC_ERR_UNDERFLOW                   = 6,   /* Would underflow */
  SILC_ERR_NOT_SUPPORTED               = 7,   /* Feature not supported */
  SILC_ERR_NOT_PERMITTED               = 8,   /* Operation not permitted */
  SILC_ERR_TRY_AGAIN                   = 9,   /* Try again */
  SILC_ERR_PERMISSION_DENIED           = 10,  /* Permission denied */
  SILC_ERR_INVALID_ARGUMENT            = 11,  /* Invalid argument */
  SILC_ERR_BAD_TIME                    = 12,  /* Bad time value */
  SILC_ERR_TIMEOUT                     = 13,  /* Timeout occurred */
  SILC_ERR_ASSERT                      = 14,  /* Assertion failed */
  SILC_ERR_NOT_FOUND                   = 15,  /* Item/entry not found */
  SILC_ERR_UNKNOWN_CHAR                = 16,  /* Unknown character */
  SILC_ERR_PROHIBITED_CHAR             = 17,  /* Prohibited character */
  SILC_ERR_BAD_CHAR_ENCODING           = 18,  /* Bad character encoding */
  SILC_ERR_UNSUPPORTED_CHAR_ENCODING   = 19,  /* Unsupported char encoding */
  SILC_ERR_BAD_VERSION                 = 20,  /* Bad/unsupported version */
  SILC_ERR_BAD_ADDRESS                 = 21,  /* Bad memory address */
  SILC_ERR_BAD_ENCODING                = 22,  /* Bad data encoding */
  SILC_ERR_INTERRUPTED                 = 23,  /* Interrupted */
  SILC_ERR_NOT_VALID                   = 24,  /* Not valid */
  SILC_ERR_LIMIT                       = 25,  /* Limit reached */

  /* File, directory and device errors */
  SILC_ERR_NO_SUCH_FILE                = 40,  /* No such file */
  SILC_ERR_ALREADY_EXISTS              = 41,  /* File already exists */
  SILC_ERR_NOT_DIRECTORY               = 42,  /* Not a directory */
  SILC_ERR_IS_DIRECTORY                = 43,  /* Is a directory */
  SILC_ERR_NOT_EMPTY                   = 44,  /* Directory not empty */
  SILC_ERR_BUSY                        = 45,  /* Device or resource busy */
  SILC_ERR_NO_SUCH_DEVICE              = 46,  /* No such device */
  SILC_ERR_NO_SPACE_LEFT               = 47,  /* No space left on device */
  SILC_ERR_BROKEN_PIPE                 = 48,  /* Broken pipe */
  SILC_ERR_READ_ONLY                   = 49,  /* Read only */
  SILC_ERR_IO                          = 50,  /* I/O error */
  SILC_ERR_BAD_FD                      = 51,  /* Bad file descriptor */
  SILC_ERR_EOF                         = 52,  /* End of file */

  /* Network errors */
  SILC_ERR_BAD_IP                      = 70,  /* Bad IP address */
  SILC_ERR_UNKNOWN_IP                  = 71,  /* Unknown IP address */
  SILC_ERR_UNKNOWN_HOST                = 72,  /* Unknown host name */
  SILC_ERR_UNREACHABLE                 = 73,  /* Destination unreachable */
  SILC_ERR_REFUSED                     = 74,  /* Connection refused */
  SILC_ERR_ABORTED                     = 75,  /* Connection aborted */
  SILC_ERR_RESET                       = 76,  /* Connection reset by peer */
  SILC_ERR_WOULD_BLOCK                 = 77,  /* Would block */
  SILC_ERR_HOST_DOWN                   = 78,  /* Host is down */
  SILC_ERR_BAD_SOCKET                  = 79,  /* Bad socket */
  SILC_ERR_BAD_STREAM                  = 80,  /* Bad stream */
  SILC_ERR_ADDR_IN_USE                 = 81,  /* Address already in use */
  SILC_ERR_NET_DOWN                    = 82,  /* Network is down */
  SILC_ERR_EOS                         = 83,  /* End of stream */

  /* Regular expression errors */
  SILC_ERR_REGEX_PAREN                 = 100, /* Unmatched parenthesis */
  SILC_ERR_REGEX_HEX                   = 101, /* Bad hex number */
  SILC_ERR_REGEX_REG                   = 102, /* Bad register number */
  SILC_ERR_REGEX_SPECIAL               = 103, /* Unmatched special character */
  SILC_ERR_REGEX_TOO_COMPLEX           = 104, /* Too complex expression */

  SILC_ERR_MAX,
} SilcResult;
/***/

/****d* silcutil/SilcErrnoAPI/silc_errno
 *
 * NAME
 *
 *    SilcResult silc_errno;
 *
 * DESCRIPTION
 *
 *    Returns the error code of the last error.  To map the error code to a
 *    string call silc_errno_string.
 *
 ***/
#define silc_errno silc_get_errno()

/****f* silcutil/SilcErrnoAPI/silc_errno_string
 *
 * NAME
 *
 *    const char *silc_errno_string(SilcResult error);
 *
 * DESCRIPTION
 *
 *    Returns the string of the error `errno'.  This routine never returns
 *    NULL.
 *
 ***/
const char *silc_errno_string(SilcResult error);

/****d* silcutil/SilcErrnoAPI/silc_errno_string
 *
 * NAME
 *
 *    const char *silc_errno_reason(void);
 *
 * DESCRIPTION
 *
 *    Returns additional reason string for the last occurred error or ""
 *    if the additional information is not available.  This routine never
 *    returns NULL.
 *
 ***/
const char *silc_errno_reason(void);

/* Low-level routines for the error handling. */

/* Return last error */
SilcResult silc_get_errno(void);

/* Set error */
void silc_set_errno(SilcResult error);

/* Set error, cannot fail. */
void silc_set_errno_nofail(SilcResult error);

/* Set error and reason string. */
void silc_set_errno_reason(SilcResult error, const char *format, ...);

/* Set error and reason string, cannot fail. */
void silc_set_errno_reason_nofail(SilcResult error, const char *format, ...);

/* Set error from POSIX errno */
void silc_set_errno_posix(int error);

#endif /* SILCERRNO_H */
