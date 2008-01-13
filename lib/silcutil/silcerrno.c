/*

  silcerrno.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2007 - 2008 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"

/* Get last error */

SilcResult silc_get_errno(void)
{
  SilcTls tls = silc_thread_get_tls();

  if (!tls)
    return SILC_OK;

  return tls->error;
}

/* Set error */

void silc_set_errno(SilcResult error)
{
  SilcTls tls = silc_thread_get_tls();

  if (!tls) {
    /* Try to create Tls */
    tls = silc_thread_tls_init();
    if (!tls)
      return;
  }

  SILC_LOG_DEBUG(("Error: %s (%d)", silc_errno_string(error), error));

  tls->error_reason[0] = '\0';
  tls->error = error;
}

/* Set error, cannot fail. */

void silc_set_errno_nofail(SilcResult error)
{
  SilcTls tls = silc_thread_get_tls();

  if (!tls)
    return;

  SILC_LOG_DEBUG(("Error: %s (%d)", silc_errno_string(error), error));

  tls->error_reason[0] = '\0';
  tls->error = error;
}

/* Set errno and reason for error. */

void silc_set_errno_reason(SilcResult error, const char *format, ...)
{
  SilcTls tls = silc_thread_get_tls();
  va_list va;

  if (!tls) {
    /* Try to create Tls */
    tls = silc_thread_tls_init();
    if (!tls)
      return;
  }

  va_start(va, format);
  silc_vsnprintf(tls->error_reason, sizeof(tls->error_reason), format, va);
  va_end(va);

  SILC_LOG_DEBUG(("Error: %s (%d): %s", silc_errno_string(error), error,
		  tls->error_reason));

  tls->error = error;
}

/* Set errno and reason for error, cannot fail. */

void silc_set_errno_reason_nofail(SilcResult error, const char *format, ...)
{
  SilcTls tls = silc_thread_get_tls();
  va_list va;

  if (!tls)
    return;

  va_start(va, format);
  silc_vsnprintf(tls->error_reason, sizeof(tls->error_reason), format, va);
  va_end(va);

  SILC_LOG_DEBUG(("Error: %s (%d): %s", silc_errno_string(error), error,
		  tls->error_reason));

  tls->error = error;
}

/* Set error from POSIX errno. */

void silc_set_errno_posix(int error)
{
  if (!error)
    return;

#ifdef SILC_WIN32
  /* WSA errors */
  switch (error) {
  case WSAEINTR:
    silc_set_errno(SILC_ERR_INTERRUPTED);
    break;
  case WSAEBADF:
    silc_set_errno(SILC_ERR_BAD_FD);
    break;
  case WSAEACCESS:
    silc_set_errno(SILC_ERR_PERMISSION_DENIED);
    break;
  case WSAEFAULT:
    silc_set_errno(SILC_ERR_BAD_ADDRESS);
    break;
  case WSA_INVALID_HANDLE:
  case WSAENOTSOCK:
    silc_set_errno(SILC_ERR_BAD_SOCKET);
    break;
  case WSA_INVALID_PARAMETER:
  case WSAEINVAL:
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
    break;
  case WSA_NOT_ENOUGH_MEMORY:
    silc_set_errno(SILC_ERR_OUT_OF_MEMORY);
    break;
  case WSAEWOULDBLOCK:
    silc_set_errno(SILC_ERR_WOULD_BLOCK);
    break;
  case WSAEOPNOTSUPPORT:
    silc_set_errno(SILC_ERR_NOT_SUPPORTED);
    break;
  case WSAEADDRINUSE:
    silc_set_errno(SILC_ERR_ADDR_IN_USE);
    break;
  case WSAEANETDOWN:
    silc_set_errno(SILC_ERR_NET_DOWN);
    break;
  case WSAENETUNREACH:
  case WSAEHOSTUNREACH:
    silc_set_errno(SILC_ERR_UNREACHABLE);
    break;
  case WSAENETRESET:
    silc_set_errno(SILC_ERR_RESET);
    break;
  case WSAECONNABORTED:
    silc_set_errno(SILC_ERR_ABORTED);
    break;
  case WSAETIMEDOUT:
    silc_set_errno(SILC_ERR_TIMEOUT);
    break;
  case WSAECONNREFUSED:
    silc_set_errno(SILC_ERR_REFUSED);
    break;
  case WSAEHOSTDOWN:
    silc_set_errno(SILC_ERR_HOST_DOWN);
    break;
  default:
    silc_set_errno(SILC_ERR);
    break;
  }

  return;
#endif /* SILC_WIN32 */

  /* POSIX, etc. errors */
  switch (error) {
#if defined(ENOMEM)
  case ENOMEM:
    silc_set_errno(SILC_ERR_OUT_OF_MEMORY);
    break;
#endif
#if defined(EAGAIN)
  case EAGAIN:
    silc_set_errno(SILC_ERR_WOULD_BLOCK);
    break;
#endif
#if defined(EINVAL)
  case EINVAL:
    silc_set_errno(SILC_ERR_INVALID_ARGUMENT);
    break;
#endif
#if defined(EINTR)
  case EINTR:
    silc_set_errno(SILC_ERR_INTERRUPTED);
    break;
#endif
#if defined(EIO)
  case EIO:
    silc_set_errno(SILC_ERR_IO);
    break;
#endif
#if defined(EPIPE)
  case EPIPE:
    silc_set_errno(SILC_ERR_BROKEN_PIPE);
    break;
#endif
#if defined(ENOENT)
  case ENOENT:
    silc_set_errno(SILC_ERR_NO_SUCH_FILE);
    break;
#endif
#if defined(EEXIST)
  case EEXIST:
    silc_set_errno(SILC_ERR_ALREADY_EXISTS);
    break;
#endif
#if defined(ENOTDIR)
  case ENOTDIR:
    silc_set_errno(SILC_ERR_NOT_DIRECTORY);
    break;
#endif
#if defined(EISDIR)
  case EISDIR:
    silc_set_errno(SILC_ERR_IS_DIRECTORY);
    break;
#endif
#if defined(EBUSY)
  case EBUSY:
    silc_set_errno(SILC_ERR_BUSY);
    break;
#endif
#if defined(ENODEV)
  case ENODEV:
    silc_set_errno(SILC_ERR_NO_SUCH_DEVICE);
    break;
#endif
#if defined(ENOSPC)
  case ENOSPC:
    silc_set_errno(SILC_ERR_NO_SPACE_LEFT);
    break;
#endif
#if defined(EROFS)
  case EROFS:
    silc_set_errno(SILC_ERR_READ_ONLY);
    break;
#endif
#if defined(EBADFS)
  case EBADFS:
    silc_set_errno(SILC_ERR_BAD_FD);
    break;
#endif
#if defined(EADDRINUSE)
  case EADDRINUSE:
    silc_set_errno(SILC_ERR_ADDR_IN_USE);
    break;
#endif
#if defined(ECONNREFUSED)
  case ECONNREFUSED:
    silc_set_errno(SILC_ERR_REFUSED);
    break;
#endif
#if defined(ECONNABORTED)
  case ECONNABORTED:
    silc_set_errno(SILC_ERR_ABORTED);
    break;
#endif
#if defined(ECONNRESET)
  case ECONNRESET:
    silc_set_errno(SILC_ERR_RESET);
    break;
#endif
#if defined(ENETUNREACH)
  case ENETUNREACH:
    silc_set_errno(SILC_ERR_UNREACHABLE);
    break;
#endif
#if defined(EHOSTUNREACH)
  case EHOSTUNREACH:
    silc_set_errno(SILC_ERR_UNREACHABLE);
    break;
#endif
#if defined(ENETDOWN)
  case ENETDOWN:
    silc_set_errno(SILC_ERR_NET_DOWN);
    break;
#endif
#if defined(ETIMEDOUT)
  case ETIMEDOUT:
    silc_set_errno(SILC_ERR_TIMEOUT);
    break;
#endif
#if defined(EHOSTDOWN)
  case EHOSTDOWN:
    silc_set_errno(SILC_ERR_HOST_DOWN);
    break;
#endif
  default:
    silc_set_errno(SILC_ERR);
    break;
  }
}

/* Get last reason for error */

const char *silc_errno_reason(void)
{
  SilcTls tls = silc_thread_get_tls();

  if (!tls || tls->error_reason[0] == '\0')
    return (const char *)"";

  return tls->error_reason;
}

const char *silc_errno_strings[] =
{
  "Ok",

  "Error",
  "Out of memory",
  "Allocation by zero",
  "Too large allocation",
  "Overflow",
  "Underflow",
  "Feature not supported",
  "Operation not permitted",
  "Try again",
  "Permission denied",
  "Invalid argument",
  "Bad time",
  "Timeout",
  "Assert",
  "Not found",
  "Unknown character",
  "Prohibited character",
  "Bad character encoding",
  "Unsupported character encoding",
  "Bad version",
  "Bad memory address",
  "Bad buffer encoding",
  "Interrupted",
  "Not valid",
  "Limit reached",
  "Syntax error",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",

  "No such file or directory",
  "Already exists",
  "Not a directory",
  "Is a directory",
  "Directory not empty",
  "Device or resource busy",
  "No such device",
  "No space left on device",
  "Broken pipe",
  "Read only",
  "I/O error",
  "Bad file descriptor",
  "End of file",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",

  "Bad IP address",
  "Unknown IP address",
  "Unknown host",
  "Destination unreachable",
  "Connection refused",
  "Connection aborted",
  "Connection reset by peer",
  "Would block",
  "Host is down",
  "Bad socket",
  "Bad stream",
  "Address already in use",
  "Network is down",
  "End of stream",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",

  "Badly placed parenthesis",
  "Bad hexadecimal number",
  "Bad match register number",
  "Badly placed special character",
  "Regular expression too complex",
  "Bad regular expression opcode",
  "Bad repeat value",
};

/* Map error to string */

const char *silc_errno_string(SilcResult error)
{
  if (error < 0 || error >= SILC_ERR_MAX)
    return (const char *)"";

  return silc_errno_strings[error];
}
