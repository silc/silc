/*

  silcincludes.h

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2001 Pekka Riikonen

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
  This file includes common definitions for SILC. This file MUST be included
  by all files in SILC (directly or through other global include file).
*/

#ifndef SILCINCLUDES_H
#define SILCINCLUDES_H

#ifdef __cplusplus
extern "C" {
#endif

#define SILC_UNIX

#ifdef WIN32
#ifndef SILC_WIN32
#define SILC_WIN32
#undef SILC_UNIX
#endif
#endif

#if defined(__EPOC32__)
#ifndef SILC_EPOC
#define SILC_EPOC
#undef SILC_UNIX
#endif
#endif

#ifdef BEOS
#ifndef SILC_BEOS
#define SILC_BEOS
#undef SILC_UNIX
#endif
#elif defined(__BEOS__)
#ifndef SILC_BEOS
#define SILC_BEOS
#undef SILC_UNIX
#endif
#endif

#if defined(OS2)
#ifndef SILC_OS2
#define SILC_OS2
#undef SILC_UNIX
#endif
#endif

/* Automatically generated configuration header */
#include "silcdefs.h"

/* Platform specific includes */

#ifdef SILC_WIN32
#include "silcwin32.h"
#endif

#ifdef SILC_EPOC
#include "silcepoc.h"
#endif

#ifdef SILC_BEOS
#include "silcbeos.h"
#endif

#ifdef SILC_OS2
#include "silcos2.h"
#endif

#ifndef DLLAPI
#define DLLAPI
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#else
#error signal.h not found in the system
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#else
#error fcntl.h not found in the system
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#else
#error errno.h not found in the system
#endif

#ifdef HAVE_ASSERT_H
#include <assert.h>
#else
#error assert.h not found in the system
#endif

#ifndef SILC_WIN32

#include <unistd.h>
#include <sys/time.h>
#include <pwd.h>
#include <grp.h>
#include <sys/times.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef SOCKS5
#include "socks.h"
#endif

#include <sys/socket.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#else
#error netinet/in.h not found in the system
#endif

#ifdef HAVE_XTI_H
#include <xti.h>
#else
#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#else
#error xti.h nor even netinet/tcp.h found in the system
#endif
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#else
#error netdb.h not found in the system
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#else
#error arpa/inet.h not found in the system
#endif

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#ifndef HAVE_REGEX_H
#include "../lib/contrib/regex.h"
#else
#include <regex.h>
#endif

#ifdef SILC_HAVE_PTHREAD
#include <pthread.h>
#endif

#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif

#endif				/* !SILC_WIN32 */

#ifndef HAVE_GETOPT_LONG
#include "../lib/contrib/getopt.h"
#endif

/* Include generic SILC type definitions */
#include "silctypes.h"

/* Math library includes */
#include "silcmp.h"
#include "silcmath.h"

/* Crypto library includes */
#include "silccipher.h"
#include "silchash.h"
#include "silchmac.h"
#include "silcrng.h"
#include "silcpkcs.h"

/* SILC util library includes */
#include "silcmutex.h"
#include "silcthread.h"
#include "silcschedule.h"
#include "silchashtable.h"
#include "silclog.h"
#include "silcmemory.h"
#include "silclist.h"
#include "silcdlist.h"
#include "silcbuffer.h"
#include "silcbuffmt.h"
#include "silcnet.h"
#include "silcfileutil.h"
#include "silcutil.h"
#include "silcconfig.h"
#include "silcprotocol.h"
#include "silcsockconn.h"

/* SILC core library includes */
#include "silcid.h"
#include "silcidcache.h"
#include "silcargument.h"
#include "silccommand.h"
#include "silcchannel.h"
#include "silcpacket.h"
#include "silcnotify.h"
#include "silcmode.h"
#include "silcauth.h"
#include "silcprivate.h"

#ifdef SILC_SIM
/* SILC Module library includes */
#include "silcsim.h"
#include "silcsimutil.h"
#endif

/* SILC Key Exchange library includes */
#include "silcske.h"
#include "silcske_payload.h"
#include "silcske_groups.h"

/* SILC SFTP library */
#include "silcsftp.h"
#include "silcsftp_fs.h"

#ifdef __cplusplus
}
#endif

#endif /* SILCINCLUDES_H */
