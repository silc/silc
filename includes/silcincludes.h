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

/* Automatically generated configuration header */
#include "silcdefs.h"

#ifdef WIN32
#ifndef SILC_WIN32
#define SILC_WIN32
#endif
#endif

#if defined(__EPOC32__)
#define SILC_EPOC
#endif

#ifdef SILC_WIN32
#include "silcwin32.h"
#endif

#ifdef SILC_EPOC
#include "silcepoc.h"
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

#endif				/* !SILC_WIN32 */

#ifndef HAVE_GETOPT_LONG
#include "../lib/contrib/getopt.h"
#endif

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/* Define offsetof */
#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

/* Define types. The types must be at least of the specified size */
#undef uint8
#undef uint16
#undef uint32
#undef uin64
#undef int8
#undef int16
#undef int32
#undef int64

typedef unsigned char uint8;
typedef signed char int8;

#if SILC_SIZEOF_SHORT > 2
#error "size of the short must be 2 bytes"
#endif

typedef unsigned short uint16;
typedef signed short int16;

#if SILC_SIZEOF_LONG == 4
typedef unsigned long uint32;
typedef signed long int32;
#else
#if SILC_SIZEOF_INT == 4
typedef unsigned long uint32;
typedef signed long int32;
#else
#if SILC_SIZEOF_LONG_LONG >= 4
#ifndef WIN32
typedef unsigned long long uint32;
typedef signed long long int32;
#endif
#endif
#endif
#endif

#if SILC_SIZEOF_LONG >= 8
typedef unsigned long uint64;
typedef signed long int64;
#else
#if SILC_SIZEOF_LONG_LONG >= 8
#ifndef WIN32
typedef unsigned long long uint64;
typedef signed long long int64;
#else
typedef uint32 uint64; /* XXX Use Windows's own 64 bit types */
typedef int32 int64;
#endif
#else
typedef uint32 uint64;
typedef int32 int64;
#endif
#endif

#if SILC_SIZEOF_VOID_P < 4
typedef uint32 * void *;
#endif

#ifndef __cplusplus
#ifndef bool
#define bool unsigned char
#endif
#endif

/* Generic global SILC includes */
#include "bitmove.h"

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
#include "silcbufutil.h"
#include "silcbuffmt.h"
#include "silcnet.h"
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
#include "payload.h"
#include "groups.h"

/* SILC SFTP library */
#include "silcsftp.h"
#include "silcsftp_fs.h"

#endif
