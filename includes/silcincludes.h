
/*

  silcincludes.h

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
  This file includes common definitions for SILC. This file MUST be included
  by all files in SILC (directly or through other global include file).
*/

#ifndef SILCINCLUDES_H
#define SILCINCLUDES_H

/* Automatically generated configuration header */
#include "silcdefs.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <pwd.h>
#include <grp.h>

#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <time.h>

#ifdef SOCKS5
#include "socks.h"
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef HAVE_SIGNAL_H
#undef __USE_GNU
#include <signal.h>
#define __USE_GNU 1
#else
#error signal.h not found in the system
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#else
#error fcntl.h not found in the system
#endif

#ifdef HAVE_ASSERT_H
#include <errno.h>
#else
#error errno.h not found in the system
#endif

#ifdef HAVE_ASSERT_H
#include <assert.h>
#else
#error assert.h not found in the system
#endif

#include <sys/socket.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#else
#error netinet/in.h not found in the system
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#else
#error netinet/tcp.h not found in the system
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

#ifndef HAVE_GETOPT_LONG
#include "../lib/contrib/getopt.h"
#endif

#ifndef HAVE_REGEX_H
#include "../lib/contrib/regex.h"
#else
#include <regex.h>
#endif

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/* Generic global SILC includes */
#include "bitmove.h"

/* Math library includes */
#include "silcmp.h"
#include "modinv.h"
#include "mpbin.h"
#include "silcprimegen.h"

/* Crypto library includes */
#include "silccipher.h"
#include "silchash.h"
#include "silchmac.h"
#include "silcrng.h"
#include "silcpkcs.h"

/* SILC util library includes */
#include "silclog.h"
#include "silcmemory.h"
#include "silcbuffer.h"
#include "silcbufutil.h"
#include "silcbuffmt.h"
#include "silcnet.h"
#include "silcutil.h"
#include "silcconfig.h"
#include "silctask.h"
#include "silcschedule.h"

/* SILC core library includes */
#include "id.h"
#include "idcache.h"
#include "silcprotocol.h"
#include "silcsockconn.h"
#include "silcpayload.h"
#include "silccommand.h"
#include "silcchannel.h"
#include "silcpacket.h"
#include "silcnotify.h"
#include "silcmode.h"
#include "silcauth.h"
#include "silcprivate.h"

/* TRQ (SilcList API and SilcDList API) */
#include "silclist.h"
#include "silcdlist.h"

#ifdef SILC_SIM
/* SILC Module library includes */
#include "silcsim.h"
#include "silcsimutil.h"
#endif

/* SILC Key Exchange library includes */
#include "silcske.h"
#include "payload.h"
#include "groups.h"

#endif

