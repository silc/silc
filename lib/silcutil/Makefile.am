#
#  Makefile.am
#
#  Author: Pekka Riikonen <priikone@silcnet.org>
#
#  Copyright (C) 2000 - 2002 Pekka Riikonen
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 2 of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#

AUTOMAKE_OPTIONS = 1.0 no-dependencies foreign

if SILC_WIN32
SUBDIRS=win32
else
if SILC_EPOC
SUBDIRS=epoc
else
if SILC_BEOS
SUBDIRS=beos
else
if SILC_OS2
SUBDIRS=os2
else
SUBDIRS=unix
endif
endif
endif
endif

if SILC_DIST_TOOLKIT
SILC_DIST_SOURCE = stacktrace.c
SILC_DIST_HEADERS = stacktrace.h
else
SILC_DIST_SOURCE =
SILC_DIST_HEADERS =
endif

noinst_LIBRARIES = libsilcutil.a

libsilcutil_a_SOURCES = \
	$(SILC_DIST_SOURCE) \
	silcbuffmt.c \
	silcconfig.c \
	silclog.c \
	silcmemory.c \
	silcnet.c \
	silcschedule.c \
	silcfileutil.c \
	silcstrutil.c \
	silcutil.c \
	silchashtable.c \
	silcsockconn.c	\
	silcprotocol.c

if SILC_DIST_TOOLKIT
include_HEADERS =	\
	$(SILC_DIST_SOURCE) \
	silcbuffer.h	\
	silcbuffmt.h	\
	silcconfig.h	\
	silchashtable.h	\
	silclog.h	\
	silcmemory.h	\
	silcmutex.h	\
	silcnet.h	\
	silcschedule.h	\
	silcsockconn.h	\
	silcprotocol.h	\
	silcthread.h	\
	silclist.h	\
	silcdlist.h	\
	silcfileutil.h	\
	silcutil.h	\
	silcstrutil.h	\
	silctypes.h
endif

EXTRA_DIST = *.h

include $(top_srcdir)/Makefile.defines.in
