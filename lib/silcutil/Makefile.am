#
#  Makefile.am
#
#  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>
#
#  Copyright (C) 2000 Pekka Riikonen
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
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
SUBDIRS=unix
endif

noinst_LIBRARIES = libsilcutil.a

libsilcutil_a_SOURCES = \
	silcbuffmt.c \
	silcconfig.c \
	silclog.c \
	silcmemory.c \
	silcnet.c \
	silctask.c \
	silcschedule.c \
	silcutil.c \
	silchashtable.c

EXTRA_DIST = *.h

include $(top_srcdir)/Makefile.defines.in
