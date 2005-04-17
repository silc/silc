#
#  Makefile.am
#
#  Author: Pekka Riikonen <priikone@silcnet.org>
#
#  Copyright (C) 2000 - 2005 Pekka Riikonen
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

noinst_LTLIBRARIES = libcontrib.la

if HAVE_GETOPT_LONG
GETOPT =
else
GETOPT = getopt.c getopt1.c
endif

if HAVE_REGEX
REGEX =
else
REGEX = regex.c
endif

STRINGPREP = nfkc.c rfc3454.c stringprep.c

if SILC_WIN32
libcontrib_la_SOURCES = $(STRINGPREP)
else
libcontrib_la_SOURCES = $(STRINGPREP) $(GETOPT) $(REGEX)
endif

EXTRA_DIST = *.c *.h

include $(top_srcdir)/Makefile.defines.in
