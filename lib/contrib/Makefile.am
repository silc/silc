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

if HAVE_GETOPT_LONG
if HAVE_REGEX
noinst_LTLIBRARIES =
else
noinst_LTLIBRARIES = libcontrib.la
endif
else
noinst_LTLIBRARIES = libcontrib.la
endif


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

if SILC_WIN32
libcontrib_la_SOURCES =
else
libcontrib_la_SOURCES = \
	$(GETOPT) \
	$(REGEX)
endif

if SILC_DIST_TOOLKIT
include_HEADERS = getopt.h regex.h
endif

EXTRA_DIST = *.c *.h

include $(top_srcdir)/Makefile.defines.in
