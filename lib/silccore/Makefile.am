#
#  Makefile.am
#
#  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>
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

noinst_LTLIBRARIES = libsilccore.la

libsilccore_la_SOURCES = \
	silcid.c \
	silcidcache.c \
	silcchannel.c \
	silccommand.c \
	silcpacket.c \
	silcargument.c \
	silcnotify.c \
	silcauth.c \
	silcattrs.c \
	silcprivate.c

if SILC_DIST_TOOLKIT
include_HEADERS =	\
	silcauth.h	\
	silcchannel.h	\
	silccommand.h	\
	silcidcache.h	\
	silcid.h	\
	silcmode.h	\
	silcnotify.h	\
	silcpacket.h	\
	silcargument.h	\
	silcstatus.h	\
	silcattrs.h	\
	silcprivate.h
endif

EXTRA_DIST = *.h

include $(top_srcdir)/Makefile.defines.in
