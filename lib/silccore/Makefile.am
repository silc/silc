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

noinst_LIBRARIES = libsilccore.a

libsilccore_a_SOURCES = \
	silcid.c \
	silcidcache.c \
	silcchannel.c \
	silccommand.c \
	silcpacket.c \
	silcpayload.c \
	silcnotify.c \
	silcauth.c \
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
	silcpayload.h	\
	silcprivate.h
endif

EXTRA_DIST = *.h

include $(top_srcdir)/Makefile.defines.in
