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

sbin_PROGRAMS = silcd testi

silcd_SOURCES = \
	protocol.c \
	route.c \
	server.c \
	packet_send.c \
	packet_receive.c \
	idlist.c \
	command.c \
	command_reply.c \
	serverconfig.c \
	serverid.c \
	silcd.c \
	server_version.c
silcd_DEPENDENCIES = ../lib/libsilc.a

testi_SOURCES = testi.c

LIBS = $(SILC_COMMON_LIBS)
LDADD =

EXTRA_DIST = *.h

include $(top_srcdir)/Makefile.defines.in
