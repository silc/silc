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

noinst_LTLIBRARIES = libsilcclient.la

libsilcclient_la_SOURCES = \
	client.c \
	client_keyagr.c \
	client_notify.c \
	client_prvmsg.c \
	client_channel.c \
	client_ftp.c	\
	client_resume.c	\
	client_attrs.c	\
	command.c \
	command_reply.c \
	idlist.c \
	protocol.c

if SILC_DIST_TOOLKIT
include_HEADERS= 	\
	client.h 	\
	command.h	\
	command_reply.h	\
	idlist.h	\
	protocol.h	\
	silcclient.h
endif

EXTRA_DIST = *.h client_ops_example.c

include $(top_srcdir)/Makefile.defines.in
