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

bin_PROGRAMS = silc

silc_SOURCES = \
	silc.c \
	client.c \
	command.c \
	command_reply.c \
	clientconfig.c \
	clientutil.c \
	idlist.c \
	protocol.c \
	screen.c

LDADD = -L. -L.. -L../lib -lsilc -lcurses

EXTRA_DIST = *.h

INCLUDES = -I. -I.. -I../lib/silccore -I../lib/silccrypt \
	-I../lib/silcmath -I../lib/silcske -I../lib/silcsim \
	-I../includes \
	-I../lib/silcmath/gmp-3.0.1
