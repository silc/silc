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
	id.c \
	idcache.c \
	silcchannel.c \
	silccommand.c \
	silcpacket.c \
	silcprotocol.c \
	silcsockconn.c \
	silcpayload.c \
	silcnotify.c \
	silcauth.c \
	silcprivate.c

EXTRA_DIST = *.h

INCLUDES = -I. -I.. -I../silccrypt -I../silcmath -I../silcske \
	-I../silcsim -I../.. -I../silcutil -I../../includes \
	-I../silcmath/gmp -I../trq
