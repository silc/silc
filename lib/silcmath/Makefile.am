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

SUBDIRS = gmp-3.0.1

noinst_LIBRARIES = libsilcmath.a

libsilcmath_a_SOURCES = \
	silcprimegen.c \
	modinv.c

EXTRA_DIST = *.h

INCLUDES = -I. -I.. -I../silccrypt -I../silccore -I../silcske \
	-I../silcsim -I../.. -I../../includes \
	-I./gmp-3.0.1
