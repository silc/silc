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

noinst_LIBRARIES = libsilccrypt.a

libsilccrypt_a_SOURCES = \
	none.c \
	blowfish.c \
	rc5.c \
	rc6.c \
	mars.c \
	md5.c \
	rijndael.c \
	rsa.c \
	sha1.c \
	twofish.c \
	silccipher.c \
	silchash.c \
	silchmac.c \
	silcrng.c \
	silcpkcs.c

EXTRA_DIST = *.h

INCLUDES = -I. -I.. -I../silccore -I../silcmath -I../silcske \
	-I../silcsim -I../.. -I../silcutil -I../../includes \
	-I../silcmath/gmp -I../trq
