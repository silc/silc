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

noinst_LTLIBRARIES = libsilccrypt.la

libsilccrypt_la_SOURCES = \
	none.c \
	rc5.c \
	rc6.c \
	md5.c \
	aes.c \
	rsa.c \
	sha1.c \
	twofish.c \
	blowfish.c \
	cast.c \
	silccipher.c \
	silchash.c \
	silchmac.c \
	silcrng.c \
	silcpkcs.c \
	pkcs1.c

if SILC_LIBTOOLFIX
# Tell libtool to compile silccrypt as shared since silcsim will need it.
LTFLAGS = --libtool-enable-shared
else
LTFLAGS = 
endif

CFLAGS = $(LTFLAGS)

if SILC_DIST_TOOLKIT
include_HEADERS =	\
	aes.h		\
	blowfish.h	\
	cast.h		\
	ciphers_def.h	\
	ciphers.h	\
	md5.h		\
	none.h		\
	pkcs1.h		\
	rc5.h		\
	rc6.h		\
	rsa.h		\
	sha1.h		\
	silccipher.h	\
	silcdh.h	\
	silchash.h	\
	silchmac.h	\
	silcpkcs.h	\
	silcrng.h	\
	twofish.h
endif

EXTRA_DIST = *.h tests

include $(top_srcdir)/Makefile.defines.in
