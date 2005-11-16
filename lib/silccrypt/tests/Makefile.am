#
#  Makefile.am
#
#  Author: Pekka Riikonen <priikone@silcnet.org>
#
#  Copyright (C) 2002 - 2003 Pekka Riikonen
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

bin_PROGRAMS = 	test_sha1 	\
		test_sha256	\
		test_md5	\
		test_hmacsha1	\
		test_hmacmd5	\
		test_aes	\
		test_twofish	\
		test_silcpkcs

test_sha1_SOURCES = test_sha1.c
test_sha256_SOURCES = test_sha256.c
test_md5_SOURCES = test_md5.c
test_hmacsha1_SOURCES = test_hmacsha1.c
test_hmacmd5_SOURCES = test_hmacmd5.c

test_aes_SOURCES = test_aes.c
test_twofish_SOURCES = test_aes.c

test_silcpkcs_SOURCES = test_silcpkcs.c

LIBS = $(SILC_COMMON_LIBS)
LDADD = -L.. -L../.. -lsilc

include $(top_srcdir)/Makefile.defines.in
