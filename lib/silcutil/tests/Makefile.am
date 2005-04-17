#
#  Makefile.am
#
#  Author: Pekka Riikonen <priikone@silcnet.org>
#
#  Copyright (C) 2004 - 2005 Pekka Riikonen
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

bin_PROGRAMS = 	test_silcstrutil test_silcstringprep test_silchashtable

test_silcstrutil_SOURCES = test_silcstrutil.c
test_silcstringprep_SOURCES = test_silcstringprep.c
test_silchashtable_SOURCES = test_silchashtable.c

LIBS = $(SILC_COMMON_LIBS)
LDADD = -L.. -L../.. -lsilc

include $(top_srcdir)/Makefile.defines.in
