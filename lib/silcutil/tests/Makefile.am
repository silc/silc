#
#  Makefile.am
#
#  Author: Pekka Riikonen <priikone@silcnet.org>
#
#  Copyright (C) 2004 - 2007 Pekka Riikonen
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

bin_PROGRAMS = 	test_silcstrutil test_silcstringprep test_silchashtable \
	test_silclist test_silcfsm test_silcasync test_silcschedule \
	test_silcnet test_silcstack test_silcmime test_silcfdstream \
	test_silcatomic test_silcmutex test_silctime test_silcthread \
	test_silcdll test_silcenv test_silctimer test_silcbitops \
	test_silcregex test_silcbuffmt test_silcdir

test_silcstrutil_SOURCES = test_silcstrutil.c
test_silcstringprep_SOURCES = test_silcstringprep.c
test_silchashtable_SOURCES = test_silchashtable.c
test_silclist_SOURCES = test_silclist.c
test_silcmime_SOURCES = test_silcmime.c
test_silcfsm_SOURCES = test_silcfsm.c
test_silcasync_SOURCES = test_silcasync.c
test_silcschedule_SOURCES = test_silcschedule.c
test_silcnet_SOURCES = test_silcnet.c
test_silcstack_SOURCES = test_silcstack.c
test_silcfdstream_SOURCES = test_silcfdstream.c
test_silcatomic_SOURCES = test_silcatomic.c
test_silcmutex_SOURCES = test_silcmutex.c
test_silctime_SOURCES = test_silctime.c
test_silcthread_SOURCES = test_silcthread.c
test_silcdll_SOURCES = test_silcdll.c
test_silcenv_SOURCES = test_silcenv.c
test_silctimer_SOURCES = test_silctimer.c
test_silcbitops_SOURCES = test_silcbitops.c
test_silcregex_SOURCES = test_silcregex.c
test_silcbuffmt_SOURCES = test_silcbuffmt.c
test_silcdir_SOURCES = test_silcdir.c

LIBS = $(SILC_COMMON_LIBS)
LDADD = -L.. -L../.. -lsilc

include $(top_srcdir)/Makefile.defines.in
