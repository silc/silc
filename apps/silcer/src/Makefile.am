#
#  Makefile.am
#
#  Author: Pekka Riikonen <priikone@silcnet.org>
#
#  Copyright (C) 2001 Pekka Riikonen
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

silc_top_srcdir = ../../

bin_PROGRAMS = silcer
silcer_SOURCES = silcer.cc		\
		silcerapp.cc		\
		silcerbasewin.cc	\
		silcerchatview.cc	\
		xtext.c			\
		gtkurl.c		\
		gtkspell.c		\
		SilcerMainDlg.cc

silcer_LDADD = @EXTRA_GNOME_LIBS@ -lxml \
	-L$(silc_top_srcdir)/lib -lsilcclient -lsilc
silcer_LDFLAGS =

INCLUDES = @EXTRA_GNOME_CFLAGS@ -DENABLE_NLS \
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\" \
	-DDATADIR=\"$(datadir)\" \
	-I$(top_srcdir)/intl \
	-I$(silc_top_srcdir)/lib/silccore \
	-I$(silc_top_srcdir)/lib/silccrypt \
        -I$(silc_top_srcdir)/lib/silcmath \
        -I$(silc_top_srcdir)/lib/silcmath/mpi \
	-I$(silc_top_srcdir)/lib/silcske \
	-I$(silc_top_srcdir)/lib/silcsim \
	-I$(silc_top_srcdir)/lib/silcutil \
	-I$(silc_top_srcdir)/lib/silcsftp \
	-I$(silc_top_srcdir)/lib/silcclient \
	-I$(silc_top_srcdir)/lib/contrib \
        -I$(silc_top_srcdir)/includes \
        -I$(silc_top_srcdir)/doc \
	-I$(silc_top_srcdir)/lib/trq

EXTRA_DIST = 
