include $(top_srcdir)/Makefile.defines.in

moduledir = $(silc_modulesdir)


IRSSI_INCLUDE=../../..

if SILCPLUGIN
EXTRA_CFLAGS=-DSILC_PLUGIN
LBDD= \
	$(top_srcdir)/../../lib/libsilc.la \
	$(top_srcdir)/../../lib/libsilcclient.la
LTLB= libsilc_core.la
NILB=
LBLDFLGS= \
	-avoid-version \
	-rpath $(moduledir)
else
EXTRA_CFLAGS=
LBDD=
NILB= libsilc_core.la
LTLB=
LBLDFLGS=
endif

ADD_INCLUDES = \
	$(GLIB_CFLAGS) -I$(IRSSI_INCLUDE) -I$(IRSSI_INCLUDE)/src \
        -DSYSCONFDIR=\""$(silc_etcdir)"\" \
        -I$(IRSSI_INCLUDE) \
	-I$(IRSSI_INCLUDE)/src \
        -I$(IRSSI_INCLUDE)/src/core \
        -I$(IRSSI_INCLUDE)/src/fe-common/core \
        -I$(IRSSI_INCLUDE)/src/fe-common/silc \
	$(EXTRA_CFLAGS)

noinst_LTLIBRARIES= $(NILB)
module_LTLIBRARIES = $(LTLB)

libsilc_core_la_SOURCES = \
	clientutil.c \
	silc-channels.c \
	silc-core.c \
	silc-nicklist.c \
	silc-queries.c \
	silc-servers.c \
	silc-expandos.c \
	silc-servers-reconnect.c \
	silc-lag.c \
	silc-chatnets.c \
	silc-cmdqueue.c \
	client_ops.c

libsilc_core_la_LIBADD = \
	$(LBDD)

libsilc_core_la_LDFLAGS = \
	$(LBDFLGS)

noinst_HEADERS = \
	module.h \
	client_ops.h \
	clientutil.h \
	silc-channels.h \
	silc-core.h \
	silc-nicklist.h \
	silc-commands.h \
	silc-queries.h \
	silc-servers.h \
	silc-chatnets.h \
	silc-cmdqueue.h

all-local: libsilc_core.a

clean-local:
	-rm -f libsilc_core.a

libsilc_core.a: libsilc_core.la
	cp .libs/libsilc_core.a .
