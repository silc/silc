include $(top_srcdir)/Makefile.defines.in

IRSSI_INCLUDE=../../..

ADD_INCLUDES = \
	$(GLIB_CFLAGS) -I$(IRSSI_INCLUDE) -I$(IRSSI_INCLUDE)/src \
        -DSYSCONFDIR=\""$(silc_etcdir)"\" \
        -I$(IRSSI_INCLUDE) \
	-I$(IRSSI_INCLUDE)/src \
        -I$(IRSSI_INCLUDE)/src/core \
        -I$(IRSSI_INCLUDE)/src/fe-common/core \
        -I$(IRSSI_INCLUDE)/src/fe-common/silc

noinst_LIBRARIES=libsilc_core.a

libsilc_core_a_SOURCES = \
	client_ops.c \
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
	silc-cmdqueue.c

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

