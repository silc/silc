IRSSI_INCLUDE=../../..
silc_top_srcdir=../../../..

INCLUDES = \
	$(GLIB_CFLAGS) -I$(IRSSI_INCLUDE) -I$(IRSSI_INCLUDE)/src \
        -DSYSCONFDIR=\""$(sysconfdir)"\" \
        -I$(IRSSI_INCLUDE) \
	-I$(IRSSI_INCLUDE)/src \
        -I$(IRSSI_INCLUDE)/src/core \
        -I$(IRSSI_INCLUDE)/src/fe-common/core \
        -I$(IRSSI_INCLUDE)/src/fe-common/silc \
	-I$(silc_top_srcdir)/lib/silccore \
	-I$(silc_top_srcdir)/lib/silccrypt \
        -I$(silc_top_srcdir)/lib/silcmath \
        -I$(silc_top_srcdir)/lib/silcmath/gmp \
	-I$(silc_top_srcdir)/lib/silcske \
	-I$(silc_top_srcdir)/lib/silcsim \
	-I$(silc_top_srcdir)/lib/silcutil \
	-I$(silc_top_srcdir)/lib/silcclient \
	-I$(silc_top_srcdir)/lib/contrib \
        -I$(silc_top_srcdir)/includes \
        -I$(silc_top_srcdir)/doc \
	-I$(silc_top_srcdir)/lib/trq

noinst_LIBRARIES=libsilc_core.a

libsilc_core_a_SOURCES = \
	client_ops.c \
	clientutil.c \
	clientconfig.c \
	silc-channels.c \
	silc-core.c \
	silc-nicklist.c \
	silc-queries.c \
	silc-servers.c \
	silc-servers-reconnect.c

noinst_HEADERS = \
	module.h \
	client_ops.h \
	clientutil.h \
	clientconfig.h \
	silc-channels.h \
	silc-core.h \
	silc-nicklist.h \
	silc-queries.h \
	silc-servers.h
