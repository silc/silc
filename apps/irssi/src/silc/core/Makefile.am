INCLUDES = $(GLIB_CFLAGS) -I$(IRSSI_INCLUDE) -I$(IRSSI_INCLUDE)/src

SILC_INCLUDE=../../../..
IRSSI_INCLUDE=../../..

INCLUDES = \
        $(GLIB_CFLAGS) \
        -DSYSCONFDIR=\""$(sysconfdir)"\" \
        -I$(IRSSI_INCLUDE) -I$(IRSSI_INCLUDE)/src \
        -I$(IRSSI_INCLUDE)/src/core \
        -I$(SILC_INCLUDE)/includes \
        -I$(SILC_INCLUDE)/lib/silccore \
        -I$(SILC_INCLUDE)/lib/silccrypt \
        -I$(SILC_INCLUDE)/lib/silcmath \
        -I$(SILC_INCLUDE)/lib/silcske \
        -I$(SILC_INCLUDE)/lib/silcsim \
        -I$(SILC_INCLUDE)/lib/silcutil \
        -I$(SILC_INCLUDE)/lib/silcclient \
        -I$(SILC_INCLUDE)/lib/silcmath/gmp \
        -I$(SILC_INCLUDE)/lib/trq

noinst_LIBRARIES=libsilc_core.a

libsilc_core_a_SOURCES = \
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
	silc-channels.h \
	silc-core.h \
	silc-nicklist.h \
	silc-queries.h \
	silc-servers.h
