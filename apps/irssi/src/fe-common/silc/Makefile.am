INCLUDES = $(GLIB_CFLAGS) -I$(IRSSI_INCLUDE) -I$(IRSSI_INCLUDE)/src

SILC_INCLUDE=../../../..
IRSSI_INCLUDE=../../..

INCLUDES = \
        $(GLIB_CFLAGS) \
        -DSYSCONFDIR=\""$(sysconfdir)"\" \
        -I$(IRSSI_INCLUDE) -I$(IRSSI_INCLUDE)/src \
        -I$(IRSSI_INCLUDE)/src/core \
        -I$(IRSSI_INCLUDE)/src/silc \
        -I$(IRSSI_INCLUDE)/src/silc/core \
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

noinst_LIBRARIES = libfe_common_silc.a

libfe_common_silc_a_SOURCES = \
	fe-channels.c \
	fe-common-silc.c \
	silc-modules.c 

noinst_HEADERS = \
	fe-common-silc.h \
	module.h
