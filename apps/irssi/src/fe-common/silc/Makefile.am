IRSSI_INCLUDE=../../..

include $(top_srcdir)/Makefile.defines.in

ADD_INCLUDES = \
        $(GLIB_CFLAGS) \
        -DSYSCONFDIR=\""$(silc_etcdir)"\" \
        -I$(IRSSI_INCLUDE) -I$(IRSSI_INCLUDE)/src \
        -I$(IRSSI_INCLUDE)/src/core \
        -I$(IRSSI_INCLUDE)/src/fe-common/core \
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
	module-formats.c \
	silc-modules.c \
	fe-messages.c \
	fe-silcnet.c

noinst_HEADERS = \
	module-formats.h \
	fe-common-silc.h \
	module.h
