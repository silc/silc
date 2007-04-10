IRSSI_INCLUDE=../../..

if SILCPLUGIN
EXTRA_CFLAGS=-DSILC_PLUGIN
NILB=
LTLB= libfe_common_silc.la
LDFLGS= \
	-avoid-version \
	-rpath $(moduledir)
else
EXTRA_CFLAGS=
NILB= libfe_common_silc.la
LTLB=
LDFLGS=
endif

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
        -I$(SILC_INCLUDE)/lib/silcapputil \
        -I$(SILC_INCLUDE)/lib/silcvcard \
        -I$(SILC_INCLUDE)/lib/silcskr \
        -I$(SILC_INCLUDE)/lib/silcsftp \
        -I$(SILC_INCLUDE)/lib/silcasn1 \
        -I$(SILC_INCLUDE)/lib/silchttp \
        -I$(SILC_INCLUDE)/lib/silcclient \
        -I$(SILC_INCLUDE)/lib/silcmath/gmp \
        -I$(SILC_INCLUDE)/lib/trq \
	$(EXTRA_CFLAGS)

noinst_LTLIBRARIES = $(NILB)
module_LTLIBRARIES = $(LTLB)

libfe_common_silc_la_LDFLAGS = \
	$(LDFGS)

libfe_common_silc_la_SOURCES = \
	fe-silc-channels.c \
	fe-common-silc.c \
	module-formats.c \
	silc-modules.c \
	fe-silc-messages.c \
	fe-silcnet.c \
	fe-silc-queries.c

noinst_HEADERS = \
	module-formats.h \
	fe-silc-channels.h \
	fe-silc-messages.h \
	fe-silc-queries.h \
	fe-silcnet.h \
	fe-common-silc.h \
	module.h
