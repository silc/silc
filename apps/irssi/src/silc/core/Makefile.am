moduledir = $(libdir)/irssi/modules

INCLUDES = $(GLIB_CFLAGS) -I$(IRSSI_INCLUDE) -I$(IRSSI_INCLUDE)/src

module_LTLIBRARIES = libsilc_core.la

libsilc_core_la_LDFLAGS = -avoid-version

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

libsilc_core_la_DEPENDENCIES = .libs/libsilcclient.a .libs/libsilcorig.a

libsilc_core_la_SOURCES = \
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

SILC_LIBS = \
	libsilcclient.la \
	libsilcorig.la

libsilc_core_la_LIBADD = \
	$(SILC_LIBS)

EXTRA_DIST = \
	$(SILC_LIBS)

.libs/libsilcclient.a:
	if [ ! -d .libs ]; then mkdir .libs; fi
	cd .libs && ln -sf ../../../libsilcclient.a . && cd ..

.libs/libsilcorig.a: .libs/libsilcclient.a
	cd .libs && ln -sf ../../../libsilcorig.a . && cd ..
