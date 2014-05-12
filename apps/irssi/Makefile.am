ACLOCAL_AMFLAGS = -I .

# create default-config.h
BUILT_SOURCES = default-config.h default-theme.h irssi-version.h

.PHONY: irssi-version.h

default-config.h: $(srcdir)/silc.conf
	$(srcdir)/file2header.sh $(srcdir)/silc.conf default_config > default-config.h
default-theme.h: $(srcdir)/default.theme
	$(srcdir)/file2header.sh $(srcdir)/default.theme default_theme > default-theme.h

#if BUILD_PLUGINS
#PLUGINS=plugins
#endif

SUBDIRS = src docs scripts

include $(top_srcdir)/Makefile.defines.in

confdir = $(silc_etcdir)
conf_DATA = silc.conf

if SILCPLUGIN
themedir = $(datadir)/irssi/themes
theme_DATA = plugin.theme
else
themedir = $(datadir)/silc/themes
theme_DATA = default.theme plugin.theme
endif

noinst_HEADERS = irssi-config.h irssi-version.h

EXTRA_DIST = \
	ChangeLog \
	autogen.sh \
	curses.m4 \
	README \
	file2header.sh \
	silc-client.spec \
	$(conf_DATA) \
	$(theme_DATA) \
	irssi-config.in \
	irssi-icon.png \
	syntax.pl \
	Makefile.defines.in \
	Makefile.defines_int.in
