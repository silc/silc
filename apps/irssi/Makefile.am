# create default-config.h
config.h: default-config.h default-theme.h

default-config.h: $(srcdir)/silc.conf
	$(srcdir)/file2header.sh $(srcdir)/silc.conf default_config > default-config.h
default-theme.h: $(srcdir)/default.theme
	$(srcdir)/file2header.sh $(srcdir)/default.theme default_theme > default-theme.h

if BUILD_PLUGINS
PLUGINS=plugins
endif
if BUILD_SERVERTEST
SERVERTEST=servertest
endif

SUBDIRS = src docs scripts

include $(top_srcdir)/Makefile.defines.in

#confdir = $(sysconfdir)
confdir = $(silc_etcdir)
conf_DATA = silc.conf

themedir = $(datadir)/silc/themes
theme_DATA = default.theme

noinst_HEADERS = irssi-version.h.in

EXTRA_DIST = \
	autogen.sh \
	curses.m4 \
	README \
	file2header.sh \
	irssi.spec \
	irssi.spec.in \
	$(conf_DATA) \
	$(theme_DATA) \
	irssi-config.in \
	irssi-icon.png \
	syntax.pl \
	Makefile.defines.in \
	Makefile.defines_int.in

## make rpms
rpm: Makefile
	$(MAKE) dist
	rpm -ta --clean $(PACKAGE)-$(VERSION).tar.gz
