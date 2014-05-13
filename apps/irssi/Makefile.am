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

## make rpms
rpm: Makefile
	$(MAKE) dist
	rpm -ta --clean $(PACKAGE)-$(VERSION).tar.gz

install-dirs-client:
	-mkdir -p $(docdir)
	-mkdir -p $(mandir)/man1

doc-install-client:
	$(INSTALL_DATA) $(silc_top_srcdir)/apps/irssi/silc.conf $(docdir)/example_silc.conf
	-@if test -f $(silc_top_srcdir)/doc/silc.1 ; then \
	  $(INSTALL_DATA) $(silc_top_srcdir)/doc/silc.1 $(mandir)/man1; \
	fi

etc-install-client:
	-@if test -d $(silc_top_srcdir)/apps/irssi ; then \
	  mkdir -p $(etcdir) ; \
	  if test '!' -f $(etcdir)/silc.conf ; then \
	     $(INSTALL_DATA) $(silc_top_srcdir)/apps/irssi/silc.conf \
		$(etcdir)/silc.conf; \
	  fi; \
	fi

if SILCPLUGIN
ETCINSTALL=
else
ETCINSTALL=etc-install-client
endif

install-data-hook:		\
	install-dirs-client	\
	doc-install-client	\
	$(ETCINSTALL)
