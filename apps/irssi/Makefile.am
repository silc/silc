# create default-config.h
config.h: default-config.h default-theme.h

default-config.h: $(srcdir)/config
	$(srcdir)/file2header.sh $(srcdir)/config default_config > default-config.h
default-theme.h: $(srcdir)/default.theme
	$(srcdir)/file2header.sh $(srcdir)/default.theme default_theme > default-theme.h

SUBDIRS = src docs

confdir = $(sysconfdir)/irssi
conf_DATA = config default.theme

noinst_HEADERS = irssi-version.h

EXTRA_DIST = \
	autogen.sh \
	README \
	file2header.sh \
	irssi.spec \
	irssi.spec.in \
	$(conf_DATA) \
	irssi-config.in

## make rpms
rpm: Makefile
	$(MAKE) dist
	rpm -ta --clean $(PACKAGE)-$(VERSION).tar.gz
