#
#  Makefile.am
#
#  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>
#
#  Copyright (C) 2000 - 2001 Pekka Riikonen
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#

AUTOMAKE_OPTIONS = 1.0 no-dependencies foreign

SUBDIRS = lib silcd silc doc includes

dist-bzip: distdir
	-chmod -R a+r $(distdir)
	-$(TAR) chof $(distdir).tar $(distdir)
	-bzip2 $(distdir).tar
	-rm -rf $(distdir)

EXTRA_DIST = CHANGES CREDITS

#
# Installing of SILC into the system
#

modulesdir = $(prefix)/@MODULESDIR@
helpdir = $(prefix)/@HELPDIR@
docdir = $(prefix)/@DOCDIR@
etcdir = @ETCDIR@

install-dirs:
	-mkdir -p $(etcdir)
	-mkdir -p $(modulesdir)
	-mkdir -p $(helpdir)
	-mkdir -p $(docdir)

generate-server-key:
	-$(sbindir)/silcd -C $(etcdir)

sim-install:
	-cp -fR $(srcdir)/lib/silcsim/modules/*.so $(modulesdir)/

doc-install:
	-cp -fR $(srcdir)/doc/* $(docdir)/
	$(INSTALL_DATA) $(srcdir)/COPYING $(docdir)/
	$(INSTALL_DATA) $(srcdir)/README $(docdir)/
	$(INSTALL_DATA) $(srcdir)/INSTALL $(docdir)/
	$(INSTALL_DATA) $(srcdir)/TODO $(docdir)/

etc-install:
	-@if test '!' -f $(etcdir)/silcd.conf ; then \
	  $(INSTALL_DATA) $(srcdir)/doc/example_silcd.conf \
	  $(etcdir)/silcd.conf; \
	fi
	-@if test '!' -f $(etcdir)/silc.conf ; then \
	  $(INSTALL_DATA) $(srcdir)/doc/example_silc.conf \
	  $(etcdir)/silc.conf; \
	fi

install-data-hook: install-dirs generate-server-key sim-install doc-install etc-install
