#
#  Makefile.am
#
#  Author: Pekka Riikonen <priikone@silcnet.org>
#
#  Copyright (C) 2005 Pekka Riikonen
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 2 of the License.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#

AUTOMAKE_OPTIONS = 1.0 no-dependencies foreign

SUBDIRS = . doc tests

AUTODIST_SOURCE = autodist.in makedist.in
bin_SCRIPTS = autodist makedist

autodistdir = @AUTODISTDIR@
autodist_DATA = autodist.conf default COPYING

CLEANFILES = $(bin_SCRIPTS)

APIVERSION = @APIVERSION@
# Install versioned links.
install-exec-hook:
	@for i in $(bin_SCRIPTS); do 					\
	  f="`echo $$i | sed '$(transform)'`"; 				\
	  fv="$$f-$(APIVERSION)"; 					\
	  rm -f $(DESTDIR)$(bindir)/$$fv; 				\
	  chmod +x $(DESTDIR)$(bindir)/$$f;				\
	  chmod a-w $(DESTDIR)$(bindir)/$$f;				\
	  ln $(DESTDIR)$(bindir)/$$f $(DESTDIR)$(bindir)/$$fv; 		\
	done

uninstall-hook:
	@for i in $(bin_SCRIPTS); do 					\
	  f="`echo $$i|sed '$(transform)'`"; 				\
	  fv="$$f-$(APIVERSION)"; 					\
	  rm -f $(DESTDIR)$(bindir)/$$fv;				\
        done

EXTRA_DIST = $(AUTODIST_SOURCE) default autodist.conf
