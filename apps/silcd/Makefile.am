#
#  Makefile.am
#
#  Author: Pekka Riikonen <priikone@silcnet.org>
#
#  Copyright (C) 2000 - 2005 Pekka Riikonen
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

sbin_PROGRAMS = silcd

silcd_SOURCES = \
	protocol.c \
	route.c \
	packet_send.c \
	packet_receive.c \
	idlist.c \
	command.c \
	command_reply.c \
	silcd.c \
	server.c \
	server_util.c \
	server_backup.c \
	serverconfig.c \
	server_query.c \
	serverid.c \
	server_version.c

LIBS = $(SILC_COMMON_LIBS)
LDADD =

EXTRA_DIST = *.h

install-dirs-server:
	-mkdir -p $(docdir)
	-mkdir -p $(etcdir)
	-mkdir -p $(logsdir)
	-mkdir -p $(mandir)/man5
	-mkdir -p $(mandir)/man8

doc-install-server:
	-$(INSTALL_DATA) $(top_srcdir)/doc/example_silcd.conf $(docdir)/
	-@if test -f $(top_srcdir)/doc/silcd.8 ; then \
	 $(INSTALL_DATA) $(top_srcdir)/doc/silcd.8 $(mandir)/man8; \
	fi
	-@if test -f $(top_srcdir)/doc/silcd.conf.5 ; then \
	 $(INSTALL_DATA) $(top_srcdir)/doc/silcd.conf.5 $(mandir)/man5; \
	fi

etc-install-server:
	-@if test '!' -f $(etcdir)/silcd.conf ; then \
	  $(INSTALL_DATA) $(top_srcdir)/doc/example_silcd.conf \
		$(etcdir)/silcd.conf; \
	  $(INSTALL_DATA) $(top_srcdir)/doc/silcalgs.conf \
		$(etcdir)/silcalgs.conf; \
          chmod go= $(etcdir)/silcd.conf; \
	fi

examples-install:
	-mkdir -p $(docdir)/examples/
	-$(INSTALL_DATA) $(top_srcdir)/doc/examples/* $(docdir)/examples/

generate-server-key:
	-@if test '!' -f $(etcdir)/silcd.pub ; then \
	  $(sbindir)/silcd -C $(etcdir); \
	fi

install-data-hook: 		\
	install-dirs-server 	\
	doc-install-server	\
	etc-install-server 	\
	examples-install 	\
	generate-server-key

include $(top_srcdir)/Makefile.defines.in
