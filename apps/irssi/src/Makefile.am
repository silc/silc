if BUILD_TEXTUI
TEXTUI=fe-text
endif

if BUILD_IRSSIBOT
BOTUI=#
endif

if HAVE_PERL
PERLDIR=perl
endif

pkginc_srcdir=$(pkgincludedir)/src
pkginc_src_HEADERS = \
	common.h
noinst_HEADERS = \
	common.h

SUBDIRS = lib-popt lib-config core silc fe-common $(PERLDIR) $(TEXTUI) $(BOTUI)
