if BUILD_TEXTUI
TEXTUI=fe-text
endif

if BUILD_IRSSIBOT
BOTUI=#
endif

if HAVE_PERL
PERLDIR=perl
endif

if SILCPLUGIN
SBDRS=
TEXTUI=
else
SBDRS=lib-config core
endif

noinst_HEADERS = \
	common.h

SUBDIRS = $(SBDRS) silc fe-common $(PERLDIR) $(TEXTUI) $(BOTUI)
