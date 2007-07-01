SUBDIRS = examples

PLUGIN_SCR = silc.pl

if SILCPLUGIN
scriptdir = $(datadir)/irssi/scripts
IRSSI_SCR =
else
scriptdir = $(datadir)/silc/scripts
IRSSI_SCR = \
	autoop.pl \
	autorejoin.pl \
	buf.pl \
	dns.pl \
	kills.pl \
	mail.pl \
	mlock.pl \
	quitmsg.pl \
	scriptassist.pl \
	splitlong.pl \
	usercount.pl
endif

script_DATA = \
        $(PLUGIN_SCR) \
        $(IRSSI_SCR)

EXTRA_DIST = $(script_DATA)
