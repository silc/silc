SUBDIRS = examples

if SILCPLUGIN
scriptdir = $(datadir)/irssi/scripts
else
scriptdir = $(datadir)/silc/scripts
endif

script_DATA = \
	autoop.pl \
	autorejoin.pl \
	buf.pl \
	dns.pl \
	kills.pl \
	mail.pl \
	mlock.pl \
	quitmsg.pl \
	scriptassist.pl \
	silc.pl \
	splitlong.pl \
	usercount.pl

EXTRA_DIST = $(script_DATA)
