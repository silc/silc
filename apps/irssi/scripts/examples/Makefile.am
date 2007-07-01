
if SILCPLUGIN
scriptdir = $(datadir)/irssi/scripts
IRSSI_EX_SCR =
else
scriptdir = $(datadir)/silc/scripts
IRSSI_EX_SCR = \
	command.pl \
	msg-event.pl \
	redirect.pl
endif

script_DATA = $(IRSSI_EX_SCR)

EXTRA_DIST = $(script_DATA)
