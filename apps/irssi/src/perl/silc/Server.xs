#include "module.h"

MODULE = Irssi::Silc::Server	PACKAGE = Irssi::Silc::Server	PREFIX = silc_server_
PROTOTYPES: ENABLE

void
silc_server_get_channels(server)
	Irssi::Silc::Server server
PREINIT:
	char *ret;
PPCODE:
	ret = silc_server_get_channels(server);
	XPUSHs(sv_2mortal(new_pv(ret)));
	g_free(ret);
