#include "module.h"

MODULE = Irssi::Silc::Query	PACKAGE = Irssi::Silc::Server	PREFIX = silc_
PROTOTYPES: ENABLE

Irssi::Silc::Query
silc_query_create(server_tag, nick, automatic)
	char *server_tag
	char *nick
	int automatic
