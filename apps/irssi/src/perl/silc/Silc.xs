#include "module.h"

static void perl_silc_server_fill_hash(HV *hv, SILC_SERVER_REC *server)
{
	perl_server_fill_hash(hv, (SERVER_REC *) server);

	hv_store(hv, "umode", 5, newSViv(server->umode), 0);
}

MODULE = Irssi::Silc	PACKAGE = Irssi::Silc

PROTOTYPES: ENABLE

void
init()
PREINIT:
	static int initialized = FALSE;
	int chat_type;
CODE:
	if (initialized) return;
	perl_api_version_check("Irssi::Silc");
	initialized = TRUE;

	chat_type = chat_protocol_lookup("SILC");

	irssi_add_object(module_get_uniq_id("SERVER", 0),
			 chat_type, "Irssi::Silc::Server",
			 (PERL_OBJECT_FUNC) perl_silc_server_fill_hash);

void
deinit()
CODE:

BOOT:
	irssi_boot(Silc__Channel);
	irssi_boot(Silc__Query);
	irssi_boot(Silc__Server);
