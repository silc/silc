#include "module.h"
#include "chat-protocols.h"

#include "chatnets.h"
#include "servers-setup.h"
#include "channels-setup.h"
#include "silc-servers.h"
#include "silc-channels.h"
#include "silc-queries.h"
#include "silc-nicklist.h"
#include "version_internal.h"

#include "signals.h"
#include "levels.h"
#include "settings.h"
#include "fe-common/core/printtext.h"
#include "fe-common/core/fe-channels.h"

#define SILC_CLIENT_PUBLIC_KEY_NAME "public_key.pub"
#define SILC_CLIENT_PRIVATE_KEY_NAME "private_key.prv"

#define SILC_CLIENT_DEF_PKCS "rsa"
#define SILC_CLIENT_DEF_PKCS_LEN 1024

SilcClient silc_client;
const char *silc_version_string = SILC_PROTOCOL_VERSION_STRING;

static int idletag;

extern SilcClientOperations ops;

static void silc_say(SilcClient client, SilcClientConnection conn,
		     char *msg, ...)
{
	SILC_SERVER_REC *server;
	va_list va;
	char *str;

	server = conn == NULL ? NULL : conn->context;

	va_start(va, msg);
	str = g_strdup_vprintf(msg, va);
	printtext(server, "#silc", MSGLEVEL_CRAP, "%s", str);
	g_free(str);
	va_end(va);
}

static void silc_channel_message(SilcClient c, SilcClientConnection conn,
				 SilcClientEntry client,
				 SilcChannelEntry channel, char *msg)
{
	SILC_SERVER_REC *server;
	SILC_NICK_REC *nick;
        SILC_CHANNEL_REC *chanrec;

	server = conn == NULL ? NULL : conn->context;
	chanrec = silc_channel_find_entry(server, channel);

	nick = client == NULL ? NULL : silc_nicklist_find(chanrec, client);
	signal_emit("message public", 6, server, msg,
		    nick == NULL ? "(unknown)" : nick->nick,
		    nick == NULL ? NULL : nick->host,
		    chanrec->name, nick);
}

static void silc_private_message(SilcClient c, SilcClientConnection conn,
				 SilcClientEntry client, char *msg)
{
	SILC_SERVER_REC *server;

	server = conn == NULL ? NULL : conn->context;
	signal_emit("message private", 4, server, msg,
		    client == NULL ? "(unknown)" : client->nickname,
		    client == NULL ? NULL : client->username);
}

typedef struct {
	int type;
	const char *name;
} NOTIFY_REC;

#define MAX_NOTIFY (sizeof(notifies)/sizeof(notifies[0]))
static NOTIFY_REC notifies[] = {
	{ SILC_NOTIFY_TYPE_NONE,		NULL },
	{ SILC_NOTIFY_TYPE_INVITE,		"invite" },
	{ SILC_NOTIFY_TYPE_JOIN,		"join" },
	{ SILC_NOTIFY_TYPE_LEAVE,		"leave" },
	{ SILC_NOTIFY_TYPE_SIGNOFF,		"signoff" },
	{ SILC_NOTIFY_TYPE_TOPIC_SET,		"topic" },
	{ SILC_NOTIFY_TYPE_NICK_CHANGE,		"nick" },
	{ SILC_NOTIFY_TYPE_CMODE_CHANGE,	"cmode" },
	{ SILC_NOTIFY_TYPE_CUMODE_CHANGE,	"cumode" },
	{ SILC_NOTIFY_TYPE_MOTD,		"motd" }
};

static void silc_notify(SilcClient client, SilcClientConnection conn,
                        SilcNotifyType type, ...)
{
	SILC_SERVER_REC *server;
	va_list va;

	server = conn == NULL ? NULL : conn->context;
	va_start(va, type);

	if (type == SILC_NOTIFY_TYPE_NONE) {
		/* some generic notice from server */
		printtext(server, NULL, MSGLEVEL_CRAP, "%s",
			  (char *) va_arg(va, char *));
	} else if (type < MAX_NOTIFY) {
		/* send signal about the notify event */
		char signal[50];

		g_snprintf(signal, sizeof(signal), "silc event %s",
			   notifies[type].name);
		signal_emit(signal, 2, server, va);
	} else {
		/* unknown notify */
		printtext(server, NULL, MSGLEVEL_CRAP,
			  "Unknown notify %d", type);
	}
	va_end(va);
}

static void silc_connect(SilcClient client, SilcClientConnection conn, int success)
{
	SILC_SERVER_REC *server = conn->context;

	if (success) {
		server->connected = TRUE;
		signal_emit("event connected", 1, server);
	} else {
		server->connection_lost = TRUE;
                server->conn->context = NULL;
		server_disconnect(SERVER(server));
	}
}

static void silc_disconnect(SilcClient client, SilcClientConnection conn)
{
	SILC_SERVER_REC *server = conn->context;

	server->conn->context = NULL;
	server->conn = NULL;
	server->connection_lost = TRUE;
	server_disconnect(SERVER(server));
}

static void silc_command(SilcClient client, SilcClientConnection conn,
			 SilcClientCommandContext cmd_context, int success,
			 SilcCommand command)
{
}

static void silc_command_reply(SilcClient client, SilcClientConnection conn,
			       SilcCommandPayload cmd_payload, int success,
			       SilcCommand command,
			       SilcCommandStatus status, ...)
{
        SILC_SERVER_REC *server = conn->context;
	SILC_CHANNEL_REC *chanrec;
	va_list va;

	va_start(va, status);

	/*g_snprintf(signal, sizeof(signal), "silc command reply %s",
		   silc_commands[type]);
	signal_emit(signal, 2, server, va);*/

	switch(command) {
	case SILC_COMMAND_JOIN: {
		char *channel, *mode;

		channel = va_arg(va, char *);
		(void)va_arg(va, SilcChannelEntry);
		mode = silc_client_chmode(va_arg(va, unsigned int));

		chanrec = silc_channel_find(server, channel);
		if (chanrec != NULL && !success)
			channel_destroy(CHANNEL(chanrec));
		else if (chanrec == NULL && success)
			chanrec = silc_channel_create(server, channel, TRUE);

		g_free_not_null(chanrec->mode);
		chanrec->mode = g_strdup(mode == NULL ? "" : mode);
		signal_emit("channel mode changed", 1, chanrec);
		break;
	}
	case SILC_COMMAND_NICK: {
		SilcClientEntry client = va_arg(va, SilcClientEntry);
                char *old;

                old = g_strdup(server->nick);
		server_change_nick(SERVER(server), client->nickname);
		nicklist_rename_unique(SERVER(server),
				       server->conn->local_entry, server->nick,
                                       client, client->nickname);

		signal_emit("message own_nick", 4,
			    server, server->nick, old, "");
                g_free(old);
		break;
	}
	case SILC_COMMAND_USERS: {
		SilcChannelEntry channel;
		SilcChannelUser user;
                NICK_REC *ownnick;

		channel = va_arg(va, SilcChannelEntry);
		chanrec = silc_channel_find_entry(server, channel);
		if (chanrec == NULL)
			break;

		silc_list_start(channel->clients);
		while ((user = silc_list_get(channel->clients)) != NULL)
			silc_nicklist_insert(chanrec, user, FALSE);

                ownnick = NICK(silc_nicklist_find(chanrec, conn->local_entry));
		nicklist_set_own(CHANNEL(chanrec), ownnick);
                signal_emit("channel joined", 1, chanrec);
		fe_channels_nicklist(CHANNEL(chanrec),
				     CHANNEL_NICKLIST_FLAG_ALL);
		break;
	}
	}

	va_end(va);
}

static int silc_verify_server_key(SilcClient client, SilcClientConnection conn,
				  unsigned char *pk, unsigned int pk_len,
				  SilcSKEPKType pk_type)
{
	return TRUE;
}

static unsigned char *silc_ask_passphrase(SilcClient client,
					  SilcClientConnection conn)
{
	return NULL;
}

static int silc_get_auth_method(SilcClient client, SilcClientConnection conn,
				char *hostname, unsigned short port,
				SilcProtocolAuthMeth *auth_meth,
				unsigned char **auth_data,
				unsigned int *auth_data_len)
{
	return FALSE;
}

static void silc_failure(SilcClient client, SilcClientConnection conn,
			 SilcProtocol protocol, void *failure)
{
}

static int key_agreement(SilcClient client, SilcClientConnection conn,
			 SilcClientEntry client_entry, char *hostname,
			 int port)
{
        return FALSE;
}

SilcClientOperations ops = {
	silc_say,
	silc_channel_message,
	silc_private_message,
	silc_notify,
	silc_command,
	silc_command_reply,
	silc_connect,
	silc_disconnect,
	silc_get_auth_method,
	silc_verify_server_key,
	silc_ask_passphrase,
	silc_failure,
        key_agreement
};

/* Loads public and private key from files. */

static void silc_client_create_key_pair(char *pkcs_name, int bits,
					char *identifier,
					SilcPublicKey *pub_key,
					SilcPrivateKey *prv_key)
{
	SilcPKCS pkcs;
	SilcRng rng;
	unsigned char *key;
	unsigned int key_len;

	rng = silc_rng_alloc();
	silc_rng_init(rng);
	silc_rng_global_init(rng);

	silc_pkcs_alloc(pkcs_name, &pkcs);
	pkcs->pkcs->init(pkcs->context, bits, rng);

	/* Create public key */
	key = silc_pkcs_get_public_key(pkcs, &key_len);
	*pub_key = silc_pkcs_public_key_alloc(pkcs->pkcs->name, identifier,
					      key, key_len);

	memset(key, 0, sizeof(key_len));
	silc_free(key);

	/* Create private key */
	key = silc_pkcs_get_private_key(pkcs, &key_len);
	*prv_key = silc_pkcs_private_key_alloc(pkcs->pkcs->name, key, key_len);

	memset(key, 0, sizeof(key_len));
	silc_free(key);

	silc_rng_free(rng);
	silc_pkcs_free(pkcs);
}

static int read_keyfiles(SilcClient client, char *public_file,
			 char *private_file)
{
	struct stat statbuf;

	if (stat(public_file, &statbuf) != 0 ||
	    stat(private_file, &statbuf) != 0)
		return FALSE;

	if (!silc_pkcs_load_private_key(private_file, &client->private_key,
					SILC_PKCS_FILE_BIN) &&
	    !silc_pkcs_load_private_key(private_file, &client->private_key,
					SILC_PKCS_FILE_PEM))
		return FALSE;

	if (!silc_pkcs_load_public_key(public_file, &client->public_key,
				       SILC_PKCS_FILE_PEM) &&
	    !silc_pkcs_load_public_key(public_file, &client->public_key,
				       SILC_PKCS_FILE_BIN))
		return FALSE;

	return TRUE;
}

static char *silc_create_identifier(SilcClient client)
{
	char hostname[256], *email, *ret;

	if (gethostname(hostname, sizeof(hostname)) != 0)
		hostname[0] = '\0';

	email = g_strdup_printf("%s@%s", client->username, hostname);
	ret = silc_pkcs_encode_identifier(client->username, hostname,
					  client->realname, email,
					  NULL, NULL);
	g_free(email);
	return ret;
}

static int load_keys(SilcClient client)
{
	char *public_file, *private_file;
	char *identifier;

	public_file = g_strdup_printf("%s/.irssi/%s", g_get_home_dir(),
				      SILC_CLIENT_PUBLIC_KEY_NAME);
	private_file = g_strdup_printf("%s/.irssi/%s", g_get_home_dir(),
				       SILC_CLIENT_PRIVATE_KEY_NAME);

	if (!read_keyfiles(client, public_file, private_file)) {
		/* couldn't read key files, recreate them */
		identifier = silc_create_identifier(client);
		silc_client_create_key_pair(SILC_CLIENT_DEF_PKCS,
					    SILC_CLIENT_DEF_PKCS_LEN,
					    identifier,
					    &client->public_key,
					    &client->private_key);
		silc_free(identifier);

		silc_pkcs_save_public_key(public_file, client->public_key,
					  SILC_PKCS_FILE_PEM);
		silc_pkcs_save_private_key(private_file, client->private_key,
					   NULL, SILC_PKCS_FILE_BIN);
	}

	g_free(public_file);
	g_free(private_file);
	return TRUE;
}

static int my_silc_scheduler(void)
{
	silc_schedule_one(0);
	return 1;
}

static CHATNET_REC *create_chatnet(void)
{
        return g_malloc0(sizeof(CHATNET_REC));
}

static SERVER_SETUP_REC *create_server_setup(void)
{
        return g_malloc0(sizeof(SERVER_SETUP_REC));
}

static CHANNEL_SETUP_REC *create_channel_setup(void)
{
        return g_malloc0(sizeof(CHANNEL_SETUP_REC));
}

static SERVER_CONNECT_REC *create_server_connect(void)
{
        return g_malloc0(sizeof(SILC_SERVER_CONNECT_REC));
}

/* Command line option variables */
void silc_core_init(void)
{
	CHAT_PROTOCOL_REC *rec;

	silc_client = silc_client_alloc(&ops, NULL);
	silc_client->username = g_strdup(settings_get_str("user_name"));
	silc_client->hostname = silc_net_localhost();
	silc_client->realname = g_strdup(settings_get_str("real_name"));

	if (!load_keys(silc_client)) {
		idletag = -1;
		return;
	}

	silc_client_init(silc_client);

	rec = g_new0(CHAT_PROTOCOL_REC, 1);
	rec->name = "SILC";
	rec->fullname = "Secure Internet Live Conferencing";
	rec->chatnet = "silcnet";

	rec->create_chatnet = create_chatnet;
        rec->create_server_setup = create_server_setup;
        rec->create_channel_setup = create_channel_setup;
	rec->create_server_connect = create_server_connect;

	rec->server_connect = (SERVER_REC *(*) (SERVER_CONNECT_REC *))
		silc_server_connect;
	rec->channel_create =
		(CHANNEL_REC *(*) (SERVER_REC *, const char *, int))
                silc_channel_create;
	rec->query_create =
		(QUERY_REC *(*) (const char *, const char *, int))
                silc_query_create;

	chat_protocol_register(rec);
	g_free(rec);

	silc_server_init();
	silc_channels_init();
	silc_queries_init();

	idletag = g_timeout_add(100, (GSourceFunc) my_silc_scheduler, NULL);
}

void silc_core_deinit(void)
{
	if (idletag != -1) {
		signal_emit("chat protocol deinit", 1,
			    chat_protocol_find("SILC"));

		silc_server_deinit();
		silc_channels_deinit();
		silc_queries_deinit();

		chat_protocol_unregister("SILC");

		g_source_remove(idletag);
	}

	g_free(silc_client->username);
	g_free(silc_client->realname);
	silc_client_free(silc_client);
}
