#include "module.h"
#include "signals.h"
#include "misc.h"
#include "settings.h"

#include "silc-servers.h"

#define	SILC_CLIENT_LAG_PING_ID	0x1337

static int timeout_tag;
static void lag_event_pong(SILC_SERVER_REC *server, 
		SilcClientCommandReplyContext cmd);

static void lag_get(SILC_SERVER_REC *server)
{
	SilcBuffer idp;
	g_get_current_time(&server->lag_sent);
	server->lag_last_check = time(NULL);

	/* register pending callback & send ping */
	silc_client_command_pending(server->conn, SILC_COMMAND_PING,
			SILC_CLIENT_LAG_PING_ID,
			(SilcCommandCb)lag_event_pong, (void *)server);
	idp = silc_id_payload_encode(server->conn->remote_id, SILC_ID_SERVER);
	silc_client_command_send(silc_client, server->conn,
			SILC_COMMAND_PING, SILC_CLIENT_LAG_PING_ID,
			1, 1, idp->data, idp->len);
	silc_buffer_free(idp);
}

static void lag_event_pong(SILC_SERVER_REC *server,
			   SilcClientCommandReplyContext cmd)
{
	GTimeVal now;

	if (cmd->error != SILC_STATUS_OK) {

		/* if the ping failed for some reason, try it again */
		lag_get(server);
		return;

	}

	if (server->lag_sent.tv_sec == 0) {
		/* not expecting lag reply.. */
		return;
	}

	g_get_current_time(&now);
	server->lag = (int) get_timeval_diff(&now, &server->lag_sent);
	memset(&server->lag_sent, 0, sizeof(server->lag_sent));

	signal_emit("server lag", 1, server);
}

static int sig_check_lag(void)
{
	GSList *tmp, *next;
	time_t now;
	int lag_check_time, max_lag;

	lag_check_time = settings_get_int("lag_check_time");
	max_lag = settings_get_int("lag_max_before_disconnect");

	if (lag_check_time <= 0)
		return 1;

	now = time(NULL);
	for (tmp = servers; tmp != NULL; tmp = next) {
		SILC_SERVER_REC *rec = tmp->data;

		next = tmp->next;
		if (!IS_SILC_SERVER(rec))
			continue;

		if (rec->lag_sent.tv_sec != 0) {
			/* waiting for lag reply */
			if (max_lag > 1 && now-rec->lag_sent.tv_sec > max_lag) {
				/* too much lag, disconnect */
				signal_emit("server lag disconnect", 1, rec);
				rec->connection_lost = TRUE;
				server_disconnect((SERVER_REC *) rec);
			}
		} else if (rec->lag_last_check+lag_check_time < now &&
			 rec->cmdcount == 0 && rec->connected) {
			/* no commands in buffer - get the lag */
			lag_get(rec);
		}
	}

	return 1;
}

void silc_lag_init(void)
{
	/* silc-client will need those... silc-plugin uses irc defaults */
	settings_add_int("misc", "lag_check_time", 60);
	settings_add_int("misc", "lag_max_before_disconnect", 300); 

	timeout_tag = g_timeout_add(1000, (GSourceFunc) sig_check_lag, NULL);
}

void silc_lag_deinit(void)
{
	g_source_remove(timeout_tag);
}
