/*
 silc-channels.c : irssi

    Copyright (C) 2000-2001 Timo Sirainen

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "module.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "misc.h"
#include "channels-setup.h"
#include "levels.h"

#include "silc-channels.h"
#include "silc-nicklist.h"

#include "fe-common/core/printtext.h"

SILC_CHANNEL_REC *silc_channel_create(SILC_SERVER_REC *server,
				      const char *name, int automatic)
{
	SILC_CHANNEL_REC *rec;

	g_return_val_if_fail(server == NULL || IS_SILC_SERVER(server), NULL);
	g_return_val_if_fail(name != NULL, NULL);

	rec = g_new0(SILC_CHANNEL_REC, 1);
	rec->chat_type = SILC_PROTOCOL;
	rec->name = g_strdup(name);
	rec->server = server;

	channel_init((CHANNEL_REC *) rec, automatic);
	return rec;
}

static void sig_channel_destroyed(SILC_CHANNEL_REC *channel)
{
	if (!IS_SILC_CHANNEL(channel))
                return;

	if (channel->server != NULL && !channel->left && !channel->kicked) {
		/* destroying channel record without actually
		   having left the channel yet */
		silc_command_exec(channel->server, "PART", channel->name);
	}
}

static void silc_channels_join(SILC_SERVER_REC *server,
			       const char *channels, int automatic)
{
	char **list, **tmp, *channel;

	list = g_strsplit(channels, ",", -1);
	for (tmp = list; *tmp != NULL; tmp++) {
		channel = **tmp == '#' ? g_strdup(*tmp) :
			g_strconcat("#", *tmp, NULL);
		silc_channel_create(server, channel, FALSE);
		silc_command_exec(server, "JOIN", channel);
		g_free(channel);
	}
        g_strfreev(list);
}

static void sig_connected(SILC_SERVER_REC *server)
{
	if (IS_SILC_SERVER(server))
                server->channels_join = (void *) silc_channels_join;
}

SILC_CHANNEL_REC *silc_channel_find_entry(SILC_SERVER_REC *server,
					  SilcChannelEntry entry)
{
	GSList *tmp;

	g_return_val_if_fail(IS_SILC_SERVER(server), NULL);

	for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
		SILC_CHANNEL_REC *rec = tmp->data;

		if (rec->entry == entry)
			return rec;
	}

	return NULL;
}

static void event_join(SILC_SERVER_REC *server, va_list va)
{
	SILC_CHANNEL_REC *chanrec;
	SILC_NICK_REC *nickrec;
	SilcClientEntry client;
	SilcChannelEntry channel;

	client = va_arg(va, SilcClientEntry);
	channel = va_arg(va, SilcChannelEntry);

	if (client == server->conn->local_entry) {
		/* you joined to channel */
                chanrec = silc_channel_find(server, channel->channel_name);
		if (chanrec != NULL && !chanrec->joined)
			chanrec->entry = channel;
	} else {
		chanrec = silc_channel_find_entry(server, channel);
		if (chanrec != NULL) {
			SilcChannelUser user;

			silc_list_start(chanrec->entry->clients);
			while ((user = silc_list_get(chanrec->entry->clients)) != NULL)
				if (user->client == client) {
					nickrec = silc_nicklist_insert(chanrec, user, TRUE);
                                        break;
				}
		}
	}

	signal_emit("message join", 4, server, channel->channel_name,
		    client->nickname,
		    client->username == NULL ? "" : client->username);
}

static void event_leave(SILC_SERVER_REC *server, va_list va)
{
	SILC_CHANNEL_REC *chanrec;
	SILC_NICK_REC *nickrec;
	SilcClientEntry client;
	SilcChannelEntry channel;

	client = va_arg(va, SilcClientEntry);
	channel = va_arg(va, SilcChannelEntry);

	signal_emit("message part", 5, server, channel->channel_name,
		    client->nickname, 
		    client->username == NULL ? "" : client->username, "");

	chanrec = silc_channel_find_entry(server, channel);
	if (chanrec != NULL) {
		nickrec = silc_nicklist_find(chanrec, client);
		if (nickrec != NULL)
			nicklist_remove(CHANNEL(chanrec), NICK(nickrec));
	}
}

static void event_signoff(SILC_SERVER_REC *server, va_list va)
{
	SilcClientEntry client;
	GSList *nicks, *tmp;

	client = va_arg(va, SilcClientEntry);

	signal_emit("message quit", 4, server, client->nickname,
		    client->username == NULL ? "" : client->username, "");

	nicks = nicklist_get_same_unique(SERVER(server), client);
	for (tmp = nicks; tmp != NULL; tmp = tmp->next->next) {
		CHANNEL_REC *channel = tmp->data;
		NICK_REC *nickrec = tmp->next->data;

		nicklist_remove(channel, nickrec);
	}
}

static void event_topic(SILC_SERVER_REC *server, va_list va)
{
	SILC_CHANNEL_REC *chanrec;
	SilcClientEntry client;
	SilcChannelEntry channel;
	char *topic;

	client = va_arg(va, SilcClientEntry);
	topic = va_arg(va, char *);
	channel = va_arg(va, SilcChannelEntry);

	chanrec = silc_channel_find_entry(server, channel);
	if (chanrec != NULL) {
		g_free_not_null(chanrec->topic);
		chanrec->topic = *topic == '\0' ? NULL : g_strdup(topic);
		signal_emit("channel topic changed", 1, chanrec);
	}

	signal_emit("message topic", 5, server, channel->channel_name,
		    topic, client->nickname, client->username);
}

static void event_invite(SILC_SERVER_REC *server, va_list va)
{
	SilcClientEntry client;
	SilcChannelEntry channel;

	client = va_arg(va, SilcClientEntry);
	channel = va_arg(va, SilcChannelEntry);

	signal_emit("message invite", 4, server, channel->channel_name,
		    client->nickname, client->username);
}

static void event_nick(SILC_SERVER_REC *server, va_list va)
{
	SilcClientEntry oldclient, newclient;

	oldclient = va_arg(va, SilcClientEntry);
	newclient = va_arg(va, SilcClientEntry);

	nicklist_rename_unique(SERVER(server),
			       oldclient, oldclient->nickname,
			       newclient, newclient->nickname);

	signal_emit("message nick", 4, server, newclient->nickname,
		    oldclient->nickname, newclient->username);
}

static void event_cmode(SILC_SERVER_REC *server, va_list va)
{
	SILC_CHANNEL_REC *chanrec;
	SilcClientEntry client;
	SilcChannelEntry channel;
	char *mode;

	client = va_arg(va, SilcClientEntry);
	mode = silc_client_chmode(va_arg(va, unsigned int));
	channel = va_arg(va, SilcChannelEntry);

	chanrec = silc_channel_find_entry(server, channel);
	if (chanrec != NULL) {
		g_free_not_null(chanrec->mode);
		chanrec->mode = g_strdup(mode == NULL ? "" : mode);
		signal_emit("channel mode changed", 1, chanrec);
	}

	/*signal_emit("message mode", 5, server, chanrec->name,
		    client->nickname, client->username, mode);*/
	printtext(server, channel->channel_name, MSGLEVEL_MODES,
		  "mode/%s [%s] by %s", channel->channel_name, mode,
		  client->nickname);

	g_free(mode);
}

static void event_cumode(SILC_SERVER_REC *server, va_list va)
{
	SILC_CHANNEL_REC *chanrec;
	SilcClientEntry client, destclient;
	SilcChannelEntry channel;
        int mode;
	char *modestr;

	client = va_arg(va, SilcClientEntry);
	mode = va_arg(va, unsigned int);
	destclient = va_arg(va, SilcClientEntry);
	channel = va_arg(va, SilcChannelEntry);

	modestr = silc_client_chumode(mode);
	chanrec = silc_channel_find_entry(server, channel);
	if (chanrec != NULL) {
		SILC_NICK_REC *nick;

		if (destclient == server->conn->local_entry) {
			chanrec->chanop =
				(mode & SILC_CHANNEL_UMODE_CHANOP) != 0;
		}

		nick = silc_nicklist_find(chanrec, client);
		if (nick != NULL) {
                        nick->op = (mode & SILC_CHANNEL_UMODE_CHANOP) != 0;
			signal_emit("nick mode changed", 2, chanrec, nick);
		}
	}

	/*signal_emit("message mode", 5, server, chanrec->name,
		    client->nickname, client->username, modestr);*/
	printtext(server, channel->channel_name, MSGLEVEL_MODES,
		  "mode/%s [%s] by %s", channel->channel_name, modestr,
		  client->nickname);

	g_free(modestr);
}

static void command_part(const char *data, SILC_SERVER_REC *server,
			 WI_ITEM_REC *item)
{
	SILC_CHANNEL_REC *chanrec;

	if (!IS_SILC_SERVER(server) || !server->connected)
		return;

	if (*data == '\0') {
		if (!IS_SILC_CHANNEL(item))
			cmd_return_error(CMDERR_NOT_JOINED);
		data = item->name;
	}

	chanrec = silc_channel_find(server, data);
	if (chanrec == NULL) cmd_return_error(CMDERR_CHAN_NOT_FOUND);

	signal_emit("message part", 5, server, chanrec->name,
		    server->nick, "", "");

	silc_command_exec(server, "LEAVE", chanrec->name);
	signal_stop();

	channel_destroy(CHANNEL(chanrec));
}

void silc_channels_init(void)
{
	signal_add("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
	signal_add("server connected", (SIGNAL_FUNC) sig_connected);

	signal_add("silc event join", (SIGNAL_FUNC) event_join);
	signal_add("silc event leave", (SIGNAL_FUNC) event_leave);
	signal_add("silc event signoff", (SIGNAL_FUNC) event_signoff);
	signal_add("silc event topic", (SIGNAL_FUNC) event_topic);
	signal_add("silc event invite", (SIGNAL_FUNC) event_invite);
	signal_add("silc event nick", (SIGNAL_FUNC) event_nick);
	signal_add("silc event cmode", (SIGNAL_FUNC) event_cmode);
	signal_add("silc event cumode", (SIGNAL_FUNC) event_cumode);

	command_bind("part", MODULE_NAME, (SIGNAL_FUNC) command_part);

	silc_nicklist_init();
}

void silc_channels_deinit(void)
{
	signal_remove("channel destroyed", (SIGNAL_FUNC) sig_channel_destroyed);
	signal_remove("server connected", (SIGNAL_FUNC) sig_connected);

	signal_remove("silc event join", (SIGNAL_FUNC) event_join);
	signal_remove("silc event leave", (SIGNAL_FUNC) event_leave);
	signal_remove("silc event signoff", (SIGNAL_FUNC) event_signoff);
	signal_remove("silc event topic", (SIGNAL_FUNC) event_topic);
	signal_remove("silc event invite", (SIGNAL_FUNC) event_invite);
	signal_remove("silc event nick", (SIGNAL_FUNC) event_nick);
	signal_remove("silc event cmode", (SIGNAL_FUNC) event_cmode);
	signal_remove("silc event cumode", (SIGNAL_FUNC) event_cumode);

	command_unbind("part", (SIGNAL_FUNC) command_part);

	silc_nicklist_deinit();
}
