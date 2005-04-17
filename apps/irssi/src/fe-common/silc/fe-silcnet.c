/*
 fe-silcnet.c : irssi

    Copyright (C) 2000 Timo Sirainen
    Copyright (C) 2003 Jochen Eisinger

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
#include "module-formats.h"
#include "signals.h"
#include "commands.h"
#include "levels.h"
#include "misc.h"
#include "chatnets.h"

#include "silc-servers.h"
#include "silc-chatnets.h"
#include "printtext.h"

static void cmd_silcnet_list(void)
{
	GString *str;
	GSList *tmp;

	str = g_string_new(NULL);
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, SILCTXT_SILCNET_HEADER);
	for (tmp = chatnets; tmp != NULL; tmp = tmp->next) {
		SILC_CHATNET_REC *rec = tmp->data;

		if (!IS_SILCNET(rec))
                        continue;

		g_string_truncate(str, 0);
		if (rec->nick != NULL)
			g_string_sprintfa(str, "nick: %s, ", rec->nick);
		if (rec->username != NULL)
			g_string_sprintfa(str, "username: %s, ", rec->username);
		if (rec->realname != NULL)
			g_string_sprintfa(str, "realname: %s, ", rec->realname);
		if (rec->own_host != NULL)
			g_string_sprintfa(str, "host: %s, ", rec->own_host);

		if (str->len > 1) g_string_truncate(str, str->len-2);
		printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP,
			    SILCTXT_SILCNET_LINE, rec->name, str->str);
	}
	g_string_free(str, TRUE);
	printformat(NULL, NULL, MSGLEVEL_CLIENTCRAP, SILCTXT_SILCNET_FOOTER);
}

/* SYNTAX: SILCNET ADD [-nick <nick>] [-user <user>] [-realname <name>]
                       [-host <host>] <name> */
static void cmd_silcnet_add(const char *data)
{
	GHashTable *optlist;
	char *name, *value;
	void *free_arg;
	SILC_CHATNET_REC *rec;

	if (!cmd_get_params(data, &free_arg, 1 | PARAM_FLAG_OPTIONS,
			    "silcnet add", &optlist, &name))
		return;
	if (*name == '\0') cmd_param_error(CMDERR_NOT_ENOUGH_PARAMS);

	rec = silcnet_find(name);
	if (rec == NULL) {
		rec = g_new0(SILC_CHATNET_REC, 1);
		rec->name = g_strdup(name);
	} else {
		if (g_hash_table_lookup(optlist, "nick")) g_free_and_null(rec->nick);
		if (g_hash_table_lookup(optlist, "user")) g_free_and_null(rec->username);
		if (g_hash_table_lookup(optlist, "realname")) g_free_and_null(rec->realname);
		if (g_hash_table_lookup(optlist, "host")) {
			g_free_and_null(rec->own_host);
                        rec->own_ip4 = rec->own_ip6 = NULL;
		}
	}


	value = g_hash_table_lookup(optlist, "nick");
	if (value != NULL && *value != '\0') rec->nick = g_strdup(value);
	value = g_hash_table_lookup(optlist, "user");
	if (value != NULL && *value != '\0') rec->username = g_strdup(value);
	value = g_hash_table_lookup(optlist, "realname");
	if (value != NULL && *value != '\0') rec->realname = g_strdup(value);

	value = g_hash_table_lookup(optlist, "host");
	if (value != NULL && *value != '\0') {
		rec->own_host = g_strdup(value);
		rec->own_ip4 = rec->own_ip6 = NULL;
	}

	silcnet_create(rec);
	printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, SILCTXT_SILCNET_ADDED, name);

	cmd_params_free(free_arg);
}

/* SYNTAX: SILCNET REMOVE <silcnet> */
static void cmd_silcnet_remove(const char *data)
{
	SILC_CHATNET_REC *rec;

	if (*data == '\0') cmd_return_error(CMDERR_NOT_ENOUGH_PARAMS);

	rec = silcnet_find(data);
	if (rec == NULL)
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, SILCTXT_SILCNET_NOT_FOUND, data);
	else {
		printformat(NULL, NULL, MSGLEVEL_CLIENTNOTICE, SILCTXT_SILCNET_REMOVED, data);
		chatnet_remove(CHATNET(rec));
	}
}

static void cmd_silcnet(const char *data, SERVER_REC *server, WI_ITEM_REC *item)
{
	if (*data == '\0')
		cmd_silcnet_list();
	else
		command_runsub("silcnet", data, server, item);
}

void fe_silcnet_init(void)
{
	command_bind("silcnet", NULL, (SIGNAL_FUNC) cmd_silcnet);
	command_bind("silcnet list", NULL, (SIGNAL_FUNC) cmd_silcnet_list);
	command_bind("silcnet add", NULL, (SIGNAL_FUNC) cmd_silcnet_add);
	command_bind("silcnet remove", NULL, (SIGNAL_FUNC) cmd_silcnet_remove);

	command_set_options("silcnet add", "-nick -user -realname -host");
}

void fe_silcnet_deinit(void)
{
	command_unbind("silcnet", (SIGNAL_FUNC) cmd_silcnet);
	command_unbind("silcnet list", (SIGNAL_FUNC) cmd_silcnet_list);
	command_unbind("silcnet add", (SIGNAL_FUNC) cmd_silcnet_add);
	command_unbind("silcnet remove", (SIGNAL_FUNC) cmd_silcnet_remove);
}
