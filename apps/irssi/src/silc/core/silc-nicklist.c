/*
 silc-nicklist.c : irssi

    Copyright (C) 2000, 2003, 2006 Timo Sirainen, Pekka Riikonen

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
#include "misc.h"
#include "servers.h"

#include "silc-channels.h"
#include "silc-nicklist.h"

SILC_NICK_REC *silc_nicklist_insert(SILC_CHANNEL_REC *channel,
				    SilcChannelUser user, int send_massjoin)
{
  SILC_NICK_REC *rec;

  g_return_val_if_fail(IS_SILC_CHANNEL(channel), NULL);
  if (!user)
    return NULL;
  if (!user->client)
    return NULL;
  if (!user->client->nickname[0])
    return NULL;

  rec = g_new0(SILC_NICK_REC, 1);
  rec->nick = g_strdup(user->client->nickname);
  rec->host = g_strdup_printf("%s@%s", user->client->username,
			      user->client->hostname);
  rec->realname = g_strdup(user->client->realname);
  rec->silc_user = user;
  rec->unique_id = user->client;

  if (user->mode & SILC_CHANNEL_UMODE_CHANOP)
    rec->op = TRUE;
  if (user->mode & SILC_CHANNEL_UMODE_CHANFO)
    rec->founder = TRUE;
  rec->send_massjoin = send_massjoin;

  nicklist_insert(CHANNEL(channel), (NICK_REC *) rec);
  return rec;
}

SILC_NICK_REC *silc_nicklist_find(SILC_CHANNEL_REC *channel,
				  SilcClientEntry client)
{
  if (!client || !client->nickname[0])
    return NULL;

  return (SILC_NICK_REC *)nicklist_find_unique(CHANNEL(channel),
					       client->nickname, client);
}

#define isnickchar(a) \
    (isalnum((int) (a)) || (a) == '`' || (a) == '-' || (a) == '_' || \
    (a) == '[' || (a) == ']' || (a) == '{' || (a) == '}' || \
    (a) == '|' || (a) == '\\' || (a) == '^')

/* Remove all "extra" characters from `nick'. Like _nick_ -> nick */
char *silc_nick_strip(const char *nick)
{
  char *stripped, *spos;

  g_return_val_if_fail(nick != NULL, NULL);

  spos = stripped = g_strdup(nick);
  while (isnickchar(*nick)) {
    if (isalnum((int) *nick))
      *spos++ = *nick;
    nick++;
  }
  if ((unsigned char) *nick >= 128)
    *spos++ = *nick; /* just add it so that nicks won't match.. */
  *spos = '\0';

  return stripped;
}

/* Check is `msg' is meant for `nick'. */
int silc_nick_match(const char *nick, const char *msg)
{
  char *stripnick, *stripmsg;
  int ret, len;

  g_return_val_if_fail(nick != NULL, FALSE);
  g_return_val_if_fail(msg != NULL, FALSE);

  len = strlen(nick);
  if (g_strncasecmp(msg, nick, len) == 0 && !isalnum((int) msg[len]))
    return TRUE;

  stripnick = silc_nick_strip(nick);
  stripmsg = silc_nick_strip(msg);

  len = strlen(stripnick);
  ret = len > 0 && g_strncasecmp(stripmsg, stripnick, len) == 0 &&
    !isalnum((int) stripmsg[len]) &&
    (unsigned char) stripmsg[len] < 128;

  g_free(stripnick);
  g_free(stripmsg);

  return ret;
}

static const char *get_nick_flags(void)
{
  static char flags[3] = { '@', '+', '\0' };
  return flags;
}

static void sig_connected(SILC_SERVER_REC *server)
{
  if (IS_SILC_SERVER(server))
    server->get_nick_flags = (void *) get_nick_flags;
}

void silc_change_nick(SILC_SERVER_REC *server, const char *newnick)
{
  server_change_nick((SERVER_REC *)server, newnick);
}

void silc_nicklist_init(void)
{
  signal_add("server connected", (SIGNAL_FUNC) sig_connected);
}

void silc_nicklist_deinit(void)
{
  signal_remove("server connected", (SIGNAL_FUNC) sig_connected);
}
