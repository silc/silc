/*

  silc-expandos.c 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "module.h"
#include "misc.h"
#include "expandos.h"
#include "settings.h"

#include "chatnets.h"
#include "servers-setup.h"
#include "channels-setup.h"
#include "silc-servers.h"
#include "silc-channels.h"
#include "silc-queries.h"
#include "silc-nicklist.h"

EXPANDO_FUNC old_expando_usermode,
            old_expando_cumode,
            old_expando_cumode_space;

/* User mode in active server */

static char *expando_usermode(SERVER_REC *server, void *item, int *free_ret)
{
  SILC_SERVER_REC *s = SILC_SERVER(server);
  static char modes[128], stat[128];
  bool se;

  if (!s) {
    if (old_expando_usermode)
      return old_expando_usermode(server, item, free_ret);
    else
      return "";
  }

  memset(modes, 0, sizeof(modes));
  memset(stat, 0, sizeof(stat));

  if (s->umode & SILC_UMODE_GONE)
    strcat(stat, "g");
  if (s->umode & SILC_UMODE_INDISPOSED)
    strcat(stat, "i");
  if (s->umode & SILC_UMODE_BUSY)
    strcat(stat, "b");
  if (s->umode & SILC_UMODE_PAGE)
    strcat(stat, "p");
  if (s->umode & SILC_UMODE_HYPER)
    strcat(stat, "h");
  if (s->umode & SILC_UMODE_ROBOT)
    strcat(stat, "t");
  if (s->umode & SILC_UMODE_ANONYMOUS)
    strcat(stat, "?");
  if (s->umode & SILC_UMODE_BLOCK_PRIVMSG)
    strcat(stat, "P");
  if (s->umode & SILC_UMODE_REJECT_WATCHING)
    strcat(stat, "w");
  if (s->umode & SILC_UMODE_BLOCK_INVITE)
    strcat(stat, "I");

  se = strlen(stat) > 0;
  snprintf(modes, sizeof(modes) - 1, "%s%s%s%s",
	   ((s->umode & SILC_UMODE_SERVER_OPERATOR) ? "Server Operator" :
	    (s->umode & SILC_UMODE_ROUTER_OPERATOR) ? "Router Operator" : ""),
	   se ? "[" : "", se ? stat : "", se ? "]" : "");

  return modes;
}

/* Expands to your usermode on channel */

static char *expando_cumode(SERVER_REC *server, void *item, int *free_ret)
{
  SILC_SERVER_REC *s = SILC_SERVER(server);
      
  if (!s) {
    if (old_expando_cumode)
      return old_expando_cumode(server, item, free_ret);
    else
      return ""; 
  }

  if (IS_SILC_CHANNEL(item) && CHANNEL(item)->ownnick) {
    SILC_NICK_REC *nick = (SILC_NICK_REC *)CHANNEL(item)->ownnick;
    return (nick->op && nick->founder) ? "*@" :
      nick->op ? "@" : nick->founder ? "*" : "";
  }

  return "";
}

static char *expando_cumode_space(SERVER_REC *server, void *item, 
				  int *free_ret)
{
  SILC_SERVER_REC *s = SILC_SERVER(server);
  char *ret;

  if (!s) {
    if (old_expando_cumode_space)
      return old_expando_cumode_space(server, item, free_ret);   
    else
      return "";
  }

  ret = expando_cumode(server, item, free_ret);
  return *ret == '\0' ? " " : ret;
}

static char *expando_silc_version(SERVER_REC *server, void *item,
                                 int *free_ret)
{
  return "";
}

void silc_expandos_init(void)
{
  old_expando_usermode = expando_find_long("usermode");
  old_expando_cumode = expando_find_long("cumode");
  old_expando_cumode_space = expando_find_long("cumode_space");
  expando_create("usermode", expando_usermode,
		 "window changed", EXPANDO_ARG_NONE,
		 "window server changed", EXPANDO_ARG_WINDOW,
		 "user mode changed", EXPANDO_ARG_SERVER, NULL);
  expando_create("cumode", expando_cumode,
		 "window changed", EXPANDO_ARG_NONE,
		 "window item changed", EXPANDO_ARG_WINDOW,
		 "nick mode changed", EXPANDO_ARG_WINDOW_ITEM, NULL);
  expando_create("cumode_space", expando_cumode_space,
		 "window changed", EXPANDO_ARG_NONE,
		 "window item changed", EXPANDO_ARG_WINDOW,
		 "nick mode changed", EXPANDO_ARG_WINDOW_ITEM, NULL);
}

void silc_expandos_deinit(void)
{
  expando_destroy("usermode", expando_usermode);
  expando_destroy("cumode", expando_cumode);
  expando_destroy("cumode_space", expando_cumode_space);
  if (old_expando_usermode)
    expando_create("usermode", old_expando_usermode, NULL);
  if (old_expando_cumode)
    expando_create("cumode", old_expando_cumode, NULL);
  if (old_expando_cumode_space)
    expando_create("cumode_space", old_expando_cumode_space, NULL);
}
