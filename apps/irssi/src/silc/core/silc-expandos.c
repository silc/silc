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

/* User mode in active server */

static char *expando_usermode(SERVER_REC *server, void *item, int *free_ret)
{
  SILC_SERVER_REC *s = SILC_SERVER(server);

  if (!s)
    return "";

  return (s->umode & SILC_UMODE_SERVER_OPERATOR) ? "Server Operator" :
    (s->umode & SILC_UMODE_ROUTER_OPERATOR) ? "Router Operator" : "";
}

/* Expands to your usermode on channel */

static char *expando_cumode(SERVER_REC *server, void *item, int *free_ret)
{
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
  char *ret;

  if (!IS_SILC_SERVER(server))
    return "";

  ret = expando_cumode(server, item, free_ret);
  return *ret == '\0' ? " " : ret;
}

void silc_expandos_init(void)
{
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
}
