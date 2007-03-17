/*
 silc-chatnets.c : irssi

    Copyright (C) 1999-2000 Timo Sirainen
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
#include "signals.h"
#include "lib-config/iconfig.h"
#include "settings.h"

#include "silc-chatnets.h"

static void sig_chatnet_read(SILC_CHATNET_REC *rec, CONFIG_NODE *node)
{
	if (!IS_SILC_CHATNET(rec))
		return;
	
	/* read settings */
}

static void sig_chatnet_saved(SILC_CHATNET_REC *rec, CONFIG_NODE *node)
{
	if (!IS_SILC_CHATNET(rec))
		return;

	/* save settings */
}

static void sig_chatnet_destroyed(SILC_CHATNET_REC *rec)
{
	if (!IS_SILC_CHATNET(rec))
		return;

	/* free eventually allocated memory */
}


void silc_chatnets_init(void)
{
	signal_add("chatnet read", (SIGNAL_FUNC) sig_chatnet_read);
	signal_add("chatnet saved", (SIGNAL_FUNC) sig_chatnet_saved);
	signal_add("chatnet destroyed", (SIGNAL_FUNC) sig_chatnet_destroyed);
}

void silc_chatnets_deinit(void)
{
	GSList *tmp, *next;

	for (tmp = chatnets; tmp != NULL; tmp = next) {
		CHATNET_REC *rec = tmp->data;

		next = tmp->next;
		if (IS_SILC_CHATNET(rec))
                        chatnet_destroy(rec);
	}

	signal_remove("chatnet read", (SIGNAL_FUNC) sig_chatnet_read);
	signal_remove("chatnet saved", (SIGNAL_FUNC) sig_chatnet_saved);
	signal_remove("chatnet destroyed", (SIGNAL_FUNC) sig_chatnet_destroyed);
}
