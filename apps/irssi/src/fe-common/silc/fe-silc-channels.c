/*
 fe-silc-channels.c : irssi

    Copyright (C) 2000 Timo Sirainen

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
#include "modules.h"
#include "themes.h"
#include "levels.h"
#include "misc.h"
#include "special-vars.h"
#include "settings.h"

#include "silc-servers.h"

#include "window-items.h"
#include "hilight-text.h"
#include "printtext.h"
#include "module-formats.h"

void sig_message_appears(SILC_SERVER_REC *server, const char *channel,
			const char *oldnick, const char *newnick,
			const char *address)
{
	printformat_module("fe-common/silc", server, channel, MSGLEVEL_NICKS,
				SILCTXT_CHANNEL_APPEARS, oldnick, newnick,
				channel, address);
}

/* FIXME: convert identifier */
void sig_message_channel_pubkeys(SILC_SERVER_REC *server,
				SilcChannelEntry channel_entry,
				SilcBuffer channel_pubkeys)
{
  SilcUInt16 argc;
  SilcArgumentPayload chpks;
  unsigned char *pk;
  SilcUInt32 pk_len, type;
  int c = 1;
  char *fingerprint, *babbleprint;
  SilcPublicKey pubkey;
  SilcPublicKeyIdentifier ident;

  if (channel_pubkeys == NULL) {
    printformat_module("fe-common/silc", server, NULL,
                     MSGLEVEL_CRAP, SILCTXT_CHANNEL_PK_NO_LIST,
                     channel_entry->channel_name);
    return;
  }

  printformat_module("fe-common/silc", server, NULL,
                     MSGLEVEL_CRAP, SILCTXT_CHANNEL_PK_LIST,
                     channel_entry->channel_name);

  SILC_GET16_MSB(argc, channel_pubkeys->data);
  chpks = silc_argument_payload_parse(channel_pubkeys->data + 2,
                                      channel_pubkeys->len - 2, argc);
  if (!chpks)
    return;

  pk = silc_argument_get_first_arg(chpks, &type, &pk_len);
  while (pk) {
    fingerprint = silc_hash_fingerprint(NULL, pk + 4, pk_len - 4);
    babbleprint = silc_hash_babbleprint(NULL, pk + 4, pk_len - 4);
    silc_pkcs_public_key_payload_decode(pk, pk_len, &pubkey);
    ident = silc_pkcs_decode_identifier(pubkey->identifier);

    printformat_module("fe-common/silc", server, NULL,
                       MSGLEVEL_CRAP, SILCTXT_CHANNEL_PK_LIST_ENTRY,
                       c++, channel_entry->channel_name,
                       type == 0x00 ? "Added" : "Removed",
                       ident->realname ? ident->realname : "",
                       fingerprint, babbleprint);

    silc_free(fingerprint);
    silc_free(babbleprint);
    silc_pkcs_public_key_free(pubkey);
    silc_pkcs_free_identifier(ident);
    pk = silc_argument_get_next_arg(chpks, &type, &pk_len);
  }

  silc_argument_payload_free(chpks);
}

void sig_message_generic(SILC_SERVER_REC *server, const char *target,
			int msglevel, const char *msg)
{
  printtext(server, target, msglevel, "%s", msg);
}

void sig_cmode_changed(SILC_SERVER_REC *server, const char *channel,
			const char *mode, const char *nick)
{
  printformat_module("fe-common/silc", server, channel, MSGLEVEL_MODES,
  			SILCTXT_CHANNEL_CMODE, channel,
			mode ? mode : "removed all", 
			nick ? nick : "");
}

void sig_cumode_changed(SILC_SERVER_REC *server, const char *channel,
			const char *who,
			const char *mode, const char *nick)
{
  printformat_module("fe-common/silc", server, channel, MSGLEVEL_MODES,
  			SILCTXT_CHANNEL_CUMODE, channel, who,
			mode ? mode : "removed all",
			nick ? nick : "");
}

void sig_channel_founder(SILC_SERVER_REC *server, const char *channel,
			const char *nick)
{
  printformat_module("fe-common/silc", server, channel, MSGLEVEL_CRAP,
  			SILCTXT_CHANNEL_FOUNDER, channel, nick);
}

void sig_quieted(SILC_SERVER_REC *server, const char *channel)
{
  printformat_module("fe-common/silc", server, channel, MSGLEVEL_CRAP,
  			SILCTXT_CHANNEL_QUIETED, channel);
}

void sig_motd(SILC_SERVER_REC *server, const char *motd)
{
  printtext_multiline(server, NULL, MSGLEVEL_CRAP, "%s", motd);
}

void fe_silc_channels_init(void)
{
	signal_add("message silc appears", 
			(SIGNAL_FUNC) sig_message_appears);
	signal_add("message silc pubkeys",
			(SIGNAL_FUNC) sig_message_channel_pubkeys);
	signal_add("message silc generic",
			(SIGNAL_FUNC) sig_message_generic);
	signal_add("message silc cmode",
			(SIGNAL_FUNC) sig_cmode_changed);
	signal_add("message silc cumode",
			(SIGNAL_FUNC) sig_cumode_changed);
	signal_add("message silc founder",
			(SIGNAL_FUNC) sig_channel_founder);
	signal_add("message silc quieted",
			(SIGNAL_FUNC) sig_quieted);
	signal_add("message silc motd",
			(SIGNAL_FUNC) sig_motd);
}

void fe_silc_channels_deinit(void)
{
	signal_remove("message silc appears", 
			(SIGNAL_FUNC) sig_message_appears);
	signal_remove("message silc pubkeys",
			(SIGNAL_FUNC) sig_message_channel_pubkeys);
	signal_remove("message silc generic",
			(SIGNAL_FUNC) sig_message_generic);
	signal_remove("message silc cmode",
			(SIGNAL_FUNC) sig_cmode_changed);
	signal_remove("message silc cumode",
			(SIGNAL_FUNC) sig_cumode_changed);
	signal_remove("message silc founder",
			(SIGNAL_FUNC) sig_channel_founder);
	signal_remove("message silc quieted",
			(SIGNAL_FUNC) sig_quieted);
	signal_remove("message silc motd",
			(SIGNAL_FUNC) sig_motd);
}
