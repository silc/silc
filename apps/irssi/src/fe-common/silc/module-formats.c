/*

  modules-formats.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "module.h"
#include "fe-common/core/formats.h"
#include "printtext.h"

FORMAT_REC fecommon_silc_formats[] = {
	{ MODULE_NAME, "SILC", 0 },

	/* Channel related messages */
	{ NULL, "Channel", 0 },

	{ "channel_founder_you", "You are channel founder on {channel $0}", 1, { 0 } },
	{ "channel_founder", "channel founder on {channel $0} is: {channick_hilight $1}", 2, { 0, 0 } },
	{ "channel_topic", "Topic for {channel $0} is: $1", 2, { 0, 0 } },
	{ "cmode", "channel mode/{channel $0} {mode $1} by {nick $2}", 3, { 0, 0, 0 } },
	{ "cumode", "channel user mode/{channel $0}/{nick $1} {mode $2} by {nick $3}", 4, { 0, 0, 0, 0 } },
	{ "action", "{action $0}", 1, { 0 } },
	{ "notice", "{notice $0}", 1, { 0 } },
	{ "ownaction", "{ownaction $0}", 1, { 0 } },
	{ "ownnotice", "{ownnotice $0}", 1, { 0 } },

	/* WHOIS, WHOWAS and USERS (alias WHO) messages */
	{ NULL, "Who Queries", 0 },

	{ "whois", "{nick $0} {nickhost $1}%: realname : $2", 3, { 0, 0, 0 } },
	{ "whois_channels", " channels : $0", 1, { 0 } },
	{ "whois_modes", " modes    : $0", 1, { 0 } },
	{ "whois_idle", " idle     : $0", 1, { 0 } },
	{ "whowas", "{nick $0} was {nickhost $1} ($2)", 3, { 0, 0, 0 } },
	{ "users_header", "Users on {channelhilight $0}", 1, { 0 } },
	{ "users", " %|{nick $[!20]0} $[!5]1 $2 {comment {hilight $3}}", 4, { 0, 0, 0, 0 } },

	/* Key management and key agreement */
	{ NULL, "Key Management And Key Agreement", 0 },

	{ "channel_private_key_add", "Private key set to channel {channel $0}", 1, { 0 } },
	{ "channel_private_key_nomode", "Private key mode is not set on channel {channel $0}", 1, { 0 } },
	{ "channel_private_key_error", "Could not add private key to channel {channel $0}", 1, { 0 } },
	{ "channel_private_key_list", "Channel {channel $0} private keys%:  Cipher           Hmac             Key", 1, { 0 } },
	{ "private_key_list", "Private message keys%:  Client                         Cipher         Key", 0, { 0 } },
	{ "private_key_list_nick", "Private message keys with {nick $0}%:  Client                         Cipher         Key", 1, { 0 } },
	{ "key_agreement", "Requesting key agreement with {nick $0}", 1, { 0 } },
	{ "key_agreement_request", "{nick $0} wants to perform key agreement", 1, { 0 } },
	{ "key_agreement_request_host", "{nick $0} wants to perform key agreement on {nickhost $1} port {hilight $2}", 3, { 0, 0, 0 } },
	{ "key_agreement_negotiate", "Starting key agreement with {nick $0}", 1, { 0 } },
	{ "key_agreement_privmsg", "The private messages with the {nick $0} are now protected with the private key", 1, { 0 } },
	{ "key_agreement_ok", "Key agreement completed successfully with {nick $0}", 1, { 0 } },
	{ "key_agreement_error", "Error occurred during key agreement with {nick $0}", 1, { 0 } },
	{ "key_agreement_failure", "Key agreement failed with {nick $0}", 1, { 0 } },
	{ "key_agreement_timeout", "Timeout during key agreement. The key agreement was not performed with {nick $0}", 1, { 0 } },

	/* Key management and key agreement */
	{ NULL, "Misc", 0 },

	{ "server_oper", "You are now {hilight server operator}", 0, { 0 } },
	{ "router_oper", "You are now {hilight SILC operator}", 0, { 0 } },
	{ "list_header", "  Channel                              Users   Topic", 0, { 0 } },
	{ "list", "  %|{channelhilight $[36]0} {hilight $[7]1} $2", 3, { 0, 0, 0 } },

	{ NULL, NULL, 0 }
};
