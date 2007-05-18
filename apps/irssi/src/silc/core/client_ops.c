/*

  client_ops.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2001 - 2007 Pekka Riikonen

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
#include "chat-protocols.h"
#include "args.h"

#include "chatnets.h"
#include "servers-setup.h"
#include "channels-setup.h"
#include "silc-servers.h"
#include "silc-channels.h"
#include "silc-queries.h"
#include "silc-nicklist.h"
#include "silc-cmdqueue.h"

#include "signals.h"
#include "levels.h"
#include "settings.h"
#include "ignore.h"
#include "special-vars.h"
#include "fe-common/core/printtext.h"
#include "fe-common/core/fe-channels.h"
#include "fe-common/core/keyboard.h"
#include "fe-common/core/window-items.h"
#include "fe-common/silc/module-formats.h"

#include "core.h"

static void
silc_verify_public_key_internal(SilcClient client, SilcClientConnection conn,
				const char *name, SilcConnectionType conn_type,
				SilcPublicKey public_key,
				SilcVerifyPublicKey completion, void *context);

char *silc_get_session_filename(SILC_SERVER_REC *server)
{
  char *file, *expanded;

  expanded = parse_special_string(settings_get_str("session_filename"),
  				SERVER(server), NULL, "", NULL, 0);

  file = silc_calloc(1, strlen(expanded) + 255);
  snprintf(file, strlen(expanded) + 255, "%s/%s", get_irssi_dir(), expanded);
  free(expanded);

  return file;
}

static void silc_get_umode_string(SilcUInt32 mode, char *buf,
				  SilcUInt32 buf_size)
{
  if ((mode & SILC_UMODE_SERVER_OPERATOR) ||
      (mode & SILC_UMODE_ROUTER_OPERATOR)) {
    strcat(buf, (mode & SILC_UMODE_SERVER_OPERATOR) ?
	   "[server operator]" :
	   (mode & SILC_UMODE_ROUTER_OPERATOR) ?
	   "[SILC operator]" : "[unknown mode]");
  }
  if (mode & SILC_UMODE_GONE)
    strcat(buf, " [away]");
  if (mode & SILC_UMODE_INDISPOSED)
    strcat(buf, " [indisposed]");
  if (mode & SILC_UMODE_BUSY)
    strcat(buf, " [busy]");
  if (mode & SILC_UMODE_PAGE)
    strcat(buf, " [page to reach]");
  if (mode & SILC_UMODE_HYPER)
    strcat(buf, " [hyper active]");
  if (mode & SILC_UMODE_ROBOT)
    strcat(buf, " [robot]");
  if (mode & SILC_UMODE_ANONYMOUS)
    strcat(buf, " [anonymous]");
  if (mode & SILC_UMODE_BLOCK_PRIVMSG)
    strcat(buf, " [blocks private messages]");
  if (mode & SILC_UMODE_DETACHED)
    strcat(buf, " [detached]");
  if (mode & SILC_UMODE_REJECT_WATCHING)
    strcat(buf, " [rejects watching]");
  if (mode & SILC_UMODE_BLOCK_INVITE)
    strcat(buf, " [blocks invites]");
}

/* converts an utf-8 string to current locale */
char * silc_convert_utf8_string(const char *str)
{
  int message_len = (str != NULL ? strlen(str) : 0);
  char *message = silc_calloc(message_len + 1, sizeof(*message));

  g_return_val_if_fail(message != NULL, NULL);

  if (str == NULL) {
    *message = 0;
    return message;
  }

  if (!silc_term_utf8() && silc_utf8_valid(str, message_len))
    silc_utf8_decode(str, message_len, SILC_STRING_LOCALE,
                     message, message_len);
  else
    strcpy(message, str);

  return message;
}

/* print "nick appears as" message to every channel of a server */
static void
silc_print_nick_change_channel(SILC_SERVER_REC *server, const char *channel,
			      const char *newnick, const char *oldnick,
			      const char *address)
{
  if (ignore_check(SERVER(server), oldnick, address,
		   channel, newnick, MSGLEVEL_NICKS))
    return;

  printformat_module("fe-common/silc", server, channel, MSGLEVEL_NICKS,
		     SILCTXT_CHANNEL_APPEARS,
		     oldnick, newnick, channel, address);
}

static void
silc_print_nick_change(SILC_SERVER_REC *server, const char *newnick,
		       const char *oldnick, const char *address)
{
  GSList *tmp, *windows;

  /* Print to each channel/query where the nick is.
     Don't print more than once to the same window. */
  windows = NULL;

  for (tmp = server->channels; tmp != NULL; tmp = tmp->next) {
    CHANNEL_REC *channel = tmp->data;
    WINDOW_REC *window = window_item_window((WI_ITEM_REC *) channel);

    if (nicklist_find(channel, newnick) == NULL ||
	g_slist_find(windows, window) != NULL)
      continue;

    windows = g_slist_append(windows, window);
    silc_print_nick_change_channel(server, channel->visible_name,
				   newnick, oldnick, address);
  }

  g_slist_free(windows);
}

static void silc_parse_channel_public_keys(SILC_SERVER_REC *server,
					   SilcChannelEntry channel_entry,
					   SilcDList channel_pubkeys)
{
  SilcArgumentDecodedList e;
  SilcPublicKey pubkey;
  SilcSILCPublicKey silc_pubkey;
  SilcUInt32 pk_len, type;
  unsigned char *pk;
  char *fingerprint, *babbleprint;
  int c = 1;

  printformat_module("fe-common/silc", server, NULL,
		     MSGLEVEL_CRAP, SILCTXT_CHANNEL_PK_LIST,
		     channel_entry->channel_name);

  silc_dlist_start(channel_pubkeys);
  while ((e = silc_dlist_get(channel_pubkeys))) {
    pubkey = e->argument;
    type = e->arg_type;

    if (silc_pkcs_get_type(pubkey) != SILC_PKCS_SILC)
      continue;

    pk = silc_pkcs_public_key_encode(pubkey, &pk_len);
    if (!pk)
      continue;

    fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
    babbleprint = silc_hash_babbleprint(NULL, pk, pk_len);
    silc_pubkey = silc_pkcs_get_context(SILC_PKCS_SILC, pubkey);

    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_CHANNEL_PK_LIST_ENTRY,
		       c++, channel_entry->channel_name,
		       type == 0x00 ? "Added" : "Removed",
		       silc_pubkey->identifier.realname ?
		       silc_pubkey->identifier.realname : "",
		       fingerprint, babbleprint);

    silc_free(fingerprint);
    silc_free(babbleprint);
    silc_free(pk);
  }
}

void silc_say(SilcClient client, SilcClientConnection conn,
	      SilcClientMessageType type, char *msg, ...)
{
  SILC_SERVER_REC *server;
  va_list va;
  char *str;

  server = conn == NULL ? NULL : conn->context;

  va_start(va, msg);
  str = g_strdup_vprintf(msg, va);
  printtext(server, NULL, MSGLEVEL_CRAP, "%s", str);
  g_free(str);
  va_end(va);
}

void silc_say_error(char *msg, ...)
{
  va_list va;
  char *str;

  va_start(va, msg);
  str = g_strdup_vprintf(msg, va);
  printtext(NULL, NULL, MSGLEVEL_CLIENTERROR, "%s", str);

  g_free(str);
  va_end(va);
}

/* Try to verify a message using locally stored public key data */

int verify_message_signature(SilcClientEntry sender,
			     SilcMessagePayload message)
{
  SilcPublicKey pk;
  char file[256], filename[256];
  char *fingerprint, *fingerprint2;
  const unsigned char *pk_data;
  SilcUInt32 pk_datalen;
  struct stat st;
  int ret = SILC_MSG_SIGNED_VERIFIED, i;

  /* get public key from the signature payload and compare it with the
     one stored in the client entry */
  pk = silc_message_signed_get_public_key(message, &pk_data, &pk_datalen);

  if (pk != NULL) {
    fingerprint = silc_hash_fingerprint(NULL, pk_data, pk_datalen);

    if (sender->fingerprint[0]) {
      fingerprint2 = silc_fingerprint(sender->fingerprint,
				      sizeof(sender->fingerprint));
      if (strcmp(fingerprint, fingerprint2)) {
        /* since the public key differs from the senders public key, the
           verification _failed_ */
        silc_pkcs_public_key_free(pk);
        silc_free(fingerprint);
        ret = SILC_MSG_SIGNED_UNKNOWN;
      }
      silc_free(fingerprint2);
    }
  } else if (sender->fingerprint[0])
    fingerprint = silc_fingerprint(sender->fingerprint,
				   sizeof(sender->fingerprint));
  else
    /* no idea, who or what signed that message ... */
    return SILC_MSG_SIGNED_UNKNOWN;

  /* search our local client key cache */
  for (i = 0; i < strlen(fingerprint); i++)
    if (fingerprint[i] == ' ')
      fingerprint[i] = '_';

  snprintf(file, sizeof(file) - 1, "clientkey_%s.pub", fingerprint);
  snprintf(filename, sizeof(filename) - 1, "%s/clientkeys/%s",
	   get_irssi_dir(), file);
  silc_free(fingerprint);

  if (stat(filename, &st) < 0)
    /* we don't have the public key cached ... use the one from the sig */
    ret = SILC_MSG_SIGNED_UNKNOWN;
  else {
    SilcPublicKey cached_pk=NULL;

    /* try to load the file */
    if (!silc_pkcs_load_public_key(filename, &cached_pk)) {
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_PUBKEY_COULD_NOT_LOAD, "client");
      if (pk == NULL)
	return SILC_MSG_SIGNED_UNKNOWN;
      else
	ret = SILC_MSG_SIGNED_UNKNOWN;
    }

    if (cached_pk) {
      if (pk)
        silc_pkcs_public_key_free(pk);
      pk = cached_pk;
    }
  }

  /* the public key is now in pk, our "level of trust" in ret */
  if ((pk) && silc_message_signed_verify(message, pk,
			  		 sha1hash) != SILC_AUTH_OK)
    ret = SILC_MSG_SIGNED_FAILED;

  if (pk)
    silc_pkcs_public_key_free(pk);

  return ret;
}

char *silc_unescape_data(const char *escaped_data, SilcUInt32 *length)
{
  char *data, *ptr;
  int i = 0, j = 0, len = strlen(escaped_data);

  data = silc_calloc(len, sizeof(char));

  while (i < len) {
    ptr = memchr(escaped_data + i, 1, len - i);
    if (ptr) {
      int inc = (ptr - escaped_data) - i;
      memcpy(data + j, escaped_data + i, inc);
      j += inc;
      i += inc + 2;
      data[j++] = *(ptr + 1) - 1;
    } else {
      memcpy(data + j, escaped_data + i, len - i);
      j += (len - i);
      break;
    }
  }

  *length = j;
  return data;
}

char *silc_escape_data(const char *data, SilcUInt32 len)
{
  char *escaped_data, *ptr, *ptr0, *ptr1;
  int i = 0, j = 0;

  escaped_data = silc_calloc(2 * len, sizeof(char));

  while (i < len) {
    ptr0 = memchr(data + i, 0, len - i);
    ptr1 = memchr(data + i, 1, len - i);

    ptr = (ptr0 < ptr1 ? (ptr0 ? ptr0 : ptr1) : (ptr1 ? ptr1 : ptr0));

    if (ptr) {
      int inc = (ptr - data) - i;
      if (inc)
	memcpy(escaped_data + j, data + i, inc);
      j += inc;
      i += inc;
      escaped_data[j++] = 1;
      escaped_data[j++] = *(data + i++) + 1;
    } else {
      memcpy(escaped_data + j, data + i, len - i);
      j += (len - i);
      break;
    }
  }

  return escaped_data;
}

void silc_emit_mime_sig(SILC_SERVER_REC *server, WI_ITEM_REC *item,
			const char *data, SilcUInt32 data_len,
			const char *nick, int verified)
{
  char *escaped_data;

  escaped_data = silc_escape_data(data, data_len);

  signal_emit("mime", 5, server, item, escaped_data, nick, verified);

  silc_free(escaped_data);
}


/* Message for a channel. The `sender' is the nickname of the sender
   received in the packet. The `channel_name' is the name of the channel. */

void silc_channel_message(SilcClient client, SilcClientConnection conn,
			  SilcClientEntry sender, SilcChannelEntry channel,
			  SilcMessagePayload payload,
			  SilcChannelPrivateKey key,
			  SilcMessageFlags flags, const unsigned char *message,
			  SilcUInt32 message_len)
{
  SILC_SERVER_REC *server;
  SILC_NICK_REC *nick;
  SILC_CHANNEL_REC *chanrec;
  int verified = 0;

  SILC_LOG_DEBUG(("Start"));

  if (!message)
    return;

  server = conn == NULL ? NULL : conn->context;
  chanrec = silc_channel_find_entry(server, channel);
  if (!chanrec)
    return;

  nick = silc_nicklist_find(chanrec, sender);
  if (!nick) {
    /* We didn't find client but it clearly exists, add it. */
    SilcChannelUser chu = silc_client_on_channel(channel, sender);
    if (chu)
      nick = silc_nicklist_insert(chanrec, chu, FALSE);
    if (!nick)
      return;
  }

  /* If the messages is digitally signed, verify it, if possible. */
  if (flags & SILC_MESSAGE_FLAG_SIGNED) {
    if (!settings_get_bool("ignore_message_signatures")) {
      verified = verify_message_signature(sender, payload);
    } else {
      flags &= ~SILC_MESSAGE_FLAG_SIGNED;
    }
  }

  if (flags & SILC_MESSAGE_FLAG_DATA) {
    silc_emit_mime_sig(server, (WI_ITEM_REC *)chanrec, message, message_len,
		       nick == NULL ? NULL : nick->nick,
		       flags & SILC_MESSAGE_FLAG_SIGNED ? verified : -1);
    message = NULL;
  }

  if (!message)
    return;

  if (flags & SILC_MESSAGE_FLAG_ACTION)
    if(flags & SILC_MESSAGE_FLAG_UTF8 && !silc_term_utf8()) {
      char tmp[256], *cp, *dm = NULL;
      memset(tmp, 0, sizeof(tmp));
      cp = tmp;
      if(message_len > sizeof(tmp) - 1) {
        dm = silc_calloc(message_len + 1, sizeof(*dm));
        cp = dm;
      }
      silc_utf8_decode(message, message_len, SILC_STRING_LOCALE,
                       cp, message_len);
      if (flags & SILC_MESSAGE_FLAG_SIGNED)
        signal_emit("message silc signed_action", 6, server, cp, nick->nick,
		    nick->host, channel->channel_name, verified);
      else
        signal_emit("message silc action", 5, server, cp, nick->nick,
		    nick->host, channel->channel_name);
      silc_free(dm);
    } else {
      if (flags & SILC_MESSAGE_FLAG_SIGNED)
        signal_emit("message silc signed_action", 6, server, message,
		    nick->nick, nick->host, channel->channel_name, verified);
      else
        signal_emit("message silc action", 5, server, message,
		    nick->nick, nick->host, channel->channel_name);
    }
  else if (flags & SILC_MESSAGE_FLAG_NOTICE)
    if(flags & SILC_MESSAGE_FLAG_UTF8 && !silc_term_utf8()) {
      char tmp[256], *cp, *dm = NULL;
      memset(tmp, 0, sizeof(tmp));
      cp = tmp;
      if(message_len > sizeof(tmp) - 1) {
        dm = silc_calloc(message_len + 1, sizeof(*dm));
        cp = dm;
      }
      silc_utf8_decode(message, message_len, SILC_STRING_LOCALE,
                       cp, message_len);
      if (flags & SILC_MESSAGE_FLAG_SIGNED)
	signal_emit("message silc signed_notice", 6, server, cp, nick->nick,
		nick->host, channel->channel_name, verified);
      else
	signal_emit("message silc notice", 5, server, cp, nick->nick,
		nick->host, channel->channel_name);
      silc_free(dm);
    } else {
      if (flags & SILC_MESSAGE_FLAG_SIGNED)
	signal_emit("message silc signed_notice", 6, server, message,
		nick->nick, nick->host, channel->channel_name, verified);
      else
	signal_emit("message silc notice", 5, server, message,
		nick->nick, nick->host, channel->channel_name);
    }
  else {
    if (flags & SILC_MESSAGE_FLAG_UTF8 && !silc_term_utf8()) {
      char tmp[256], *cp, *dm = NULL;

      memset(tmp, 0, sizeof(tmp));
      cp = tmp;
      if (message_len > sizeof(tmp) - 1) {
	dm = silc_calloc(message_len + 1, sizeof(*dm));
	cp = dm;
      }

      silc_utf8_decode(message, message_len, SILC_STRING_LOCALE,
		       cp, message_len);
      if (flags & SILC_MESSAGE_FLAG_SIGNED)
        signal_emit("message signed_public", 6, server, cp,
		    nick == NULL ? "[<unknown>]" : nick->nick,
		    nick == NULL ? "" : nick->host == NULL ? "" : nick->host,
		    chanrec->name, verified);
      else
        signal_emit("message public", 6, server, cp,
		    nick == NULL ? "[<unknown>]" : nick->nick,
		    nick == NULL ? "" : nick->host == NULL ? "" : nick->host,
		    chanrec->name, nick);
      silc_free(dm);
      return;
    }

    if (flags & SILC_MESSAGE_FLAG_SIGNED)
      signal_emit("message signed_public", 6, server, message,
		  nick == NULL ? "[<unknown>]" : nick->nick,
		  nick == NULL ? "" : nick->host == NULL ? "" : nick->host,
		  chanrec->name, verified);
    else
      signal_emit("message public", 6, server, message,
		  nick == NULL ? "[<unknown>]" : nick->nick,
		  nick == NULL ? "" : nick->host == NULL ? "" : nick->host,
		  chanrec->name, nick);
  }
}

/* Private message to the client. The `sender' is the nickname of the
   sender received in the packet. */

void silc_private_message(SilcClient client, SilcClientConnection conn,
			  SilcClientEntry sender, SilcMessagePayload payload,
			  SilcMessageFlags flags,
			  const unsigned char *message,
			  SilcUInt32 message_len)
{
  SILC_SERVER_REC *server;
  char userhost[256];
  int verified = 0;

  SILC_LOG_DEBUG(("Start"));

  server = conn == NULL ? NULL : conn->context;
  memset(userhost, 0, sizeof(userhost));
  if (sender->username[0])
    snprintf(userhost, sizeof(userhost) - 1, "%s@%s",
	     sender->username, sender->hostname);

  /* If the messages is digitally signed, verify it, if possible. */
  if (flags & SILC_MESSAGE_FLAG_SIGNED) {
    if (!settings_get_bool("ignore_message_signatures")) {
      verified = verify_message_signature(sender, payload);
    } else {
      flags &= ~SILC_MESSAGE_FLAG_SIGNED;
    }
  }

  if (flags & SILC_MESSAGE_FLAG_DATA) {
    silc_emit_mime_sig(server,
		sender->nickname[0] ?
		(WI_ITEM_REC *)query_find(SERVER(server), sender->nickname) :
		NULL,
		message, message_len,
      		sender->nickname[0] ? sender->nickname : "[<unknown>]",
		flags & SILC_MESSAGE_FLAG_SIGNED ? verified : -1);
    message = NULL;
  }

  if (!message)
    return;

  if (flags & SILC_MESSAGE_FLAG_ACTION)
    if(flags & SILC_MESSAGE_FLAG_UTF8 && !silc_term_utf8()) {
      char tmp[256], *cp, *dm = NULL;
      memset(tmp, 0, sizeof(tmp));
      cp = tmp;
      if(message_len > sizeof(tmp) - 1) {
        dm = silc_calloc(message_len + 1, sizeof(*dm));
        cp = dm;
      }
      silc_utf8_decode(message, message_len, SILC_STRING_LOCALE,
                       cp, message_len);
      if (flags & SILC_MESSAGE_FLAG_SIGNED)
        signal_emit("message silc signed_private_action", 6, server, cp,
		    sender->nickname[0] ? sender->nickname : "[<unknown>]",
		    sender->username[0] ? userhost : NULL,
		    NULL, verified);
      else
        signal_emit("message silc private_action", 5, server, cp,
		    sender->nickname[0] ? sender->nickname : "[<unknown>]",
		    sender->username[0] ? userhost : NULL, NULL);
      silc_free(dm);
    } else {
      if (flags & SILC_MESSAGE_FLAG_SIGNED)
        signal_emit("message silc signed_private_action", 6, server, message,
		    sender->nickname[0] ? sender->nickname : "[<unknown>]",
		    sender->username[0] ? userhost : NULL,
		    NULL, verified);
      else
        signal_emit("message silc private_action", 5, server, message,
		    sender->nickname[0] ? sender->nickname : "[<unknown>]",
		    sender->username[0] ? userhost : NULL, NULL);
    }
  else if (flags & SILC_MESSAGE_FLAG_NOTICE)
    if(flags & SILC_MESSAGE_FLAG_UTF8 && !silc_term_utf8()) {
      char tmp[256], *cp, *dm = NULL;
      memset(tmp, 0, sizeof(tmp));
      cp = tmp;
      if(message_len > sizeof(tmp) - 1) {
        dm = silc_calloc(message_len + 1, sizeof(*dm));
        cp = dm;
      }
      silc_utf8_decode(message, message_len, SILC_STRING_LOCALE,
                       cp, message_len);
      if (flags & SILC_MESSAGE_FLAG_SIGNED)
        signal_emit("message silc signed_private_notice", 6, server, cp,
		    sender->nickname[0] ? sender->nickname : "[<unknown>]",
		    sender->username[0] ? userhost : NULL,
		    NULL, verified);
      else
        signal_emit("message silc private_notice", 5, server, cp,
		    sender->nickname[0] ? sender->nickname : "[<unknown>]",
		    sender->username[0] ? userhost : NULL, NULL);
      silc_free(dm);
    } else {
      if (flags & SILC_MESSAGE_FLAG_SIGNED)
        signal_emit("message silc signed_private_notice", 6, server, message,
		    sender->nickname[0] ? sender->nickname : "[<unknown>]",
		    sender->username[0] ? userhost : NULL,
		    NULL, verified);
      else
        signal_emit("message silc private_notice", 5, server, message,
		    sender->nickname[0] ? sender->nickname : "[<unknown>]",
		    sender->username[0] ? userhost : NULL, NULL);
    }
  else {
    if (flags & SILC_MESSAGE_FLAG_UTF8 && !silc_term_utf8()) {
      char tmp[256], *cp, *dm = NULL;

      memset(tmp, 0, sizeof(tmp));
      cp = tmp;
      if (message_len > sizeof(tmp) - 1) {
        dm = silc_calloc(message_len + 1, sizeof(*dm));
        cp = dm;
      }

      silc_utf8_decode(message, message_len, SILC_STRING_LOCALE,
  		     cp, message_len);
      if (flags & SILC_MESSAGE_FLAG_SIGNED)
        signal_emit("message signed_private", 5, server, cp,
  		  sender->nickname[0] ? sender->nickname : "[<unknown>]",
  		  sender->username[0] ? userhost : NULL, verified);
      else
        signal_emit("message private", 4, server, cp,
  		  sender->nickname[0] ? sender->nickname : "[<unknown>]",
  		  sender->username[0] ? userhost : NULL);
      silc_free(dm);
      return;
    }

    if (flags & SILC_MESSAGE_FLAG_SIGNED)
      signal_emit("message signed_private", 5, server, message,
              sender->nickname[0] ? sender->nickname : "[<unknown>]",
              sender->username[0] ? userhost : NULL, verified);
    else
      signal_emit("message private", 4, server, message,
              sender->nickname[0] ? sender->nickname : "[<unknown>]",
              sender->username[0] ? userhost : NULL);
  }
}

/* Notify message to the client. The notify arguments are sent in the
   same order as servers sends them. The arguments are same as received
   from the server except for ID's.  If ID is received application receives
   the corresponding entry to the ID. For example, if Client ID is received
   application receives SilcClientEntry.  Also, if the notify type is
   for channel the channel entry is sent to application (even if server
   does not send it). */

void silc_notify(SilcClient client, SilcClientConnection conn,
		 SilcNotifyType type, ...)
{
  va_list va;
  SILC_SERVER_REC *server;
  SILC_CHANNEL_REC *chanrec;
  SILC_NICK_REC *nickrec;
  SilcClientEntry client_entry, client_entry2;
  SilcChannelEntry channel, channel2;
  SilcServerEntry server_entry;
  SilcIdType idtype;
  void *entry;
  SilcUInt32 mode;
  char buf[512];
  char *name, *tmp, *cipher, *hmac;
  GSList *list1, *list_tmp;
  SilcDList chpks, clients;

  SILC_LOG_DEBUG(("Start"));

  va_start(va, type);

  server = conn == NULL ? NULL : conn->context;

  switch(type) {
  case SILC_NOTIFY_TYPE_NONE:
    /* Some generic notice from server */
    printtext(server, NULL, MSGLEVEL_CRAP, "%s", (char *)va_arg(va, char *));
    break;

  case SILC_NOTIFY_TYPE_INVITE:
    /*
     * Invited or modified invite list.
     */

    SILC_LOG_DEBUG(("Notify: INVITE"));

    channel = va_arg(va, SilcChannelEntry);
    name = va_arg(va, char *);
    client_entry = va_arg(va, SilcClientEntry);

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf) - 1, "%s@%s",
	     client_entry->username, client_entry->hostname);
    signal_emit("message invite", 4, server, channel ? channel->channel_name :
		name, client_entry->nickname, buf);
    break;

  case SILC_NOTIFY_TYPE_JOIN:
    /*
     * Joined channel.
     */

    SILC_LOG_DEBUG(("Notify: JOIN"));

    client_entry = va_arg(va, SilcClientEntry);
    channel = va_arg(va, SilcChannelEntry);

    if (client_entry == server->conn->local_entry) {
      /* You joined to channel */
      chanrec = silc_channel_find(server, channel->channel_name);
      if (chanrec == NULL)
	chanrec = silc_channel_create(server, channel->channel_name,
					channel->channel_name, TRUE);
      if (!chanrec->joined)
	chanrec->entry = channel;
    } else {
      chanrec = silc_channel_find_entry(server, channel);
      if (chanrec != NULL) {
	SilcChannelUser chu = silc_client_on_channel(channel, client_entry);
	if (chu)
	  nickrec = silc_nicklist_insert(chanrec, chu, TRUE);
      }
    }

    memset(buf, 0, sizeof(buf));
    if (client_entry->username[0])
      snprintf(buf, sizeof(buf) - 1, "%s@%s",
	       client_entry->username, client_entry->hostname);
    signal_emit("message join", 4, server, channel->channel_name,
		client_entry->nickname,
		!client_entry->username[0] ? "" : buf);

    /* If there are multiple same nicknames on channel now, tell it to user. */
    if (client_entry != server->conn->local_entry) {
      char *nick, tmp[32];
      int count = 0;

      silc_client_nickname_parse(client, conn, client_entry->nickname, &nick);
      clients = silc_client_get_clients_local(client, conn, nick, TRUE);
      if (!clients || silc_dlist_count(clients) < 2) {
	silc_free(nick);
	silc_client_list_free(client, conn, clients);
	break;
      }
      silc_dlist_start(clients);
      while ((client_entry2 = silc_dlist_get(clients)))
	if (silc_client_on_channel(channel, client_entry2))
	  count++;
      if (count > 1) {
	silc_snprintf(tmp, sizeof(tmp), "%d", silc_dlist_count(clients));
	printformat_module("fe-common/silc", server, channel->channel_name,
			   MSGLEVEL_CRAP, SILCTXT_CHANNEL_MANY_NICKS,
			   tmp, nick);
	printformat_module("fe-common/silc", server, channel->channel_name,
			   MSGLEVEL_CRAP, SILCTXT_CHANNEL_USER_APPEARS,
			   buf, client_entry->nickname);
      }
      silc_client_list_free(client, conn, clients);
      silc_free(nick);
    }
    break;

  case SILC_NOTIFY_TYPE_LEAVE:
    /*
     * Left a channel.
     */

    SILC_LOG_DEBUG(("Notify: LEAVE"));

    client_entry = va_arg(va, SilcClientEntry);
    channel = va_arg(va, SilcChannelEntry);

    memset(buf, 0, sizeof(buf));
    if (client_entry->username)
      snprintf(buf, sizeof(buf) - 1, "%s@%s",
	       client_entry->username, client_entry->hostname);
    signal_emit("message part", 5, server, channel->channel_name,
	 	client_entry->nickname,  client_entry->username[0] ?
		buf : "", client_entry->nickname);

    chanrec = silc_channel_find_entry(server, channel);
    if (chanrec != NULL) {
      nickrec = silc_nicklist_find(chanrec, client_entry);
      if (nickrec != NULL)
	nicklist_remove(CHANNEL(chanrec), NICK(nickrec));
    }

    /* If there is only one client with this same nickname on channel now
       change it to the base format if it is formatted nickname. */
    if (channel) {
      silc_client_nickname_parse(client, conn, client_entry->nickname, &name);
      clients = silc_client_get_clients_local(client, conn, name, TRUE);
      if (!clients || silc_dlist_count(clients) != 2) {
	silc_free(name);
	silc_client_list_free(client, conn, clients);
	break;
      }
      silc_dlist_start(clients);
      client_entry2 = silc_dlist_get(clients);
      if (client_entry2 == client_entry)
        client_entry2 = silc_dlist_get(clients);
      if (silc_client_on_channel(channel, client_entry2)) {
	silc_snprintf(buf, sizeof(buf), "%s", client_entry2->nickname);
	silc_client_nickname_format(client, conn, client_entry2, TRUE);
	if (!silc_utf8_strcasecmp(buf, client_entry2->nickname))
	  printformat_module("fe-common/silc", server, channel->channel_name,
			     MSGLEVEL_CRAP, SILCTXT_CHANNEL_USER_APPEARS,
			     buf, client_entry2->nickname);
      }
      silc_client_list_free(client, conn, clients);
      silc_free(name);
    }
    break;

  case SILC_NOTIFY_TYPE_SIGNOFF:
    /*
     * Left the network.
     */

    SILC_LOG_DEBUG(("Notify: SIGNOFF"));

    client_entry = va_arg(va, SilcClientEntry);
    tmp = va_arg(va, char *);
    channel = va_arg(va, SilcChannelEntry);

    silc_server_free_ftp(server, client_entry);

    memset(buf, 0, sizeof(buf));
    if (client_entry->username)
      snprintf(buf, sizeof(buf) - 1, "%s@%s",
	       client_entry->username, client_entry->hostname);
    signal_emit("message quit", 4, server, client_entry->nickname,
		client_entry->username[0] ? buf : "", tmp ? tmp : "");

    list1 = nicklist_get_same_unique(SERVER(server), client_entry);
    for (list_tmp = list1; list_tmp != NULL; list_tmp =
	   list_tmp->next->next) {
      CHANNEL_REC *channel = list_tmp->data;
      NICK_REC *nickrec = list_tmp->next->data;

      nicklist_remove(channel, nickrec);
    }

    /* If there is only one client with this same nickname on channel now
       change it to the base format if it is formatted nickname. */
    if (channel) {
      silc_client_nickname_parse(client, conn, client_entry->nickname, &name);
      clients = silc_client_get_clients_local(client, conn, name, TRUE);
      if (!clients || silc_dlist_count(clients) != 2) {
	silc_free(name);
	silc_client_list_free(client, conn, clients);
	break;
      }
      silc_dlist_start(clients);
      client_entry2 = silc_dlist_get(clients);
      if (client_entry2 == client_entry)
        client_entry2 = silc_dlist_get(clients);
      if (silc_client_on_channel(channel, client_entry2)) {
	silc_snprintf(buf, sizeof(buf), "%s", client_entry2->nickname);
	silc_client_nickname_format(client, conn, client_entry2, TRUE);
	if (!silc_utf8_strcasecmp(buf, client_entry2->nickname))
	  printformat_module("fe-common/silc", server, channel->channel_name,
			     MSGLEVEL_CRAP, SILCTXT_CHANNEL_USER_APPEARS,
			     buf, client_entry2->nickname);
      }
      silc_client_list_free(client, conn, clients);
      silc_free(name);
    }
    break;

  case SILC_NOTIFY_TYPE_TOPIC_SET:
    /*
     * Changed topic.
     */

    SILC_LOG_DEBUG(("Notify: TOPIC_SET"));

    idtype = va_arg(va, int);
    entry = va_arg(va, void *);
    tmp = va_arg(va, char *);
    channel = va_arg(va, SilcChannelEntry);

    chanrec = silc_channel_find_entry(server, channel);
    if (chanrec != NULL) {
      char tmp2[256], *cp, *dm = NULL;

      g_free_not_null(chanrec->topic);
      if (tmp && !silc_term_utf8() && silc_utf8_valid(tmp, strlen(tmp))) {
	memset(tmp2, 0, sizeof(tmp2));
	cp = tmp2;
	if (strlen(tmp) > sizeof(tmp2) - 1) {
	  dm = silc_calloc(strlen(tmp) + 1, sizeof(*dm));
	  cp = dm;
	}

	silc_utf8_decode(tmp, strlen(tmp), SILC_STRING_LANGUAGE,
			 cp, strlen(tmp));
	tmp = cp;
      }

      chanrec->topic = *tmp == '\0' ? NULL : g_strdup(tmp);
      signal_emit("channel topic changed", 1, chanrec);

      silc_free(dm);
    }

    if (idtype == SILC_ID_CLIENT) {
      client_entry = (SilcClientEntry)entry;
      memset(buf, 0, sizeof(buf));
      snprintf(buf, sizeof(buf) - 1, "%s@%s",
	       client_entry->username, client_entry->hostname);
      signal_emit("message topic", 5, server, channel->channel_name,
		  tmp, client_entry->nickname, buf);
    } else if (idtype == SILC_ID_SERVER) {
      server_entry = (SilcServerEntry)entry;
      signal_emit("message topic", 5, server, channel->channel_name,
		  tmp, server_entry->server_name,
		  server_entry->server_name);
    } else if (idtype == SILC_ID_CHANNEL) {
      channel = (SilcChannelEntry)entry;
      signal_emit("message topic", 5, server, channel->channel_name,
		  tmp, channel->channel_name, channel->channel_name);
    }
    break;

  case SILC_NOTIFY_TYPE_NICK_CHANGE:
    /*
     * Changed nickname.
     */

    SILC_LOG_DEBUG(("Notify: NICK_CHANGE"));

    client_entry = va_arg(va, SilcClientEntry);
    name = va_arg(va, char *);	               /* old nickname */

    if (!strcmp(client_entry->nickname, name))
      break;

    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf) - 1, "%s@%s",
	     client_entry->username, client_entry->hostname);
    nicklist_rename_unique(SERVER(server),
			   client_entry, name,
			   client_entry, client_entry->nickname);
    signal_emit("message nick", 4, server, client_entry->nickname, name, buf);
    break;

  case SILC_NOTIFY_TYPE_CMODE_CHANGE:
    /*
     * Changed channel mode.
     */

    SILC_LOG_DEBUG(("Notify: CMODE_CHANGE"));

    idtype = va_arg(va, int);
    entry = va_arg(va, void *);
    mode = va_arg(va, SilcUInt32);
    cipher = va_arg(va, char *);               /* cipher */
    hmac = va_arg(va, char *);		       /* hmac */
    (void)va_arg(va, char *);		       /* passphrase */
    (void)va_arg(va, SilcPublicKey);	       /* founder key */
    chpks = va_arg(va, SilcDList);	       /* channel public keys */
    channel = va_arg(va, SilcChannelEntry);

    tmp = silc_client_chmode(mode, cipher ? cipher : "",
			     hmac ? hmac : "");

    chanrec = silc_channel_find_entry(server, channel);
    if (chanrec != NULL) {
      g_free_not_null(chanrec->mode);
      chanrec->mode = g_strdup(tmp == NULL ? "" : tmp);
      signal_emit("channel mode changed", 1, chanrec);
    }

    if (idtype == SILC_ID_CLIENT) {
      client_entry = (SilcClientEntry)entry;
      printformat_module("fe-common/silc", server, channel->channel_name,
			 MSGLEVEL_MODES, SILCTXT_CHANNEL_CMODE,
			 channel->channel_name, tmp ? tmp : "removed all",
			 client_entry->nickname);
    } else if (idtype == SILC_ID_SERVER) {
      server_entry = (SilcServerEntry)entry;
      printformat_module("fe-common/silc", server, channel->channel_name,
			 MSGLEVEL_MODES, SILCTXT_CHANNEL_CMODE,
			 channel->channel_name, tmp ? tmp : "removed all",
			 server_entry->server_name);
    } else if (idtype == SILC_ID_CHANNEL) {
      channel2 = (SilcChannelEntry)entry;
      printformat_module("fe-common/silc", server, channel->channel_name,
			 MSGLEVEL_MODES, SILCTXT_CHANNEL_CMODE,
			 channel->channel_name, tmp ? tmp : "removed all",
			 channel2->channel_name);
    }

    /* Print the channel public key list */
    if (chpks)
      silc_parse_channel_public_keys(server, channel, chpks);

    silc_free(tmp);
    break;

  case SILC_NOTIFY_TYPE_CUMODE_CHANGE:
    /*
     * Changed user's mode on channel.
     */

    SILC_LOG_DEBUG(("Notify: CUMODE_CHANGE"));

    idtype = va_arg(va, int);
    entry = va_arg(va, void *);
    mode = va_arg(va, SilcUInt32);
    client_entry2 = va_arg(va, SilcClientEntry);
    channel = va_arg(va, SilcChannelEntry);

    tmp = silc_client_chumode(mode);
    chanrec = silc_channel_find_entry(server, channel);
    if (chanrec != NULL) {
      SILC_NICK_REC *nick;

      if (client_entry2 == server->conn->local_entry)
	chanrec->chanop = (mode & SILC_CHANNEL_UMODE_CHANOP) != 0;

      nick = silc_nicklist_find(chanrec, client_entry2);
      if (nick != NULL) {
	nick->op = (mode & SILC_CHANNEL_UMODE_CHANOP) != 0;
	nick->founder = (mode & SILC_CHANNEL_UMODE_CHANFO) != 0;
	signal_emit("nick mode changed", 2, chanrec, nick);
      }
    }

    if (idtype == SILC_ID_CLIENT) {
      client_entry = (SilcClientEntry)entry;
      printformat_module("fe-common/silc", server, channel->channel_name,
			 MSGLEVEL_MODES, SILCTXT_CHANNEL_CUMODE,
			 channel->channel_name, client_entry2->nickname,
			 tmp ? tmp : "removed all",
			 client_entry->nickname);
    } else if (idtype == SILC_ID_SERVER) {
      server_entry = (SilcServerEntry)entry;
      printformat_module("fe-common/silc", server, channel->channel_name,
			 MSGLEVEL_MODES, SILCTXT_CHANNEL_CUMODE,
			 channel->channel_name, client_entry2->nickname,
			 tmp ? tmp : "removed all",
			 server_entry->server_name);
    } else if (idtype == SILC_ID_CHANNEL) {
      channel2 = (SilcChannelEntry)entry;
      printformat_module("fe-common/silc", server, channel->channel_name,
			 MSGLEVEL_MODES, SILCTXT_CHANNEL_CUMODE,
			 channel->channel_name, client_entry2->nickname,
			 tmp ? tmp : "removed all",
			 channel2->channel_name);
    }

    if (mode & SILC_CHANNEL_UMODE_CHANFO)
      printformat_module("fe-common/silc",
			 server, channel->channel_name, MSGLEVEL_CRAP,
			 SILCTXT_CHANNEL_FOUNDER,
			 channel->channel_name, client_entry2->nickname);

    if (mode & SILC_CHANNEL_UMODE_QUIET && conn->local_entry == client_entry2)
      printformat_module("fe-common/silc",
			 server, channel->channel_name, MSGLEVEL_CRAP,
			 SILCTXT_CHANNEL_QUIETED, channel->channel_name);

    silc_free(tmp);
    break;

  case SILC_NOTIFY_TYPE_MOTD:
    /*
     * Received MOTD.
     */

    SILC_LOG_DEBUG(("Notify: MOTD"));

    tmp = va_arg(va, char *);

    if (!settings_get_bool("skip_motd"))
      printtext_multiline(server, NULL, MSGLEVEL_CRAP, "%s", tmp);
    break;

  case SILC_NOTIFY_TYPE_KICKED:
    /*
     * Someone was kicked from channel.
     */

    SILC_LOG_DEBUG(("Notify: KICKED"));

    client_entry = va_arg(va, SilcClientEntry);
    tmp = va_arg(va, char *);
    client_entry2 = va_arg(va, SilcClientEntry);
    channel = va_arg(va, SilcChannelEntry);

    chanrec = silc_channel_find_entry(server, channel);

    if (client_entry == conn->local_entry) {
      printformat_module("fe-common/silc", server, channel->channel_name,
			 MSGLEVEL_CRAP, SILCTXT_CHANNEL_KICKED_YOU,
			 channel->channel_name,
			 client_entry ? client_entry2->nickname : "",
			 tmp ? tmp : "");
      if (chanrec) {
	chanrec->kicked = TRUE;
	channel_destroy((CHANNEL_REC *)chanrec);
      }
    } else {
      printformat_module("fe-common/silc", server, channel->channel_name,
			 MSGLEVEL_CRAP, SILCTXT_CHANNEL_KICKED,
			 client_entry->nickname, channel->channel_name,
			 client_entry2 ? client_entry2->nickname : "",
			 tmp ? tmp : "");

      if (chanrec) {
	SILC_NICK_REC *nickrec = silc_nicklist_find(chanrec, client_entry);
	if (nickrec != NULL)
	  nicklist_remove(CHANNEL(chanrec), NICK(nickrec));
      }
    }
    break;

  case SILC_NOTIFY_TYPE_KILLED:
    /*
     * Someone was killed from the network.
     */

    SILC_LOG_DEBUG(("Notify: KILLED"));

    client_entry = va_arg(va, SilcClientEntry);
    tmp = va_arg(va, char *);
    idtype = va_arg(va, int);
    entry = va_arg(va, SilcClientEntry);

    if (client_entry == conn->local_entry) {
      if (idtype == SILC_ID_CLIENT) {
	client_entry2 = (SilcClientEntry)entry;
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_CHANNEL_KILLED_YOU,
			   client_entry2 ? client_entry2->nickname : "",
			   tmp ? tmp : "");
      } else if (idtype == SILC_ID_SERVER) {
	server_entry = (SilcServerEntry)entry;
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_CHANNEL_KILLED_YOU,
			   server_entry->server_name, tmp ? tmp : "");
      } else if (idtype == SILC_ID_CHANNEL) {
	channel = (SilcChannelEntry)entry;
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_CHANNEL_KILLED_YOU,
			   channel->channel_name, tmp ? tmp : "");
      }
    } else {
      list1 = nicklist_get_same_unique(SERVER(server), client_entry);
      for (list_tmp = list1; list_tmp != NULL; list_tmp =
	     list_tmp->next->next) {
	CHANNEL_REC *channel = list_tmp->data;
	NICK_REC *nickrec = list_tmp->next->data;
	nicklist_remove(channel, nickrec);
      }

      if (idtype == SILC_ID_CLIENT) {
	client_entry2 = (SilcClientEntry)entry;
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_CHANNEL_KILLED,
			   client_entry->nickname,
			   client_entry2 ? client_entry2->nickname : "",
			   tmp ? tmp : "");
      } else if (idtype == SILC_ID_SERVER) {
	server_entry = (SilcServerEntry)entry;
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_CHANNEL_KILLED,
			   client_entry->nickname,
			   server_entry->server_name, tmp ? tmp : "");
      } else if (idtype == SILC_ID_CHANNEL) {
	channel = (SilcChannelEntry)entry;
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_CHANNEL_KILLED,
			   client_entry->nickname,
			   channel->channel_name, tmp ? tmp : "");
      }
    }
    break;

  case SILC_NOTIFY_TYPE_CHANNEL_CHANGE:
    break;

  case SILC_NOTIFY_TYPE_SERVER_SIGNOFF:
    {
      /*
       * Server has quit the network.
       */
      SilcDList clients;

      SILC_LOG_DEBUG(("Notify: SERVER_SIGNOFF"));

      (void)va_arg(va, void *);
      clients = va_arg(va, SilcDList);

      silc_dlist_start(clients);
      while ((client_entry = silc_dlist_get(clients))) {
	memset(buf, 0, sizeof(buf));

	/* Print only if we have the nickname.  If this client has just quit
	   when we were only resolving it, it is possible we don't have the
	   nickname. */
	if (client_entry->nickname[0]) {
	  if (client_entry->username[0])
	    snprintf(buf, sizeof(buf) - 1, "%s@%s",
		     client_entry->username, client_entry->hostname);
	  signal_emit("message quit", 4, server, client_entry->nickname,
		      client_entry->username[0] ? buf : "",
		      "server signoff");
	}

	silc_server_free_ftp(server, client_entry);

	list1 = nicklist_get_same_unique(SERVER(server), client_entry);
	for (list_tmp = list1; list_tmp != NULL; list_tmp =
	       list_tmp->next->next) {
	  CHANNEL_REC *channel = list_tmp->data;
	  NICK_REC *nickrec = list_tmp->next->data;
	  nicklist_remove(channel, nickrec);
	}
      }
    }
    break;

  case SILC_NOTIFY_TYPE_ERROR:
    {
      SilcStatus error = va_arg(va, int);

      silc_say(client, conn, SILC_CLIENT_MESSAGE_ERROR,
		"%s", silc_get_status_message(error));
    }
    break;

  case SILC_NOTIFY_TYPE_WATCH:
    {
      SilcNotifyType notify;

      client_entry = va_arg(va, SilcClientEntry);
      name = va_arg(va, char *);          /* Maybe NULL */
      mode = va_arg(va, SilcUInt32);
      notify = va_arg(va, int);

      if (notify == SILC_NOTIFY_TYPE_NICK_CHANGE) {
	if (name)
	  printformat_module("fe-common/silc", server, NULL,
			     MSGLEVEL_CRAP, SILCTXT_WATCH_NICK_CHANGE,
			     client_entry->nickname, name);
	else
	  printformat_module("fe-common/silc", server, NULL,
			     MSGLEVEL_CRAP, SILCTXT_WATCH_PRESENT,
			     client_entry->nickname);
      } else if (notify == SILC_NOTIFY_TYPE_UMODE_CHANGE) {
	/* See if client was away and is now present */
	if (!(mode & (SILC_UMODE_GONE | SILC_UMODE_INDISPOSED |
		      SILC_UMODE_BUSY | SILC_UMODE_PAGE |
		      SILC_UMODE_DETACHED)) &&
	    (client_entry->mode & SILC_UMODE_GONE ||
	     client_entry->mode & SILC_UMODE_INDISPOSED ||
	     client_entry->mode & SILC_UMODE_BUSY ||
	     client_entry->mode & SILC_UMODE_PAGE ||
	     client_entry->mode & SILC_UMODE_DETACHED)) {
	  printformat_module("fe-common/silc", server, NULL,
			     MSGLEVEL_CRAP, SILCTXT_WATCH_PRESENT,
			     client_entry->nickname);
	}

	if (mode) {
	  memset(buf, 0, sizeof(buf));
	  silc_get_umode_string(mode, buf, sizeof(buf) - 1);
	  printformat_module("fe-common/silc", server, NULL,
			     MSGLEVEL_CRAP, SILCTXT_WATCH_UMODE_CHANGE,
			     client_entry->nickname, buf);
	}
      } else if (notify == SILC_NOTIFY_TYPE_KILLED) {
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_WATCH_KILLED,
			   client_entry->nickname);
      } else if (notify == SILC_NOTIFY_TYPE_SIGNOFF ||
		 notify == SILC_NOTIFY_TYPE_SERVER_SIGNOFF) {
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_WATCH_SIGNOFF,
			   client_entry->nickname);
      } else if (notify == SILC_NOTIFY_TYPE_NONE) {
	/* Client logged in to the network */
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_WATCH_PRESENT,
			   client_entry->nickname);
      }
    }
    break;

  default:
    /* Unknown notify */
    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_UNKNOWN_NOTIFY, type);
    break;
  }

  va_end(va);
}

/* Command handler. This function is called always in the command function.
   If error occurs it will be called as well. `conn' is the associated
   client connection. `cmd_context' is the command context that was
   originally sent to the command. `success' is FALSE if error occured
   during command. `command' is the command being processed. It must be
   noted that this is not reply from server. This is merely called just
   after application has called the command. Just to tell application
   that the command really was processed. */

static SilcBool cmode_list_chpks = FALSE;

void silc_command(SilcClient client, SilcClientConnection conn,
		  SilcBool success, SilcCommand command, SilcStatus status,
		  SilcUInt32 argc, unsigned char **argv)
{
  SILC_SERVER_REC *server = conn->context;

  SILC_LOG_DEBUG(("Start"));

  if (!success) {
    silc_say_error("%s", silc_get_status_message(status));
    return;
  }

  switch (command) {

  case SILC_COMMAND_INVITE:
    if (argc > 2)
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_CHANNEL_INVITING,
			 argv[2],
			 (argv[1][0] == '*' ?
			  (char *)conn->current_channel->channel_name :
			  (char *)argv[1]));
    break;

  case SILC_COMMAND_DETACH:
    server->no_reconnect = TRUE;
    break;

  case SILC_COMMAND_CMODE:
    if (argc == 3 && !strcmp(argv[2], "+C"))
      cmode_list_chpks = TRUE;
    else
      cmode_list_chpks = FALSE;
    break;

  default:
    break;
  }
}

typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  void *entry;
  SilcIdType id_type;
} *GetkeyContext;

void silc_getkey_cb(bool success, void *context)
{
  GetkeyContext getkey = (GetkeyContext)context;
  char *entity = (getkey->id_type == SILC_ID_CLIENT ? "user" : "server");
  char *name = (getkey->id_type == SILC_ID_CLIENT ?
		((SilcClientEntry)getkey->entry)->nickname :
		((SilcServerEntry)getkey->entry)->server_name);
  SilcPublicKey public_key = (getkey->id_type == SILC_ID_CLIENT ?
			      ((SilcClientEntry)getkey->entry)->public_key :
			      ((SilcServerEntry)getkey->entry)->public_key);
  SilcSILCPublicKey silc_pubkey;

  silc_pubkey = silc_pkcs_get_context(SILC_PKCS_SILC, public_key);

  if (success) {
    if (getkey->id_type == SILC_ID_CLIENT)
      printformat_module("fe-common/silc", NULL, NULL,
			 MSGLEVEL_CRAP, SILCTXT_PUBKEY_VERIFIED_CLIENT,
			 name,
			 silc_pubkey->identifier.realname ?
			 silc_pubkey->identifier.realname : "",
			 silc_pubkey->identifier.email ?
			 silc_pubkey->identifier.email : "");
    else
      printformat_module("fe-common/silc", NULL, NULL,
			 MSGLEVEL_CRAP, SILCTXT_PUBKEY_VERIFIED,
			 entity, name);
  } else {
    printformat_module("fe-common/silc", NULL, NULL,
		       MSGLEVEL_CRAP, SILCTXT_PUBKEY_NOTVERIFIED,
		       entity, name);
  }

  silc_free(getkey);
}

/* Parse an invite or ban list */
void silc_parse_inviteban_list(SilcClient client,
			       SilcClientConnection conn,
			       SILC_SERVER_REC *server,
			       SilcChannelEntry channel,
			       const char *list_type,
			       SilcArgumentPayload list)
{
  unsigned char *tmp;
  SilcUInt32 type, len;
  SILC_CHANNEL_REC *chanrec = silc_channel_find_entry(server, channel);
  int counter=0, resolving = FALSE;

  if (!silc_argument_get_arg_num(list)) {
    printformat_module("fe-common/silc", server,
		       (chanrec ? chanrec->visible_name : NULL),
		       MSGLEVEL_CRAP, SILCTXT_CHANNEL_NO_INVITEBAN_LIST,
		       channel->channel_name, list_type);
    return;
  }

  printformat_module("fe-common/silc", server,
		     (chanrec ? chanrec->visible_name : NULL),
		     MSGLEVEL_CRAP, SILCTXT_CHANNEL_INVITEBAN_LIST,
		     channel->channel_name, list_type);

  /* Parse the list */
  tmp = silc_argument_get_first_arg(list, &type, &len);
  while (tmp) {
    switch (type) {
      case 1:
	{
	  /* An invite string */
	  char **list;
	  int i=0;

	  if (tmp[len-1] == ',')
	    tmp[len-1] = '\0';

	  list = g_strsplit(tmp, ",", -1);
	  while (list[i])
	    printformat_module("fe-common/silc", server,
			       (chanrec ? chanrec->visible_name : NULL),
			       MSGLEVEL_CRAP, SILCTXT_CHANNEL_INVITEBAN_STRING,
			       ++counter, channel->channel_name, list_type,
			       list[i++]);
	  g_strfreev(list);
	}
	break;

      case 2:
	{
	  /* A public key */
	  char *fingerprint, *babbleprint;

	  /* tmp is Public Key Payload, take public key from it. */
	  fingerprint = silc_hash_fingerprint(NULL, tmp + 4, len - 4);
	  babbleprint = silc_hash_babbleprint(NULL, tmp + 4, len - 4);

	  printformat_module("fe-common/silc", server,
			     (chanrec ? chanrec->visible_name : NULL),
			     MSGLEVEL_CRAP, SILCTXT_CHANNEL_INVITEBAN_PUBKEY,
			     ++counter, channel->channel_name, list_type,
			     fingerprint, babbleprint);
	}
	break;

      case 3:
	{
	  /* A Client ID */
	  SilcClientEntry client_entry;
	  SilcID id;

	  if (!silc_id_payload_parse_id(tmp, len, &id)) {
	    silc_say_error("Invalid data in %s list encountered", list_type);
	    break;
	  }

	  client_entry = silc_client_get_client_by_id(client, conn,
						      &id.u.client_id);
	  if (client_entry) {
	    printformat_module("fe-common/silc", server,
			       (chanrec ? chanrec->visible_name : NULL),
			       MSGLEVEL_CRAP, SILCTXT_CHANNEL_INVITEBAN_STRING,
			       ++counter, channel->channel_name, list_type,
			       client_entry->nickname);
	    silc_client_unref_client(client, conn, client_entry);
	  } else {
	    resolving = TRUE;
	    silc_client_get_client_by_id_resolve(client, conn, &id.u.client_id,
						 NULL, NULL, NULL);
	  }
	}
	break;

      default:
	/* "trash" */
	silc_say_error("Unkown type in %s list: %u (len %u)",
		       list_type, type, len);
	break;
    }
    tmp = silc_argument_get_next_arg(list, &type, &len);
  }

  if (resolving)
    printformat_module("fe-common/silc", server,
		       (chanrec ? chanrec->visible_name : NULL),
		       MSGLEVEL_CRAP, SILCTXT_CHANNEL_INVITEBAN_REGET,
		       list_type, channel->channel_name);
}

/* Command reply handler. This function is called always in the command reply
   function. If error occurs it will be called as well. Normal scenario
   is that it will be called after the received command data has been parsed
   and processed. The function is used to pass the received command data to
   the application.

   `conn' is the associated client connection. `cmd_payload' is the command
   payload data received from server and it can be ignored. It is provided
   if the application would like to re-parse the received command data,
   however, it must be noted that the data is parsed already by the library
   thus the payload can be ignored. `success' is FALSE if error occured.
   In this case arguments are not sent to the application. `command' is the
   command reply being processed. The function has variable argument list
   and each command defines the number and type of arguments it passes to the
   application (on error they are not sent). */

void silc_command_reply(SilcClient client, SilcClientConnection conn,
			SilcCommand command, SilcStatus status,
			SilcStatus error, va_list vp)
{
  SILC_SERVER_REC *server = conn->context;
  SILC_CHANNEL_REC *chanrec;

  SILC_LOG_DEBUG(("Start"));

  switch(command) {
  case SILC_COMMAND_WHOIS:
    {
      char buf[1024], *nickname, *username, *realname, *nick;
      unsigned char *fingerprint;
      SilcUInt32 idle, mode, *user_modes;
      SilcDList channels;
      SilcClientEntry client_entry;
      SilcDList attrs;

      if (status == SILC_STATUS_ERR_NO_SUCH_NICK) {
	/* Print the unknown nick for user */
	char *tmp = va_arg(vp, char *);
	if (tmp)
	  silc_say_error("%s: %s", tmp, silc_get_status_message(status));
	break;
      } else if (status == SILC_STATUS_ERR_NO_SUCH_CLIENT_ID) {
	/* Try to find the entry for the unknown client ID, since we
	   might have, and print the nickname of it for user. */
	SilcClientID *id = va_arg(vp, SilcClientID *);
	if (id) {
	  client_entry = silc_client_get_client_by_id(client, conn, id);
	  if (client_entry && client_entry->nickname[0])
	    silc_say_error("%s: %s", client_entry->nickname,
			   silc_get_status_message(status));
	  silc_client_unref_client(client, conn, client_entry);
	}
	break;
      } else if (SILC_STATUS_IS_ERROR(status)) {
	silc_say_error("WHOIS: %s", silc_get_status_message(status));
	return;
      }

      client_entry = va_arg(vp, SilcClientEntry);
      nickname = va_arg(vp, char *);
      username = va_arg(vp, char *);
      realname = va_arg(vp, char *);
      channels = va_arg(vp, SilcDList);
      mode = va_arg(vp, SilcUInt32);
      idle = va_arg(vp, SilcUInt32);
      fingerprint = va_arg(vp, unsigned char *);
      user_modes = va_arg(vp, SilcUInt32 *);
      attrs = va_arg(vp, SilcDList);

      silc_client_nickname_parse(client, conn, client_entry->nickname, &nick);
      printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			 SILCTXT_WHOIS_USERINFO, nickname,
			 client_entry->username, client_entry->hostname,
			 nick, client_entry->nickname);
      printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			 SILCTXT_WHOIS_REALNAME, realname);
      silc_free(nick);

      if (channels && user_modes) {
	SilcChannelPayload entry;
	int i = 0;

	memset(buf, 0, sizeof(buf));
	silc_dlist_start(channels);
	while ((entry = silc_dlist_get(channels))) {
	  SilcUInt32 name_len;
	  char *m = silc_client_chumode_char(user_modes[i++]);
	  char *name = silc_channel_get_name(entry, &name_len);

	  if (m)
	    silc_strncat(buf, sizeof(buf) - 1, m, strlen(m));
	  silc_strncat(buf, sizeof(buf) - 1, name, name_len);
	  silc_strncat(buf, sizeof(buf) - 1, " ", 1);
	  silc_free(m);
	}

	printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			   SILCTXT_WHOIS_CHANNELS, buf);
      }

      if (mode) {
	memset(buf, 0, sizeof(buf));
	silc_get_umode_string(mode, buf, sizeof(buf - 1));
	printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			   SILCTXT_WHOIS_MODES, buf);
      }

      if (idle && nickname) {
	memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf) - 1, "%lu %s",
		 idle > 60 ? (idle / 60) : idle,
		 idle > 60 ? "minutes" : "seconds");

	printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			   SILCTXT_WHOIS_IDLE, buf);
      }

      if (fingerprint) {
	fingerprint = silc_fingerprint(fingerprint, 20);
	printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			   SILCTXT_WHOIS_FINGERPRINT, fingerprint);
	silc_free(fingerprint);
      }

      if (attrs)
	silc_query_attributes_print(server, silc_client, conn, attrs,
				    client_entry);
    }
    break;

  case SILC_COMMAND_WHOWAS:
    {
      char *nickname, *username, *realname;

      if (status == SILC_STATUS_ERR_NO_SUCH_NICK) {
	char *tmp = va_arg(vp, char *);
	if (tmp)
	  silc_say_error("%s: %s", tmp,
			 silc_get_status_message(status));
	break;
      } else if (SILC_STATUS_IS_ERROR(status)) {
	silc_say_error("WHOWAS: %s", silc_get_status_message(status));
	return;
      }

      (void)va_arg(vp, SilcClientEntry);
      nickname = va_arg(vp, char *);
      username = va_arg(vp, char *);
      realname = va_arg(vp, char *);

      printformat_module("fe-common/silc", server, NULL, MSGLEVEL_CRAP,
			 SILCTXT_WHOWAS_USERINFO, nickname, username,
			 realname ? realname : "");
    }
    break;

  case SILC_COMMAND_INVITE:
    {
      SilcChannelEntry channel;
      SilcArgumentPayload invite_list;

      if (SILC_STATUS_IS_ERROR(status))
	return;

      channel = va_arg(vp, SilcChannelEntry);
      invite_list = va_arg(vp, SilcArgumentPayload);

      if (invite_list)
	silc_parse_inviteban_list(client, conn, server, channel,
				  "invite", invite_list);
    }
    break;

  case SILC_COMMAND_JOIN:
    {
      char *channel, *mode, *topic, *cipher, *hmac;
      SilcUInt32 modei;
      SilcHashTableList *user_list;
      SilcChannelEntry channel_entry;
      SilcChannelUser chu;
      SilcClientEntry founder = NULL;
      NICK_REC *ownnick;

      if (SILC_STATUS_IS_ERROR(status)) {
	silc_say_error("JOIN: %s", silc_get_status_message(status));
	return;
      }

      channel = va_arg(vp, char *);
      channel_entry = va_arg(vp, SilcChannelEntry);
      modei = va_arg(vp, SilcUInt32);
      user_list = va_arg(vp, SilcHashTableList *);
      topic = va_arg(vp, char *);
      cipher = va_arg(vp, char *);
      hmac = va_arg(vp, char *);

      chanrec = silc_channel_find(server, channel);
      if (!chanrec)
	chanrec = silc_channel_create(server, channel, channel, TRUE);

      if (topic) {
	char tmp[256], *cp, *dm = NULL;
	g_free_not_null(chanrec->topic);

	if (!silc_term_utf8() && silc_utf8_valid(topic, strlen(topic))) {
	  memset(tmp, 0, sizeof(tmp));
	  cp = tmp;
	  if (strlen(topic) > sizeof(tmp) - 1) {
	    dm = silc_calloc(strlen(topic) + 1, sizeof(*dm));
	    cp = dm;
	  }

	  silc_utf8_decode(topic, strlen(topic), SILC_STRING_LOCALE,
			   cp, strlen(topic));
	  topic = cp;
	}

	chanrec->topic = *topic == '\0' ? NULL : g_strdup(topic);
	signal_emit("channel topic changed", 1, chanrec);

	silc_free(dm);
      }

      mode = silc_client_chmode(modei, cipher ? cipher : "", hmac ? hmac : "");
      g_free_not_null(chanrec->mode);
      chanrec->mode = g_strdup(mode == NULL ? "" : mode);
      signal_emit("channel mode changed", 1, chanrec);

      /* Get user list */
      while (silc_hash_table_get(user_list, NULL, (void *)&chu)) {
	if (!chu->client->nickname[0])
	  continue;
	if (chu->mode & SILC_CHANNEL_UMODE_CHANFO)
	  founder = chu->client;
	silc_nicklist_insert(chanrec, chu, FALSE);
      }

      ownnick = NICK(silc_nicklist_find(chanrec, conn->local_entry));
      if (!ownnick)
	break;
      nicklist_set_own(CHANNEL(chanrec), ownnick);
      signal_emit("channel joined", 1, chanrec);
      chanrec->entry = channel_entry;

      if (chanrec->topic)
	printformat_module("fe-common/silc", server,
			   channel_entry->channel_name,
			   MSGLEVEL_CRAP, SILCTXT_CHANNEL_TOPIC,
			   channel_entry->channel_name, chanrec->topic);

      if (founder) {
	if (founder == conn->local_entry) {
	  printformat_module("fe-common/silc",
			     server, channel_entry->channel_name,
			     MSGLEVEL_CRAP, SILCTXT_CHANNEL_FOUNDER_YOU,
			     channel_entry->channel_name);
	  signal_emit("nick mode changed", 2, chanrec, ownnick);
	} else
	  printformat_module("fe-common/silc",
			     server, channel_entry->channel_name,
			     MSGLEVEL_CRAP, SILCTXT_CHANNEL_FOUNDER,
			     channel_entry->channel_name, founder->nickname);
      }

      break;
    }

  case SILC_COMMAND_NICK:
    {
      char *old;
      SilcClientEntry client_entry = va_arg(vp, SilcClientEntry);
      GSList *nicks;

      if (SILC_STATUS_IS_ERROR(status)) {
	silc_say_error("NICK: %s", silc_get_status_message(status));
	return;
      }

      nicks = nicklist_get_same(SERVER(server), client_entry->nickname);
      if ((nicks != NULL) &&
	  (strcmp(SERVER(server)->nick, client_entry->nickname))) {
	char buf[512];
	SilcClientEntry collider, old;

	old = ((SILC_NICK_REC *)(nicks->next->data))->silc_user->client;
	collider = silc_client_get_client_by_id(client, conn, &old->id);
	if (collider != client_entry) {
	  memset(buf, 0, sizeof(buf));
	  snprintf(buf, sizeof(buf) - 1, "%s@%s",
		   collider->username, collider->hostname);
	  nicklist_rename_unique(SERVER(server),
				 old, old->nickname,
				 collider, collider->nickname);
	  silc_print_nick_change(server, collider->nickname,
				 client_entry->nickname, buf);
	}
	silc_client_unref_client(client, conn, collider);
      }

      if (nicks != NULL)
	g_slist_free(nicks);

      old = g_strdup(server->nick);
      server_change_nick(SERVER(server), client_entry->nickname);
      nicklist_rename_unique(SERVER(server),
			     server->conn->local_entry, server->nick,
			     client_entry, client_entry->nickname);
      signal_emit("message own_nick", 4, server, server->nick, old, "");
      g_free(old);

      /* when connecting to a server, the last thing we receive
         is a SILC_COMMAND_LIST reply. Since we enable queueing
	 during the connection, we can now safely disable it again */
      silc_queue_disable(conn);
      break;
    }

  case SILC_COMMAND_LIST:
    {
      char *topic, *name;
      int usercount;
      char users[20];
      char tmp[256], *cp, *dm = NULL;

      if (SILC_STATUS_IS_ERROR(status))
	return;

      (void)va_arg(vp, SilcChannelEntry);
      name = va_arg(vp, char *);
      topic = va_arg(vp, char *);
      usercount = va_arg(vp, int);

      if (topic && !silc_term_utf8() &&
	  silc_utf8_valid(topic, strlen(topic))) {
	memset(tmp, 0, sizeof(tmp));
	cp = tmp;
	if (strlen(topic) > sizeof(tmp) - 1) {
	  dm = silc_calloc(strlen(topic) + 1, sizeof(*dm));
	  cp = dm;
	}

	silc_utf8_decode(topic, strlen(topic), SILC_STRING_LOCALE,
			 cp, strlen(topic));
	topic = cp;
      }

      if (status == SILC_STATUS_LIST_START ||
	  status == SILC_STATUS_OK)
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_LIST_HEADER);

      if (!usercount)
	snprintf(users, sizeof(users) - 1, "N/A");
      else
	snprintf(users, sizeof(users) - 1, "%d", usercount);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_LIST,
			 name, users, topic ? topic : "");
      silc_free(dm);
    }
    break;

  case SILC_COMMAND_UMODE:
    {
      SilcUInt32 mode;
      char *reason;

      if (SILC_STATUS_IS_ERROR(status))
	return;

      mode = va_arg(vp, SilcUInt32);

      if (mode & SILC_UMODE_SERVER_OPERATOR &&
	  !(server->umode & SILC_UMODE_SERVER_OPERATOR))
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_SERVER_OPER);

      if (mode & SILC_UMODE_ROUTER_OPERATOR &&
	  !(server->umode & SILC_UMODE_ROUTER_OPERATOR))
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_ROUTER_OPER);

      if ((mode & SILC_UMODE_GONE) != (server->umode & SILC_UMODE_GONE)) {
	if (mode & SILC_UMODE_GONE) {
	  if ((server->away_reason != NULL) && (server->away_reason[0] != '\0'))
	    reason = g_strdup(server->away_reason);
	  else
	    reason = g_strdup("away");
	} else
	  reason = g_strdup("");

	silc_set_away(reason, server);

	g_free(reason);
      }

      server->umode = mode;
      signal_emit("user mode changed", 2, server, NULL);
    }
    break;

  case SILC_COMMAND_OPER:
    if (SILC_STATUS_IS_ERROR(status)) {
      silc_say_error("OPER: %s", silc_get_status_message(status));
      return;
    }

    server->umode |= SILC_UMODE_SERVER_OPERATOR;
    signal_emit("user mode changed", 2, server, NULL);

    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_SERVER_OPER);
    break;

  case SILC_COMMAND_SILCOPER:
    if (SILC_STATUS_IS_ERROR(status)) {
      silc_say_error("SILCOPER: %s", silc_get_status_message(status));
      return;
    }

    server->umode |= SILC_UMODE_ROUTER_OPERATOR;
    signal_emit("user mode changed", 2, server, NULL);

    printformat_module("fe-common/silc", server, NULL,
		       MSGLEVEL_CRAP, SILCTXT_ROUTER_OPER);
    break;

  case SILC_COMMAND_USERS:
    {
      SilcHashTableList htl;
      SilcChannelEntry channel;
      SilcChannelUser chu;

      if (SILC_STATUS_IS_ERROR(status)) {
	silc_say_error("USERS: %s", silc_get_status_message(status));
	return;
      }

      channel = va_arg(vp, SilcChannelEntry);

      printformat_module("fe-common/silc", server, channel->channel_name,
			 MSGLEVEL_CRAP, SILCTXT_USERS_HEADER,
			 channel->channel_name);

      silc_hash_table_list(channel->user_list, &htl);
      while (silc_hash_table_get(&htl, NULL, (void *)&chu)) {
	SilcClientEntry e = chu->client;
	char stat[5], *mode;

	if (!e->nickname[0])
	  continue;

	memset(stat, 0, sizeof(stat));
	mode = silc_client_chumode_char(chu->mode);
	if (e->mode & SILC_UMODE_GONE)
	  strcat(stat, "G");
	else if (e->mode & SILC_UMODE_INDISPOSED)
	  strcat(stat, "I");
	else if (e->mode & SILC_UMODE_BUSY)
	  strcat(stat, "B");
	else if (e->mode & SILC_UMODE_PAGE)
	  strcat(stat, "P");
	else if (e->mode & SILC_UMODE_HYPER)
	  strcat(stat, "H");
	else if (e->mode & SILC_UMODE_ROBOT)
	  strcat(stat, "R");
	else if (e->mode & SILC_UMODE_ANONYMOUS)
	  strcat(stat, "?");
	else
	  strcat(stat, "A");
	if (mode)
	  strcat(stat, mode);

	printformat_module("fe-common/silc", server, channel->channel_name,
			   MSGLEVEL_CRAP, SILCTXT_USERS,
			   e->nickname, stat,
			   e->username[0] ? e->username : "",
			   e->hostname[0] ? e->hostname : "",
			   e->realname ? e->realname : "");
	if (mode)
	  silc_free(mode);
      }
      silc_hash_table_list_reset(&htl);
    }
    break;

  case SILC_COMMAND_BAN:
    {
      SilcChannelEntry channel;
      SilcArgumentPayload invite_list;

      if (SILC_STATUS_IS_ERROR(status))
	return;

      channel = va_arg(vp, SilcChannelEntry);
      invite_list = va_arg(vp, SilcArgumentPayload);

      if (invite_list)
	silc_parse_inviteban_list(client, conn, server, channel,
				  "ban", invite_list);
    }
    break;

  case SILC_COMMAND_GETKEY:
    {
      SilcIdType id_type;
      void *entry;
      SilcPublicKey public_key;
      GetkeyContext getkey;
      char *name;

      if (SILC_STATUS_IS_ERROR(status)) {
	silc_say_error("GETKEY: %s", silc_get_status_message(status));
	return;
      }

      id_type = va_arg(vp, SilcUInt32);
      entry = va_arg(vp, void *);
      public_key = va_arg(vp, SilcPublicKey);

      if (public_key) {
	getkey = silc_calloc(1, sizeof(*getkey));
	getkey->entry = entry;
	getkey->id_type = id_type;
	getkey->client = client;
	getkey->conn = conn;

	name = (id_type == SILC_ID_CLIENT ?
		((SilcClientEntry)entry)->nickname :
		((SilcServerEntry)entry)->server_name);

	silc_verify_public_key_internal(client, conn, name,
					(id_type == SILC_ID_CLIENT ?
					 SILC_CONN_CLIENT :
					 SILC_CONN_SERVER),
					public_key, silc_getkey_cb, getkey);
      } else {
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_PUBKEY_NOKEY);
      }
    }
    break;

  case SILC_COMMAND_INFO:
    {
      SilcServerEntry server_entry;
      char *server_name;
      char *server_info;

      if (SILC_STATUS_IS_ERROR(status))
	return;

      server_entry = va_arg(vp, SilcServerEntry);
      server_name = va_arg(vp, char *);
      server_info = va_arg(vp, char *);

      if (server_name && server_info )
	{
	  printtext(server, NULL, MSGLEVEL_CRAP, "Server: %s", server_name);
	  printtext(server, NULL, MSGLEVEL_CRAP, "%s", server_info);
	}
    }
    break;

  case SILC_COMMAND_TOPIC:
    {
      SilcChannelEntry channel;
      char *topic;
      char tmp[256], *cp, *dm = NULL;

      if (SILC_STATUS_IS_ERROR(status))
	return;

      channel = va_arg(vp, SilcChannelEntry);
      topic = va_arg(vp, char *);

      if (topic && !silc_term_utf8() &&
	  silc_utf8_valid(topic, strlen(topic))) {
	memset(tmp, 0, sizeof(tmp));
	cp = tmp;
	if (strlen(topic) > sizeof(tmp) - 1) {
	  dm = silc_calloc(strlen(topic) + 1, sizeof(*dm));
	  cp = dm;
	}

	silc_utf8_decode(topic, strlen(topic), SILC_STRING_LOCALE,
			 cp, strlen(topic));
	topic = cp;
      }

      if (topic) {
	chanrec = silc_channel_find_entry(server, channel);
	if (chanrec) {
	  g_free_not_null(chanrec->topic);
	  chanrec->topic = *topic == '\0' ? NULL : g_strdup(topic);
	  signal_emit("channel topic changed", 1, chanrec);
	}
	printformat_module("fe-common/silc", server, channel->channel_name,
			   MSGLEVEL_CRAP, SILCTXT_CHANNEL_TOPIC,
			   channel->channel_name, topic);
      } else {
	printformat_module("fe-common/silc", server, channel->channel_name,
			   MSGLEVEL_CRAP, SILCTXT_CHANNEL_TOPIC_NOT_SET,
			   channel->channel_name);
      }
      silc_free(dm);
    }
    break;

  case SILC_COMMAND_WATCH:
    break;

  case SILC_COMMAND_STATS:
    {
      SilcClientStats *cstats;
      char tmp[40];
      const char *tmptime;
      int days, hours, mins, secs;

      if (SILC_STATUS_IS_ERROR(status))
	return;

      cstats = va_arg(vp, SilcClientStats *);
      if (!cstats) {
	printtext(server, NULL, MSGLEVEL_CRAP, "No statistics available");
	return;
      }

      tmptime = silc_time_string(cstats->starttime);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_STATS,
			 "Local server start time", tmptime);

      days = cstats->uptime / (24 * 60 * 60);
      cstats->uptime -= days * (24 * 60 * 60);
      hours = cstats->uptime / (60 * 60);
      cstats->uptime -= hours * (60 * 60);
      mins = cstats->uptime / 60;
      cstats->uptime -= mins * 60;
      secs = cstats->uptime;
      snprintf(tmp, sizeof(tmp) - 1, "%d days %d hours %d mins %d secs",
	       days, hours, mins, secs);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_STATS,
			 "Local server uptime", tmp);

      snprintf(tmp, sizeof(tmp) - 1, "%d", (int)cstats->my_clients);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_STATS,
			 "Local server clients", tmp);

      snprintf(tmp, sizeof(tmp) - 1, "%d", (int)cstats->my_channels);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_STATS,
			 "Local server channels", tmp);

      snprintf(tmp, sizeof(tmp) - 1, "%d", (int)cstats->my_server_ops);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_STATS,
			 "Local server operators", tmp);

      snprintf(tmp, sizeof(tmp) - 1, "%d", (int)cstats->my_router_ops);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_STATS,
			 "Local router operators", tmp);

      snprintf(tmp, sizeof(tmp) - 1, "%d", (int)cstats->cell_clients);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_STATS,
			 "Local cell clients", tmp);

      snprintf(tmp, sizeof(tmp) - 1, "%d", (int)cstats->cell_channels);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_STATS,
			 "Local cell channels", tmp);

      snprintf(tmp, sizeof(tmp) - 1, "%d", (int)cstats->cell_servers);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_STATS,
			 "Local cell servers", tmp);

      snprintf(tmp, sizeof(tmp) - 1, "%d", (int)cstats->clients);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_STATS,
			 "Total clients", tmp);

      snprintf(tmp, sizeof(tmp) - 1, "%d", (int)cstats->channels);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_STATS,
			 "Total channels", tmp);

      snprintf(tmp, sizeof(tmp) - 1, "%d", (int)cstats->servers);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_STATS,
			 "Total servers", tmp);

      snprintf(tmp, sizeof(tmp) - 1, "%d", (int)cstats->routers);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_STATS,
			 "Total routers", tmp);

      snprintf(tmp, sizeof(tmp) - 1, "%d", (int)cstats->server_ops);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_STATS,
			   "Total server operators", tmp);

      snprintf(tmp, sizeof(tmp) - 1, "%d", (int)cstats->router_ops);
      printformat_module("fe-common/silc", server, NULL,
			 MSGLEVEL_CRAP, SILCTXT_STATS,
			 "Total router operators", tmp);
    }
    break;

  case SILC_COMMAND_CMODE:
    {
      SilcChannelEntry channel_entry;
      SilcDList chpks;

      channel_entry = va_arg(vp, SilcChannelEntry);
      (void)va_arg(vp, SilcUInt32);
      (void)va_arg(vp, SilcPublicKey);
      chpks = va_arg(vp, SilcDList);

      if (SILC_STATUS_IS_ERROR(status) || !cmode_list_chpks ||
	  !channel_entry || !channel_entry->channel_name)
	return;

      /* Print the channel public key list */
      if (chpks)
        silc_parse_channel_public_keys(server, channel_entry, chpks);
      else
        printformat_module("fe-common/silc", server, NULL,
                         MSGLEVEL_CRAP, SILCTXT_CHANNEL_PK_NO_LIST,
                         channel_entry->channel_name);

    }
    break;

  case SILC_COMMAND_LEAVE:
    {
      if (SILC_STATUS_IS_ERROR(status))
	return;

      /* We might be cycling, so disable queueing again */
      silc_queue_disable(conn);
    }
    break;

  case SILC_COMMAND_DETACH:
    {
      /* Save the detachment data to file. */
      char *file;
      SilcBuffer detach;

      if (SILC_STATUS_IS_ERROR(status))
	return;

      detach = va_arg(vp, SilcBuffer);
      file = silc_get_session_filename(server);
      silc_file_writefile(file, silc_buffer_data(detach),
			  silc_buffer_len(detach));
      silc_free(file);
    }
    break;

  case SILC_COMMAND_KILL:
    {
      SilcClientEntry client_entry;

      if (SILC_STATUS_IS_ERROR(status)) {
	silc_say_error("KILL: %s", silc_get_status_message(status));
	return;
      }

      client_entry = va_arg(vp, SilcClientEntry);
      if (!client_entry || !client_entry->nickname[0])
	break;

      /* Print this only if the killed client isn't joined on channels.
	 If it is, we receive KILLED notify and we'll print this there. */
      if (!silc_hash_table_count(client_entry->channels))
	printformat_module("fe-common/silc", server, NULL,
			   MSGLEVEL_CRAP, SILCTXT_CHANNEL_KILLED,
			   client_entry->nickname,
			   conn->local_entry->nickname, "");
    }
  }
}

typedef struct {
  SilcClient client;
  SilcClientConnection conn;
  char *filename;
  char *entity;
  char *entity_name;
  SilcPublicKey public_key;
  SilcVerifyPublicKey completion;
  void *context;
} *PublicKeyVerify;

static void verify_public_key_completion(const char *line, void *context)
{
  PublicKeyVerify verify = (PublicKeyVerify)context;

  if (line[0] == 'Y' || line[0] == 'y') {
    /* Call the completion */
    if (verify->completion)
      verify->completion(TRUE, verify->context);

    /* Save the key for future checking */
    silc_pkcs_save_public_key(verify->filename, verify->public_key,
			      SILC_PKCS_FILE_BASE64);
  } else {
    /* Call the completion */
    if (verify->completion)
      verify->completion(FALSE, verify->context);

    printformat_module("fe-common/silc", NULL, NULL,
		       MSGLEVEL_CRAP, SILCTXT_PUBKEY_DISCARD,
		       verify->entity_name ? verify->entity_name :
		       verify->entity);
  }

  silc_free(verify->filename);
  silc_free(verify->entity);
  silc_free(verify->entity_name);
  silc_free(verify);
}

/* Internal routine to verify public key. If the `completion' is provided
   it will be called to indicate whether public was verified or not. For
   server/router public key this will check for filename that includes the
   remote host's IP address and remote host's hostname. */

static void
silc_verify_public_key_internal(SilcClient client, SilcClientConnection conn,
				const char *name,
				SilcConnectionType conn_type,
				SilcPublicKey public_key,
				SilcVerifyPublicKey completion, void *context)
{
  PublicKeyVerify verify;
  char file[256], filename[256], filename2[256], *ipf, *hostf = NULL;
  char *fingerprint, *babbleprint, *format;
  SilcPublicKey local_pubkey;
  SilcSILCPublicKey silc_pubkey;
  SilcUInt16 port;
  const char *hostname, *ip;
  unsigned char *pk;
  SilcUInt32 pk_len;
  struct passwd *pw;
  struct stat st;
  char *entity = ((conn_type == SILC_CONN_SERVER ||
		   conn_type == SILC_CONN_ROUTER) ?
		  "server" : "client");
  int i;

  if (silc_pkcs_get_type(public_key) != SILC_PKCS_SILC) {
    printformat_module("fe-common/silc", NULL, NULL,
		       MSGLEVEL_CRAP, SILCTXT_PUBKEY_UNSUPPORTED,
		       entity, silc_pkcs_get_type(public_key));
    if (completion)
      completion(FALSE, context);
    return;
  }

  /* Encode public key */
  pk = silc_pkcs_public_key_encode(public_key, &pk_len);
  if (!pk) {
    if (completion)
      completion(FALSE, context);
    return;
  }

  silc_pubkey = silc_pkcs_get_context(SILC_PKCS_SILC, public_key);

  pw = getpwuid(getuid());
  if (!pw) {
    if (completion)
      completion(FALSE, context);
    silc_free(pk);
    return;
  }

  memset(filename, 0, sizeof(filename));
  memset(filename2, 0, sizeof(filename2));
  memset(file, 0, sizeof(file));

  /* Get remote host information */
  silc_socket_stream_get_info(silc_packet_stream_get_stream(conn->stream),
			      NULL, &hostname, &ip, &port);

  if (conn_type == SILC_CONN_SERVER ||
      conn_type == SILC_CONN_ROUTER) {
    if (!name) {
      snprintf(file, sizeof(file) - 1, "%skey_%s_%d.pub", entity, ip, port);
      snprintf(filename, sizeof(filename) - 1, "%s/%skeys/%s",
	       get_irssi_dir(), entity, file);

      snprintf(file, sizeof(file) - 1, "%skey_%s_%d.pub", entity,
	       hostname, port);
      snprintf(filename2, sizeof(filename2) - 1, "%s/%skeys/%s",
	       get_irssi_dir(), entity, file);

      ipf = filename;
      hostf = filename2;
    } else {
      snprintf(file, sizeof(file) - 1, "%skey_%s_%d.pub", entity,
	       name, port);
      snprintf(filename, sizeof(filename) - 1, "%s/%skeys/%s",
	       get_irssi_dir(), entity, file);

      ipf = filename;
    }
  } else {
    /* Replace all whitespaces with `_'. */
    fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
    for (i = 0; i < strlen(fingerprint); i++)
      if (fingerprint[i] == ' ')
	fingerprint[i] = '_';

    snprintf(file, sizeof(file) - 1, "%skey_%s.pub", entity, fingerprint);
    snprintf(filename, sizeof(filename) - 1, "%s/%skeys/%s",
	     get_irssi_dir(), entity, file);
    silc_free(fingerprint);

    ipf = filename;
  }

  /* Take fingerprint of the public key */
  fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
  babbleprint = silc_hash_babbleprint(NULL, pk, pk_len);

  verify = silc_calloc(1, sizeof(*verify));
  verify->client = client;
  verify->conn = conn;
  verify->filename = strdup(ipf);
  verify->entity = strdup(entity);
  verify->entity_name = (conn_type != SILC_CONN_CLIENT ?
			 (name ? strdup(name) : strdup(hostname))
			 : NULL);
  verify->public_key = public_key;
  verify->completion = completion;
  verify->context = context;

  /* Check whether this key already exists */
  if (stat(ipf, &st) < 0 && (!hostf || stat(hostf, &st) < 0)) {
    /* Key does not exist, ask user to verify the key and save it */

    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
		       SILCTXT_PUBKEY_RECEIVED,verify->entity_name ?
		       verify->entity_name : entity);
    if (conn_type == SILC_CONN_CLIENT && name &&
	silc_pubkey->identifier.realname)
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_PUBKEY_RECEIVED_CLIENT, name,
			 silc_pubkey->identifier.realname,
			 silc_pubkey->identifier.email ?
			 silc_pubkey->identifier.email : "");
    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
		       SILCTXT_PUBKEY_FINGERPRINT, entity, fingerprint);
    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
		       SILCTXT_PUBKEY_BABBLEPRINT, babbleprint);
    format = format_get_text("fe-common/silc", NULL, NULL, NULL,
			     SILCTXT_PUBKEY_ACCEPT);
    keyboard_entry_redirect((SIGNAL_FUNC)verify_public_key_completion,
			    format, 0, verify);
    g_free(format);
    silc_free(fingerprint);
    silc_free(babbleprint);
    silc_free(pk);
    return;
  } else {
    /* The key already exists, verify it. */
    unsigned char *encpk;
    SilcUInt32 encpk_len;

    /* Load the key file, try for both IP filename and hostname filename */
    if (!silc_pkcs_load_public_key(ipf, &local_pubkey) &&
	(!hostf || (!silc_pkcs_load_public_key(hostf, &local_pubkey)))) {
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_PUBKEY_RECEIVED,verify->entity_name ?
			 verify->entity_name : entity);
      if (conn_type == SILC_CONN_CLIENT && name &&
	  silc_pubkey->identifier.realname)
	printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			   SILCTXT_PUBKEY_RECEIVED_CLIENT, name,
			   silc_pubkey->identifier.realname,
			   silc_pubkey->identifier.email ?
			   silc_pubkey->identifier.email : "");
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_PUBKEY_FINGERPRINT, entity, fingerprint);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_PUBKEY_BABBLEPRINT, babbleprint);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_PUBKEY_COULD_NOT_LOAD, entity);
      format = format_get_text("fe-common/silc", NULL, NULL, NULL,
			       SILCTXT_PUBKEY_ACCEPT_ANYWAY);
      keyboard_entry_redirect((SIGNAL_FUNC)verify_public_key_completion,
			      format, 0, verify);
      g_free(format);
      silc_free(fingerprint);
      silc_free(babbleprint);
      silc_free(pk);
      return;
    }

    /* Encode the key data */
    encpk = silc_pkcs_public_key_encode(local_pubkey, &encpk_len);
    if (!encpk) {
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_PUBKEY_RECEIVED,verify->entity_name ?
			 verify->entity_name : entity);
      if (conn_type == SILC_CONN_CLIENT && name &&
	  silc_pubkey->identifier.realname)
	printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			   SILCTXT_PUBKEY_RECEIVED_CLIENT, name,
			   silc_pubkey->identifier.realname,
			   silc_pubkey->identifier.email ?
			   silc_pubkey->identifier.email : "");
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_PUBKEY_FINGERPRINT, entity, fingerprint);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_PUBKEY_BABBLEPRINT, babbleprint);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_PUBKEY_MALFORMED, entity);
      format = format_get_text("fe-common/silc", NULL, NULL, NULL,
			       SILCTXT_PUBKEY_ACCEPT_ANYWAY);
      keyboard_entry_redirect((SIGNAL_FUNC)verify_public_key_completion,
			      format, 0, verify);
      g_free(format);
      silc_free(fingerprint);
      silc_free(babbleprint);
      silc_free(pk);
      return;
    }
    silc_pkcs_public_key_free(local_pubkey);

    /* Compare the keys */
    if (memcmp(encpk, pk, encpk_len)) {
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_PUBKEY_RECEIVED,verify->entity_name ?
			 verify->entity_name : entity);
      if (conn_type == SILC_CONN_CLIENT && name &&
	  silc_pubkey->identifier.realname)
	printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			   SILCTXT_PUBKEY_RECEIVED_CLIENT, name,
			   silc_pubkey->identifier.realname,
			   silc_pubkey->identifier.email ?
			   silc_pubkey->identifier.email : "");
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_PUBKEY_FINGERPRINT, entity, fingerprint);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_PUBKEY_BABBLEPRINT, babbleprint);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_PUBKEY_NO_MATCH, entity);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_PUBKEY_MAYBE_EXPIRED, entity);
      printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
			 SILCTXT_PUBKEY_MITM_ATTACK, entity);

      /* Ask user to verify the key and save it */
      format = format_get_text("fe-common/silc", NULL, NULL, NULL,
			       SILCTXT_PUBKEY_ACCEPT_ANYWAY);
      keyboard_entry_redirect((SIGNAL_FUNC)verify_public_key_completion,
			      format, 0, verify);
      g_free(format);
      silc_free(fingerprint);
      silc_free(babbleprint);
      silc_free(encpk);
      silc_free(pk);
      return;
    }

    /* Local copy matched */
    if (completion)
      completion(TRUE, context);
    silc_free(encpk);
    silc_free(fingerprint);
    silc_free(babbleprint);
    silc_free(verify->filename);
    silc_free(verify->entity);
    silc_free(verify->entity_name);
    silc_free(verify);
    silc_free(pk);
  }
}

/* Verifies received public key. The `conn_type' indicates which entity
   (server, client etc.) has sent the public key. If user decides to trust
   the key may be saved as trusted public key for later use. The
   `completion' must be called after the public key has been verified. */

void
silc_verify_public_key(SilcClient client, SilcClientConnection conn,
		       SilcConnectionType conn_type,
	 	       SilcPublicKey public_key,
		       SilcVerifyPublicKey completion, void *context)
{
  silc_verify_public_key_internal(client, conn, NULL, conn_type, public_key,
				  completion, context);
}

/* Asks passphrase from user on the input line. */

typedef struct {
  SilcAskPassphrase completion;
  void *context;
} *AskPassphrase;

void ask_passphrase_completion(const char *passphrase, void *context)
{
  AskPassphrase p = (AskPassphrase)context;
  if (passphrase && passphrase[0] == '\0')
    passphrase = NULL;
  p->completion((unsigned char *)passphrase,
		passphrase ? strlen(passphrase) : 0, p->context);
  silc_free(p);
}

void silc_ask_passphrase(SilcClient client, SilcClientConnection conn,
			 SilcAskPassphrase completion, void *context)
{
  AskPassphrase p = silc_calloc(1, sizeof(*p));
  p->completion = completion;
  p->context = context;

  keyboard_entry_redirect((SIGNAL_FUNC)ask_passphrase_completion,
			  "Passphrase: ", ENTRY_REDIRECT_FLAG_HIDDEN, p);
}

typedef struct {
  SilcGetAuthMeth completion;
  void *context;
} *GetAuthMethod;

static void silc_get_auth_ask_passphrase(unsigned char *passphrase,
					 SilcUInt32 passphrase_len,
					 void *context)
{
  GetAuthMethod a = context;
  a->completion(passphrase ? SILC_AUTH_PASSWORD : SILC_AUTH_NONE,
		passphrase, passphrase_len, a->context);
  silc_free(a);
}

/* Find authentication data by hostname and port. The hostname may be IP
   address as well.*/

void silc_get_auth_method(SilcClient client, SilcClientConnection conn,
			  char *hostname, SilcUInt16 port,
			  SilcAuthMethod auth_meth,
			  SilcGetAuthMeth completion, void *context)
{
  SERVER_SETUP_REC *setup;

  SILC_LOG_DEBUG(("Start"));

  if (auth_meth == SILC_AUTH_PUBLIC_KEY) {
    /* Returning NULL will cause library to use our private key configured
       for this connection */
    completion(SILC_AUTH_PUBLIC_KEY, NULL, 0, context);
    return;
  }

  /* Check whether we find the password for this server in our
     configuration.  If it's set, always send it server. */
  setup = server_setup_find_port(hostname, port);
  if (setup && setup->password) {
    completion(SILC_AUTH_PASSWORD, setup->password, strlen(setup->password),
	       context);
    return;
  }

  /* Didn't find password.  If server wants it, ask it from user. */
  if (auth_meth == SILC_AUTH_PASSWORD) {
    GetAuthMethod a;
    a = silc_calloc(1, sizeof(*a));
    if (a) {
      a->completion = completion;
      a->context = context;
      silc_ask_passphrase(client, conn, silc_get_auth_ask_passphrase, a);
      return;
    }
  }

  /* No authentication */
  completion(SILC_AUTH_NONE, NULL, 0, context);
}

/* Asks whether the user would like to perform the key agreement protocol.
   This is called after we have received an key agreement packet or an
   reply to our key agreement packet. This returns TRUE if the user wants
   the library to perform the key agreement protocol and FALSE if it is not
   desired (application may start it later by calling the function
   silc_client_perform_key_agreement). */

void silc_key_agreement(SilcClient client, SilcClientConnection conn,
		        SilcClientEntry client_entry, const char *hostname,
		        SilcUInt16 protocol, SilcUInt16 port)
{
  char portstr[12], protostr[5];

  SILC_LOG_DEBUG(("Start"));

  /* We will just display the info on the screen and return FALSE and user
     will have to start the key agreement with a command. */

  if (hostname) {
    snprintf(portstr, sizeof(portstr) - 1, "%d", port);
    snprintf(protostr, sizeof(protostr) - 1, "%s", protocol == 1 ? "UDP" :
	     "TCP");
  }

  if (!hostname)
    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
		       SILCTXT_KEY_AGREEMENT_REQUEST, client_entry->nickname);
  else
    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
		       SILCTXT_KEY_AGREEMENT_REQUEST_HOST,
		       client_entry->nickname, hostname, portstr, protostr);
}

/* Notifies application that file transfer protocol session is being
   requested by the remote client indicated by the `client_entry' from
   the `hostname' and `port'. The `session_id' is the file transfer
   session and it can be used to either accept or reject the file
   transfer request, by calling the silc_client_file_receive or
   silc_client_file_close, respectively. */

void silc_ftp(SilcClient client, SilcClientConnection conn,
	      SilcClientEntry client_entry, SilcUInt32 session_id,
	      const char *hostname, SilcUInt16 port)
{
  SILC_SERVER_REC *server;
  char portstr[12];
  FtpSession ftp = NULL;

  SILC_LOG_DEBUG(("Start"));

  server = conn->context;

  silc_dlist_start(server->ftp_sessions);
  while ((ftp = silc_dlist_get(server->ftp_sessions)) != SILC_LIST_END) {
    if (ftp->client_entry == client_entry &&
	ftp->session_id == session_id) {
      server->current_session = ftp;
      break;
    }
  }
  if (ftp == SILC_LIST_END) {
    ftp = silc_calloc(1, sizeof(*ftp));
    ftp->client_entry = client_entry;
    ftp->session_id = session_id;
    ftp->send = FALSE;
    ftp->conn = conn;
    silc_dlist_add(server->ftp_sessions, ftp);
    server->current_session = ftp;
  }

  if (hostname)
    snprintf(portstr, sizeof(portstr) - 1, "%d", port);

  if (!hostname)
    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
		       SILCTXT_FILE_REQUEST, client_entry->nickname);
  else
    printformat_module("fe-common/silc", NULL, NULL, MSGLEVEL_CRAP,
		       SILCTXT_FILE_REQUEST_HOST,
		       client_entry->nickname, hostname, portstr);
}

/* SILC client operations */
SilcClientOperations ops = {
  silc_say,
  silc_channel_message,
  silc_private_message,
  silc_notify,
  silc_command,
  silc_command_reply,
  silc_get_auth_method,
  silc_verify_public_key,
  silc_ask_passphrase,
  silc_key_agreement,
  silc_ftp,
};
