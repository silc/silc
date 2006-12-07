/*

  client_notify.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silc.h"
#include "silcclient.h"
#include "client_internal.h"

/************************** Types and definitions ***************************/

#define NOTIFY conn->client->internal->ops->notify

/* Notify processing context */
typedef struct {
  SilcPacket packet;
  SilcNotifyPayload payload;
  SilcFSMThread fsm;
  SilcChannelEntry channel;
} *SilcClientNotify;

/************************ Static utility functions **************************/

/* Entry resolving callback.  This will continue processing the notify. */

static void silc_client_notify_resolved(SilcClient client,
					SilcClientConnection conn,
					SilcStatus status,
					SilcDList entries,
					void *context)
{
  SilcClientNotify notify = context;

  /* If no entries found, just finish the notify processing, a silent error */
  if (!entries)
    silc_fsm_next(notify->fsm, silc_client_notify_processed);

  if (notify->channel) {
    notify->channel->internal.resolve_cmd_ident = 0;
    silc_client_unref_channel(client, conn, notify->channel);
  }

  /* Continue processing the notify */
  SILC_FSM_CALL_CONTINUE_SYNC(notify->fsm);
}

/* Continue notify processing after it was suspended while waiting for
   channel information being resolved. */

static SilcBool silc_client_notify_wait_continue(SilcClient client,
						 SilcClientConnection conn,
						 SilcCommand command,
						 SilcStatus status,
						 SilcStatus error,
						 void *context,
						 va_list ap)
{
  SilcClientNotify notify = context;

  /* Continue after last command reply received */
  if (SILC_STATUS_IS_ERROR(status) || status == SILC_STATUS_OK ||
      status == SILC_STATUS_LIST_END)
    SILC_FSM_CALL_CONTINUE(notify->fsm);

  return TRUE;
}

/********************************* Notify ***********************************/

/* Process received notify packet */

SILC_FSM_STATE(silc_client_notify)
{
  SilcPacket packet = state_context;
  SilcClientNotify notify;
  SilcNotifyPayload payload;

  payload = silc_notify_payload_parse(silc_buffer_data(&packet->buffer),
				      silc_buffer_len(&packet->buffer));
  if (!payload) {
    SILC_LOG_DEBUG(("Malformed notify payload"));
    silc_packet_free(packet);
    return SILC_FSM_FINISH;
  }

  if (!silc_notify_get_args(payload)) {
    SILC_LOG_DEBUG(("Malformed notify"));
    silc_notify_payload_free(payload);
    silc_packet_free(packet);
    return SILC_FSM_FINISH;
  }

  notify = silc_calloc(1, sizeof(*notify));
  if (!notify) {
    silc_notify_payload_free(payload);
    silc_packet_free(packet);
    return SILC_FSM_FINISH;
  }

  /* Save notify payload to packet context during processing */
  notify->packet = packet;
  notify->payload = payload;
  notify->fsm = fsm;
  silc_fsm_set_state_context(fsm, notify);

  /* Process the notify */
  switch (silc_notify_get_type(payload)) {

  case SILC_NOTIFY_TYPE_NONE:
    /** NONE */
    silc_fsm_next(fsm, silc_client_notify_none);
    break;

  case SILC_NOTIFY_TYPE_INVITE:
    /** INVITE */
    silc_fsm_next(fsm, silc_client_notify_invite);
    break;

  case SILC_NOTIFY_TYPE_JOIN:
    /** JOIN */
    silc_fsm_next(fsm, silc_client_notify_join);
    break;

  case SILC_NOTIFY_TYPE_LEAVE:
    /** LEAVE */
    silc_fsm_next(fsm, silc_client_notify_leave);
    break;

  case SILC_NOTIFY_TYPE_SIGNOFF:
    /** SIGNOFF */
    silc_fsm_next(fsm, silc_client_notify_signoff);
    break;

  case SILC_NOTIFY_TYPE_TOPIC_SET:
    /** TOPIC_SET */
    silc_fsm_next(fsm, silc_client_notify_topic_set);
    break;

  case SILC_NOTIFY_TYPE_NICK_CHANGE:
    /** NICK_CHANGE */
    silc_fsm_next(fsm, silc_client_notify_nick_change);
    break;

  case SILC_NOTIFY_TYPE_CMODE_CHANGE:
    /** CMODE_CHANGE */
    silc_fsm_next(fsm, silc_client_notify_cmode_change);
    break;

  case SILC_NOTIFY_TYPE_CUMODE_CHANGE:
    /** CUMODE_CHANGE */
    silc_fsm_next(fsm, silc_client_notify_cumode_change);
    break;

  case SILC_NOTIFY_TYPE_MOTD:
    /** MOTD */
    silc_fsm_next(fsm, silc_client_notify_motd);
    break;

  case SILC_NOTIFY_TYPE_CHANNEL_CHANGE:
    /** CHANNEL_CHANGE */
    silc_fsm_next(fsm, silc_client_notify_channel_change);
    break;

  case SILC_NOTIFY_TYPE_KICKED:
    /** KICKED */
    silc_fsm_next(fsm, silc_client_notify_kicked);
    break;

  case SILC_NOTIFY_TYPE_KILLED:
    /** KILLED */
    silc_fsm_next(fsm, silc_client_notify_killed);
    break;

  case SILC_NOTIFY_TYPE_SERVER_SIGNOFF:
    /** SERVER_SIGNOFF */
    silc_fsm_next(fsm, silc_client_notify_server_signoff);
    break;

  case SILC_NOTIFY_TYPE_ERROR:
    /** ERROR */
    silc_fsm_next(fsm, silc_client_notify_error);
    break;

  case SILC_NOTIFY_TYPE_WATCH:
    /** WATCH */
    silc_fsm_next(fsm, silc_client_notify_watch);
    break;

  default:
    /** Unknown notify */
    silc_notify_payload_free(payload);
    silc_packet_free(packet);
    silc_free(notify);
    return SILC_FSM_FINISH;
    break;
  }

  return SILC_FSM_YIELD;
}

/* Notify processed, finish the packet processing thread */

SILC_FSM_STATE(silc_client_notify_processed)
{
  SilcClientNotify notify = state_context;
  SilcPacket packet = notify->packet;
  SilcNotifyPayload payload = notify->payload;

  silc_notify_payload_free(payload);
  silc_packet_free(packet);
  silc_free(notify);
  return SILC_FSM_FINISH;
}

/********************************** NONE ************************************/

SILC_FSM_STATE(silc_client_notify_none)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientNotify notify = state_context;
  SilcNotifyPayload payload = notify->payload;
  SilcNotifyType type = silc_notify_get_type(payload);
  SilcArgumentPayload args = silc_notify_get_args(payload);

  SILC_LOG_DEBUG(("Notify: NONE"));

  /* Notify application */
  NOTIFY(client, conn, type, silc_argument_get_arg_type(args, 1, NULL));

  /** Notify processed */
  silc_fsm_next(fsm, silc_client_notify_processed);
  return SILC_FSM_CONTINUE;
}

/********************************* INVITE ***********************************/

/* Someone invite me to a channel */

SILC_FSM_STATE(silc_client_notify_invite)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientNotify notify = state_context;
  SilcNotifyPayload payload = notify->payload;
  SilcNotifyType type = silc_notify_get_type(payload);
  SilcArgumentPayload args = silc_notify_get_args(payload);
  SilcClientEntry client_entry;
  SilcChannelEntry channel = NULL;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcID id;

  SILC_LOG_DEBUG(("Notify: INVITE"));

  /* Get Channel ID */
  if (!silc_argument_get_decoded(args, 1, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  /* Get the channel name */
  tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
  if (!tmp)
    goto out;

  /* Get the channel entry */
  channel = silc_client_get_channel_by_id(client, conn, &id.u.channel_id);

  /* If channel is being resolved handle notify after resolving */
  if (channel->internal.resolve_cmd_ident) {
    silc_client_unref_channel(client, conn, channel);
    SILC_FSM_CALL(silc_client_command_pending(
			              conn, SILC_COMMAND_NONE,
				      channel->internal.resolve_cmd_ident,
				      silc_client_notify_wait_continue,
				      notify));
    /* NOT REACHED */
  }

  /* Get sender Client ID */
  if (!silc_argument_get_decoded(args, 3, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  /* Find Client entry and if not found query it */
  client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
  if (!client_entry || !client_entry->nickname[0]) {
    /** Resolve client */
    silc_client_unref_client(client, conn, client_entry);
    notify->channel = channel;
    SILC_FSM_CALL(channel->internal.resolve_cmd_ident =
		  silc_client_get_client_by_id_resolve(
					 client, conn, &id.u.client_id, NULL,
					 silc_client_notify_resolved,
					 notify));
    /* NOT REACHED */
  }

  /* Notify application */
  NOTIFY(client, conn, type, channel, tmp, client_entry);

  silc_client_unref_client(client, conn, client_entry);

 out:
  /** Notify processed */
  silc_client_unref_channel(client, conn, channel);
  silc_fsm_next(fsm, silc_client_notify_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** JOIN ************************************/

/* Someone joined a channel */

SILC_FSM_STATE(silc_client_notify_join)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientNotify notify = state_context;
  SilcNotifyPayload payload = notify->payload;
  SilcNotifyType type = silc_notify_get_type(payload);
  SilcArgumentPayload args = silc_notify_get_args(payload);
  SilcClientEntry client_entry;
  SilcChannelEntry channel = NULL;
  SilcID id;

  SILC_LOG_DEBUG(("Notify: JOIN"));

  /* Get Channel ID */
  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  /* Get channel entry */
  channel = silc_client_get_channel_by_id(client, conn, &id.u.channel_id);
  if (!channel)
    goto out;

  /* If channel is being resolved handle notify after resolving */
  if (channel->internal.resolve_cmd_ident) {
    silc_client_unref_channel(client, conn, channel);
    SILC_FSM_CALL(silc_client_command_pending(
			              conn, SILC_COMMAND_NONE,
				      channel->internal.resolve_cmd_ident,
				      silc_client_notify_wait_continue,
				      notify));
    /* NOT REACHED */
  }

  /* Get Client ID */
  if (!silc_argument_get_decoded(args, 1, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  /* Find Client entry and if not found query it */
  client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
  if (!client_entry || !client_entry->nickname[0] ||
      !client_entry->username[0]) {
    /** Resolve client */
    silc_client_unref_client(client, conn, client_entry);
    notify->channel = channel;
    SILC_FSM_CALL(channel->internal.resolve_cmd_ident =
		  silc_client_get_client_by_id_resolve(
					 client, conn, &id.u.client_id, NULL,
					 silc_client_notify_resolved,
					 notify));
    /* NOT REACHED */
  }

  if (client_entry != conn->local_entry)
    silc_client_nickname_format(client, conn, client_entry);

  /* Join the client to channel */
  if (!silc_client_add_to_channel(client, conn, channel, client_entry, 0))
    goto out;

  /* Notify application. */
  NOTIFY(client, conn, type, client_entry, channel);

  silc_client_unref_client(client, conn, client_entry);

 out:
  /** Notify processed */
  silc_client_unref_channel(client, conn, channel);
  silc_fsm_next(fsm, silc_client_notify_processed);
  return SILC_FSM_CONTINUE;
}

/********************************** LEAVE ***********************************/

/* Someone left a channel */

SILC_FSM_STATE(silc_client_notify_leave)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientNotify notify = state_context;
  SilcNotifyPayload payload = notify->payload;
  SilcPacket packet = notify->packet;
  SilcNotifyType type = silc_notify_get_type(payload);
  SilcArgumentPayload args = silc_notify_get_args(payload);
  SilcClientEntry client_entry = NULL;
  SilcChannelEntry channel = NULL;
  SilcID id;

  SILC_LOG_DEBUG(("Notify: LEAVE"));

  /* Get channel entry */
  if (!silc_id_str2id(packet->dst_id, packet->dst_id_len, SILC_ID_CHANNEL,
		      &id.u.channel_id, sizeof(id.u.channel_id)))
    goto out;
  channel = silc_client_get_channel_by_id(client, conn, &id.u.channel_id);
  if (!channel)
    goto out;

  /* If channel is being resolved handle notify after resolving */
  if (channel->internal.resolve_cmd_ident) {
    silc_client_unref_channel(client, conn, channel);
    SILC_FSM_CALL(silc_client_command_pending(
			              conn, SILC_COMMAND_NONE,
				      channel->internal.resolve_cmd_ident,
				      silc_client_notify_wait_continue,
				      notify));
    /* NOT REACHED */
  }

  /* Get Client ID */
  if (!silc_argument_get_decoded(args, 1, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  /* Find Client entry */
  client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
  if (!client_entry)
    goto out;

  /* Remove client from channel */
  silc_client_remove_from_channel(client, conn, channel, client_entry);

  /* Notify application. */
  NOTIFY(client, conn, type, client_entry, channel);

  silc_client_unref_client(client, conn, client_entry);

 out:
  /** Notify processed */
  silc_client_unref_channel(client, conn, channel);
  silc_fsm_next(fsm, silc_client_notify_processed);
  return SILC_FSM_CONTINUE;
}

/********************************* SIGNOFF **********************************/

/* Someone quit SILC network */

SILC_FSM_STATE(silc_client_notify_signoff)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientNotify notify = state_context;
  SilcNotifyPayload payload = notify->payload;
  SilcNotifyType type = silc_notify_get_type(payload);
  SilcArgumentPayload args = silc_notify_get_args(payload);
  SilcClientEntry client_entry;
   unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcID id;

  SILC_LOG_DEBUG(("Notify: SIGNOFF"));

  /* Get Client ID */
  if (!silc_argument_get_decoded(args, 1, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  /* Find Client entry */
  client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
  if (!client_entry)
    goto out;

  /* Get signoff message */
  tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
  if (tmp_len > 128)
    tmp[128] = '\0';

  /* Notify application */
  NOTIFY(client, conn, type, client_entry, tmp);

  /* Delete client */
  silc_client_del_client(client, conn, client_entry);
  silc_client_unref_client(client, conn, client_entry);

 out:
  /** Notify processed */
  silc_fsm_next(fsm, silc_client_notify_processed);
  return SILC_FSM_CONTINUE;
}

/******************************** TOPIC_SET *********************************/

/* Someone set topic on a channel */

SILC_FSM_STATE(silc_client_notify_topic_set)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientNotify notify = state_context;
  SilcNotifyPayload payload = notify->payload;
  SilcPacket packet = notify->packet;
  SilcNotifyType type = silc_notify_get_type(payload);
  SilcArgumentPayload args = silc_notify_get_args(payload);
  SilcClientEntry client_entry = NULL;
  SilcChannelEntry channel = NULL, channel_entry = NULL;
  SilcServerEntry server = NULL;
  void *entry;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcID id;

  SILC_LOG_DEBUG(("Notify: TOPIC_SET"));

  /* Get channel entry */
  if (!silc_id_str2id(packet->dst_id, packet->dst_id_len, SILC_ID_CHANNEL,
		      &id.u.channel_id, sizeof(id.u.channel_id)))
    goto out;
  channel = silc_client_get_channel_by_id(client, conn, &id.u.channel_id);
  if (!channel)
    goto out;

  /* If channel is being resolved handle notify after resolving */
  if (channel->internal.resolve_cmd_ident) {
    silc_client_unref_channel(client, conn, channel);
    SILC_FSM_CALL(silc_client_command_pending(
			              conn, SILC_COMMAND_NONE,
				      channel->internal.resolve_cmd_ident,
				      silc_client_notify_wait_continue,
				      notify));
    /* NOT REACHED */
  }

  /* Get ID */
  if (!silc_argument_get_decoded(args, 1, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  /* Get topic */
  tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
  if (!tmp)
    goto out;

  if (id.type == SILC_ID_CLIENT) {
    /* Find Client entry */
    client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
    if (!client_entry || !client_entry->nickname[0]) {
      /** Resolve client */
      silc_client_unref_client(client, conn, client_entry);
      notify->channel = channel;
      SILC_FSM_CALL(channel->internal.resolve_cmd_ident =
		    silc_client_get_client_by_id_resolve(
					   client, conn, &id.u.client_id, NULL,
					   silc_client_notify_resolved,
					   notify));
      /* NOT REACHED */
    }
    entry = client_entry;
  } else if (id.type == SILC_ID_SERVER) {
    /* Find Server entry */
    server = silc_client_get_server_by_id(client, conn, &id.u.server_id);
    if (!server) {
      /** Resolve server */
      notify->channel = channel;
      SILC_FSM_CALL(channel->internal.resolve_cmd_ident =
		    silc_client_get_server_by_id_resolve(
					   client, conn, &id.u.server_id,
					   silc_client_notify_resolved,
					   notify));
      /* NOT REACHED */
    }
    entry = server;
  } else {
    /* Find Channel entry */
    channel_entry = silc_client_get_channel_by_id(client, conn,
						  &id.u.channel_id);
    if (!channel_entry) {
      /** Resolve channel */
      notify->channel = channel;
      SILC_FSM_CALL(channel->internal.resolve_cmd_ident =
		    silc_client_get_channel_by_id_resolve(
				    client, conn, &id.u.channel_id,
				    silc_client_notify_resolved,
				    notify));
      /* NOT REACHED */
    }
    entry = channel_entry;
  }

  silc_free(channel->topic);
  channel->topic = silc_memdup(tmp, strlen(tmp));

  /* Notify application. */
  NOTIFY(client, conn, type, id.type, entry, channel->topic, channel);

  if (client_entry)
    silc_client_unref_client(client, conn, client_entry);
  if (server)
    silc_client_unref_server(client, conn, server);
  if (channel_entry)
    silc_client_unref_channel(client, conn, channel_entry);

 out:
  /** Notify processed */
  silc_client_unref_channel(client, conn, channel);
  silc_fsm_next(fsm, silc_client_notify_processed);
  return SILC_FSM_CONTINUE;
}

/****************************** NICK_CHANGE *********************************/

/* Someone changed their nickname on a channel */

SILC_FSM_STATE(silc_client_notify_nick_change)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientNotify notify = state_context;
  SilcNotifyPayload payload = notify->payload;
  SilcNotifyType type = silc_notify_get_type(payload);
  SilcArgumentPayload args = silc_notify_get_args(payload);
  SilcClientEntry client_entry = NULL;
  unsigned char *tmp, *nick, oldnick[128 + 1];
  SilcUInt32 tmp_len;
  SilcID id, id2;

  SILC_LOG_DEBUG(("Notify: NICK_CHANGE"));

  /* Get ID */
  if (!silc_argument_get_decoded(args, 1, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  /* Ignore my ID */
  if (conn->local_id &&
      SILC_ID_CLIENT_COMPARE(&id.u.client_id, conn->local_id))
    goto out;

  /* Get new Client ID */
  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id2, NULL))
    goto out;

  /* Ignore my ID */
  if (conn->local_id &&
      SILC_ID_CLIENT_COMPARE(&id2.u.client_id, conn->local_id))
    goto out;

  /* Find old Client entry */
  client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
  if (!client_entry || !client_entry->nickname[0]) {
    /** Resolve client */
    silc_client_unref_client(client, conn, client_entry);
    SILC_FSM_CALL(silc_client_get_client_by_id_resolve(
					 client, conn, &id.u.client_id, NULL,
					 silc_client_notify_resolved,
					 notify));
    /* NOT REACHED */
  }

  /* Take the new nickname */
  tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
  if (!tmp)
    goto out;

  /* Check whether nickname changed at all.  It is possible that nick
     change notify is received but nickname didn't change, only the
     ID changes.  If Client ID hash match, nickname didn't change. */
  if (SILC_ID_COMPARE_HASH(&client_entry->id, &id2.u.client_id) &&
      silc_utf8_strcasecmp(tmp, client_entry->nickname)) {
    /* Nickname didn't change.  Update only Client ID.  We don't notify
       application because nickname didn't change. */
    silc_mutex_lock(conn->internal->lock);
    silc_idcache_update_by_context(conn->internal->client_cache, client_entry,
				   &id2.u.client_id, NULL, FALSE);
    silc_mutex_unlock(conn->internal->lock);
    goto out;
  }

  /* Normalize nickname */
  nick = silc_identifier_check(tmp, tmp_len, SILC_STRING_UTF8, 128, NULL);
  if (!nick)
    goto out;

  /* Update nickname */
  silc_mutex_lock(conn->internal->lock);
  if (!silc_idcache_update_by_context(conn->internal->client_cache,
				      client_entry, NULL, nick, TRUE)) {
    silc_free(nick);
    silc_mutex_unlock(conn->internal->lock);
    goto out;
  }
  silc_mutex_unlock(conn->internal->lock);
  memcpy(oldnick, client_entry->nickname, sizeof(client_entry->nickname));
  memcpy(client_entry->nickname, tmp, tmp_len);
  client_entry->nickname_normalized = nick;
  silc_client_nickname_format(client, conn, client_entry);

  /* Notify application */
  NOTIFY(client, conn, type, client_entry, client_entry->nickname, oldnick);

 out:
  /** Notify processed */
  silc_client_unref_client(client, conn, client_entry);
  silc_fsm_next(fsm, silc_client_notify_processed);
  return SILC_FSM_CONTINUE;
}

/****************************** CMODE_CHANGE ********************************/

/* Someone changed channel mode */

SILC_FSM_STATE(silc_client_notify_cmode_change)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientNotify notify = state_context;
  SilcNotifyPayload payload = notify->payload;
  SilcPacket packet = notify->packet;
  SilcNotifyType type = silc_notify_get_type(payload);
  SilcArgumentPayload args = silc_notify_get_args(payload);
  SilcClientEntry client_entry = NULL;
  SilcChannelEntry channel = NULL, channel_entry = NULL;
  SilcServerEntry server = NULL;
  void *entry;
  unsigned char *tmp;
  SilcUInt32 tmp_len, mode;
  SilcID id;
  char *passphrase, *cipher, *hmac;
  SilcPublicKey founder_key = NULL;
  SilcDList chpks = NULL;

  SILC_LOG_DEBUG(("Notify: CMODE_CHANGE"));

  /* Get channel entry */
  if (!silc_id_str2id(packet->dst_id, packet->dst_id_len, SILC_ID_CHANNEL,
		      &id.u.channel_id, sizeof(id.u.channel_id)))
    goto out;
  channel = silc_client_get_channel_by_id(client, conn, &id.u.channel_id);
  if (!channel)
    goto out;

  /* If channel is being resolved handle notify after resolving */
  if (channel->internal.resolve_cmd_ident) {
    silc_client_unref_channel(client, conn, channel);
    SILC_FSM_CALL(silc_client_command_pending(
			              conn, SILC_COMMAND_NONE,
				      channel->internal.resolve_cmd_ident,
				      silc_client_notify_wait_continue,
				      notify));
    /* NOT REACHED */
  }

  /* Get the mode */
  tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
  if (!tmp)
    goto out;
  SILC_GET32_MSB(mode, tmp);

  /* Get ID */
  if (!silc_argument_get_decoded(args, 1, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  if (id.type == SILC_ID_CLIENT) {
    /* Find Client entry */
    client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
    if (!client_entry || !client_entry->nickname[0]) {
      /** Resolve client */
      silc_client_unref_client(client, conn, client_entry);
      notify->channel = channel;
      SILC_FSM_CALL(channel->internal.resolve_cmd_ident =
		    silc_client_get_client_by_id_resolve(
					   client, conn, &id.u.client_id, NULL,
					   silc_client_notify_resolved,
					   notify));
      /* NOT REACHED */
    }
    entry = client_entry;
  } else if (id.type == SILC_ID_SERVER) {
    /* Find Server entry */
    server = silc_client_get_server_by_id(client, conn, &id.u.server_id);
    if (!server) {
      /** Resolve server */
      notify->channel = channel;
      SILC_FSM_CALL(channel->internal.resolve_cmd_ident =
		    silc_client_get_server_by_id_resolve(
					   client, conn, &id.u.server_id,
					   silc_client_notify_resolved,
					   notify));
      /* NOT REACHED */
    }
    entry = server;
  } else {
    /* Find Channel entry */
    channel_entry = silc_client_get_channel_by_id(client, conn,
						  &id.u.channel_id);
    if (!channel_entry) {
      /** Resolve channel */
      notify->channel = channel;
      SILC_FSM_CALL(channel->internal.resolve_cmd_ident =
		    silc_client_get_channel_by_id_resolve(
				    client, conn, &id.u.channel_id,
				    silc_client_notify_resolved,
				    notify));
      /* NOT REACHED */
    }
    entry = channel_entry;
  }

  /* Get the channel founder key if it was set */
  tmp = silc_argument_get_arg_type(args, 6, &tmp_len);
  if (tmp) {
    if (!silc_public_key_payload_decode(tmp, tmp_len, &founder_key))
      goto out;
    if (!channel->founder_key) {
      channel->founder_key = founder_key;
      founder_key = NULL;
    }
  }

  /* Get the cipher */
  cipher = silc_argument_get_arg_type(args, 3, &tmp_len);

  /* Get the hmac */
  hmac = silc_argument_get_arg_type(args, 4, &tmp_len);
  if (hmac) {
    unsigned char hash[SILC_HASH_MAXLEN];
    SilcHmac newhmac;

    if (!silc_hmac_alloc(hmac, NULL, &newhmac))
      goto out;

    /* Get HMAC key from the old HMAC context, and update it to the new one */
    tmp = (unsigned char *)silc_hmac_get_key(channel->internal.hmac, &tmp_len);
    if (tmp) {
      silc_hash_make(silc_hmac_get_hash(newhmac), tmp, tmp_len, hash);
      silc_hmac_set_key(newhmac, hash,
			silc_hash_len(silc_hmac_get_hash(newhmac)));
      if (channel->internal.hmac)
	silc_hmac_free(channel->internal.hmac);
      channel->internal.hmac = newhmac;
      memset(hash, 0, sizeof(hash));
    }
  }

  /* Get the passphrase if it was set */
  passphrase = silc_argument_get_arg_type(args, 5, &tmp_len);

  /* Get user limit */
  tmp = silc_argument_get_arg_type(args, 8, &tmp_len);
  if (tmp && tmp_len == 4)
    SILC_GET32_MSB(channel->user_limit, tmp);
  if (!(channel->mode & SILC_CHANNEL_MODE_ULIMIT))
    channel->user_limit = 0;

  /* Save the new mode */
  channel->mode = mode;

  /* Get the channel public key that was added or removed */
  tmp = silc_argument_get_arg_type(args, 7, &tmp_len);
  if (tmp)
    chpks = silc_argument_list_parse_decoded(tmp, tmp_len,
					     SILC_ARGUMENT_PUBLIC_KEY);

  /* Notify application. */
  NOTIFY(client, conn, type, id.type, entry, mode, cipher, hmac,
	 passphrase, channel->founder_key, chpks, channel);

 out:
  if (founder_key)
    silc_pkcs_public_key_free(founder_key);
  if (chpks)
    silc_argument_list_free(chpks, SILC_ARGUMENT_PUBLIC_KEY);
  if (client_entry)
    silc_client_unref_client(client, conn, client_entry);
  if (server)
    silc_client_unref_server(client, conn, server);
  if (channel_entry)
    silc_client_unref_channel(client, conn, channel_entry);
  silc_client_unref_channel(client, conn, channel);

  /** Notify processed */
  silc_fsm_next(fsm, silc_client_notify_processed);
  return SILC_FSM_CONTINUE;
}

/***************************** CUMODE_CHANGE ********************************/

/* Someone changed a user's mode on a channel */

SILC_FSM_STATE(silc_client_notify_cumode_change)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientNotify notify = state_context;
  SilcNotifyPayload payload = notify->payload;
  SilcPacket packet = notify->packet;
  SilcNotifyType type = silc_notify_get_type(payload);
  SilcArgumentPayload args = silc_notify_get_args(payload);
  SilcClientEntry client_entry = NULL, client_entry2 = NULL;
  SilcChannelEntry channel = NULL, channel_entry = NULL;
  SilcServerEntry server = NULL;
  SilcChannelUser chu;
  void *entry;
  unsigned char *tmp;
  SilcUInt32 tmp_len, mode;
  SilcID id, id2;

  SILC_LOG_DEBUG(("Notify: CUMODE_CHANGE"));

  /* Get channel entry */
  if (!silc_id_str2id(packet->dst_id, packet->dst_id_len, SILC_ID_CHANNEL,
		      &id.u.channel_id, sizeof(id.u.channel_id)))
    goto out;
  channel = silc_client_get_channel_by_id(client, conn, &id.u.channel_id);
  if (!channel)
    goto out;

  /* If channel is being resolved handle notify after resolving */
  if (channel->internal.resolve_cmd_ident) {
    silc_client_unref_channel(client, conn, channel);
    SILC_FSM_CALL(silc_client_command_pending(
			              conn, SILC_COMMAND_NONE,
				      channel->internal.resolve_cmd_ident,
				      silc_client_notify_wait_continue,
				      notify));
    /* NOT REACHED */
  }

  /* Get target Client ID */
  if (!silc_argument_get_decoded(args, 3, SILC_ARGUMENT_ID, &id2, NULL))
    goto out;

  /* Find target Client entry */
  client_entry2 = silc_client_get_client_by_id(client, conn, &id2.u.client_id);
  if (!client_entry2 || !client_entry2->nickname[0]) {
    /** Resolve client */
    silc_client_unref_client(client, conn, client_entry2);
    SILC_FSM_CALL(silc_client_get_client_by_id_resolve(
					 client, conn, &id2.u.client_id, NULL,
					 silc_client_notify_resolved,
					 notify));
    /* NOT REACHED */
  }

  /* Get the mode */
  tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
  if (!tmp)
    goto out;
  SILC_GET32_MSB(mode, tmp);

  /* Get ID */
  if (!silc_argument_get_decoded(args, 1, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  if (id.type == SILC_ID_CLIENT) {
    /* Find Client entry */
    client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
    if (!client_entry || !client_entry->nickname[0]) {
      /** Resolve client */
      silc_client_unref_client(client, conn, client_entry);
      notify->channel = channel;
      SILC_FSM_CALL(channel->internal.resolve_cmd_ident =
		    silc_client_get_client_by_id_resolve(
					   client, conn, &id.u.client_id, NULL,
					   silc_client_notify_resolved,
					   notify));
      /* NOT REACHED */
    }
    entry = client_entry;
  } else if (id.type == SILC_ID_SERVER) {
    /* Find Server entry */
    server = silc_client_get_server_by_id(client, conn, &id.u.server_id);
    if (!server) {
      /** Resolve server */
      notify->channel = channel;
      SILC_FSM_CALL(channel->internal.resolve_cmd_ident =
		    silc_client_get_server_by_id_resolve(
					   client, conn, &id.u.server_id,
					   silc_client_notify_resolved,
					   notify));
      /* NOT REACHED */
    }
    entry = server;
  } else {
    /* Find Channel entry */
    channel_entry = silc_client_get_channel_by_id(client, conn,
						  &id.u.channel_id);
    if (!channel_entry) {
      /** Resolve channel */
      notify->channel = channel;
      SILC_FSM_CALL(channel->internal.resolve_cmd_ident =
		    silc_client_get_channel_by_id_resolve(
				    client, conn, &id.u.channel_id,
				    silc_client_notify_resolved,
				    notify));
      /* NOT REACHED */
    }
    entry = channel_entry;
  }

  /* Save the mode */
  chu = silc_client_on_channel(channel, client_entry2);
  if (chu)
    chu->mode = mode;

  /* Notify application. */
  NOTIFY(client, conn, type, id.type, entry, mode, client_entry2, channel);

 out:
  silc_client_unref_client(client, conn, client_entry2);
  if (client_entry)
    silc_client_unref_client(client, conn, client_entry);
  if (server)
    silc_client_unref_server(client, conn, server);
  if (channel_entry)
    silc_client_unref_channel(client, conn, channel_entry);
  silc_client_unref_channel(client, conn, channel);

  /** Notify processed */
  silc_fsm_next(fsm, silc_client_notify_processed);
  return SILC_FSM_CONTINUE;
}

/********************************* MOTD *************************************/

/* Received Message of the day */

SILC_FSM_STATE(silc_client_notify_motd)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientNotify notify = state_context;
  SilcNotifyPayload payload = notify->payload;
  SilcNotifyType type = silc_notify_get_type(payload);
  SilcArgumentPayload args = silc_notify_get_args(payload);
  unsigned char *tmp;
  SilcUInt32 tmp_len;

  SILC_LOG_DEBUG(("Notify: MOTD"));

  /* Get motd */
  tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
  if (!tmp)
    goto out;

  /* Notify application */
  NOTIFY(client, conn, type, tmp);

 out:
  /** Notify processed */
  silc_fsm_next(fsm, silc_client_notify_processed);
  return SILC_FSM_CONTINUE;
}

/**************************** CHANNEL CHANGE ********************************/

/* Router has enforced a new ID to a channel, change it */

SILC_FSM_STATE(silc_client_notify_channel_change)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientNotify notify = state_context;
  SilcNotifyPayload payload = notify->payload;
  SilcNotifyType type = silc_notify_get_type(payload);
  SilcArgumentPayload args = silc_notify_get_args(payload);
  SilcChannelEntry channel = NULL;
  SilcID id;

  SILC_LOG_DEBUG(("Notify: CHANNEL_CHANGE"));

  /* Get the old ID */
  if (!silc_argument_get_decoded(args, 1, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  /* Get the channel entry */
  channel = silc_client_get_channel_by_id(client, conn, &id.u.channel_id);
  if (!channel)
    goto out;

  /* If channel is being resolved handle notify after resolving */
  if (channel->internal.resolve_cmd_ident) {
    silc_client_unref_channel(client, conn, channel);
    SILC_FSM_CALL(silc_client_command_pending(
			              conn, SILC_COMMAND_NONE,
				      channel->internal.resolve_cmd_ident,
				      silc_client_notify_wait_continue,
				      notify));
    /* NOT REACHED */
  }

  /* Get the new ID */
  if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  /* Replace the Channel ID */
  if (!silc_client_replace_channel_id(client, conn, channel, &id.u.channel_id))
    goto out;

  /* Notify application */
  NOTIFY(client, conn, type, channel, channel);

 out:
  /** Notify processed */
  silc_client_unref_channel(client, conn, channel);
  silc_fsm_next(fsm, silc_client_notify_processed);
  return SILC_FSM_CONTINUE;
}

/******************************** KICKED ************************************/

/* Some client was kicked from a channel */

SILC_FSM_STATE(silc_client_notify_kicked)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientNotify notify = state_context;
  SilcNotifyPayload payload = notify->payload;
  SilcPacket packet = notify->packet;
  SilcNotifyType type = silc_notify_get_type(payload);
  SilcArgumentPayload args = silc_notify_get_args(payload);
  SilcClientEntry client_entry, client_entry2;
  SilcChannelEntry channel = NULL;
  SilcChannelUser chu;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcID id;

  SILC_LOG_DEBUG(("Notify: KICKED"));

  /* Get channel entry */
  if (!silc_id_str2id(packet->dst_id, packet->dst_id_len, SILC_ID_CHANNEL,
		      &id.u.channel_id, sizeof(id.u.channel_id)))
    goto out;
  channel = silc_client_get_channel_by_id(client, conn, &id.u.channel_id);
  if (!channel)
    goto out;

  /* If channel is being resolved handle notify after resolving */
  if (channel->internal.resolve_cmd_ident) {
    silc_client_unref_channel(client, conn, channel);
    SILC_FSM_CALL(silc_client_command_pending(
			              conn, SILC_COMMAND_NONE,
				      channel->internal.resolve_cmd_ident,
				      silc_client_notify_wait_continue,
				      notify));
    /* NOT REACHED */
  }

  /* Get Client ID */
  if (!silc_argument_get_decoded(args, 1, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  /* Find Client entry */
  client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
  if (!client_entry)
    goto out;

  /* Get kicker's Client ID */
  if (!silc_argument_get_decoded(args, 3, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  /* Find kicker's client entry and if not found resolve it */
  client_entry2 = silc_client_get_client_by_id(client, conn, &id.u.client_id);
  if (!client_entry2 || !client_entry2->nickname[0]) {
    /** Resolve client */
    silc_client_unref_client(client, conn, client_entry);
    silc_client_unref_client(client, conn, client_entry2);
    notify->channel = channel;
    SILC_FSM_CALL(channel->internal.resolve_cmd_ident =
		  silc_client_get_client_by_id_resolve(
					 client, conn, &id.u.client_id, NULL,
					 silc_client_notify_resolved,
					 notify));
    /* NOT REACHED */
  }

  /* Get comment */
  tmp = silc_argument_get_arg_type(args, 2, &tmp_len);

  /* Remove kicked client from channel */
  if (client_entry != conn->local_entry) {
    chu = silc_client_on_channel(channel, client_entry);
    if (chu) {
      silc_hash_table_del(client_entry->channels, channel);
      silc_hash_table_del(channel->user_list, client_entry);
      silc_free(chu);
    }
  }

  /* Notify application. */
  NOTIFY(client, conn, type, client_entry, tmp, client_entry2, channel);

  /* If I was kicked from channel, remove the channel */
  if (client_entry == conn->local_entry) {
    if (conn->current_channel == channel)
      conn->current_channel = NULL;
    silc_client_del_channel(client, conn, channel);
  }

  silc_client_unref_client(client, conn, client_entry);
  silc_client_unref_client(client, conn, client_entry2);

 out:
  /** Notify processed */
  silc_client_unref_channel(client, conn, channel);
  silc_fsm_next(fsm, silc_client_notify_processed);
  return SILC_FSM_CONTINUE;
}

/******************************** KILLED ************************************/

/* Some client was killed from the network */

SILC_FSM_STATE(silc_client_notify_killed)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientNotify notify = state_context;
  SilcNotifyPayload payload = notify->payload;
  SilcNotifyType type = silc_notify_get_type(payload);
  SilcArgumentPayload args = silc_notify_get_args(payload);
  SilcClientEntry client_entry = NULL, client_entry2 = NULL;
  SilcChannelEntry channel_entry = NULL;
  SilcServerEntry server = NULL;
  void *entry;
  char *comment;
  SilcUInt32 comment_len;
  SilcID id;

  SILC_LOG_DEBUG(("Notify: KILLED"));

  /* Get Client ID */
  if (!silc_argument_get_decoded(args, 1, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  /* Find Client entry */
  client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
  if (!client_entry)
    goto out;

  /* Get comment */
  comment = silc_argument_get_arg_type(args, 2, &comment_len);

  /* Get killer's ID */
  if (!silc_argument_get_decoded(args, 3, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  if (id.type == SILC_ID_CLIENT) {
    /* Find Client entry */
    client_entry2 = silc_client_get_client_by_id(client, conn,
						 &id.u.client_id);
    if (!client_entry2 || !client_entry2->nickname[0]) {
      /** Resolve client */
      silc_client_unref_client(client, conn, client_entry);
      silc_client_unref_client(client, conn, client_entry2);
      SILC_FSM_CALL(silc_client_get_client_by_id_resolve(
					   client, conn, &id.u.client_id, NULL,
					   silc_client_notify_resolved,
					   notify));
      /* NOT REACHED */
    }
    entry = client_entry2;
  } else if (id.type == SILC_ID_SERVER) {
    /* Find Server entry */
    server = silc_client_get_server_by_id(client, conn, &id.u.server_id);
    if (!server) {
      /** Resolve server */
      SILC_FSM_CALL(silc_client_get_server_by_id_resolve(
					   client, conn, &id.u.server_id,
					   silc_client_notify_resolved,
					   notify));
      /* NOT REACHED */
    }
    entry = server;
  } else {
    /* Find Channel entry */
    channel_entry = silc_client_get_channel_by_id(client, conn,
						  &id.u.channel_id);
    if (!channel_entry) {
      /** Resolve channel */
      SILC_FSM_CALL(silc_client_get_channel_by_id_resolve(
				    client, conn, &id.u.channel_id,
				    silc_client_notify_resolved,
				    notify));
      /* NOT REACHED */
    }
    entry = channel_entry;
  }

  /* Notify application. */
  NOTIFY(client, conn, type, client_entry, comment, id.type, entry);

  /* Delete the killed client */
  if (client_entry != conn->local_entry)
    silc_client_del_client(client, conn, client_entry);

 out:
  silc_client_unref_client(client, conn, client_entry);
  if (client_entry2)
    silc_client_unref_client(client, conn, client_entry2);
  if (server)
    silc_client_unref_server(client, conn, server);
  if (channel_entry)
    silc_client_unref_channel(client, conn, channel_entry);

  /** Notify processed */
  silc_fsm_next(fsm, silc_client_notify_processed);
  return SILC_FSM_CONTINUE;
}

/**************************** SERVER SIGNOFF ********************************/

/* Some server quit SILC network.  Remove its clients from channels. */

SILC_FSM_STATE(silc_client_notify_server_signoff)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientNotify notify = state_context;
  SilcNotifyPayload payload = notify->payload;
  SilcNotifyType type = silc_notify_get_type(payload);
  SilcArgumentPayload args = silc_notify_get_args(payload);
  SilcClientEntry client_entry;
  SilcDList clients;
  SilcID id;
  int i;

  SILC_LOG_DEBUG(("Notify: SIGNOFF"));

  clients = silc_dlist_init();
  if (!clients)
    goto out;

  for (i = 1; i < silc_argument_get_arg_num(args); i++) {
    /* Get Client ID */
    if (!silc_argument_get_decoded(args, i + 1, SILC_ARGUMENT_ID, &id, NULL))
      goto out;

    /* Get the client entry */
    client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
    if (client_entry)
      silc_dlist_add(clients, client_entry);
  }

  /* Notify application.  We don't keep server entries so the server
     entry is returned as NULL. The client's are returned as list. */
  NOTIFY(client, conn, type, NULL, clients);

  /* Delete the clients */
  silc_dlist_start(clients);
  while ((client_entry = silc_dlist_get(clients)))
    silc_client_del_client(client, conn, client_entry);

 out:
  /** Notify processed */
  silc_client_list_free(client, conn, clients);
  silc_fsm_next(fsm, silc_client_notify_processed);
  return SILC_FSM_CONTINUE;
}

/******************************** ERROR *************************************/

/* Some error occurred */

SILC_FSM_STATE(silc_client_notify_error)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientNotify notify = state_context;
  SilcNotifyPayload payload = notify->payload;
  SilcNotifyType type = silc_notify_get_type(payload);
  SilcArgumentPayload args = silc_notify_get_args(payload);
  SilcClientEntry client_entry;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  SilcID id;
  SilcStatus error;

  /* Get error */
  tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
  if (!tmp && tmp_len != 1)
    goto out;
  error = (SilcStatus)tmp[0];

  SILC_LOG_DEBUG(("Notify: ERROR (%d)", error));

  /* Handle the error */
  if (error == SILC_STATUS_ERR_NO_SUCH_CLIENT_ID) {
    if (!silc_argument_get_decoded(args, 2, SILC_ARGUMENT_ID, &id, NULL))
      goto out;
    client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
    if (client_entry) {
      silc_client_del_client(client, conn, client_entry);
      silc_client_unref_client(client, conn, client_entry);
    }
  }

  /* Notify application. */
  NOTIFY(client, conn, type, error);

 out:
  /** Notify processed */
  silc_fsm_next(fsm, silc_client_notify_processed);
  return SILC_FSM_CONTINUE;
}

/******************************** WATCH *************************************/

/* Received notify about some client we are watching */

SILC_FSM_STATE(silc_client_notify_watch)
{
  SilcClientConnection conn = fsm_context;
  SilcClient client = conn->client;
  SilcClientNotify notify = state_context;
  SilcNotifyPayload payload = notify->payload;
  SilcNotifyType type = silc_notify_get_type(payload);
  SilcArgumentPayload args = silc_notify_get_args(payload);
  SilcClientEntry client_entry = NULL;
  SilcNotifyType ntype = 0;
  SilcBool del_client = FALSE;
  unsigned char *pk, *tmp;
  SilcUInt32 mode, pk_len, tmp_len;
  SilcPublicKey public_key = NULL;
  SilcID id;

  SILC_LOG_DEBUG(("Notify: WATCH"));

  /* Get sender Client ID */
  if (!silc_argument_get_decoded(args, 1, SILC_ARGUMENT_ID, &id, NULL))
    goto out;

  /* Find Client entry and if not found resolve it */
  client_entry = silc_client_get_client_by_id(client, conn, &id.u.client_id);
  if (!client_entry || !client_entry->nickname[0]) {
    /** Resolve client */
    silc_client_unref_client(client, conn, client_entry);
    SILC_FSM_CALL(silc_client_get_client_by_id_resolve(
					 client, conn, &id.u.client_id, NULL,
					 silc_client_notify_resolved,
					 notify));
    /* NOT REACHED */
  }

  /* Get user mode */
  tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
  if (!tmp || tmp_len != 4)
    goto out;
  SILC_GET32_MSB(mode, tmp);

  /* Get notify type */
  tmp = silc_argument_get_arg_type(args, 4, &tmp_len);
  if (tmp && tmp_len != 2)
    goto out;
  if (tmp)
    SILC_GET16_MSB(ntype, tmp);

  /* Get nickname */
  tmp = silc_argument_get_arg_type(args, 2, NULL);
  if (tmp) {
    char *tmp_nick = NULL;

    if (client->internal->params->nickname_parse)
      client->internal->params->nickname_parse(client_entry->nickname,
					       &tmp_nick);
    else
      tmp_nick = strdup(tmp);

    /* If same nick, the client was new to us and has become "present"
       to network.  Send NULL as nick to application. */
    if (tmp_nick && silc_utf8_strcasecmp(tmp, tmp_nick))
      tmp = NULL;

    silc_free(tmp_nick);
  }

  /* Get public key, if present */
  pk = silc_argument_get_arg_type(args, 5, &pk_len);
  if (pk && !client_entry->public_key) {
    if (silc_public_key_payload_decode(pk, pk_len, &public_key)) {
      client_entry->public_key = public_key;
      public_key = NULL;
    }
  }

  /* Notify application. */
  NOTIFY(client, conn, type, client_entry, tmp, mode, ntype,
	 client_entry->public_key);

  client_entry->mode = mode;

  /* If nickname was changed, remove the client entry unless the
     client is on some channel */
  /* XXX, why do we need to remove the client entry?? */
  if (tmp && ntype == SILC_NOTIFY_TYPE_NICK_CHANGE &&
      !silc_hash_table_count(client_entry->channels))
    del_client = TRUE;
  else if (ntype == SILC_NOTIFY_TYPE_SIGNOFF ||
	   ntype == SILC_NOTIFY_TYPE_SERVER_SIGNOFF ||
	   ntype == SILC_NOTIFY_TYPE_KILLED)
    del_client = TRUE;

  if (del_client)
    silc_client_del_client(client, conn, client_entry);

  if (public_key)
    silc_pkcs_public_key_free(public_key);

 out:
  /** Notify processed */
  silc_client_unref_client(client, conn, client_entry);
  silc_fsm_next(fsm, silc_client_notify_processed);
  return SILC_FSM_CONTINUE;
}
