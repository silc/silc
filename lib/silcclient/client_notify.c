/*

  client_notify.c 

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */
/* This file includes the Notify packet handling. Notify packets are
   important packets sent by the server. They tell different things to the
   client such as nick changes, mode changes etc. */

#include "clientlibincludes.h"
#include "client_internal.h"

typedef struct {
  SilcPacketContext *packet;
  void *context;
  SilcSocketConnection sock;
} *SilcClientNotifyResolve;

/* Called when notify is received and some async operation (such as command)
   is required before processing the notify message. This calls again the
   silc_client_notify_by_server and reprocesses the original notify packet. */

static void silc_client_notify_by_server_pending(void *context, void *context2)
{
  SilcClientNotifyResolve res = (SilcClientNotifyResolve)context;
  SilcClientCommandReplyContext reply = 
    (SilcClientCommandReplyContext)context2;

  SILC_LOG_DEBUG(("Start"));

  if (reply) {
    SilcCommandStatus status;
    unsigned char *tmp = silc_argument_get_arg_type(reply->args, 1, NULL);
    SILC_GET16_MSB(status, tmp);
    if (status != SILC_STATUS_OK)
      goto out;
  }

  silc_client_notify_by_server(res->context, res->sock, res->packet);

 out:
  silc_socket_free(res->sock);
  silc_packet_context_free(res->packet);
  silc_free(res);
}

/* Resolve client information from server by Client ID. */

static void silc_client_notify_by_server_resolve(SilcClient client,
						 SilcClientConnection conn,
						 SilcPacketContext *packet,
						 SilcClientID *client_id)
{
  SilcClientNotifyResolve res = silc_calloc(1, sizeof(*res));
  SilcBuffer idp = silc_id_payload_encode(client_id, SILC_ID_CLIENT);

  res->packet = silc_packet_context_dup(packet);
  res->context = client;
  res->sock = silc_socket_dup(conn->sock);

  silc_client_command_register(client, SILC_COMMAND_WHOIS, NULL, NULL,
			       silc_client_command_reply_whois_i, 0,
			       ++conn->cmd_ident);
  silc_client_command_send(client, conn, SILC_COMMAND_WHOIS, conn->cmd_ident,
			   1, 3, idp->data, idp->len);
  silc_client_command_pending(conn, SILC_COMMAND_WHOIS, conn->cmd_ident,
			      silc_client_notify_by_server_pending, res);
  silc_buffer_free(idp);
}

/* Received notify message from server */

void silc_client_notify_by_server(SilcClient client,
				  SilcSocketConnection sock,
				  SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcClientConnection conn = (SilcClientConnection)sock->user_data;
  SilcNotifyPayload payload;
  SilcNotifyType type;
  SilcArgumentPayload args;

  SilcIDPayload idp;
  SilcClientID *client_id = NULL;
  SilcChannelID *channel_id = NULL;
  SilcServerID *server_id = NULL;
  SilcClientEntry client_entry;
  SilcClientEntry client_entry2;
  SilcChannelEntry channel;
  SilcChannelUser chu;
  SilcServerEntry server;
  unsigned char *tmp;
  uint32 tmp_len, mode;

  SILC_LOG_DEBUG(("Start"));

  payload = silc_notify_payload_parse(buffer->data, buffer->len);
  if (!payload)
    goto out;

  type = silc_notify_get_type(payload);
  args = silc_notify_get_args(payload);
  if (!args)
    goto out;

  switch(type) {
  case SILC_NOTIFY_TYPE_NONE:
    /* Notify application */
    client->internal->ops->notify(client, conn, type, 
				  silc_argument_get_arg_type(args, 1, NULL));
    break;

  case SILC_NOTIFY_TYPE_INVITE:
    /* 
     * Someone invited me to a channel. Find Client and Channel entries
     * for the application.
     */
    
    SILC_LOG_DEBUG(("Notify: INVITE"));

    /* Get Channel ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    channel_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!channel_id)
      goto out;

    /* Get the channel entry */
    channel = silc_client_get_channel_by_id(client, conn, channel_id);

    /* Get sender Client ID */
    tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find Client entry and if not found query it */
    client_entry = silc_client_get_client_by_id(client, conn, client_id);
    if (!client_entry) {
      silc_client_notify_by_server_resolve(client, conn, packet, client_id);
      goto out;
    }

    /* Get the channel name */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;

    /* Notify application */
    client->internal->ops->notify(client, conn, type, channel, tmp, 
				  client_entry);
    break;

  case SILC_NOTIFY_TYPE_JOIN:
    /*
     * Someone has joined to a channel. Get their ID and nickname and
     * cache them for later use.
     */

    SILC_LOG_DEBUG(("Notify: JOIN"));

    /* Get Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find Client entry and if not found query it */
    client_entry = silc_client_get_client_by_id(client, conn, client_id);
    if (!client_entry) {
      silc_client_notify_by_server_resolve(client, conn, packet, client_id);
      goto out;
    }

    /* If nickname or username hasn't been resolved, do so */
    if (!client_entry->nickname || !client_entry->username) {
      if (client_entry->status & SILC_CLIENT_STATUS_RESOLVING) {
	client_entry->status &= ~SILC_CLIENT_STATUS_RESOLVING;
	goto out;
      }
      client_entry->status |= SILC_CLIENT_STATUS_RESOLVING;
      silc_client_notify_by_server_resolve(client, conn, packet, client_id);
      goto out;
    } else {
      if (client_entry != conn->local_entry)
	silc_client_nickname_format(client, conn, client_entry);
    }

    /* Get Channel ID */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;

    channel_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!channel_id)
      goto out;

    /* Get channel entry */
    channel = silc_client_get_channel_by_id(client, conn, channel_id);
    if (!channel)
      break;

    /* Join the client to channel */
    if (!silc_client_on_channel(channel, client_entry)) {
      chu = silc_calloc(1, sizeof(*chu));
      chu->client = client_entry;
      chu->channel = channel;
      silc_hash_table_add(channel->user_list, client_entry, chu);
      silc_hash_table_add(client_entry->channels, channel, chu);
    }

    /* Notify application. The channel entry is sent last as this notify
       is for channel but application don't know it from the arguments
       sent by server. */
    client->internal->ops->notify(client, conn, type, client_entry, channel);
    break;

  case SILC_NOTIFY_TYPE_LEAVE:
    /*
     * Someone has left a channel. We will remove it from the channel but
     * we'll keep it in the cache in case we'll need it later.
     */
    
    SILC_LOG_DEBUG(("Notify: LEAVE"));

    /* Get Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find Client entry */
    client_entry = 
      silc_client_get_client_by_id(client, conn, client_id);
    if (!client_entry)
      goto out;

    /* Get channel entry */
    channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				SILC_ID_CHANNEL);
    if (!channel_id)
      goto out;
    channel = silc_client_get_channel_by_id(client, conn, channel_id);
    if (!channel)
      break;

    /* Remove client from channel */
    chu = silc_client_on_channel(channel, client_entry);
    if (chu) {
      silc_hash_table_del(client_entry->channels, channel);
      silc_hash_table_del(channel->user_list, client_entry);
      silc_free(chu);
    }

    /* Notify application. The channel entry is sent last as this notify
       is for channel but application don't know it from the arguments
       sent by server. */
    client->internal->ops->notify(client, conn, type, client_entry, channel);
    break;

  case SILC_NOTIFY_TYPE_SIGNOFF:
    /*
     * Someone left SILC. We'll remove it from all channels and from cache.
     */

    SILC_LOG_DEBUG(("Notify: SIGNOFF"));

    /* Get Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find Client entry */
    client_entry = 
      silc_client_get_client_by_id(client, conn, client_id);
    if (!client_entry)
      goto out;

    /* Remove from all channels */
    silc_client_remove_from_channels(client, conn, client_entry);

    /* Remove from cache */
    silc_idcache_del_by_context(conn->client_cache, client_entry);

    /* Get signoff message */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (tmp_len > 128)
      tmp = NULL;

    /* Notify application */
    client->internal->ops->notify(client, conn, type, client_entry, tmp);

    /* Free data */
    silc_client_del_client_entry(client, conn, client_entry);
    break;

  case SILC_NOTIFY_TYPE_TOPIC_SET:
    /*
     * Someone set the topic on a channel.
     */

    SILC_LOG_DEBUG(("Notify: TOPIC_SET"));

    /* Get Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    idp = silc_id_payload_parse(tmp, tmp_len);
    if (!idp)
      goto out;

    /* Find Client entry */
    if (silc_id_payload_get_type(idp) == SILC_ID_CLIENT) {
      client_id = silc_id_payload_parse_id(tmp, tmp_len);
      if (!client_id) {
	silc_id_payload_free(idp);
	goto out;
      }

      /* Find Client entry */
      client_entry = 
	silc_client_get_client_by_id(client, conn, client_id);
      if (!client_entry)
	goto out;
    } else if (silc_id_payload_get_type(idp) == SILC_ID_SERVER) {
      server_id = silc_id_payload_parse_id(tmp, tmp_len);
      if (!server_id) {
	silc_id_payload_free(idp);
	goto out;
      }
      
      server = silc_client_get_server_by_id(client, conn, server_id);
      if (!server) {
	silc_id_payload_free(idp);
	silc_free(server_id);
	goto out;
      }
      
      /* Save the pointer to the client_entry pointer */
      client_entry = (SilcClientEntry)server;
      silc_free(server_id);
    } else {
      channel_id = silc_id_payload_parse_id(tmp, tmp_len);
      if (!channel_id) {
	silc_id_payload_free(idp);
	goto out;
      }
      
      channel = silc_client_get_channel_by_id(client, conn, channel_id);
      if (!channel) {
	silc_id_payload_free(idp);
	silc_free(channel_id);
	goto out;
      }
      
      /* Save the pointer to the client_entry pointer */
      client_entry = (SilcClientEntry)channel;
      silc_free(channel_id);
    }

    /* Get topic */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;

    /* Get channel entry */
    channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				SILC_ID_CHANNEL);
    if (!channel_id)
      goto out;
    channel = silc_client_get_channel_by_id(client, conn, channel_id);
    if (!channel)
      break;

    /* Notify application. The channel entry is sent last as this notify
       is for channel but application don't know it from the arguments
       sent by server. */
    client->internal->ops->notify(client, conn, type, 
				  silc_id_payload_get_type(idp),
				  client_entry, tmp, channel);

    silc_id_payload_free(idp);
    break;

  case SILC_NOTIFY_TYPE_NICK_CHANGE:
    /*
     * Someone changed their nickname. If we don't have entry for the new
     * ID we will query it and return here after it's done. After we've
     * returned we fetch the old entry and free it and notify the 
     * application.
     */

    SILC_LOG_DEBUG(("Notify: NICK_CHANGE"));

    /* Get old Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Ignore my ID */
    if (SILC_ID_CLIENT_COMPARE(client_id, conn->local_id))
      break;

    /* Find old Client entry */
    client_entry = silc_client_get_client_by_id(client, conn, client_id);
    if (!client_entry)
      goto out;
    silc_free(client_id);

    client_entry->valid = FALSE;

    /* Get new Client ID */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find Client entry and if not found resolve it */
    client_entry2 = silc_client_get_client_by_id(client, conn, client_id);
    if (!client_entry2) {
      /* Resolve the entry information */
      silc_client_notify_by_server_resolve(client, conn, packet, client_id);

      /* Add the new entry even though we resolved it. This is because we
	 want to replace the old entry with the new entry here right now. */
      client_entry2 = 
	silc_client_add_client(client, conn, NULL, NULL, NULL, 
			       silc_id_dup(client_id, SILC_ID_CLIENT), 
			       client_entry->mode);

      /* Replace old ID entry with new one on all channels. */
      silc_client_replace_from_channels(client, conn, client_entry,
					client_entry2);
    } else {
      if (client_entry2 != conn->local_entry)
	silc_client_nickname_format(client, conn, client_entry2);

      /* Remove the old from cache */
      silc_idcache_del_by_context(conn->client_cache, client_entry);

      /* Replace old ID entry with new one on all channels. */
      silc_client_replace_from_channels(client, conn, client_entry,
					client_entry2);

      /* Notify application */
      client->internal->ops->notify(client, conn, type, 
				    client_entry, client_entry2);

      /* Free data */
      silc_client_del_client_entry(client, conn, client_entry);
    }
    break;

  case SILC_NOTIFY_TYPE_CMODE_CHANGE:
    /*
     * Someone changed a channel mode
     */

    SILC_LOG_DEBUG(("Notify: CMODE_CHANGE"));

    /* Get Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    idp = silc_id_payload_parse(tmp, tmp_len);
    if (!idp)
      goto out;

    /* Find Client entry */
    if (silc_id_payload_get_type(idp) == SILC_ID_CLIENT) {
      client_id = silc_id_payload_parse_id(tmp, tmp_len);
      if (!client_id) {
	silc_id_payload_free(idp);
	goto out;
      }

      client_entry = silc_client_get_client_by_id(client, conn, client_id);
      if (!client_entry) {
	silc_id_payload_free(idp);
	goto out;
      }
    } else {
      server_id = silc_id_payload_parse_id(tmp, tmp_len);
      if (!server_id) {
	silc_id_payload_free(idp);
	goto out;
      }
      
      server = silc_client_get_server_by_id(client, conn, server_id);
      if (!server) {
	silc_id_payload_free(idp);
	silc_free(server_id);
	goto out;
      }
      
      /* Save the pointer to the client_entry pointer */
      client_entry = (SilcClientEntry)server;
      silc_free(server_id);
    }

    /* Get the mode */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp) {
      silc_id_payload_free(idp);
      goto out;
    }

    SILC_GET32_MSB(mode, tmp);

    /* Get channel entry */
    channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				SILC_ID_CHANNEL);
    if (!channel_id) {
      silc_id_payload_free(idp);
      goto out;
    }
    channel = silc_client_get_channel_by_id(client, conn, channel_id);
    if (!channel) {
      silc_id_payload_free(idp);
      goto out;
    }

    /* Save the new mode */
    channel->mode = mode;

    /* Get the hmac */
    tmp = silc_argument_get_arg_type(args, 4, &tmp_len);
    if (tmp) {
      unsigned char hash[32];

      if (channel->hmac)
	silc_hmac_free(channel->hmac);
      if (!silc_hmac_alloc(tmp, NULL, &channel->hmac))
	goto out;

      silc_hash_make(silc_hmac_get_hash(channel->hmac), 
		     channel->key, channel->key_len / 8,
		     hash);
      silc_hmac_set_key(channel->hmac, hash, 
			silc_hash_len(silc_hmac_get_hash(channel->hmac)));
      memset(hash, 0, sizeof(hash));
    }

    /* Notify application. The channel entry is sent last as this notify
       is for channel but application don't know it from the arguments
       sent by server. */
    client->internal->ops->notify(client, conn, type, 
				  silc_id_payload_get_type(idp), 
				  client_entry, mode, NULL, tmp, channel);

    silc_id_payload_free(idp);
    break;

  case SILC_NOTIFY_TYPE_CUMODE_CHANGE:
    /*
     * Someone changed user's mode on a channel
     */

    SILC_LOG_DEBUG(("Notify: CUMODE_CHANGE"));

    /* Get Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find Client entry */
    client_entry = silc_client_get_client_by_id(client, conn, client_id);
    if (!client_entry) {
      silc_client_notify_by_server_resolve(client, conn, packet, client_id);
      goto out;
    }

    /* Get the mode */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;

    SILC_GET32_MSB(mode, tmp);

    /* Get target Client ID */
    tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
    if (!tmp)
      goto out;

    silc_free(client_id);
    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find target Client entry */
    client_entry2 = 
      silc_client_get_client_by_id(client, conn, client_id);
    if (!client_entry2)
      goto out;

    /* Get channel entry */
    channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				SILC_ID_CHANNEL);
    if (!channel_id)
      goto out;
    channel = silc_client_get_channel_by_id(client, conn, channel_id);
    if (!channel)
      break;

    /* Save the mode */
    chu = silc_client_on_channel(channel, client_entry);
    if (chu)
      chu->mode = mode;

    /* Notify application. The channel entry is sent last as this notify
       is for channel but application don't know it from the arguments
       sent by server. */
    client->internal->ops->notify(client, conn, type, 
				  client_entry, mode, 
				  client_entry2, channel);
    break;

  case SILC_NOTIFY_TYPE_MOTD:
    /*
     * Received Message of the day
     */

    SILC_LOG_DEBUG(("Notify: MOTD"));

    /* Get motd */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;
    
    /* Notify application */
    client->internal->ops->notify(client, conn, type, tmp);
    break;

  case SILC_NOTIFY_TYPE_CHANNEL_CHANGE:
    /*
     * Router has enforced a new ID to a channel. Let's change the old
     * ID to the one provided here.
     */

    SILC_LOG_DEBUG(("Notify: CHANNEL_CHANGE"));

    /* Get the old ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;
    channel_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!channel_id)
      goto out;

    /* Get the channel entry */
    channel = silc_client_get_channel_by_id(client, conn, channel_id);
    if (!channel)
      goto out;

    silc_free(channel_id);

    /* Get the new ID */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;
    channel_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!channel_id)
      goto out;

    /* Replace the Channel ID */
    silc_client_replace_channel_id(client, conn, channel, channel_id);

    /* Notify application */
    client->internal->ops->notify(client, conn, type, channel, channel);
    break;

  case SILC_NOTIFY_TYPE_KICKED:
    /*
     * A client (maybe me) was kicked from a channel
     */

    SILC_LOG_DEBUG(("Notify: KICKED"));

    /* Get Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find Client entry */
    client_entry = silc_client_get_client_by_id(client, conn, client_id);
    if (!client_entry)
      goto out;

    /* Get channel entry */
    channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				SILC_ID_CHANNEL);
    if (!channel_id)
      goto out;
    channel = silc_client_get_channel_by_id(client, conn, channel_id);
    if (!channel)
      break;

    /* Get the kicker */
    tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find kicker's client entry and if not found resolve it */
    client_entry2 = silc_client_get_client_by_id(client, conn, client_id);
    if (!client_entry2) {
      silc_client_notify_by_server_resolve(client, conn, packet, client_id);
      goto out;
    } else {
      if (client_entry2 != conn->local_entry)
	silc_client_nickname_format(client, conn, client_entry2);
    }

    /* Get comment */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);

    /* Notify application. The channel entry is sent last as this notify
       is for channel but application don't know it from the arguments
       sent by server. */
    client->internal->ops->notify(client, conn, type, client_entry, tmp, 
				  client_entry2, channel);

    /* If I was kicked from channel, remove the channel */
    if (client_entry == conn->local_entry) {
      if (conn->current_channel == channel)
	conn->current_channel = NULL;
      silc_idcache_del_by_id(conn->channel_cache, channel->id);
      silc_free(channel->channel_name);
      silc_free(channel->id);
      silc_free(channel->key);
      silc_cipher_free(channel->channel_key);
      silc_free(channel);
    }
    break;

  case SILC_NOTIFY_TYPE_KILLED:
    /*
     * A client (maybe me) was killed from the network.
     */

    SILC_LOG_DEBUG(("Notify: KILLED"));

    /* Get Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    client_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!client_id)
      goto out;

    /* Find Client entry */
    client_entry = silc_client_get_client_by_id(client, conn, client_id);
    if (!client_entry)
      goto out;

    /* Get comment */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);

    /* Notify application. */
    client->internal->ops->notify(client, conn, type, client_entry, tmp);

    if (client_entry != conn->local_entry)
      /* Remove the client from all channels and free it */
      silc_client_del_client(client, conn, client_entry);

    break;
    
  case SILC_NOTIFY_TYPE_SERVER_SIGNOFF:
    {
      /*
       * A server quit the SILC network and some clients must be removed
       * from channels as they quit as well.
       */
      SilcClientEntry *clients = NULL;
      uint32 clients_count = 0;
      int i;

      SILC_LOG_DEBUG(("Notify: SIGNOFF"));

      for (i = 1; i < silc_argument_get_arg_num(args); i++) {
	/* Get Client ID */
	tmp = silc_argument_get_arg_type(args, i + 1, &tmp_len);
	if (tmp) {
	  client_id = silc_id_payload_parse_id(tmp, tmp_len);
	  if (!client_id)
	    goto out;
	  
	  /* Get the client entry */
	  client_entry = silc_client_get_client_by_id(client, conn, client_id);
	  if (client_entry) {
	    clients = silc_realloc(clients, sizeof(*clients) * 
				   (clients_count + 1));
	    clients[clients_count] = client_entry;
	    clients_count++;
	  }
	  silc_free(client_id);
	}
      }
      client_id = NULL;

      /* Notify application. We don't keep server entries so the server
	 entry is returned as NULL. The client's are returned as array
	 of SilcClientEntry pointers. */
      client->internal->ops->notify(client, conn, type, NULL, 
				    clients, clients_count);

      for (i = 0; i < clients_count; i++) {
	/* Remove client from all channels */
	client_entry = clients[i];
	if (client_entry == conn->local_entry)
	  continue;

	/* Remove the client from all channels and free it */
	silc_client_del_client(client, conn, client_entry);
      }
      silc_free(clients);

    }
    break;

  default:
    break;
  }

 out:
  silc_notify_payload_free(payload);
  silc_free(client_id);
  silc_free(channel_id);
}
