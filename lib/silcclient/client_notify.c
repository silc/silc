/*

  client_notify.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2001 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
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

/* Called when notify is received and some async operation (such as command)
   is required before processing the notify message. This calls again the
   silc_client_notify_by_server and reprocesses the original notify packet. */

static void silc_client_notify_by_server_pending(void *context, void *context2)
{
  SilcPacketContext *p = (SilcPacketContext *)context;
  silc_client_notify_by_server(p->context, p->sock, p);
  silc_socket_free(p->sock);
}

/* Destructor for the pending command callback */

static void silc_client_notify_by_server_destructor(void *context)
{
  silc_packet_context_free((SilcPacketContext *)context);
}

/* Resolve client information from server by Client ID. */

static void silc_client_notify_by_server_resolve(SilcClient client,
						 SilcClientConnection conn,
						 SilcPacketContext *packet,
						 SilcClientID *client_id)
{
  SilcPacketContext *p = silc_packet_context_dup(packet);
  SilcBuffer idp = silc_id_payload_encode(client_id, SILC_ID_CLIENT);

  p->context = (void *)client;
  p->sock = silc_socket_dup(conn->sock);

  silc_client_send_command(client, conn, SILC_COMMAND_WHOIS, ++conn->cmd_ident,
			   1, 3, idp->data, idp->len);
  silc_client_command_pending(conn, SILC_COMMAND_WHOIS, conn->cmd_ident,
			      silc_client_notify_by_server_destructor,
			      silc_client_notify_by_server_pending, p);
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
  SilcIDCacheEntry id_cache = NULL;
  unsigned char *tmp;
  uint32 tmp_len, mode;

  payload = silc_notify_payload_parse(buffer);
  if (!payload)
    goto out;

  type = silc_notify_get_type(payload);
  args = silc_notify_get_args(payload);
  if (!args)
    goto out;

  switch(type) {
  case SILC_NOTIFY_TYPE_NONE:
    /* Notify application */
    client->ops->notify(client, conn, type, 
			silc_argument_get_arg_type(args, 1, NULL));
    break;

  case SILC_NOTIFY_TYPE_INVITE:
    /* 
     * Someone invited me to a channel. Find Client and Channel entries
     * for the application.
     */
    
    /* Get Channel ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    channel_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!channel_id)
      goto out;

    /* Get the channel entry */
    channel = NULL;
    if (silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
				    &id_cache))
      channel = (SilcChannelEntry)id_cache->context;

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
    client->ops->notify(client, conn, type, channel, tmp, client_entry);
    break;

  case SILC_NOTIFY_TYPE_JOIN:
    /*
     * Someone has joined to a channel. Get their ID and nickname and
     * cache them for later use.
     */

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
      silc_client_notify_by_server_resolve(client, conn, packet, client_id);
      goto out;
    }

    /* Get Channel ID */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;

    channel_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!channel_id)
      goto out;

    /* Get channel entry */
    if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
				     &id_cache))
      break;

    channel = (SilcChannelEntry)id_cache->context;

    /* Add client to channel */
    if (client_entry != conn->local_entry) {
      chu = silc_calloc(1, sizeof(*chu));
      chu->client = client_entry;
      silc_list_add(channel->clients, chu);
    }

    /* Notify application. The channel entry is sent last as this notify
       is for channel but application don't know it from the arguments
       sent by server. */
    client->ops->notify(client, conn, type, client_entry, channel);
    break;

  case SILC_NOTIFY_TYPE_LEAVE:
    /*
     * Someone has left a channel. We will remove it from the channel but
     * we'll keep it in the cache in case we'll need it later.
     */
    
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
    if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
				 &id_cache))
      break;

    channel = (SilcChannelEntry)id_cache->context;

    /* Remove client from channel */
    silc_list_start(channel->clients);
    while ((chu = silc_list_get(channel->clients)) != SILC_LIST_END) {
      if (chu->client == client_entry) {
	silc_list_del(channel->clients, chu);
	silc_free(chu);
	break;
      }
    }

    /* Notify application. The channel entry is sent last as this notify
       is for channel but application don't know it from the arguments
       sent by server. */
    client->ops->notify(client, conn, type, client_entry, channel);
    break;

  case SILC_NOTIFY_TYPE_SIGNOFF:
    /*
     * Someone left SILC. We'll remove it from all channels and from cache.
     */

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
    client->ops->notify(client, conn, type, client_entry, tmp);

    /* Free data */
    silc_client_del_client_entry(client, client_entry);
    break;

  case SILC_NOTIFY_TYPE_TOPIC_SET:
    /*
     * Someone set the topic on a channel.
     */

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

    /* Get topic */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;

    /* Get channel entry */
    channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				SILC_ID_CHANNEL);
    if (!channel_id)
      goto out;
    if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
				 &id_cache))
      break;

    channel = (SilcChannelEntry)id_cache->context;

    /* Notify application. The channel entry is sent last as this notify
       is for channel but application don't know it from the arguments
       sent by server. */
    client->ops->notify(client, conn, type, client_entry, tmp, channel);
    break;

  case SILC_NOTIFY_TYPE_NICK_CHANGE:
    /*
     * Someone changed their nickname. If we don't have entry for the new
     * ID we will query it and return here after it's done. After we've
     * returned we fetch the old entry and free it and notify the 
     * application.
     */

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
      silc_client_notify_by_server_resolve(client, conn, packet, client_id);
      goto out;
    }

    /* Remove the old from cache */
    silc_idcache_del_by_context(conn->client_cache, client_entry);

    /* Replace old ID entry with new one on all channels. */
    silc_client_replace_from_channels(client, conn, client_entry,
				      client_entry2);

    /* Notify application */
    client->ops->notify(client, conn, type, client_entry, client_entry2);

    /* Free data */
    silc_client_del_client_entry(client, client_entry);
    break;

  case SILC_NOTIFY_TYPE_CMODE_CHANGE:
    /*
     * Someone changed a channel mode
     */

    /* Get Client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;

    idp = silc_id_payload_parse_data(tmp, tmp_len);
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
    if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
				     &id_cache)) {
      silc_id_payload_free(idp);
      goto out;
    }

    channel = (SilcChannelEntry)id_cache->context;

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

      silc_hash_make(channel->hmac->hash, channel->key, channel->key_len / 8,
		     hash);
      silc_hmac_set_key(channel->hmac, hash, 
			silc_hash_len(channel->hmac->hash));
      memset(hash, 0, sizeof(hash));
    }

    /* Notify application. The channel entry is sent last as this notify
       is for channel but application don't know it from the arguments
       sent by server. */
    client->ops->notify(client, conn, type, silc_id_payload_get_type(idp), 
			client_entry, mode, NULL, tmp, channel);

    silc_id_payload_free(idp);
    break;

  case SILC_NOTIFY_TYPE_CUMODE_CHANGE:
    /*
     * Someone changed user's mode on a channel
     */

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
    if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
				 &id_cache))
      break;

    channel = (SilcChannelEntry)id_cache->context;

    /* Save the mode */
    silc_list_start(channel->clients);
    while ((chu = silc_list_get(channel->clients)) != SILC_LIST_END) {
      if (chu->client == client_entry) {
	chu->mode = mode;
	break;
      }
    }

    /* Notify application. The channel entry is sent last as this notify
       is for channel but application don't know it from the arguments
       sent by server. */
    client->ops->notify(client, conn, type, client_entry, mode, 
			client_entry2, channel);
    break;

  case SILC_NOTIFY_TYPE_MOTD:
    /*
     * Received Message of the day
     */

    /* Get motd */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;
    
    /* Notify application */
    client->ops->notify(client, conn, type, tmp);
    break;

  case SILC_NOTIFY_TYPE_CHANNEL_CHANGE:
    /*
     * Router has enforced a new ID to a channel. Let's change the old
     * ID to the one provided here.
     */

    /* Get the old ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;
    channel_id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!channel_id)
      goto out;
    
    /* Get the channel entry */
    if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
				     &id_cache))
      break;

    channel = (SilcChannelEntry)id_cache->context;

    SILC_LOG_DEBUG(("Old Channel ID id(%s)", 
		    silc_id_render(channel->id, SILC_ID_CHANNEL)));

    /* Free the old ID */
    silc_free(channel->id);

    /* Get the new ID */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;
    channel->id = silc_id_payload_parse_id(tmp, tmp_len);
    if (!channel->id)
      goto out;

    SILC_LOG_DEBUG(("New Channel ID id(%s)", 
		    silc_id_render(channel->id, SILC_ID_CHANNEL)));

    /* Remove the old cache entry and create a new one */
    silc_idcache_del_by_context(conn->channel_cache, channel);
    silc_idcache_add(conn->channel_cache, channel->channel_name, 
		     channel->id, channel, FALSE);

    /* Notify application */
    client->ops->notify(client, conn, type, channel, channel);
    break;

  case SILC_NOTIFY_TYPE_KICKED:
    /*
     * A client (maybe me) was kicked from a channel
     */

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
    if (!silc_idcache_find_by_id_one(conn->channel_cache, (void *)channel_id,
				 &id_cache))
      break;

    channel = (SilcChannelEntry)id_cache->context;

    /* Get comment */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);

    /* Notify application. The channel entry is sent last as this notify
       is for channel but application don't know it from the arguments
       sent by server. */
    client->ops->notify(client, conn, type, client_entry, tmp, channel);

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
    client->ops->notify(client, conn, type, client_entry, tmp);

    if (client_entry != conn->local_entry) {
      /* Remove client from all channels */
      silc_client_remove_from_channels(client, conn, client_entry);
      silc_client_del_client(client, conn, client_entry);
    }

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
      client->ops->notify(client, conn, type, NULL, clients, clients_count);

      for (i = 0; i < clients_count; i++) {
	/* Remove client from all channels */
	client_entry = clients[i];
	if (client_entry == conn->local_entry)
	  continue;

	silc_client_remove_from_channels(client, conn, client_entry);
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
