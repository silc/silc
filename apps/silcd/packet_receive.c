/*

  packet_receive.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

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
/*
 * Server packet routines to handle received packets.
 */
/* $Id$ */

#include "serverincludes.h"
#include "server_internal.h"

extern char *server_version;

/* Received notify packet. Server can receive notify packets from router. 
   Server then relays the notify messages to clients if needed. */

void silc_server_notify(SilcServer server,
			SilcSocketConnection sock,
			SilcPacketContext *packet)
{
  SilcNotifyPayload payload;
  SilcNotifyType type;
  SilcArgumentPayload args;
  SilcChannelID *channel_id = NULL, *channel_id2;
  SilcClientID *client_id, *client_id2;
  SilcServerID *server_id;
  SilcIdType id_type;
  SilcChannelEntry channel = NULL;
  SilcClientEntry client = NULL, client2 = NULL;
  SilcServerEntry server_entry = NULL;
  SilcChannelClientEntry chl;
  SilcIDCacheEntry cache;
  SilcHashTableList htl;
  SilcUInt32 mode;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  bool local;

  SILC_LOG_DEBUG(("Start"));

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      packet->src_id_type != SILC_ID_SERVER)
    return;

  if (!packet->dst_id)
    return;

  /* If the packet is destined directly to a client then relay the packet
     before processing it. */
  if (packet->dst_id_type == SILC_ID_CLIENT) {
    SilcIDListData idata;
    SilcSocketConnection dst_sock;

    /* Get the route to the client */
    dst_sock = silc_server_get_client_route(server, packet->dst_id,
					    packet->dst_id_len, NULL, &idata);
    if (dst_sock)
      /* Relay the packet */
      silc_server_relay_packet(server, dst_sock, idata->send_key,
			       idata->hmac_receive, idata->psn_send++,
			       packet, TRUE);
  }

  /* Parse the Notify Payload */
  payload = silc_notify_payload_parse(packet->buffer->data,
				      packet->buffer->len);
  if (!payload)
    return;

  /* If we are router and this packet is not already broadcast packet
     we will broadcast it. The sending socket really cannot be router or
     the router is buggy. If this packet is coming from router then it must
     have the broadcast flag set already and we won't do anything. */
  if (!server->standalone && server->server_type == SILC_ROUTER &&
      sock->type == SILC_SOCKET_TYPE_SERVER &&
      !(packet->flags & SILC_PACKET_FLAG_BROADCAST)) {
    SILC_LOG_DEBUG(("Broadcasting received Notify packet"));
    if (packet->dst_id_type == SILC_ID_CHANNEL) {
      /* Packet is destined to channel */
      channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				  packet->dst_id_type);
      if (!channel_id)
	goto out;

      silc_server_packet_send_dest(server, server->router->connection, 
				   packet->type,
				   packet->flags | SILC_PACKET_FLAG_BROADCAST, 
				   channel_id, SILC_ID_CHANNEL,
				   packet->buffer->data, packet->buffer->len, 
				   FALSE);
      silc_server_backup_send_dest(server, (SilcServerEntry)sock->user_data, 
				   packet->type, packet->flags,
				   channel_id, SILC_ID_CHANNEL,
				   packet->buffer->data, packet->buffer->len, 
				   FALSE, TRUE);
    } else {
      /* Packet is destined to client or server */
      silc_server_packet_send(server, server->router->connection, 
			      packet->type,
			      packet->flags | SILC_PACKET_FLAG_BROADCAST, 
			      packet->buffer->data, packet->buffer->len, 
			      FALSE);
      silc_server_backup_send(server, (SilcServerEntry)sock->user_data,
			      packet->type, packet->flags,
			      packet->buffer->data, packet->buffer->len, 
			      FALSE, TRUE);
    }
  }

  type = silc_notify_get_type(payload);
  args = silc_notify_get_args(payload);
  if (!args)
    goto out;

  switch(type) {
  case SILC_NOTIFY_TYPE_JOIN:
    /* 
     * Distribute the notify to local clients on the channel
     */
    SILC_LOG_DEBUG(("JOIN notify"));

    /* Get Channel ID */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;
    channel_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
    if (!channel_id)
      goto out;

    /* Get channel entry */
    channel = silc_idlist_find_channel_by_id(server->global_list, 
					     channel_id, NULL);
    if (!channel) {
      channel = silc_idlist_find_channel_by_id(server->local_list, 
					       channel_id, NULL);
      if (!channel) {
	silc_free(channel_id);
	goto out;
      }
    }
    silc_free(channel_id);

    /* Get client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;
    client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
    if (!client_id)
      goto out;

    /* If the the client is not in local list we check global list (ie. the
       channel will be global channel) and if it does not exist then create
       entry for the client. */
    client = silc_idlist_find_client_by_id(server->global_list, 
					   client_id, server->server_type, 
					   NULL);
    if (!client) {
      client = silc_idlist_find_client_by_id(server->local_list, 
					     client_id, server->server_type,
					     NULL);
      if (!client) {
	/* If router did not find the client the it is bogus */
	if (server->server_type != SILC_SERVER)
	  goto out;

	client = 
	  silc_idlist_add_client(server->global_list, NULL, NULL, NULL,
				 silc_id_dup(client_id, SILC_ID_CLIENT), 
				 sock->user_data, NULL, 0);
	if (!client) {
	  SILC_LOG_ERROR(("Could not add new client to the ID Cache"));
	  silc_free(client_id);
	  goto out;
	}

	client->data.status |= SILC_IDLIST_STATUS_REGISTERED;
      }
    }

    /* Do not process the notify if the client is not registered */
    if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED))
      break;

    /* Do not add client to channel if it is there already */
    if (silc_server_client_on_channel(client, channel, NULL)) {
      SILC_LOG_DEBUG(("Client already on channel"));
      break;
    }

    /* Send to channel */
    silc_server_packet_send_to_channel(server, sock, channel, packet->type, 
				       FALSE, packet->buffer->data, 
				       packet->buffer->len, FALSE);

    if (server->server_type != SILC_ROUTER && 
	sock->type == SILC_SOCKET_TYPE_ROUTER)
      /* The channel is global now */
      channel->global_users = TRUE;

    SILC_LOG_DEBUG(("Joining to channel %s", channel->channel_name));

    /* JOIN the global client to the channel (local clients (if router 
       created the channel) is joined in the pending JOIN command). */
    chl = silc_calloc(1, sizeof(*chl));
    chl->client = client;
    chl->channel = channel;

    /* If this is the first one on the channel then it is the founder of
       the channel. */
    if (!silc_hash_table_count(channel->user_list))
      chl->mode = (SILC_CHANNEL_UMODE_CHANOP | SILC_CHANNEL_UMODE_CHANFO);

    silc_hash_table_add(channel->user_list, client, chl);
    silc_hash_table_add(client->channels, channel, chl);
    silc_free(client_id);
    channel->user_count++;

    break;

  case SILC_NOTIFY_TYPE_LEAVE:
    /* 
     * Distribute the notify to local clients on the channel
     */
    SILC_LOG_DEBUG(("LEAVE notify"));

    if (!channel_id) {
      channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				  packet->dst_id_type);
      if (!channel_id)
	goto out;
    }

    /* Get channel entry */
    channel = silc_idlist_find_channel_by_id(server->global_list, 
					     channel_id, NULL);
    if (!channel) { 
      channel = silc_idlist_find_channel_by_id(server->local_list, 
					       channel_id, NULL);
      if (!channel) {
	silc_free(channel_id);
	goto out;
      }
    }

    /* Get client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp) {
      silc_free(channel_id);
      goto out;
    }
    client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
    if (!client_id) {
      silc_free(channel_id);
      goto out;
    }

    /* Get client entry */
    client = silc_idlist_find_client_by_id(server->global_list, 
					   client_id, TRUE, NULL);
    if (!client) {
      client = silc_idlist_find_client_by_id(server->local_list, 
					     client_id, TRUE, NULL);
      if (!client) {
	silc_free(client_id);
	silc_free(channel_id);
	goto out;
      }
    }
    silc_free(client_id);

    /* Check if on channel */
    if (!silc_server_client_on_channel(client, channel, NULL))
      break;

    /* Send the leave notify to channel */
    silc_server_packet_send_to_channel(server, sock, channel, packet->type, 
				       FALSE, packet->buffer->data, 
				       packet->buffer->len, FALSE);

    /* Remove the user from channel */
    silc_server_remove_from_one_channel(server, sock, channel, client, FALSE);
    break;

  case SILC_NOTIFY_TYPE_SIGNOFF:
    /* 
     * Distribute the notify to local clients on the channel
     */
    SILC_LOG_DEBUG(("SIGNOFF notify"));

    /* Get client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;
    client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
    if (!client_id)
      goto out;

    /* Get client entry */
    client = silc_idlist_find_client_by_id(server->global_list, 
					   client_id, TRUE, &cache);
    if (!client) {
      client = silc_idlist_find_client_by_id(server->local_list, 
					     client_id, TRUE, &cache);
      if (!client) {
	silc_free(client_id);
	goto out;
      }
    }
    silc_free(client_id);

    /* Get signoff message */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (tmp_len > 128)
      tmp = NULL;

    /* Update statistics */
    server->stat.clients--;
    if (server->server_type == SILC_ROUTER)
      server->stat.cell_clients--;
    SILC_OPER_STATS_UPDATE(client, server, SILC_UMODE_SERVER_OPERATOR);
    SILC_OPER_STATS_UPDATE(client, router, SILC_UMODE_ROUTER_OPERATOR);

    /* Remove the client from all channels. */
    silc_server_remove_from_channels(server, NULL, client, TRUE, tmp, FALSE);

    client->data.status &= ~SILC_IDLIST_STATUS_REGISTERED;
    cache->expire = SILC_ID_CACHE_EXPIRE_DEF;
    break;

  case SILC_NOTIFY_TYPE_TOPIC_SET:
    /* 
     * Distribute the notify to local clients on the channel
     */

    SILC_LOG_DEBUG(("TOPIC SET notify"));

    /* Get client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;
    client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
    if (!client_id)
      goto out;

    /* Get client entry */
    client = silc_idlist_find_client_by_id(server->global_list, 
					   client_id, TRUE, &cache);
    if (!client) {
      client = silc_idlist_find_client_by_id(server->local_list, 
					     client_id, TRUE, &cache);
      if (!client) {
	silc_free(client_id);
	goto out;
      }
    }
    silc_free(client_id);

    /* Get the topic */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp) {
      silc_free(channel_id);
      goto out;
    }

    if (channel->topic && !strcmp(channel->topic, tmp))
      goto out;

    if (!channel_id) {
      channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				  packet->dst_id_type);
      if (!channel_id)
	goto out;
    }

    /* Get channel entry */
    channel = silc_idlist_find_channel_by_id(server->global_list, 
					     channel_id, NULL);
    if (!channel) {
      channel = silc_idlist_find_channel_by_id(server->local_list, 
					       channel_id, NULL);
      if (!channel) {
	silc_free(channel_id);
	goto out;
      }
    }

    /* Get user's channel entry and check that topic set is allowed. */
    if (!silc_server_client_on_channel(client, channel, &chl))
      goto out;
    if (chl->mode == SILC_CHANNEL_UMODE_NONE && 
	channel->mode & SILC_CHANNEL_MODE_TOPIC) {
      SILC_LOG_DEBUG(("Topic change is not allowed"));
      goto out;
    }

    /* Change the topic */
    silc_free(channel->topic);
    channel->topic = strdup(tmp);

    /* Send the same notify to the channel */
    silc_server_packet_send_to_channel(server, sock, channel, packet->type, 
				       FALSE, packet->buffer->data, 
				       packet->buffer->len, FALSE);
    silc_free(channel_id);
    break;

  case SILC_NOTIFY_TYPE_NICK_CHANGE:
    {
      /* 
       * Distribute the notify to local clients on the channel
       */
      unsigned char *id, *id2;

      SILC_LOG_DEBUG(("NICK CHANGE notify"));
      
      /* Get old client ID */
      id = silc_argument_get_arg_type(args, 1, &tmp_len);
      if (!id)
	goto out;
      client_id = silc_id_payload_parse_id(id, tmp_len, NULL);
      if (!client_id)
	goto out;
      
      /* Get new client ID */
      id2 = silc_argument_get_arg_type(args, 2, &tmp_len);
      if (!id2)
	goto out;
      client_id2 = silc_id_payload_parse_id(id2, tmp_len, NULL);
      if (!client_id2)
	goto out;
      
      SILC_LOG_DEBUG(("Old Client ID id(%s)", 
		      silc_id_render(client_id, SILC_ID_CLIENT)));
      SILC_LOG_DEBUG(("New Client ID id(%s)", 
		      silc_id_render(client_id2, SILC_ID_CLIENT)));

      /* Replace the Client ID */
      client = silc_idlist_replace_client_id(server->global_list, client_id,
					     client_id2);
      if (!client)
	client = silc_idlist_replace_client_id(server->local_list, client_id, 
					       client_id2);

      if (client) {
	/* The nickname is not valid anymore, set it NULL. This causes that
	   the nickname will be queried if someone wants to know it. */
	if (client->nickname)
	  silc_free(client->nickname);
	client->nickname = NULL;

	/* Send the NICK_CHANGE notify type to local clients on the channels
	   this client is joined to. */
	silc_server_send_notify_on_channels(server, NULL, client, 
					    SILC_NOTIFY_TYPE_NICK_CHANGE, 2,
					    id, tmp_len, 
					    id2, tmp_len);
      }

      silc_free(client_id);
      if (!client)
	silc_free(client_id2);
      break;
    }

  case SILC_NOTIFY_TYPE_CMODE_CHANGE:
    /* 
     * Distribute the notify to local clients on the channel
     */
    
    SILC_LOG_DEBUG(("CMODE CHANGE notify"));
      
    /* Get client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;
    client_id = silc_id_payload_parse_id(tmp, tmp_len, &id_type);
    if (!client_id)
      goto out;

    /* Get client entry */
    if (id_type == SILC_ID_CLIENT) {
      client = silc_idlist_find_client_by_id(server->global_list, 
					     client_id, TRUE, &cache);
      if (!client) {
	client = silc_idlist_find_client_by_id(server->local_list, 
					       client_id, TRUE, &cache);
	if (!client) {
	  silc_free(client_id);
	  goto out;
	}
      }
      silc_free(client_id);
    }

    if (!channel_id) {
      channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				  packet->dst_id_type);
      if (!channel_id)
	goto out;
    }

    /* Get channel entry */
    channel = silc_idlist_find_channel_by_id(server->global_list, 
					     channel_id, NULL);
    if (!channel) {
      channel = silc_idlist_find_channel_by_id(server->local_list, 
					       channel_id, NULL);
      if (!channel) {
	silc_free(channel_id);
	goto out;
      }
    }
    silc_free(channel_id);

    /* Get the mode */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;
    SILC_GET32_MSB(mode, tmp);

    /* Check if mode changed */
    if (channel->mode == mode)
      break;

    /* Get user's channel entry and check that mode change is allowed */
    if (client) {
      if (!silc_server_client_on_channel(client, channel, &chl))
	goto out;
      if (!silc_server_check_cmode_rights(server, channel, chl, mode)) {
	SILC_LOG_DEBUG(("CMODE change is not allowed"));
	goto out;
      }
    }

    /* Send the same notify to the channel */
    silc_server_packet_send_to_channel(server, sock, channel, packet->type, 
				       FALSE, packet->buffer->data, 
				       packet->buffer->len, FALSE);

    /* If the channel had private keys set and the mode was removed then
       we must re-generate and re-distribute a new channel key */
    if (channel->mode & SILC_CHANNEL_MODE_PRIVKEY &&
	!(mode & SILC_CHANNEL_MODE_PRIVKEY)) {
      /* Re-generate channel key */
      if (!silc_server_create_channel_key(server, channel, 0))
	goto out;
      
      /* Send the channel key. This sends it to our local clients and if
	 we are normal server to our router as well. */
      silc_server_send_channel_key(server, NULL, channel, 
				   server->server_type == SILC_ROUTER ? 
				   FALSE : !server->standalone);
    }

    /* Change mode */
    channel->mode = mode;

    /* Get the hmac */
    tmp = silc_argument_get_arg_type(args, 4, &tmp_len);
    if (tmp) {
      unsigned char hash[32];

      if (channel->hmac)
	silc_hmac_free(channel->hmac);
      if (!silc_hmac_alloc(tmp, NULL, &channel->hmac))
	goto out;

      /* Set the HMAC key out of current channel key. The client must do
	 this locally. */
      silc_hash_make(silc_hmac_get_hash(channel->hmac), channel->key, 
		     channel->key_len / 8, 
		     hash);
      silc_hmac_set_key(channel->hmac, hash, 
			silc_hash_len(silc_hmac_get_hash(channel->hmac)));
      memset(hash, 0, sizeof(hash));
    }

    /* Get the passphrase */
    tmp = silc_argument_get_arg_type(args, 5, &tmp_len);
    if (tmp) {
      silc_free(channel->passphrase);
      channel->passphrase = strdup(tmp);
    }

    break;

  case SILC_NOTIFY_TYPE_CUMODE_CHANGE:
    {
      /* 
       * Distribute the notify to local clients on the channel
       */
      SilcChannelClientEntry chl2 = NULL;
      bool notify_sent = FALSE;
      
      SILC_LOG_DEBUG(("CUMODE CHANGE notify"));
      
      /* Get client ID */
      tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
      if (!tmp)
	goto out;
      client_id = silc_id_payload_parse_id(tmp, tmp_len, &id_type);
      if (!client_id)
	goto out;

      /* Get client entry */
      if (id_type == SILC_ID_CLIENT) {
	client = silc_idlist_find_client_by_id(server->global_list, 
					       client_id, TRUE, &cache);
	if (!client) {
	  client = silc_idlist_find_client_by_id(server->local_list, 
						 client_id, TRUE, &cache);
	  if (!client) {
	    silc_free(client_id);
	    goto out;
	  }
	}
	silc_free(client_id);
      }

      if (!channel_id) {
	channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				    packet->dst_id_type);
	if (!channel_id)
	  goto out;
      }

      /* Get channel entry */
      channel = silc_idlist_find_channel_by_id(server->global_list, 
					       channel_id, NULL);
      if (!channel) {
	channel = silc_idlist_find_channel_by_id(server->local_list, 
						 channel_id, NULL);
	if (!channel) {
	  silc_free(channel_id);
	  goto out;
	}
      }

      /* Get the mode */
      tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
      if (!tmp) {
	silc_free(channel_id);
	goto out;
      }
      
      SILC_GET32_MSB(mode, tmp);
      
      /* Get target client */
      tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
      if (!tmp)
	goto out;
      client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
      if (!client_id)
	goto out;
      
      /* Get client entry */
      client2 = silc_idlist_find_client_by_id(server->global_list, 
					      client_id, TRUE, NULL);
      if (!client2) {
	client2 = silc_idlist_find_client_by_id(server->local_list, 
						client_id, TRUE, NULL);
	if (!client2) {
	  silc_free(client_id);
	  goto out;
	}
      }
      silc_free(client_id);

      if (client) {
	/* Check that sender is on channel */
	if (!silc_server_client_on_channel(client, channel, &chl))
	  goto out;
	
	if (client != client2) {
	  /* Sender must be operator */
	  if (chl->mode == SILC_CHANNEL_UMODE_NONE) {
	    SILC_LOG_DEBUG(("CUMODE change is not allowed"));
	    goto out;
	  }

	  /* Check that target is on channel */
	  if (!silc_server_client_on_channel(client2, channel, &chl))
	    goto out;

	  /* If target is founder mode change is not allowed. */
	  if (chl->mode & SILC_CHANNEL_UMODE_CHANFO) {
	    SILC_LOG_DEBUG(("CUMODE change is not allowed"));
	    goto out;
	  }
	}
      }

      /* Get entry to the channel user list */
      silc_hash_table_list(channel->user_list, &htl);
      while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
	/* If the mode is channel founder and we already find a client 
	   to have that mode on the channel we will enforce the sender
	   to change the channel founder mode away. There can be only one
	   channel founder on the channel. */
	if (server->server_type == SILC_ROUTER &&
	    mode & SILC_CHANNEL_UMODE_CHANFO &&
	    chl->mode & SILC_CHANNEL_UMODE_CHANFO) {
	  SilcBuffer idp;
	  unsigned char cumode[4];

	  if (chl->client == client && chl->mode == mode) {
	    notify_sent = TRUE;
	    break;
	  }

	  mode &= ~SILC_CHANNEL_UMODE_CHANFO;
	  silc_server_send_notify_cumode(server, sock, FALSE, channel, mode,
					 client2->id, SILC_ID_CLIENT,
					 client2->id);
	  
	  idp = silc_id_payload_encode(client2->id, SILC_ID_CLIENT);
	  SILC_PUT32_MSB(mode, cumode);
	  silc_server_send_notify_to_channel(server, sock, channel, FALSE, 
					     SILC_NOTIFY_TYPE_CUMODE_CHANGE,
					     3, idp->data, idp->len,
					     cumode, 4,
					     idp->data, idp->len);
	  silc_buffer_free(idp);
	  notify_sent = TRUE;

	  /* Force the mode change if we alredy set the mode */
	  if (chl2) {
	    chl2->mode = mode;
	    silc_free(channel_id);
	    silc_hash_table_list_reset(&htl);
	    goto out;
	  }
	}
	
	if (chl->client == client2) {
	  if (chl->mode == mode) {
	    notify_sent = TRUE;
	    break;
	  }

	  SILC_LOG_DEBUG(("Changing the channel user mode"));

	  /* Change the mode */
	  chl->mode = mode;
	  if (!(mode & SILC_CHANNEL_UMODE_CHANFO))
	    break;
	  
	  chl2 = chl;
	}
      }
      silc_hash_table_list_reset(&htl);
      
      /* Send the same notify to the channel */
      if (!notify_sent)
	silc_server_packet_send_to_channel(server, sock, channel, 
					   packet->type, 
					   FALSE, packet->buffer->data, 
					   packet->buffer->len, FALSE);
      
      silc_free(channel_id);
      break;
    }

  case SILC_NOTIFY_TYPE_INVITE:

    if (packet->dst_id_type == SILC_ID_CLIENT)
      goto out;

    SILC_LOG_DEBUG(("INVITE notify"));

    /* Get Channel ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;
    channel_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
    if (!channel_id)
      goto out;

    /* Get channel entry */
    channel = silc_idlist_find_channel_by_id(server->global_list, 
					     channel_id, NULL);
    if (!channel) {
      channel = silc_idlist_find_channel_by_id(server->local_list, 
					       channel_id, NULL);
      if (!channel) {
	silc_free(channel_id);
	goto out;
      }
    }
    silc_free(channel_id);

    /* Get client ID */
    tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
    if (!tmp)
      goto out;
    client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
    if (!client_id)
      goto out;

    /* Get client entry */
    client = silc_idlist_find_client_by_id(server->global_list, 
					   client_id, TRUE, &cache);
    if (!client) {
      client = silc_idlist_find_client_by_id(server->local_list, 
					     client_id, TRUE, &cache);
      if (!client) {
	silc_free(client_id);
	goto out;
      }
    }
    silc_free(client_id);

    /* Get user's channel entry and check that inviting is allowed. */
    if (!silc_server_client_on_channel(client, channel, &chl))
      goto out;
    if (chl->mode == SILC_CHANNEL_UMODE_NONE && 
	channel->mode & SILC_CHANNEL_MODE_INVITE) {
      SILC_LOG_DEBUG(("Inviting is not allowed"));
      goto out;
    }

    /* Get the added invite */
    tmp = silc_argument_get_arg_type(args, 4, &tmp_len);
    if (tmp) {
      if (!channel->invite_list)
	channel->invite_list = silc_calloc(tmp_len + 2, 
					   sizeof(*channel->invite_list));
      else
	channel->invite_list = silc_realloc(channel->invite_list, 
					    sizeof(*channel->invite_list) * 
					    (tmp_len + 
					     strlen(channel->invite_list) + 
					     2));
      if (tmp[tmp_len - 1] == ',')
	tmp[tmp_len - 1] = '\0';
      
      strncat(channel->invite_list, tmp, tmp_len);
      strncat(channel->invite_list, ",", 1);
    }

    /* Get the deleted invite */
    tmp = silc_argument_get_arg_type(args, 5, &tmp_len);
    if (tmp && channel->invite_list) {
      char *start, *end, *n;
      
      if (!strncmp(channel->invite_list, tmp, 
		   strlen(channel->invite_list) - 1)) {
	silc_free(channel->invite_list);
	channel->invite_list = NULL;
      } else {
	start = strstr(channel->invite_list, tmp);
	if (start && strlen(start) >= tmp_len) {
	  end = start + tmp_len;
	  n = silc_calloc(strlen(channel->invite_list) - tmp_len, sizeof(*n));
	  strncat(n, channel->invite_list, start - channel->invite_list);
	  strncat(n, end + 1, ((channel->invite_list + 
				strlen(channel->invite_list)) - end) - 1);
	  silc_free(channel->invite_list);
	  channel->invite_list = n;
	}
      }
    }

    break;

  case SILC_NOTIFY_TYPE_CHANNEL_CHANGE:
    /*
     * Distribute to the local clients on the channel and change the
     * channel ID.
     */

    SILC_LOG_DEBUG(("CHANNEL CHANGE"));

    if (sock->type != SILC_SOCKET_TYPE_ROUTER)
      break;

    /* Get the old Channel ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;
    channel_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
    if (!channel_id)
      goto out;

    /* Get the channel entry */
    channel = silc_idlist_find_channel_by_id(server->local_list, 
					     channel_id, NULL);
    if (!channel) {
      channel = silc_idlist_find_channel_by_id(server->global_list, 
					       channel_id, NULL);
      if (!channel) {
	silc_free(channel_id);
	goto out;
      }
    }

    /* Send the notify to the channel */
    silc_server_packet_send_to_channel(server, sock, channel, packet->type, 
				       FALSE, packet->buffer->data, 
				       packet->buffer->len, FALSE);

    /* Get the new Channel ID */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;
    channel_id2 = silc_id_payload_parse_id(tmp, tmp_len, NULL);
    if (!channel_id2)
      goto out;

    SILC_LOG_DEBUG(("Old Channel ID id(%s)", 
		    silc_id_render(channel_id, SILC_ID_CHANNEL)));
    SILC_LOG_DEBUG(("New Channel ID id(%s)", 
		    silc_id_render(channel_id2, SILC_ID_CHANNEL)));

    /* Replace the Channel ID */
    if (!silc_idlist_replace_channel_id(server->local_list, channel_id,
					channel_id2))
      if (!silc_idlist_replace_channel_id(server->global_list, channel_id,
					  channel_id2)) {
	silc_free(channel_id2);
	channel_id2 = NULL;
      }

    if (channel_id2) {
      SilcBuffer users = NULL, users_modes = NULL;

      /* Re-announce this channel which ID was changed. */
      silc_server_send_new_channel(server, sock, FALSE, channel->channel_name,
				   channel->id, 
				   silc_id_get_len(channel->id, 
						   SILC_ID_CHANNEL),
				   channel->mode);

      /* Re-announce our clients on the channel as the ID has changed now */
      silc_server_announce_get_channel_users(server, channel, &users,
					     &users_modes);
      if (users) {
	silc_buffer_push(users, users->data - users->head);
	silc_server_packet_send(server, sock,
				SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
				users->data, users->len, FALSE);
	silc_buffer_free(users);
      }
      if (users_modes) {
	silc_buffer_push(users_modes, users_modes->data - users_modes->head);
	silc_server_packet_send_dest(server, sock,
				     SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
				     channel->id, SILC_ID_CHANNEL,
				     users_modes->data, 
				     users_modes->len, FALSE);
	silc_buffer_free(users_modes);
      }

      /* Re-announce channel's topic */
      if (channel->topic) {
	silc_server_send_notify_topic_set(server, sock,
					  server->server_type == SILC_ROUTER ?
					  TRUE : FALSE, channel, 
					  channel->id, SILC_ID_CHANNEL,
					  channel->topic);
      }
    }

    silc_free(channel_id);

    break;

  case SILC_NOTIFY_TYPE_SERVER_SIGNOFF:
    /* 
     * Remove the server entry and all clients that this server owns.
     */

    SILC_LOG_DEBUG(("SERVER SIGNOFF notify"));

    /* Get Server ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;
    server_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
    if (!server_id)
      goto out;

    /* Get server entry */
    server_entry = silc_idlist_find_server_by_id(server->global_list, 
						 server_id, TRUE, NULL);
    local = TRUE;
    if (!server_entry) {
      server_entry = silc_idlist_find_server_by_id(server->local_list, 
						   server_id, TRUE, NULL);
      local = TRUE;
      if (!server_entry) {
	/* If we are normal server then we might not have the server. Check
	   whether router was kind enough to send the list of all clients
	   that actually was to be removed. Remove them if the list is
	   available. */
	if (server->server_type != SILC_ROUTER &&
	    silc_argument_get_arg_num(args) > 1) {
	  int i;

	  for (i = 1; i < silc_argument_get_arg_num(args); i++) {
	    /* Get Client ID */
	    tmp = silc_argument_get_arg_type(args, i + 1, &tmp_len);
	    if (!tmp)
	      continue;
	    client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
	    if (!client_id)
	      continue;

	    /* Get client entry */
	    client = silc_idlist_find_client_by_id(server->global_list, 
						   client_id, TRUE, &cache);
	    local = TRUE;
	    if (!client) {
	      client = silc_idlist_find_client_by_id(server->local_list, 
						     client_id, TRUE, &cache);
	      local = FALSE;
	      if (!client) {
		silc_free(client_id);
		continue;
	      }
	    }
	    silc_free(client_id);

	    /* Update statistics */
	    server->stat.clients--;
	    if (server->server_type == SILC_ROUTER)
	      server->stat.cell_clients--;
	    SILC_OPER_STATS_UPDATE(client, server, SILC_UMODE_SERVER_OPERATOR);
	    SILC_OPER_STATS_UPDATE(client, router, SILC_UMODE_ROUTER_OPERATOR);

	    /* Remove the client from all channels. */
	    silc_server_remove_from_channels(server, NULL, client, 
					     TRUE, NULL, FALSE);

	    /* Remove the client */
	    silc_idlist_del_client(local ? server->local_list :
				   server->global_list, client);
	  }
	}

	silc_free(server_id);
	goto out;
      }
    }
    silc_free(server_id);

    /* Free all client entries that this server owns as they will
       become invalid now as well. */
    silc_server_remove_clients_by_server(server, server_entry, TRUE);

    /* Remove the server entry */
    silc_idlist_del_server(local ? server->local_list :
			   server->global_list, server_entry);

    /* XXX update statistics */

    break;

  case SILC_NOTIFY_TYPE_KICKED:
    /* 
     * Distribute the notify to local clients on the channel
     */
    
    SILC_LOG_DEBUG(("KICKED notify"));
      
    if (!channel_id) {
      channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				  packet->dst_id_type);
      if (!channel_id)
	goto out;
    }

    /* Get channel entry */
    channel = silc_idlist_find_channel_by_id(server->global_list, 
					     channel_id, NULL);
    if (!channel) {
      channel = silc_idlist_find_channel_by_id(server->local_list, 
					       channel_id, NULL);
      if (!channel) {
	silc_free(channel_id);
	goto out;
      }
    }
    silc_free(channel_id);

    /* Get client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;
    client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
    if (!client_id)
      goto out;

    /* If the the client is not in local list we check global list */
    client = silc_idlist_find_client_by_id(server->global_list, 
					   client_id, TRUE, NULL);
    if (!client) {
      client = silc_idlist_find_client_by_id(server->local_list, 
					     client_id, TRUE, NULL);
      if (!client) {
	silc_free(client_id);
	goto out;
      }
    }
    silc_free(client_id);

    /* If target is founder they cannot be kicked */
    if (!silc_server_client_on_channel(client, channel, &chl))
      goto out;
    if (chl->mode & SILC_CHANNEL_UMODE_CHANFO)
      goto out;
    
    /* Get kicker. In protocol version 1.0 this is not mandatory argument
       so we check it only if it is provided. */
    tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
    if (tmp) {
      client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
      if (!client_id)
	goto out;

      /* If the the client is not in local list we check global list */
      client2 = silc_idlist_find_client_by_id(server->global_list, 
					      client_id, TRUE, NULL);
      if (!client2) {
	client2 = silc_idlist_find_client_by_id(server->local_list, 
						client_id, TRUE, NULL);
	if (!client2) {
	  silc_free(client_id);
	  goto out;
	}
      }
      silc_free(client_id);

      /* Kicker must be operator on channel */
      if (!silc_server_client_on_channel(client2, channel, &chl))
	goto out;
      if (chl->mode == SILC_CHANNEL_UMODE_NONE) {
	SILC_LOG_DEBUG(("Kicking is not allowed"));
	goto out;
      }
    }

    /* Send to channel */
    silc_server_packet_send_to_channel(server, sock, channel, packet->type, 
				       FALSE, packet->buffer->data, 
				       packet->buffer->len, FALSE);

    /* Remove the client from channel */
    silc_server_remove_from_one_channel(server, sock, channel, client, FALSE);

    break;

  case SILC_NOTIFY_TYPE_KILLED:
    {
      /* 
       * Distribute the notify to local clients on channels
       */
      unsigned char *id;
      SilcUInt32 id_len;
    
      SILC_LOG_DEBUG(("KILLED notify"));
      
      /* Get client ID */
      id = silc_argument_get_arg_type(args, 1, &id_len);
      if (!id)
	goto out;
      client_id = silc_id_payload_parse_id(id, id_len, NULL);
      if (!client_id)
	goto out;

      /* If the the client is not in local list we check global list */
      client = silc_idlist_find_client_by_id(server->global_list, 
					     client_id, TRUE, NULL);
      if (!client) {
	client = silc_idlist_find_client_by_id(server->local_list, 
					       client_id, TRUE, NULL);
	if (!client) {
	  silc_free(client_id);
	  goto out;
	}
      }
      silc_free(client_id);

      /* If the client is one of ours, then close the connection to the
	 client now. This removes the client from all channels as well. */
      if (packet->dst_id_type == SILC_ID_CLIENT && client->connection) {
	sock = client->connection;
	silc_server_free_client_data(server, NULL, client, FALSE, NULL);
	silc_server_close_connection(server, sock);
	break;
      }

      /* Get comment */
      tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
      if (tmp_len > 128)
	tmp = NULL;

      /* Send the notify to local clients on the channels except to the
	 client who is killed. */
      silc_server_send_notify_on_channels(server, client, client,
					  SILC_NOTIFY_TYPE_KILLED, 
					  tmp ? 2 : 1,
					  id, id_len, 
					  tmp, tmp_len);

      /* Remove the client from all channels */
      silc_server_remove_from_channels(server, NULL, client, FALSE, NULL, 
				       FALSE);

      break;
    }

  case SILC_NOTIFY_TYPE_UMODE_CHANGE:
    /*
     * Save the mode of the client.
     */

    SILC_LOG_DEBUG(("UMODE_CHANGE notify"));

    /* Get client ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;
    client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
    if (!client_id)
      goto out;

    /* Get client entry */
    client = silc_idlist_find_client_by_id(server->global_list, 
					   client_id, TRUE, NULL);
    if (!client) {
      client = silc_idlist_find_client_by_id(server->local_list, 
					     client_id, TRUE, NULL);
      if (!client) {
	silc_free(client_id);
	goto out;
      }
    }
    silc_free(client_id);

    /* Get the mode */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp)
      goto out;
    SILC_GET32_MSB(mode, tmp);

    /* Check that mode changing is allowed. */
    if (!silc_server_check_umode_rights(server, client, mode)) {
      SILC_LOG_DEBUG(("UMODE change is not allowed"));
      goto out;
    }

    /* Change the mode */
    client->mode = mode;

    break;

  case SILC_NOTIFY_TYPE_BAN:
    /*
     * Save the ban
     */

    SILC_LOG_DEBUG(("BAN notify"));
    
    /* Get Channel ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;
    channel_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
    if (!channel_id)
      goto out;
    
    /* Get channel entry */
    channel = silc_idlist_find_channel_by_id(server->global_list, 
					     channel_id, NULL);
    if (!channel) {
      channel = silc_idlist_find_channel_by_id(server->local_list, 
					       channel_id, NULL);
      if (!channel) {
	silc_free(channel_id);
	goto out;
      }
    }
    silc_free(channel_id);

    /* Get the new ban and add it to the ban list */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (tmp) {
      if (!channel->ban_list)
	channel->ban_list = silc_calloc(tmp_len + 2, 
					sizeof(*channel->ban_list));
      else
	channel->ban_list = silc_realloc(channel->ban_list, 
					 sizeof(*channel->ban_list) * 
					 (tmp_len + 
					  strlen(channel->ban_list) + 2));
      strncat(channel->ban_list, tmp, tmp_len);
      strncat(channel->ban_list, ",", 1);
    }

    /* Get the ban to be removed and remove it from the list */
    tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
    if (tmp && channel->ban_list) {
      char *start, *end, *n;
      
      if (!strncmp(channel->ban_list, tmp, strlen(channel->ban_list) - 1)) {
	silc_free(channel->ban_list);
	channel->ban_list = NULL;
      } else {
	start = strstr(channel->ban_list, tmp);
	if (start && strlen(start) >= tmp_len) {
	  end = start + tmp_len;
	  n = silc_calloc(strlen(channel->ban_list) - tmp_len, sizeof(*n));
	  strncat(n, channel->ban_list, start - channel->ban_list);
	  strncat(n, end + 1, ((channel->ban_list + 
				strlen(channel->ban_list)) - end) - 1);
	  silc_free(channel->ban_list);
	  channel->ban_list = n;
	}
      }
    }
    break;

    /* Ignore rest of the notify types for now */
  case SILC_NOTIFY_TYPE_NONE:
  case SILC_NOTIFY_TYPE_MOTD:
    break;
  default:
    break;
  }

 out:
  silc_notify_payload_free(payload);
}

void silc_server_notify_list(SilcServer server,
			     SilcSocketConnection sock,
			     SilcPacketContext *packet)
{
  SilcPacketContext *new;
  SilcBuffer buffer;
  SilcUInt16 len;

  SILC_LOG_DEBUG(("Processing Notify List"));

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      packet->src_id_type != SILC_ID_SERVER)
    return;

  /* Make copy of the original packet context, except for the actual
     data buffer, which we will here now fetch from the original buffer. */
  new = silc_packet_context_alloc();
  new->type = SILC_PACKET_NOTIFY;
  new->flags = packet->flags;
  new->src_id = packet->src_id;
  new->src_id_len = packet->src_id_len;
  new->src_id_type = packet->src_id_type;
  new->dst_id = packet->dst_id;
  new->dst_id_len = packet->dst_id_len;
  new->dst_id_type = packet->dst_id_type;

  buffer = silc_buffer_alloc(1024);
  new->buffer = buffer;

  while (packet->buffer->len) {
    SILC_GET16_MSB(len, packet->buffer->data + 2);
    if (len > packet->buffer->len)
      break;

    if (len > buffer->truelen) {
      silc_buffer_free(buffer);
      buffer = silc_buffer_alloc(1024 + len);
    }

    silc_buffer_pull_tail(buffer, len);
    silc_buffer_put(buffer, packet->buffer->data, len);

    /* Process the Notify */
    silc_server_notify(server, sock, new);

    silc_buffer_push_tail(buffer, len);
    silc_buffer_pull(packet->buffer, len);
  }

  silc_buffer_free(buffer);
  silc_free(new);
}

/* Received private message. This resolves the destination of the message 
   and sends the packet. This is used by both server and router.  If the
   destination is our locally connected client this sends the packet to
   the client. This may also send the message for further routing if
   the destination is not in our server (or router). */

void silc_server_private_message(SilcServer server,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet)
{
  SilcSocketConnection dst_sock;
  SilcIDListData idata;

  SILC_LOG_DEBUG(("Start"));

  if (packet->src_id_type != SILC_ID_CLIENT ||
      packet->dst_id_type != SILC_ID_CLIENT || !packet->dst_id)
    return;

  /* Get the route to the client */
  dst_sock = silc_server_get_client_route(server, packet->dst_id,
					  packet->dst_id_len, NULL, &idata);
  if (!dst_sock) {
    /* Send IDENTIFY command reply with error status to indicate that
       such destination ID does not exist or is invalid */
    SilcBuffer idp = silc_id_payload_encode_data(packet->dst_id,
						 packet->dst_id_len,
						 packet->dst_id_type);
    if (!idp)
      return;

    if (packet->src_id_type == SILC_ID_CLIENT) {
      SilcClientID *client_id = silc_id_str2id(packet->src_id,
					       packet->src_id_len,
					       packet->src_id_type);
      silc_server_send_dest_command_reply(server, sock, 
					  client_id, SILC_ID_CLIENT,
					  SILC_COMMAND_IDENTIFY,
					  SILC_STATUS_ERR_NO_SUCH_CLIENT_ID, 
					  0, 1, 2, idp->data, idp->len);
      silc_free(client_id);
    } else {
      silc_server_send_command_reply(server, sock, SILC_COMMAND_IDENTIFY,
				     SILC_STATUS_ERR_NO_SUCH_CLIENT_ID, 
				     0, 1, 2, idp->data, idp->len);
    }

    silc_buffer_free(idp);
    return;
  }

  /* Send the private message */
  silc_server_send_private_message(server, dst_sock, idata->send_key,
				   idata->hmac_send, idata->psn_send++,
				   packet);
}

/* Received private message key packet.. This packet is never for us. It is to
   the client in the packet's destination ID. Sending of this sort of packet
   equals sending private message, ie. it is sent point to point from
   one client to another. */

void silc_server_private_message_key(SilcServer server,
				     SilcSocketConnection sock,
				     SilcPacketContext *packet)
{
  SilcSocketConnection dst_sock;
  SilcIDListData idata;

  SILC_LOG_DEBUG(("Start"));

  if (packet->src_id_type != SILC_ID_CLIENT ||
      packet->dst_id_type != SILC_ID_CLIENT)
    return;

  if (!packet->dst_id)
    return;

  /* Get the route to the client */
  dst_sock = silc_server_get_client_route(server, packet->dst_id,
					  packet->dst_id_len, NULL, &idata);
  if (!dst_sock)
    return;

  /* Relay the packet */
  silc_server_relay_packet(server, dst_sock, idata->send_key,
			   idata->hmac_send, idata->psn_send++, packet, FALSE);
}

/* Processes incoming command reply packet. The command reply packet may
   be destined to one of our clients or it may directly for us. We will 
   call the command reply routine after processing the packet. */

void silc_server_command_reply(SilcServer server,
			       SilcSocketConnection sock,
			       SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcClientEntry client = NULL;
  SilcSocketConnection dst_sock;
  SilcIDListData idata;
  SilcClientID *id = NULL;

  SILC_LOG_DEBUG(("Start"));

  /* Source must be server or router */
  if (packet->src_id_type != SILC_ID_SERVER &&
      sock->type != SILC_SOCKET_TYPE_ROUTER)
    return;

  if (packet->dst_id_type == SILC_ID_CHANNEL)
    return;

  if (packet->dst_id_type == SILC_ID_CLIENT) {
    /* Destination must be one of ours */
    id = silc_id_str2id(packet->dst_id, packet->dst_id_len, SILC_ID_CLIENT);
    if (!id)
      return;
    client = silc_idlist_find_client_by_id(server->local_list, id, TRUE, NULL);
    if (!client) {
      SILC_LOG_ERROR(("Cannot process command reply to unknown client"));
      silc_free(id);
      return;
    }
  }

  if (packet->dst_id_type == SILC_ID_SERVER) {
    /* For now this must be for us */
    if (memcmp(packet->dst_id, server->id_string, server->id_string_len)) {
      SILC_LOG_ERROR(("Cannot process command reply to unknown server"));
      return;
    }
  }

  /* Execute command reply locally for the command */
  silc_server_command_reply_process(server, sock, buffer);

  if (packet->dst_id_type == SILC_ID_CLIENT && client && id) {
    /* Relay the packet to the client */
    const SilcBufferStruct p;
    
    dst_sock = (SilcSocketConnection)client->connection;
    idata = (SilcIDListData)client;
    
    silc_buffer_push(buffer, SILC_PACKET_HEADER_LEN + packet->src_id_len 
		     + packet->dst_id_len + packet->padlen);
    if (!silc_packet_send_prepare(dst_sock, 0, 0, buffer->len,
                                  idata->hmac_send, (const SilcBuffer)&p)) {
      SILC_LOG_ERROR(("Cannot send packet"));
      return;
    }
    silc_buffer_put((SilcBuffer)&p, buffer->data, buffer->len);
    
    /* Encrypt packet */
    silc_packet_encrypt(idata->send_key, idata->hmac_send, idata->psn_send++,
			(SilcBuffer)&p, buffer->len);
    
    /* Send the packet */
    silc_server_packet_send_real(server, dst_sock, TRUE);

    silc_free(id);
  }
}

/* Process received channel message. The message can be originated from
   client or server. */

void silc_server_channel_message(SilcServer server,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet)
{
  SilcChannelEntry channel = NULL;
  SilcChannelID *id = NULL;
  void *sender_id = NULL;
  SilcClientEntry sender_entry = NULL;
  bool local = TRUE;

  SILC_LOG_DEBUG(("Processing channel message"));

  /* Sanity checks */
  if (packet->dst_id_type != SILC_ID_CHANNEL) {
    SILC_LOG_DEBUG(("Received bad message for channel, dropped"));
    goto out;
  }

  /* Find channel entry */
  id = silc_id_str2id(packet->dst_id, packet->dst_id_len, SILC_ID_CHANNEL);
  if (!id)
    goto out;
  channel = silc_idlist_find_channel_by_id(server->local_list, id, NULL);
  if (!channel) {
    channel = silc_idlist_find_channel_by_id(server->global_list, id, NULL);
    if (!channel) {
      SILC_LOG_DEBUG(("Could not find channel"));
      goto out;
    }
  }

  /* See that this client is on the channel. If the original sender is
     not client (as it can be server as well) we don't do the check. */
  sender_id = silc_id_str2id(packet->src_id, packet->src_id_len, 
			     packet->src_id_type);
  if (!sender_id)
    goto out;
  if (packet->src_id_type == SILC_ID_CLIENT) {
    sender_entry = silc_idlist_find_client_by_id(server->local_list, 
						 sender_id, TRUE, NULL);
    if (!sender_entry) {
      local = FALSE;
      sender_entry = silc_idlist_find_client_by_id(server->global_list, 
						   sender_id, TRUE, NULL);
    }
    if (!sender_entry || !silc_server_client_on_channel(sender_entry, 
							channel, NULL)) {
      SILC_LOG_DEBUG(("Client not on channel"));
      goto out;
    }

    /* If the packet is coming from router, but the client entry is local 
       entry to us then some router is rerouting this to us and it is not 
       allowed. When the client is local to us it means that we've routed
       this packet to network, and now someone is routing it back to us. */
    if (server->server_type == SILC_ROUTER &&
	sock->type == SILC_SOCKET_TYPE_ROUTER && local) {
      SILC_LOG_DEBUG(("Channel message rerouted to the sender, drop it"));
      goto out;
    }
  }

  /* Distribute the packet to our local clients. This will send the
     packet for further routing as well, if needed. */
  silc_server_packet_relay_to_channel(server, sock, channel, sender_id,
				      packet->src_id_type, sender_entry,
				      packet->buffer->data,
				      packet->buffer->len, FALSE);

 out:
  silc_free(sender_id);
  silc_free(id);
}

/* Received channel key packet. We distribute the key to all of our locally
   connected clients on the channel. */

void silc_server_channel_key(SilcServer server,
			     SilcSocketConnection sock,
			     SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcChannelEntry channel;

  if (packet->src_id_type != SILC_ID_SERVER ||
      (server->server_type == SILC_ROUTER &&
       sock->type == SILC_SOCKET_TYPE_ROUTER))
    return;

  /* Save the channel key */
  channel = silc_server_save_channel_key(server, buffer, NULL);
  if (!channel)
    return;

  /* Distribute the key to everybody who is on the channel. If we are router
     we will also send it to locally connected servers. */
  silc_server_send_channel_key(server, sock, channel, FALSE);
  
  if (server->server_type != SILC_BACKUP_ROUTER) {
    /* Distribute to local cell backup routers. */
    silc_server_backup_send(server, (SilcServerEntry)sock->user_data, 
			    SILC_PACKET_CHANNEL_KEY, 0,
			    buffer->data, buffer->len, FALSE, TRUE);
  }
}

/* Received New Client packet and processes it.  Creates Client ID for the
   client. Client becomes registered after calling this functions. */

SilcClientEntry silc_server_new_client(SilcServer server,
				       SilcSocketConnection sock,
				       SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcClientEntry client;
  SilcClientID *client_id;
  SilcBuffer reply;
  SilcIDListData idata;
  char *username = NULL, *realname = NULL, *id_string;
  SilcUInt16 username_len;
  SilcUInt32 id_len;
  int ret;
  char *hostname, *nickname;
  int nickfail = 0;

  SILC_LOG_DEBUG(("Creating new client"));

  if (sock->type != SILC_SOCKET_TYPE_CLIENT)
    return NULL;

  /* Take client entry */
  client = (SilcClientEntry)sock->user_data;
  idata = (SilcIDListData)client;

  /* Remove the old cache entry. */
  if (!silc_idcache_del_by_context(server->local_list->clients, client)) {
    SILC_LOG_INFO(("Unauthenticated client attempted to register to network"));
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
                                  "You have not been authenticated");
    return NULL;
  }

  /* Parse incoming packet */
  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI16_NSTRING_ALLOC(&username, 
							 &username_len),
			     SILC_STR_UI16_STRING_ALLOC(&realname),
			     SILC_STR_END);
  if (ret == -1) {
    silc_free(username);
    silc_free(realname);
    SILC_LOG_ERROR(("Client %s (%s) sent incomplete information, closing "
		    "connection", sock->hostname, sock->ip));
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
                                  "Incomplete client information");
    return NULL;
  }

  if (!username) {
    silc_free(username);
    silc_free(realname);
    SILC_LOG_ERROR(("Client %s (%s) did not send its username, closing "
		    "connection", sock->hostname, sock->ip));
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
                                  "Incomplete client information");
    return NULL;
  }

  if (username_len > 128)
    username[128] = '\0';

  /* Check for bad characters for nickname, and modify the nickname if
     it includes those. */
  if (silc_server_name_bad_chars(username, username_len)) {
    nickname = silc_server_name_modify_bad(username, username_len);
  } else {
    nickname = strdup(username);
  }

  /* Make sanity checks for the hostname of the client. If the hostname
     is provided in the `username' check that it is the same than the
     resolved hostname, or if not resolved the hostname that appears in
     the client's public key. If the hostname is not present then put
     it from the resolved name or from the public key. */
  if (strchr(username, '@')) {
    SilcPublicKeyIdentifier pident;
    int tlen = strcspn(username, "@");
    char *phostname = NULL;

    hostname = silc_memdup(username + tlen + 1, strlen(username) - tlen - 1);

    if (strcmp(sock->hostname, sock->ip) && 
	strcmp(sock->hostname, hostname)) {
      silc_free(username);
      silc_free(hostname);
      silc_free(realname);
      SILC_LOG_ERROR(("Client %s (%s) sent incomplete information, closing "
		      "connection", sock->hostname, sock->ip));
      silc_server_disconnect_remote(server, sock, 
				    "Server closed connection: "
				    "Incomplete client information");
      return NULL;
    }
    
    pident = silc_pkcs_decode_identifier(client->data.public_key->identifier);
    if (pident) {
      phostname = strdup(pident->host);
      silc_pkcs_free_identifier(pident);
    }

    if (!strcmp(sock->hostname, sock->ip) && 
	phostname && strcmp(phostname, hostname)) {
      silc_free(username);
      silc_free(hostname);
      silc_free(phostname);
      silc_free(realname);
      SILC_LOG_ERROR(("Client %s (%s) sent incomplete information, closing "
		      "connection", sock->hostname, sock->ip));
      silc_server_disconnect_remote(server, sock, 
				    "Server closed connection: "
				    "Incomplete client information");
      return NULL;
    }
    
    silc_free(phostname);
  } else {
    /* The hostname is not present, add it. */
    char *newusername;
    /* XXX For now we cannot take the host name from the public key since
       they are not trusted or we cannot verify them as trusted. Just take
       what the resolved name or address is. */
#if 0
    if (strcmp(sock->hostname, sock->ip)) {
#endif
      newusername = silc_calloc(strlen(username) + 
				strlen(sock->hostname) + 2,
				sizeof(*newusername));
      strncat(newusername, username, strlen(username));
      strncat(newusername, "@", 1);
      strncat(newusername, sock->hostname, strlen(sock->hostname));
      silc_free(username);
      username = newusername;
#if 0
    } else {
      SilcPublicKeyIdentifier pident = 
	silc_pkcs_decode_identifier(client->data.public_key->identifier);
      
      if (pident) {
	newusername = silc_calloc(strlen(username) + 
				  strlen(pident->host) + 2,
				  sizeof(*newusername));
	strncat(newusername, username, strlen(username));
	strncat(newusername, "@", 1);
	strncat(newusername, pident->host, strlen(pident->host));
	silc_free(username);
	username = newusername;
	silc_pkcs_free_identifier(pident);
      }
    }
#endif
  }

  /* Create Client ID */
  while (!silc_id_create_client_id(server, server->id, server->rng, 
				   server->md5hash, nickname, &client_id)) {
    nickfail++;
    snprintf(&nickname[strlen(nickname) - 1], 1, "%d", nickfail);
  }

  /* Update client entry */
  idata->status |= SILC_IDLIST_STATUS_REGISTERED;
  client->nickname = nickname;
  client->username = username;
  client->userinfo = realname ? realname : strdup(" ");
  client->id = client_id;
  id_len = silc_id_get_len(client_id, SILC_ID_CLIENT);

  /* Add the client again to the ID cache */
  silc_idcache_add(server->local_list->clients, client->nickname,
		   client_id, client, 0, NULL);

  /* Notify our router about new client on the SILC network */
  if (!server->standalone)
    silc_server_send_new_id(server, (SilcSocketConnection) 
			    server->router->connection, 
			    server->server_type == SILC_ROUTER ? TRUE : FALSE,
			    client->id, SILC_ID_CLIENT, id_len);
  
  /* Send the new client ID to the client. */
  id_string = silc_id_id2str(client->id, SILC_ID_CLIENT);
  reply = silc_buffer_alloc(2 + 2 + id_len);
  silc_buffer_pull_tail(reply, SILC_BUFFER_END(reply));
  silc_buffer_format(reply,
		     SILC_STR_UI_SHORT(SILC_ID_CLIENT),
		     SILC_STR_UI_SHORT(id_len),
		     SILC_STR_UI_XNSTRING(id_string, id_len),
		     SILC_STR_END);
  silc_server_packet_send(server, sock, SILC_PACKET_NEW_ID, 0, 
			  reply->data, reply->len, FALSE);
  silc_free(id_string);
  silc_buffer_free(reply);

  /* Send some nice info to the client */
  SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			  ("Welcome to the SILC Network %s",
			   username));
  SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			  ("Your host is %s, running version %s",
			   server->server_name, server_version));
  if (server->server_type == SILC_ROUTER) {
    SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			    ("There are %d clients on %d servers in SILC "
			     "Network", server->stat.clients,
			     server->stat.servers + 1));
    SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			    ("There are %d clients on %d server in our cell",
			     server->stat.cell_clients,
			     server->stat.cell_servers + 1));
    SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			    ("I have %d clients, %d channels, %d servers and "
			     "%d routers",
			     server->stat.my_clients, 
			     server->stat.my_channels,
			     server->stat.my_servers,
			     server->stat.my_routers));
    SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			    ("There are %d server operators and %d router "
			     "operators online",
			     server->stat.server_ops,
			     server->stat.router_ops));
    SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			    ("I have %d operators online",
			     server->stat.my_router_ops +
			     server->stat.my_server_ops));
  } else {
    SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			    ("I have %d clients and %d channels formed",
			     server->stat.my_clients,
			     server->stat.my_channels));
    SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			    ("%d operators online",
			     server->stat.my_server_ops));
  }
  SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			  ("Your connection is secured with %s cipher, "
			   "key length %d bits",
			   idata->send_key->cipher->name,
			   idata->send_key->cipher->key_len));
  SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			  ("Your current nickname is %s",
			   client->nickname));

  /* Send motd */
  silc_server_send_motd(server, sock);

  return client;
}

/* Create new server. This processes received New Server packet and
   saves the received Server ID. The server is our locally connected
   server thus we save all the information and save it to local list. 
   This funtion can be used by both normal server and router server.
   If normal server uses this it means that its router has connected
   to the server. If router uses this it means that one of the cell's
   servers is connected to the router. */

SilcServerEntry silc_server_new_server(SilcServer server,
				       SilcSocketConnection sock,
				       SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcServerEntry new_server, server_entry;
  SilcServerID *server_id;
  SilcIDListData idata;
  unsigned char *server_name, *id_string;
  SilcUInt16 id_len, name_len;
  int ret;
  bool local = TRUE;

  SILC_LOG_DEBUG(("Creating new server"));

  if (sock->type != SILC_SOCKET_TYPE_SERVER &&
      sock->type != SILC_SOCKET_TYPE_ROUTER)
    return NULL;

  /* Take server entry */
  new_server = (SilcServerEntry)sock->user_data;
  idata = (SilcIDListData)new_server;

  /* Remove the old cache entry */
  if (!silc_idcache_del_by_context(server->local_list->servers, new_server)) {
    if (!silc_idcache_del_by_context(server->global_list->servers, 
				     new_server)) {
      SILC_LOG_INFO(("Unauthenticated %s attempted to register to "
		     "network", (sock->type == SILC_SOCKET_TYPE_SERVER ?
				 "server" : "router")));
      silc_server_disconnect_remote(server, sock, "Server closed connection: "
				    "You have not been authenticated");
      return NULL;
    }
    local = FALSE;
  }

  /* Parse the incoming packet */
  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI16_NSTRING_ALLOC(&id_string, &id_len),
			     SILC_STR_UI16_NSTRING_ALLOC(&server_name, 
							 &name_len),
			     SILC_STR_END);
  if (ret == -1) {
    if (id_string)
      silc_free(id_string);
    if (server_name)
      silc_free(server_name);
    return NULL;
  }

  if (id_len > buffer->len) {
    silc_free(id_string);
    silc_free(server_name);
    return NULL;
  }

  if (name_len > 256)
    server_name[255] = '\0';

  /* Get Server ID */
  server_id = silc_id_str2id(id_string, id_len, SILC_ID_SERVER);
  if (!server_id) {
    silc_free(id_string);
    silc_free(server_name);
    return NULL;
  }
  silc_free(id_string);

  /* Check for valid server ID */
  if (!silc_id_is_valid_server_id(server, server_id, sock)) {
    SILC_LOG_INFO(("Invalid server ID sent by %s (%s)",
		   sock->ip, sock->hostname));
    silc_server_disconnect_remote(server, sock, "Server closed connection: "
				  "Your Server ID is not valid");
    silc_free(server_name);
    return NULL;
  }

  /* Check that we do not have this ID already */
  server_entry = silc_idlist_find_server_by_id(server->local_list, 
					       server_id, TRUE, NULL);
  if (server_entry) {
    silc_idcache_del_by_context(server->local_list->servers, server_entry);
  } else {
    server_entry = silc_idlist_find_server_by_id(server->global_list, 
						 server_id, TRUE, NULL);
    if (server_entry) 
      silc_idcache_del_by_context(server->global_list->servers, server_entry);
  }

  /* Update server entry */
  idata->status |= SILC_IDLIST_STATUS_REGISTERED;
  new_server->server_name = server_name;
  new_server->id = server_id;
  
  SILC_LOG_DEBUG(("New server id(%s)",
		  silc_id_render(server_id, SILC_ID_SERVER)));

  /* Add again the entry to the ID cache. */
  silc_idcache_add(local ? server->local_list->servers : 
		   server->global_list->servers, server_name, server_id, 
		   new_server, 0, NULL);

  /* Distribute the information about new server in the SILC network
     to our router. If we are normal server we won't send anything
     since this connection must be our router connection. */
  if (server->server_type == SILC_ROUTER && !server->standalone &&
      server->router->connection != sock)
    silc_server_send_new_id(server, server->router->connection,
			    TRUE, new_server->id, SILC_ID_SERVER, 
			    silc_id_get_len(server_id, SILC_ID_SERVER));

  if (server->server_type == SILC_ROUTER)
    server->stat.cell_servers++;

  /* Check whether this router connection has been replaced by an
     backup router. If it has been then we'll disable the server and will
     ignore everything it will send until the backup router resuming
     protocol has been completed. */
  if (sock->type == SILC_SOCKET_TYPE_ROUTER &&
      silc_server_backup_replaced_get(server, server_id, NULL)) {
    /* Send packet to the server indicating that it cannot use this
       connection as it has been replaced by backup router. */
    SilcBuffer packet = silc_buffer_alloc(2);
    silc_buffer_pull_tail(packet, SILC_BUFFER_END(packet));
    silc_buffer_format(packet,
		       SILC_STR_UI_CHAR(SILC_SERVER_BACKUP_REPLACED),
		       SILC_STR_UI_CHAR(0),
		       SILC_STR_END);
    silc_server_packet_send(server, sock, 
			    SILC_PACKET_RESUME_ROUTER, 0, 
			    packet->data, packet->len, TRUE);
    silc_buffer_free(packet);

    /* Mark the router disabled. The data sent earlier will go but nothing
       after this does not go to this connection. */
    idata->status |= SILC_IDLIST_STATUS_DISABLED;
  } else {
    /* If it is router announce our stuff to it. */
    if (sock->type == SILC_SOCKET_TYPE_ROUTER && 
	server->server_type == SILC_ROUTER) {
      silc_server_announce_servers(server, FALSE, 0, sock);
      silc_server_announce_clients(server, 0, sock);
      silc_server_announce_channels(server, 0, sock);
    }
  }

  return new_server;
}

/* Processes incoming New ID packet. New ID Payload is used to distribute
   information about newly registered clients and servers. */

static void silc_server_new_id_real(SilcServer server, 
				    SilcSocketConnection sock,
				    SilcPacketContext *packet,
				    int broadcast)
{
  SilcBuffer buffer = packet->buffer;
  SilcIDList id_list;
  SilcServerEntry router, server_entry;
  SilcSocketConnection router_sock;
  SilcIDPayload idp;
  SilcIdType id_type;
  void *id;

  SILC_LOG_DEBUG(("Processing new ID"));

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      server->server_type == SILC_SERVER ||
      packet->src_id_type != SILC_ID_SERVER)
    return;

  idp = silc_id_payload_parse(buffer->data, buffer->len);
  if (!idp)
    return;

  id_type = silc_id_payload_get_type(idp);

  /* Normal server cannot have other normal server connections */
  server_entry = (SilcServerEntry)sock->user_data;
  if (id_type == SILC_ID_SERVER && sock->type == SILC_SOCKET_TYPE_SERVER &&
      server_entry->server_type == SILC_SERVER)
    goto out;

  id = silc_id_payload_get_id(idp);
  if (!id)
    goto out;

  /* If the packet is coming from server then use the sender as the
     origin of the the packet. If it came from router then check the real
     sender of the packet and use that as the origin. */
  if (sock->type == SILC_SOCKET_TYPE_SERVER) {
    id_list = server->local_list;
    router_sock = sock;
    router = sock->user_data;

    /* If the sender is backup router and ID is server (and we are not
       backup router) then switch the entry to global list. */
    if (server_entry->server_type == SILC_BACKUP_ROUTER && 
	id_type == SILC_ID_SERVER && 
	server->id_entry->server_type != SILC_BACKUP_ROUTER) {
      id_list = server->global_list;
      router_sock = server->router ? server->router->connection : sock;
    }
  } else {
    void *sender_id = silc_id_str2id(packet->src_id, packet->src_id_len,
				     packet->src_id_type);
    router = silc_idlist_find_server_by_id(server->global_list,
					   sender_id, TRUE, NULL);
    if (!router)
      router = silc_idlist_find_server_by_id(server->local_list,
					     sender_id, TRUE, NULL);
    silc_free(sender_id);
    router_sock = sock;
    id_list = server->global_list;
  }

  if (!router)
    goto out;

  switch(id_type) {
  case SILC_ID_CLIENT:
    {
      SilcClientEntry entry;

      /* Check that we do not have this client already */
      entry = silc_idlist_find_client_by_id(server->global_list, 
					    id, server->server_type, 
					    NULL);
      if (!entry)
	entry = silc_idlist_find_client_by_id(server->local_list, 
					      id, server->server_type,
					      NULL);
      if (entry) {
	SILC_LOG_DEBUG(("Ignoring client that we already have"));
	goto out;
      }

      SILC_LOG_DEBUG(("New client id(%s) from [%s] %s",
		      silc_id_render(id, SILC_ID_CLIENT),
		      sock->type == SILC_SOCKET_TYPE_SERVER ?
		      "Server" : "Router", sock->hostname));
    
      /* As a router we keep information of all global information in our
	 global list. Cell wide information however is kept in the local
	 list. */
      entry = silc_idlist_add_client(id_list, NULL, NULL, NULL, 
				     id, router, NULL, 0);
      if (!entry) {
	SILC_LOG_ERROR(("Could not add new client to the ID Cache"));

	/* Inform the sender that the ID is not usable */
	silc_server_send_notify_signoff(server, sock, FALSE, id, NULL);
	goto out;
      }
      entry->nickname = NULL;
      entry->data.status |= SILC_IDLIST_STATUS_REGISTERED;

      if (sock->type == SILC_SOCKET_TYPE_SERVER)
	server->stat.cell_clients++;
      server->stat.clients++;
    }
    break;

  case SILC_ID_SERVER:
    {
      SilcServerEntry entry;

      /* If the ID is mine, ignore it. */
      if (SILC_ID_SERVER_COMPARE(id, server->id)) {
	SILC_LOG_DEBUG(("Ignoring my own ID as new ID"));
	break;
      }

      /* If the ID is the sender's ID, ignore it (we have it already) */
      if (SILC_ID_SERVER_COMPARE(id, router->id)) {
	SILC_LOG_DEBUG(("Ignoring sender's own ID"));
	break;
      }
      
      /* Check that we do not have this server already */
      entry = silc_idlist_find_server_by_id(server->global_list, 
					    id, server->server_type, 
					    NULL);
      if (!entry)
	entry = silc_idlist_find_server_by_id(server->local_list, 
					      id, server->server_type,
					      NULL);
      if (entry) {
	SILC_LOG_DEBUG(("Ignoring server that we already have"));
	goto out;
      }

      SILC_LOG_DEBUG(("New server id(%s) from [%s] %s",
		      silc_id_render(id, SILC_ID_SERVER),
		      sock->type == SILC_SOCKET_TYPE_SERVER ?
		      "Server" : "Router", sock->hostname));
      
      /* As a router we keep information of all global information in our 
	 global list. Cell wide information however is kept in the local
	 list. */
      entry = silc_idlist_add_server(id_list, NULL, 0, id, router, 
				     router_sock);
      if (!entry) {
	SILC_LOG_ERROR(("Could not add new server to the ID Cache"));
	goto out;
      }
      entry->data.status |= SILC_IDLIST_STATUS_REGISTERED;
      
      if (sock->type == SILC_SOCKET_TYPE_SERVER)
	server->stat.cell_servers++;
      server->stat.servers++;
    }
    break;

  case SILC_ID_CHANNEL:
    SILC_LOG_ERROR(("Channel cannot be registered with NEW_ID packet"));
    goto out;
    break;

  default:
    goto out;
    break;
  }

  /* If the sender of this packet is server and we are router we need to
     broadcast this packet to other routers in the network. */
  if (broadcast && !server->standalone && server->server_type == SILC_ROUTER &&
      sock->type == SILC_SOCKET_TYPE_SERVER &&
      !(packet->flags & SILC_PACKET_FLAG_BROADCAST)) {
    SILC_LOG_DEBUG(("Broadcasting received New ID packet"));
    silc_server_packet_send(server, server->router->connection,
			    packet->type, 
			    packet->flags | SILC_PACKET_FLAG_BROADCAST,
			    buffer->data, buffer->len, FALSE);
    silc_server_backup_send(server, (SilcServerEntry)sock->user_data, 
			    packet->type, packet->flags,
			    packet->buffer->data, packet->buffer->len, 
			    FALSE, TRUE);
  }

 out:
  silc_id_payload_free(idp);
}


/* Processes incoming New ID packet. New ID Payload is used to distribute
   information about newly registered clients and servers. */

void silc_server_new_id(SilcServer server, SilcSocketConnection sock,
			SilcPacketContext *packet)
{
  silc_server_new_id_real(server, sock, packet, TRUE);
}

/* Receoved New Id List packet, list of New ID payloads inside one
   packet. Process the New ID payloads one by one. */

void silc_server_new_id_list(SilcServer server, SilcSocketConnection sock,
			     SilcPacketContext *packet)
{
  SilcPacketContext *new_id;
  SilcBuffer idp;
  SilcUInt16 id_len;

  SILC_LOG_DEBUG(("Processing New ID List"));

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      packet->src_id_type != SILC_ID_SERVER)
    return;

  /* If the sender of this packet is server and we are router we need to
     broadcast this packet to other routers in the network. Broadcast
     this list packet instead of multiple New ID packets. */
  if (!server->standalone && server->server_type == SILC_ROUTER &&
      sock->type == SILC_SOCKET_TYPE_SERVER &&
      !(packet->flags & SILC_PACKET_FLAG_BROADCAST)) {
    SILC_LOG_DEBUG(("Broadcasting received New ID List packet"));
    silc_server_packet_send(server, server->router->connection,
			    packet->type, 
			    packet->flags | SILC_PACKET_FLAG_BROADCAST,
			    packet->buffer->data, packet->buffer->len, FALSE);
    silc_server_backup_send(server, (SilcServerEntry)sock->user_data, 
			    packet->type, packet->flags,
			    packet->buffer->data, packet->buffer->len, 
			    FALSE, TRUE);
  }

  /* Make copy of the original packet context, except for the actual
     data buffer, which we will here now fetch from the original buffer. */
  new_id = silc_packet_context_alloc();
  new_id->type = SILC_PACKET_NEW_ID;
  new_id->flags = packet->flags;
  new_id->src_id = packet->src_id;
  new_id->src_id_len = packet->src_id_len;
  new_id->src_id_type = packet->src_id_type;
  new_id->dst_id = packet->dst_id;
  new_id->dst_id_len = packet->dst_id_len;
  new_id->dst_id_type = packet->dst_id_type;

  idp = silc_buffer_alloc(256);
  new_id->buffer = idp;

  while (packet->buffer->len) {
    SILC_GET16_MSB(id_len, packet->buffer->data + 2);
    if ((id_len > packet->buffer->len) ||
	(id_len > idp->truelen))
      break;

    silc_buffer_pull_tail(idp, 4 + id_len);
    silc_buffer_put(idp, packet->buffer->data, 4 + id_len);

    /* Process the New ID */
    silc_server_new_id_real(server, sock, new_id, FALSE);

    silc_buffer_push_tail(idp, 4 + id_len);
    silc_buffer_pull(packet->buffer, 4 + id_len);
  }

  silc_buffer_free(idp);
  silc_free(new_id);
}

/* Received New Channel packet. Information about new channels in the 
   network are distributed using this packet. Save the information about
   the new channel. This usually comes from router but also normal server
   can send this to notify channels it has when it connects to us. */

void silc_server_new_channel(SilcServer server,
			     SilcSocketConnection sock,
			     SilcPacketContext *packet)
{
  SilcChannelPayload payload;
  SilcChannelID *channel_id;
  char *channel_name;
  SilcUInt32 name_len;
  unsigned char *id;
  SilcUInt32 id_len;
  SilcUInt32 mode;
  SilcServerEntry server_entry;
  SilcChannelEntry channel;

  SILC_LOG_DEBUG(("Processing New Channel"));

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      packet->src_id_type != SILC_ID_SERVER ||
      server->server_type == SILC_SERVER)
    return;

  /* Parse the channel payload */
  payload = silc_channel_payload_parse(packet->buffer->data,
				       packet->buffer->len);
  if (!payload)
    return;
    
  /* Get the channel ID */
  channel_id = silc_channel_get_id_parse(payload);
  if (!channel_id) {
    silc_channel_payload_free(payload);
    return;
  }

  channel_name = silc_channel_get_name(payload, &name_len);
  if (name_len > 256)
    channel_name[255] = '\0';

  id = silc_channel_get_id(payload, &id_len);

  server_entry = (SilcServerEntry)sock->user_data;

  if (sock->type == SILC_SOCKET_TYPE_ROUTER) {
    /* Add the channel to global list as it is coming from router. It 
       cannot be our own channel as it is coming from router. */

    /* Check that we don't already have this channel */
    channel = silc_idlist_find_channel_by_name(server->local_list, 
					       channel_name, NULL);
    if (!channel)
      channel = silc_idlist_find_channel_by_name(server->global_list, 
						 channel_name, NULL);
    if (!channel) {
      SILC_LOG_DEBUG(("New channel id(%s) from [Router] %s",
		      silc_id_render(channel_id, SILC_ID_CHANNEL), 
		      sock->hostname));
    
      silc_idlist_add_channel(server->global_list, strdup(channel_name), 
			      0, channel_id, sock->user_data, NULL, NULL, 0);
      server->stat.channels++;
    }
  } else {
    /* The channel is coming from our server, thus it is in our cell
       we will add it to our local list. */
    SilcBuffer chk;

    SILC_LOG_DEBUG(("Channel id(%s) from [Server] %s",
		    silc_id_render(channel_id, SILC_ID_CHANNEL), 
		    sock->hostname));

    /* Check that we don't already have this channel */
    channel = silc_idlist_find_channel_by_name(server->local_list, 
					       channel_name, NULL);
    if (!channel)
      channel = silc_idlist_find_channel_by_name(server->global_list, 
						 channel_name, NULL);

    /* If the channel does not exist, then create it. This creates a new
       key to the channel as well that we will send to the server. */
    if (!channel) {
      /* The protocol says that the Channel ID's IP address must be based
	 on the router's IP address.  Check whether the ID is based in our
	 IP and if it is not then create a new ID and enforce the server
	 to switch the ID. */
      if (server_entry->server_type != SILC_BACKUP_ROUTER &&
	  !SILC_ID_COMPARE(channel_id, server->id, server->id->ip.data_len)) {
	SilcChannelID *tmp;
	SILC_LOG_DEBUG(("Forcing the server to change Channel ID"));
	
	if (silc_id_create_channel_id(server, server->id, server->rng, &tmp)) {
	  silc_server_send_notify_channel_change(server, sock, FALSE, 
						 channel_id, tmp);
	  silc_free(channel_id);
	  channel_id = tmp;
	}
      }

      /* Create the channel with the provided Channel ID */
      channel = silc_server_create_new_channel_with_id(server, NULL, NULL,
						       channel_name,
						       channel_id, FALSE);
      if (!channel) {
	silc_channel_payload_free(payload);
	silc_free(channel_id);
	return;
      }

      /* Get the mode and set it to the channel */
      channel->mode = silc_channel_get_mode(payload);

      /* Send the new channel key to the server */
      id = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
      id_len = silc_id_get_len(channel->id, SILC_ID_CHANNEL);
      chk = silc_channel_key_payload_encode(id_len, id,
					    strlen(channel->channel_key->
						   cipher->name),
					    channel->channel_key->cipher->name,
					    channel->key_len / 8, 
					    channel->key);
      silc_server_packet_send(server, sock, SILC_PACKET_CHANNEL_KEY, 0, 
			      chk->data, chk->len, FALSE);
      silc_buffer_free(chk);

    } else {
      /* The channel exist by that name, check whether the ID's match.
	 If they don't then we'll force the server to use the ID we have.
	 We also create a new key for the channel. */
      SilcBuffer users = NULL, users_modes = NULL;

      if (!SILC_ID_CHANNEL_COMPARE(channel_id, channel->id)) {
	/* They don't match, send CHANNEL_CHANGE notify to the server to
	   force the ID change. */
	SILC_LOG_DEBUG(("Forcing the server to change Channel ID"));
	silc_server_send_notify_channel_change(server, sock, FALSE, 
					       channel_id, channel->id);
      }

      /* If the mode is different from what we have then enforce the
	 mode change. */
      mode = silc_channel_get_mode(payload);
      if (channel->mode != mode) {
	SILC_LOG_DEBUG(("Forcing the server to change channel mode"));
	silc_server_send_notify_cmode(server, sock, FALSE, channel,
				      channel->mode, server->id,
				      SILC_ID_SERVER,
				      channel->cipher, channel->hmac_name,
				      channel->passphrase);
      }

      /* Create new key for the channel and send it to the server and
	 everybody else possibly on the channel. */

      if (!(channel->mode & SILC_CHANNEL_MODE_PRIVKEY)) {
	if (!silc_server_create_channel_key(server, channel, 0))
	  return;
	
	/* Send to the channel */
	silc_server_send_channel_key(server, sock, channel, FALSE);
	id = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
	id_len = silc_id_get_len(channel->id, SILC_ID_CHANNEL);

	/* Send to the server */
	chk = silc_channel_key_payload_encode(id_len, id,
					      strlen(channel->channel_key->
						     cipher->name),
					      channel->channel_key->
					      cipher->name,
					      channel->key_len / 8, 
					      channel->key);
	silc_server_packet_send(server, sock, SILC_PACKET_CHANNEL_KEY, 0, 
				chk->data, chk->len, FALSE);
	silc_buffer_free(chk);
	silc_free(id);
      }

      silc_free(channel_id);

      /* Since the channel is coming from server and we also know about it
	 then send the JOIN notify to the server so that it see's our
	 users on the channel "joining" the channel. */
      silc_server_announce_get_channel_users(server, channel, &users,
					     &users_modes);
      if (users) {
	silc_buffer_push(users, users->data - users->head);
	silc_server_packet_send(server, sock,
				SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
				users->data, users->len, FALSE);
	silc_buffer_free(users);
      }
      if (users_modes) {
	silc_buffer_push(users_modes, users_modes->data - users_modes->head);
	silc_server_packet_send_dest(server, sock,
				     SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
				     channel->id, SILC_ID_CHANNEL,
				     users_modes->data, 
				     users_modes->len, FALSE);
	silc_buffer_free(users_modes);
      }
    }
  }

  silc_channel_payload_free(payload);
}

/* Received New Channel List packet, list of New Channel List payloads inside
   one packet. Process the New Channel payloads one by one. */

void silc_server_new_channel_list(SilcServer server,
				  SilcSocketConnection sock,
				  SilcPacketContext *packet)
{
  SilcPacketContext *new;
  SilcBuffer buffer;
  SilcUInt16 len1, len2;

  SILC_LOG_DEBUG(("Processing New Channel List"));

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      packet->src_id_type != SILC_ID_SERVER ||
      server->server_type == SILC_SERVER)
    return;

  /* If the sender of this packet is server and we are router we need to
     broadcast this packet to other routers in the network. Broadcast
     this list packet instead of multiple New Channel packets. */
  if (!server->standalone && server->server_type == SILC_ROUTER &&
      sock->type == SILC_SOCKET_TYPE_SERVER &&
      !(packet->flags & SILC_PACKET_FLAG_BROADCAST)) {
    SILC_LOG_DEBUG(("Broadcasting received New Channel List packet"));
    silc_server_packet_send(server, server->router->connection,
			    packet->type, 
			    packet->flags | SILC_PACKET_FLAG_BROADCAST,
			    packet->buffer->data, packet->buffer->len, FALSE);
    silc_server_backup_send(server, (SilcServerEntry)sock->user_data, 
			    packet->type, packet->flags,
			    packet->buffer->data, packet->buffer->len, 
			    FALSE, TRUE);
  }

  /* Make copy of the original packet context, except for the actual
     data buffer, which we will here now fetch from the original buffer. */
  new = silc_packet_context_alloc();
  new->type = SILC_PACKET_NEW_CHANNEL;
  new->flags = packet->flags;
  new->src_id = packet->src_id;
  new->src_id_len = packet->src_id_len;
  new->src_id_type = packet->src_id_type;
  new->dst_id = packet->dst_id;
  new->dst_id_len = packet->dst_id_len;
  new->dst_id_type = packet->dst_id_type;

  buffer = silc_buffer_alloc(512);
  new->buffer = buffer;

  while (packet->buffer->len) {
    SILC_GET16_MSB(len1, packet->buffer->data);
    if ((len1 > packet->buffer->len) ||
	(len1 > buffer->truelen))
      break;

    SILC_GET16_MSB(len2, packet->buffer->data + 2 + len1);
    if ((len2 > packet->buffer->len) ||
	(len2 > buffer->truelen))
      break;

    silc_buffer_pull_tail(buffer, 8 + len1 + len2);
    silc_buffer_put(buffer, packet->buffer->data, 8 + len1 + len2);

    /* Process the New Channel */
    silc_server_new_channel(server, sock, new);

    silc_buffer_push_tail(buffer, 8 + len1 + len2);
    silc_buffer_pull(packet->buffer, 8 + len1 + len2);
  }

  silc_buffer_free(buffer);
  silc_free(new);
}

/* Received key agreement packet. This packet is never for us. It is to
   the client in the packet's destination ID. Sending of this sort of packet
   equals sending private message, ie. it is sent point to point from
   one client to another. */

void silc_server_key_agreement(SilcServer server,
			       SilcSocketConnection sock,
			       SilcPacketContext *packet)
{
  SilcSocketConnection dst_sock;
  SilcIDListData idata;

  SILC_LOG_DEBUG(("Start"));

  if (packet->src_id_type != SILC_ID_CLIENT ||
      packet->dst_id_type != SILC_ID_CLIENT)
    return;

  if (!packet->dst_id)
    return;

  /* Get the route to the client */
  dst_sock = silc_server_get_client_route(server, packet->dst_id,
					  packet->dst_id_len, NULL, &idata);
  if (!dst_sock)
    return;

  /* Relay the packet */
  silc_server_relay_packet(server, dst_sock, idata->send_key,
			   idata->hmac_send, idata->psn_send++,
			   packet, FALSE);
}

/* Received connection auth request packet that is used during connection
   phase to resolve the mandatory authentication method.  This packet can
   actually be received at anytime but usually it is used only during
   the connection authentication phase. Now, protocol says that this packet
   can come from client or server, however, we support only this coming
   from client and expect that server always knows what authentication
   method to use. */

void silc_server_connection_auth_request(SilcServer server,
					 SilcSocketConnection sock,
					 SilcPacketContext *packet)
{
  SilcServerConfigClient *client = NULL;
  SilcUInt16 conn_type;
  int ret;
  SilcAuthMethod auth_meth = SILC_AUTH_NONE;

  SILC_LOG_DEBUG(("Start"));

  if (packet->src_id_type && packet->src_id_type != SILC_ID_CLIENT)
    return;

  /* Parse the payload */
  ret = silc_buffer_unformat(packet->buffer,
			     SILC_STR_UI_SHORT(&conn_type),
			     SILC_STR_UI_SHORT(NULL),
			     SILC_STR_END);
  if (ret == -1)
    return;

  if (conn_type != SILC_SOCKET_TYPE_CLIENT)
    return;

  /* Get the authentication method for the client */
  auth_meth = SILC_AUTH_NONE;
  client = silc_server_config_find_client(server, sock->ip);
  if (!client)
    client = silc_server_config_find_client(server, sock->hostname);
  if (client) {
    if (client->passphrase) {
      if (client->publickeys && !server->config->prefer_passphrase_auth)
	auth_meth = SILC_AUTH_PUBLIC_KEY;
      else
	auth_meth = SILC_AUTH_PASSWORD;
    } else if (client->publickeys)
      auth_meth = SILC_AUTH_PUBLIC_KEY;
  }

  /* Send it back to the client */
  silc_server_send_connection_auth_request(server, sock, conn_type, auth_meth);
}

/* Received REKEY packet. The sender of the packet wants to regenerate
   its session keys. This starts the REKEY protocol. */

void silc_server_rekey(SilcServer server,
		       SilcSocketConnection sock,
		       SilcPacketContext *packet)
{
  SilcProtocol protocol;
  SilcServerRekeyInternalContext *proto_ctx;
  SilcIDListData idata = (SilcIDListData)sock->user_data;

  SILC_LOG_DEBUG(("Start"));

  /* Allocate internal protocol context. This is sent as context
     to the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = (void *)server;
  proto_ctx->sock = sock;
  proto_ctx->responder = TRUE;
  proto_ctx->pfs = idata->rekey->pfs;
      
  /* Perform rekey protocol. Will call the final callback after the
     protocol is over. */
  silc_protocol_alloc(SILC_PROTOCOL_SERVER_REKEY, 
		      &protocol, proto_ctx, silc_server_rekey_final);
  sock->protocol = protocol;

  if (proto_ctx->pfs == FALSE)
    /* Run the protocol */
    silc_protocol_execute(protocol, server->schedule, 0, 0);
}

/* Received file transger packet. This packet is never for us. It is to
   the client in the packet's destination ID. Sending of this sort of packet
   equals sending private message, ie. it is sent point to point from
   one client to another. */

void silc_server_ftp(SilcServer server,
		     SilcSocketConnection sock,
		     SilcPacketContext *packet)
{
  SilcSocketConnection dst_sock;
  SilcIDListData idata;

  SILC_LOG_DEBUG(("Start"));

  if (packet->src_id_type != SILC_ID_CLIENT ||
      packet->dst_id_type != SILC_ID_CLIENT)
    return;

  if (!packet->dst_id)
    return;

  /* Get the route to the client */
  dst_sock = silc_server_get_client_route(server, packet->dst_id,
					  packet->dst_id_len, NULL, &idata);
  if (!dst_sock)
    return;

  /* Relay the packet */
  silc_server_relay_packet(server, dst_sock, idata->send_key,
			   idata->hmac_send, idata->psn_send++,
			   packet, FALSE);
}
