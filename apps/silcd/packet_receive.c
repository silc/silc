/*

  packet_receive.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2004 Pekka Riikonen

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
  SilcIDCacheEntry cache = NULL;
  SilcHashTableList htl;
  SilcUInt32 mode;
  unsigned char *tmp;
  SilcUInt32 tmp_len;
  bool local;

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      packet->src_id_type != SILC_ID_SERVER || !packet->dst_id) {
    SILC_LOG_DEBUG(("Bad notify packet received"));
    return;
  }

  /* If the packet is destined directly to a client then relay the packet
     before processing it. */
  if (packet->dst_id_type == SILC_ID_CLIENT) {
    SilcIDListData idata;
    SilcSocketConnection dst_sock;

    /* Get the route to the client */
    dst_sock = silc_server_get_client_route(server, packet->dst_id,
					    packet->dst_id_len, NULL,
					    &idata, NULL);
    if (dst_sock)
      /* Relay the packet */
      silc_server_relay_packet(server, dst_sock, idata->send_key,
			       idata->hmac_send, idata->psn_send++,
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
  if (server->server_type == SILC_ROUTER &&
      sock->type == SILC_SOCKET_TYPE_SERVER &&
      !(packet->flags & SILC_PACKET_FLAG_BROADCAST)) {
    SILC_LOG_DEBUG(("Broadcasting received Notify packet"));
    if (packet->dst_id_type == SILC_ID_CHANNEL) {
      /* Packet is destined to channel */
      channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_len,
				  packet->dst_id_type);
      if (!channel_id)
	goto out;

      silc_server_packet_send_dest(server, SILC_PRIMARY_ROUTE(server),
				   packet->type, packet->flags |
				   SILC_PACKET_FLAG_BROADCAST,
				   channel_id, SILC_ID_CHANNEL,
				   packet->buffer->data,
				   packet->buffer->len, FALSE);
      silc_server_backup_send_dest(server, sock->user_data,
				   packet->type, packet->flags,
				   channel_id, SILC_ID_CHANNEL,
				   packet->buffer->data, packet->buffer->len,
				   FALSE, TRUE);
    } else {
      /* Packet is destined to client or server */
      silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			      packet->type,
			      packet->flags | SILC_PACKET_FLAG_BROADCAST,
			      packet->buffer->data, packet->buffer->len,
			      FALSE);
      silc_server_backup_send(server, sock->user_data,
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

    if (channel_id)
      silc_free(channel_id);

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
	SILC_LOG_DEBUG(("Notify for unknown channel"));
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
					   &cache);
    if (!client) {
      client = silc_idlist_find_client_by_id(server->local_list,
					     client_id, server->server_type,
					     &cache);
      if (!client) {
	/* If router did not find the client the it is bogus */
	if (server->server_type != SILC_SERVER) {
	  silc_free(client_id);
	  goto out;
	}

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
    silc_free(client_id);

    /* Do not process the notify if the client is not registered */
    if (!(client->data.status & SILC_IDLIST_STATUS_REGISTERED))
      break;

    /* Do not add client to channel if it is there already */
    if (silc_server_client_on_channel(client, channel, NULL)) {
      SILC_LOG_DEBUG(("Client already on channel %s",
		      channel->channel_name));
      break;
    }

    /* Send to channel */
    silc_server_packet_send_to_channel(server, sock, channel, packet->type,
				       FALSE, TRUE, packet->buffer->data,
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

    if (server->server_type != SILC_ROUTER ||
	sock->type == SILC_SOCKET_TYPE_ROUTER) {
      /* If this is the first one on the channel then it is the founder of
	 the channel. This is done on normal server and on router if this
	 notify is coming from router */
      if (!silc_hash_table_count(channel->user_list)) {
	SILC_LOG_DEBUG(("Client %s is founder on channel",
			silc_id_render(chl->client->id, SILC_ID_CLIENT)));
	chl->mode = (SILC_CHANNEL_UMODE_CHANOP | SILC_CHANNEL_UMODE_CHANFO);
      }
    }

    silc_hash_table_add(channel->user_list, client, chl);
    silc_hash_table_add(client->channels, channel, chl);
    channel->user_count++;
    channel->disabled = FALSE;

    /* Make sure we don't expire clients that are on channel */
    if (cache)
      cache->expire = 0;

    /* Update statistics */
    if (server->server_type == SILC_ROUTER) {
      if (sock->type != SILC_SOCKET_TYPE_ROUTER)
	server->stat.cell_chanclients++;
      server->stat.chanclients++;
    }

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
	SILC_LOG_DEBUG(("Notify for unknown channel"));
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
    silc_free(channel_id);

    /* Check if on channel */
    if (!silc_server_client_on_channel(client, channel, NULL))
      break;

    /* Send the leave notify to channel */
    silc_server_packet_send_to_channel(server, sock, channel, packet->type,
				       FALSE, TRUE, packet->buffer->data,
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
    if (server->stat.cell_clients)
      server->stat.cell_clients--;
    SILC_OPER_STATS_UPDATE(client, server, SILC_UMODE_SERVER_OPERATOR);
    SILC_OPER_STATS_UPDATE(client, router, SILC_UMODE_ROUTER_OPERATOR);
    silc_schedule_task_del_by_context(server->schedule, client);

    /* Remove from public key hash table. */
    if (client->data.public_key)
      silc_hash_table_del_by_context(server->pk_hash, client->data.public_key,
                                     client);

    /* Remove the client from all channels. */
    silc_server_remove_from_channels(server, NULL, client, TRUE,
				     tmp, FALSE, FALSE);

    /* Check if anyone is watching this nickname */
    if (server->server_type == SILC_ROUTER)
      silc_server_check_watcher_list(server, client, NULL,
				     SILC_NOTIFY_TYPE_SIGNOFF);

    /* Remove this client from watcher list if it is */
    silc_server_del_from_watcher_list(server, client);

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

    /* Get the topic */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (!tmp) {
      silc_free(channel_id);
      goto out;
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
	SILC_LOG_DEBUG(("Notify for unknown channel"));
	silc_free(channel_id);
	goto out;
      }
    }
    silc_free(channel_id);

    if (channel->topic && !strcmp(channel->topic, tmp)) {
      SILC_LOG_DEBUG(("Topic is already set and same"));
      goto out;
    }

    if (client) {
      /* Get user's channel entry and check that topic set is allowed. */
      if (!silc_server_client_on_channel(client, channel, &chl))
	goto out;
      if (channel->mode & SILC_CHANNEL_MODE_TOPIC &&
	  !(chl->mode & SILC_CHANNEL_UMODE_CHANOP) &&
	  !(chl->mode & SILC_CHANNEL_UMODE_CHANFO)) {
	SILC_LOG_DEBUG(("Topic change is not allowed"));
	goto out;
      }
    }

    /* Change the topic */
    silc_free(channel->topic);
    channel->topic = strdup(tmp);

    /* Send the same notify to the channel */
    silc_server_packet_send_to_channel(server, NULL, channel, packet->type,
				       FALSE, TRUE, packet->buffer->data,
				       packet->buffer->len, FALSE);
    break;

  case SILC_NOTIFY_TYPE_NICK_CHANGE:
    {
      /*
       * Distribute the notify to local clients on the channel
       */
      unsigned char *id, *id2;
      char *nickname;
      SilcUInt32 nickname_len;

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
      if (!client_id2) {
	silc_free(client_id);
	goto out;
      }

      SILC_LOG_DEBUG(("Old Client ID id(%s)",
		      silc_id_render(client_id, SILC_ID_CLIENT)));
      SILC_LOG_DEBUG(("New Client ID id(%s)",
		      silc_id_render(client_id2, SILC_ID_CLIENT)));

      /* From protocol version 1.1 we also get the new nickname */
      nickname = silc_argument_get_arg_type(args, 3, &nickname_len);;

      /* Replace the Client ID */
      client = silc_idlist_replace_client_id(server,
					     server->global_list, client_id,
					     client_id2, nickname);
      if (!client)
	client = silc_idlist_replace_client_id(server,
					       server->local_list, client_id,
					       client_id2, nickname);

      if (client) {
	/* Send the NICK_CHANGE notify type to local clients on the channels
	   this client is joined to. */
	silc_server_send_notify_on_channels(server, client, client,
					    SILC_NOTIFY_TYPE_NICK_CHANGE, 3,
					    id, tmp_len, id2, tmp_len,
					    nickname, nickname ?
					    nickname_len : 0);
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
    }
    silc_free(client_id);

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
	SILC_LOG_DEBUG(("Notify for unknown channel"));
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
    if (channel->mode == mode) {
      SILC_LOG_DEBUG(("Mode is changed already"));

      /* If this mode change has founder mode then we'll enforce the
	 change so that the server gets the real founder public key */
      if (server->server_type != SILC_SERVER &&
	  sock != SILC_PRIMARY_ROUTE(server) &&
	  mode & SILC_CHANNEL_MODE_FOUNDER_AUTH && channel->founder_key) {
	SILC_LOG_DEBUG(("Sending founder public key to server"));
	silc_server_send_notify_cmode(server, sock, FALSE, channel,
				      channel->mode, server->id,
				      SILC_ID_SERVER, channel->cipher,
				      channel->hmac_name,
				      channel->passphrase,
				      channel->founder_key, NULL);
      }

      /* If we received same mode from our primary check whether founder
	 mode and key in the notify is set.  We update the founder key
	 here since we may have wrong one */
      if (server->server_type == SILC_SERVER &&
	  sock == SILC_PRIMARY_ROUTE(server) &&
	  mode & SILC_CHANNEL_MODE_FOUNDER_AUTH) {
	SILC_LOG_DEBUG(("Founder public key received from router"));
	tmp = silc_argument_get_arg_type(args, 6, &tmp_len);
	if (!tmp)
	  break;

	if (channel->founder_key)
	  silc_pkcs_public_key_free(channel->founder_key);
	channel->founder_key = NULL;
	silc_pkcs_public_key_payload_decode(tmp, tmp_len,
					    &channel->founder_key);
      }

      /* Check also for channel public key list */
      if (server->server_type == SILC_SERVER &&
	  sock == SILC_PRIMARY_ROUTE(server) &&
	  mode & SILC_CHANNEL_MODE_CHANNEL_AUTH) {
	SilcBuffer chpklist;
	SilcBuffer sidp;
	unsigned char mask[4], ulimit[4];

	SILC_LOG_DEBUG(("Channel public key list received from router"));
	tmp = silc_argument_get_arg_type(args, 7, &tmp_len);
	if (!tmp)
	  break;

	/* Set the router's list, and send the notify to channel too so that
	   channel gets the list */
	silc_server_set_channel_pk_list(server, sock, channel, tmp, tmp_len);
	chpklist = silc_server_get_channel_pk_list(server, channel,
						   FALSE, FALSE);
	if (!chpklist)
	  break;
	sidp = silc_id_payload_encode(server->router->id, SILC_ID_SERVER);
	SILC_PUT32_MSB(channel->mode, mask);
	if (channel->mode & SILC_CHANNEL_MODE_ULIMIT)
	  SILC_PUT32_MSB(channel->user_limit, ulimit);
	silc_server_send_notify_to_channel(server, NULL, channel, FALSE, TRUE,
					   SILC_NOTIFY_TYPE_CMODE_CHANGE, 8,
					   sidp->data, sidp->len,
					   mask, 4,
					   channel->cipher,
					   channel->cipher ?
					   strlen(channel->cipher) : 0,
					   channel->hmac_name,
					   channel->hmac_name ?
					   strlen(channel->hmac_name) : 0,
					   channel->passphrase,
					   channel->passphrase ?
					   strlen(channel->passphrase) : 0,
					   NULL, 0,
					   chpklist->data, chpklist->len,
					   (channel->mode &
					    SILC_CHANNEL_MODE_ULIMIT ?
					    ulimit : NULL),
					   (channel->mode &
					    SILC_CHANNEL_MODE_ULIMIT ?
					    sizeof(ulimit) : 0));
	silc_buffer_free(sidp);
	silc_buffer_free(chpklist);
	goto out;
      }

      break;
    }

    /* Get user's channel entry and check that mode change is allowed */
    if (client) {
      if (!silc_server_client_on_channel(client, channel, &chl))
	goto out;
      if (!silc_server_check_cmode_rights(server, channel, chl, mode)) {
	SILC_LOG_DEBUG(("CMODE change is not allowed"));
	silc_server_send_notify_cmode(server, sock, FALSE, channel,
				      channel->mode, server->id,
				      SILC_ID_SERVER, channel->cipher,
				      channel->hmac_name,
				      channel->passphrase,
				      channel->founder_key, NULL);
	goto out;
      }
    } else {
      /* Assure that server is not removing founder mode from us */
      if (server->server_type == SILC_ROUTER &&
	  sock != SILC_PRIMARY_ROUTE(server) &&
	  channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH &&
	  !(mode & SILC_CHANNEL_MODE_FOUNDER_AUTH)) {
	SILC_LOG_DEBUG(("Enforcing sender to change channel mode"));
	silc_server_send_notify_cmode(server, sock, FALSE, channel,
				      channel->mode, server->id,
				      SILC_ID_SERVER, channel->cipher,
				      channel->hmac_name,
				      channel->passphrase,
				      channel->founder_key, NULL);
	goto out;
      }

      /* If server is adding founder mode, check whether there is founder
	 on channel already and is not from this server */
      if (server->server_type == SILC_ROUTER &&
	  sock != SILC_PRIMARY_ROUTE(server) &&
	  mode & SILC_CHANNEL_MODE_FOUNDER_AUTH) {
	silc_hash_table_list(channel->user_list, &htl);
	while (silc_hash_table_get(&htl, NULL, (void *)&chl))
	  if (chl->mode & SILC_CHANNEL_UMODE_CHANFO &&
	      chl->client->router != sock->user_data) {
	    SILC_LOG_DEBUG(("Enforcing sender to change channel mode"));
	    silc_server_send_notify_cmode(server, sock, FALSE, channel,
					  channel->mode, server->id,
					  SILC_ID_SERVER, channel->cipher,
					  channel->hmac_name,
					  channel->passphrase,
					  channel->founder_key, NULL);
	    silc_hash_table_list_reset(&htl);
	    goto out;
	  }
	silc_hash_table_list_reset(&htl);
      }
    }

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
		     channel->key_len / 8, hash);
      silc_hmac_set_key(channel->hmac, hash,
			silc_hash_len(silc_hmac_get_hash(channel->hmac)));
      memset(hash, 0, sizeof(hash));
    }

    /* Get the passphrase */
    tmp = silc_argument_get_arg_type(args, 5, &tmp_len);
    if (tmp) {
      silc_free(channel->passphrase);
      channel->passphrase = silc_memdup(tmp, tmp_len);
    }

    /* Get founder public key */
    tmp = silc_argument_get_arg_type(args, 6, &tmp_len);
    if (tmp && mode & SILC_CHANNEL_MODE_FOUNDER_AUTH) {
      if (channel->founder_key)
	silc_pkcs_public_key_free(channel->founder_key);
      channel->founder_key = NULL;
      if (!silc_pkcs_public_key_payload_decode(tmp, tmp_len,
					       &channel->founder_key)) {
	SILC_LOG_DEBUG(("Enforcing sender to change channel mode"));
	mode &= ~SILC_CHANNEL_MODE_FOUNDER_AUTH;
	silc_server_send_notify_cmode(server, sock, FALSE, channel,
				      mode, server->id, SILC_ID_SERVER,
				      channel->cipher,
				      channel->hmac_name,
				      channel->passphrase, NULL, NULL);
	if (channel->founder_key)
	  silc_pkcs_public_key_free(channel->founder_key);
	channel->founder_key = NULL;
      }
    }

    if (mode & SILC_CHANNEL_MODE_FOUNDER_AUTH && !channel->founder_key &&
	server->server_type == SILC_ROUTER) {
      SILC_LOG_DEBUG(("Enforcing sender to change channel mode"));
      mode &= ~SILC_CHANNEL_MODE_FOUNDER_AUTH;
      silc_server_send_notify_cmode(server, sock, FALSE, channel,
				    mode, server->id, SILC_ID_SERVER,
				    channel->cipher,
				    channel->hmac_name,
				    channel->passphrase, NULL, NULL);
    }

    /* Process channel public key(s). */
    tmp = silc_argument_get_arg_type(args, 7, &tmp_len);
    if (tmp && mode & SILC_CHANNEL_MODE_CHANNEL_AUTH) {
      SilcStatus ret =
	silc_server_set_channel_pk_list(server, sock, channel, tmp, tmp_len);

      /* If list was set already we will enforce the same list to server. */
      if (ret == SILC_STATUS_ERR_OPERATION_ALLOWED) {
	SilcBuffer chpklist = silc_server_get_channel_pk_list(server, channel,
							      TRUE, FALSE);
	silc_server_send_notify_cmode(server, sock, FALSE, channel,
				      mode, server->id, SILC_ID_SERVER,
				      channel->cipher,
				      channel->hmac_name,
				      channel->passphrase, NULL,
				      chpklist);
	silc_buffer_free(chpklist);
      }
    }

    /* Get the user limit */
    tmp = silc_argument_get_arg_type(args, 8, &tmp_len);
    if (tmp && tmp_len == 4 && mode & SILC_CHANNEL_MODE_ULIMIT)
      SILC_GET32_MSB(channel->user_limit, tmp);

    /* Send the same notify to the channel */
    silc_server_packet_send_to_channel(server, NULL, channel, packet->type,
				       FALSE, TRUE, packet->buffer->data,
				       packet->buffer->len, FALSE);

    /* Change mode */
    channel->mode = mode;

    /* Cleanup if some modes are removed */

    if (!(channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH) &&
	channel->founder_key) {
      silc_pkcs_public_key_free(channel->founder_key);
      channel->founder_key = NULL;
    }

    if (!(channel->mode & SILC_CHANNEL_MODE_CHANNEL_AUTH) &&
	channel->channel_pubkeys) {
      silc_hash_table_free(channel->channel_pubkeys);
      channel->channel_pubkeys = NULL;
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
      }
      silc_free(client_id);

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
	  SILC_LOG_DEBUG(("Notify for unknown channel"));
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

	if (client != client2 && server->server_type == SILC_ROUTER) {
	  /* Sender must be operator */
	  if (!(chl->mode & SILC_CHANNEL_UMODE_CHANOP) &&
	      !(chl->mode & SILC_CHANNEL_UMODE_CHANFO)) {
	    SILC_LOG_DEBUG(("CUMODE change is not allowed"));
	    goto out;
	  }

	  if (!silc_server_client_on_channel(client2, channel, &chl))
	    goto out;

	  /* If target is founder mode change is not allowed. */
	  if (chl->mode & SILC_CHANNEL_UMODE_CHANFO) {
	    SILC_LOG_DEBUG(("CUMODE change is not allowed"));
	    goto out;
	  }
	}
      }

      /* Get target channel user entry */
      if (!silc_server_client_on_channel(client2, channel, &chl))
	goto out;

      if (server->server_type == SILC_SERVER && chl->mode == mode) {
	SILC_LOG_DEBUG(("Mode is changed already"));
	break;
      }

      /* Check whether to give founder rights to this user or not.  The
	 problem here is that we get only the public key of the client,
	 but no authentication data.  We must assume that server has
	 already authenticated the user (and thus we must trust the
	 server). */
      if (mode & SILC_CHANNEL_UMODE_CHANFO &&
	  !(chl->mode & SILC_CHANNEL_UMODE_CHANFO) &&
	  server->server_type == SILC_ROUTER &&
	  sock != SILC_PRIMARY_ROUTE(server)) {
	SilcPublicKey founder_key = NULL;

	/* If channel doesn't have founder auth mode then it's impossible
	   that someone would be getting founder rights with CUMODE command.
	   In that case there already either is founder or there isn't
	   founder at all on the channel (valid only when 'client' is
	   valid). */
	if (client && !(channel->mode & SILC_CHANNEL_MODE_FOUNDER_AUTH)) {
	  /* Force the mode to not have founder mode */
	  chl->mode = mode &= ~SILC_CHANNEL_UMODE_CHANFO;
	  silc_server_force_cumode_change(server, sock, channel, chl, mode);
	  notify_sent = TRUE;
	  break;
	}

	/* Get the founder of the channel and if found then this client
	   cannot be the founder since there already is one. */
	silc_hash_table_list(channel->user_list, &htl);
	while (silc_hash_table_get(&htl, NULL, (void *)&chl2))
	  if (chl2->mode & SILC_CHANNEL_UMODE_CHANFO) {
	    SILC_LOG_DEBUG(("Founder already on channel"));
	    chl->mode = mode &= ~SILC_CHANNEL_UMODE_CHANFO;
	    silc_server_force_cumode_change(server, sock, channel,
					    chl, mode);
	    notify_sent = TRUE;
	    break;
	  }
	silc_hash_table_list_reset(&htl);
	if (!(mode & SILC_CHANNEL_UMODE_CHANFO))
	  break;

	/* Founder not found on the channel.  Since the founder auth mode
	   is set on the channel now check whether this is the client that
	   originally set the mode. */

	if (channel->founder_key) {
	  /* Get public key that must be present in notify */
	  tmp = silc_argument_get_arg_type(args, 4, &tmp_len);
	  if (!tmp || !silc_pkcs_public_key_payload_decode(tmp, tmp_len,
							   &founder_key)) {
	    chl->mode = mode &= ~SILC_CHANNEL_UMODE_CHANFO;
	    SILC_LOG_DEBUG(("Founder public key not present"));
	    silc_server_force_cumode_change(server, sock, channel, chl, mode);
	    notify_sent = TRUE;
	    break;
	  }

	  /* Now match the public key we have cached and public key sent.
	     They must match. */
	  if (!silc_pkcs_public_key_compare(channel->founder_key,
					    founder_key)) {
	    chl->mode = mode &= ~SILC_CHANNEL_UMODE_CHANFO;
	    SILC_LOG_DEBUG(("Founder public key mismatch"));
	    silc_server_force_cumode_change(server, sock, channel, chl, mode);
	    notify_sent = TRUE;
	    break;
	  }
	}

	/* There cannot be anyone else as founder on the channel now.  This
	   client is definitely the founder due to this 'authentication'.
	   We trust the server did the actual signature verification
	   earlier (bad, yes). */
	silc_hash_table_list(channel->user_list, &htl);
	while (silc_hash_table_get(&htl, NULL, (void *)&chl2))
	  if (chl2->mode & SILC_CHANNEL_UMODE_CHANFO) {
	    chl2->mode &= ~SILC_CHANNEL_UMODE_CHANFO;
	    SILC_LOG_DEBUG(("Removing old founder rights, new authenticated"));
	    silc_server_force_cumode_change(server, NULL, channel, chl2,
					    chl2->mode);
	    break;
	  }
	silc_hash_table_list_reset(&htl);

	if (founder_key)
	  silc_pkcs_public_key_free(founder_key);
      }

      if (server->server_type != SILC_SERVER && chl->mode == mode) {
	SILC_LOG_DEBUG(("Mode is changed already"));
	break;
      }

      SILC_LOG_DEBUG(("Changing %s channel user mode",
		      chl->client->nickname ? chl->client->nickname :
		      (unsigned char *)""));

      /* Change the mode */
      chl->mode = mode;

      /* Send the same notify to the channel */
      if (!notify_sent)
	silc_server_packet_send_to_channel(server, NULL, channel,
					   packet->type,
					   FALSE, TRUE, packet->buffer->data,
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
	SILC_LOG_DEBUG(("Notify for unknown channel"));
	silc_free(channel_id);
	goto out;
      }
    }
    silc_free(channel_id);

#if 0 /* These aren't actually used anywhere or needed, since this
	 notify is for handling the invite list (direct invite
	 goes to client and is not handled here at all). */

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
    if (server->server_type == SILC_ROUTER) {
      if (!silc_server_client_on_channel(client, channel, &chl))
        goto out;
      if (channel->mode & SILC_CHANNEL_MODE_INVITE &&
	  !(chl->mode & SILC_CHANNEL_UMODE_CHANOP) &&
	  !(chl->mode & SILC_CHANNEL_UMODE_CHANFO)) {
        SILC_LOG_DEBUG(("Inviting is not allowed"));
        goto out;
      }
    }
#endif

    /* Get the invite action */
    tmp = silc_argument_get_arg_type(args, 4, &tmp_len);
    if (tmp && tmp_len == 1) {
      SilcUInt8 action = (SilcUInt8)tmp[0];
      SilcUInt16 iargc = 0;
      SilcArgumentPayload iargs;

      /* Get invite list */
      tmp = silc_argument_get_arg_type(args, 5, &tmp_len);
      if (!tmp || tmp_len < 2)
	goto out;

      /* Parse the arguments to see they are constructed correctly */
      SILC_GET16_MSB(iargc, tmp);
      iargs = silc_argument_payload_parse(tmp + 2, tmp_len - 2, iargc);
      if (!iargs)
	goto out;

      if (action != 0x01 && !channel->invite_list)
	channel->invite_list =
	  silc_hash_table_alloc(0, silc_hash_ptr,
				NULL, NULL, NULL,
				silc_server_inviteban_destruct, channel, TRUE);

      /* Proces the invite action */
      silc_server_inviteban_process(server, channel->invite_list, action,
				    iargs);
      silc_argument_payload_free(iargs);

      /* If we are router we must send this notify to our local servers on
         the channel.  Normal server does nothing.  The notify is not
         sent to clients. */
      if (server->server_type == SILC_ROUTER)
	silc_server_packet_send_to_channel(server, sock, channel,
					   packet->type, FALSE, FALSE,
					   packet->buffer->data,
					   packet->buffer->len, FALSE);
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
	SILC_LOG_DEBUG(("Notify for unknown channel"));
	silc_free(channel_id);
	goto out;
      }
    }

    /* Send the notify to the channel */
    silc_server_packet_send_to_channel(server, sock, channel, packet->type,
				       FALSE, TRUE, packet->buffer->data,
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
      SilcBuffer modes = NULL, users = NULL, users_modes = NULL;

      /* Re-announce this channel which ID was changed. */
      silc_server_send_new_channel(server, sock, FALSE, channel->channel_name,
				   channel->id,
				   silc_id_get_len(channel->id,
						   SILC_ID_CHANNEL),
				   channel->mode);

      /* Re-announce our clients on the channel as the ID has changed now */
      silc_server_announce_get_channel_users(server, channel, &modes, &users,
					     &users_modes);
      if (users) {
	silc_buffer_push(users, users->data - users->head);
	silc_server_packet_send(server, sock,
				SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
				users->data, users->len, FALSE);
	silc_buffer_free(users);
      }
      if (modes) {
	silc_buffer_push(modes, modes->data - modes->head);
	silc_server_packet_send_dest(server, sock,
				     SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
				     channel->id, SILC_ID_CHANNEL,
				     modes->data, modes->len, FALSE);
	silc_buffer_free(modes);
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
					  server->id, SILC_ID_SERVER,
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

    /* Backup router shouldn't accept SERVER_SIGNOFF's from normal routers
       when the backup isn't acting as primary router. */
    if (sock->type == SILC_SOCKET_TYPE_SERVER &&
	server->backup_router && server->server_type == SILC_BACKUP_ROUTER)
      return;

    /* Get Server ID */
    tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
    if (!tmp)
      goto out;
    server_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
    if (!server_id)
      goto out;

    /* If the ID is mine, this notify is not allowed. */
    if (SILC_ID_SERVER_COMPARE(server_id, server->id)) {
      SILC_LOG_DEBUG(("Ignoring my own ID for SERVER_SIGNOFF"));
      break;
    }

    /* Get server entry */
    server_entry = silc_idlist_find_server_by_id(server->global_list,
						 server_id, TRUE, NULL);
    local = FALSE;
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
	    local = FALSE;
	    if (!client) {
	      client = silc_idlist_find_client_by_id(server->local_list,
						     client_id, TRUE, &cache);
	      local = TRUE;
	      if (!client) {
		silc_free(client_id);
		continue;
	      }
	    }
	    silc_free(client_id);

	    /* Update statistics */
	    server->stat.clients--;
	    if (server->stat.cell_clients)
	      server->stat.cell_clients--;
	    SILC_OPER_STATS_UPDATE(client, server, SILC_UMODE_SERVER_OPERATOR);
	    SILC_OPER_STATS_UPDATE(client, router, SILC_UMODE_ROUTER_OPERATOR);

	    /* Remove the client from all channels. */
	    silc_server_remove_from_channels(server, NULL, client,
					     TRUE, NULL, FALSE, FALSE);

	    /* Check if anyone is watching this nickname */
	    if (server->server_type == SILC_ROUTER)
	      silc_server_check_watcher_list(server, client, NULL,
					     SILC_NOTIFY_TYPE_SERVER_SIGNOFF);

	    /* Remove this client from watcher list if it is */
	    if (local)
	      silc_server_del_from_watcher_list(server, client);

	    /* Remove from public key hash table. */
	    if (client->data.public_key)
	      silc_hash_table_del_by_context(server->pk_hash,
                                             client->data.public_key,
                                             client);

	    /* Remove the client */
	    silc_idlist_del_data(client);
	    silc_idlist_del_client(local ? server->local_list :
				   server->global_list, client);
	  }
	}

	silc_free(server_id);
	goto out;
      }
    }
    silc_free(server_id);

    /* For local entrys SERVER_SIGNOFF is processed only on backup router.
       It is possible that router sends server signoff for a server.  If
       backup router has it as local connection it will be closed. */
    if (SILC_IS_LOCAL(server_entry)) {
      if (server->server_type == SILC_BACKUP_ROUTER) {
	sock = server_entry->connection;
	SILC_LOG_DEBUG(("Closing connection %s after SERVER_SIGNOFF",
		       sock->hostname));
	if (sock->user_data)
	  silc_server_free_sock_user_data(server, sock, NULL);
	SILC_SET_DISCONNECTING(sock);
	silc_server_close_connection(server, sock);
      }

      break;
    }

    /* Remove all servers that are originated from this server, and
       remove the clients of those servers too. */
    silc_server_remove_servers_by_server(server, server_entry, TRUE);

    /* Remove the clients that this server owns as they will become
       invalid now too. */
    silc_server_remove_clients_by_server(server, server_entry->router,
					 server_entry, TRUE);
    silc_server_backup_del(server, server_entry);

    /* Remove the server entry */
    silc_idlist_del_server(local ? server->local_list :
			   server->global_list, server_entry);

    /* Update statistics */
    if (server->server_type == SILC_ROUTER)
      server->stat.servers--;

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
	SILC_LOG_DEBUG(("Notify for unknown channel"));
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

    /* Get the kicker's Client ID */
    tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
    if (!tmp)
      goto out;
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
    if (!(chl->mode & SILC_CHANNEL_UMODE_CHANOP) &&
	!(chl->mode & SILC_CHANNEL_UMODE_CHANFO)) {
      SILC_LOG_DEBUG(("Kicking is not allowed"));
      goto out;
    }

    /* Send to channel */
    silc_server_packet_send_to_channel(server, sock, channel, packet->type,
				       FALSE, TRUE, packet->buffer->data,
				       packet->buffer->len, FALSE);

    /* Remove the client from channel's invite list */
    if (channel->invite_list && silc_hash_table_count(channel->invite_list)) {
      SilcBuffer ab;
      SilcArgumentPayload iargs;
      tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
      ab = silc_argument_payload_encode_one(NULL, tmp, tmp_len, 3);
      iargs = silc_argument_payload_parse(ab->data, ab->len, 1);
      silc_server_inviteban_process(server, channel->invite_list, 1, iargs);
      silc_buffer_free(ab);
      silc_argument_payload_free(iargs);
    }

    /* Remove the client from channel */
    silc_server_remove_from_one_channel(server, sock, channel, client, FALSE);

    break;

  case SILC_NOTIFY_TYPE_KILLED:
    {
      /*
       * Distribute the notify to local clients on channels
       */
      unsigned char *id, *comment;
      SilcUInt32 id_len, comment_len;

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

      /* If the client is one of ours, then close the connection to the
	 client now. This removes the client from all channels as well. */
      if (packet->dst_id_type == SILC_ID_CLIENT && client->connection) {
	sock = client->connection;
	silc_server_free_client_data(server, NULL, client, FALSE, NULL);
	silc_server_close_connection(server, sock);
	break;
      }

      /* Get comment */
      comment = silc_argument_get_arg_type(args, 2, &comment_len);
      if (comment_len > 128)
	comment_len = 127;

      /* Get the killer's Client ID */
      tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
      if (!tmp)
	goto out;
      client_id = silc_id_payload_parse_id(tmp, tmp_len, &id_type);
      if (!client_id)
	goto out;

      if (id_type == SILC_ID_CLIENT) {
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

	/* Killer must be router operator */
	if (server->server_type != SILC_SERVER &&
	    !(client2->mode & SILC_UMODE_ROUTER_OPERATOR)) {
	  SILC_LOG_DEBUG(("Killing is not allowed"));
	  goto out;
	}
      }

      /* Send the notify to local clients on the channels except to the
	 client who is killed. */
      silc_server_send_notify_on_channels(server, client, client,
					  SILC_NOTIFY_TYPE_KILLED, 3,
					  id, id_len, comment, comment_len,
					  tmp, tmp_len);

      /* Remove the client from all channels */
      silc_server_remove_from_channels(server, NULL, client, FALSE, NULL,
				       FALSE, TRUE);

      /* Check if anyone is watching this nickname */
      silc_server_check_watcher_list(server, client, NULL,
				     SILC_NOTIFY_TYPE_KILLED);

      /* Remove from public key hash table. */
      if (client->data.public_key)
	silc_hash_table_del_by_context(server->pk_hash,
	                               client->data.public_key,
	  			       client);

      /* Update statistics */
      server->stat.clients--;
      if (server->stat.cell_clients)
	server->stat.cell_clients--;
      SILC_OPER_STATS_UPDATE(client, server, SILC_UMODE_SERVER_OPERATOR);
      SILC_OPER_STATS_UPDATE(client, router, SILC_UMODE_ROUTER_OPERATOR);

      if (SILC_IS_LOCAL(client)) {
 	server->stat.my_clients--;
	silc_schedule_task_del_by_context(server->schedule, client);
	silc_idlist_del_data(client);
	client->mode = 0;
      }

      client->data.status &= ~SILC_IDLIST_STATUS_REGISTERED;
      cache->expire = SILC_ID_CACHE_EXPIRE_DEF;
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

    /* Remove internal resumed flag if client is marked detached now */
    if (mode & SILC_UMODE_DETACHED)
      client->data.status &= ~SILC_IDLIST_STATUS_RESUMED;

    /* Update statistics */
    if (server->server_type == SILC_ROUTER) {
      if (mode & SILC_UMODE_GONE) {
	if (!(client->mode & SILC_UMODE_GONE))
	  server->stat.aways++;
      } else {
	if (client->mode & SILC_UMODE_GONE)
	  server->stat.aways--;
      }
      if (mode & SILC_UMODE_DETACHED) {
	if (!(client->mode & SILC_UMODE_DETACHED))
	  server->stat.detached++;
      } else {
	if (client->mode & SILC_UMODE_DETACHED)
	  server->stat.detached--;
      }
    }
    SILC_UMODE_STATS_UPDATE(server, SILC_UMODE_SERVER_OPERATOR);
    SILC_UMODE_STATS_UPDATE(router, SILC_UMODE_ROUTER_OPERATOR);

    /* Change the mode */
    client->mode = mode;

    /* Check if anyone is watching this nickname */
    if (server->server_type == SILC_ROUTER)
      silc_server_check_watcher_list(server, client, NULL,
				     SILC_NOTIFY_TYPE_UMODE_CHANGE);

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
	SILC_LOG_DEBUG(("Notify for unknown channel"));
	silc_free(channel_id);
	goto out;
      }
    }
    silc_free(channel_id);

    /* Get the ban action */
    tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
    if (tmp && tmp_len == 1) {
      SilcUInt8 action = (SilcUInt8)tmp[0];
      SilcUInt16 iargc = 0;
      SilcArgumentPayload iargs;

      /* Get ban list */
      tmp = silc_argument_get_arg_type(args, 3, &tmp_len);
      if (!tmp || tmp_len < 2)
	goto out;

      /* Parse the arguments to see they are constructed correctly */
      SILC_GET16_MSB(iargc, tmp);
      iargs = silc_argument_payload_parse(tmp + 2, tmp_len - 2, iargc);
      if (!iargs)
	goto out;

      if (action != 0x01 && !channel->ban_list)
	channel->ban_list =
	  silc_hash_table_alloc(0, silc_hash_ptr,
				NULL, NULL, NULL,
				silc_server_inviteban_destruct, channel, TRUE);

      /* Proces the ban action */
      silc_server_inviteban_process(server, channel->ban_list, action,
				    iargs);
      silc_argument_payload_free(iargs);

      /* If we are router we must send this notify to our local servers on
         the channel.  Normal server does nothing.  The notify is not
         sent to clients. */
      if (server->server_type == SILC_ROUTER)
	silc_server_packet_send_to_channel(server, sock, channel,
					   packet->type, FALSE, FALSE,
					   packet->buffer->data,
					   packet->buffer->len, FALSE);
    }
    break;

  case SILC_NOTIFY_TYPE_ERROR:
    {
      /*
       * Error notify
       */
      SilcStatus error;

      tmp = silc_argument_get_arg_type(args, 1, &tmp_len);
      if (!tmp && tmp_len != 1)
	goto out;
      error = (SilcStatus)tmp[0];

      SILC_LOG_DEBUG(("ERROR notify (%d)", error));

      if (error == SILC_STATUS_ERR_NO_SUCH_CLIENT_ID &&
	  sock->type == SILC_SOCKET_TYPE_ROUTER) {
	tmp = silc_argument_get_arg_type(args, 2, &tmp_len);
	if (tmp) {
	  SILC_LOG_DEBUG(("Received invalid client ID notification, deleting "
			  "the entry from cache"));
	  client_id = silc_id_payload_parse_id(tmp, tmp_len, NULL);
	  if (!client_id)
	    goto out;
	  client = silc_idlist_find_client_by_id(server->global_list,
						 client_id, FALSE, NULL);
	  if (client) {
	    if (client->data.public_key)
	      silc_hash_table_del_by_context(server->pk_hash,
		                             client->data.public_key,
		                             client);

	    silc_server_remove_from_channels(server, NULL, client, TRUE,
					     NULL, TRUE, FALSE);
	    silc_idlist_del_data(client);
	    silc_idlist_del_client(server->global_list, client);
	  }
	  silc_free(client_id);
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
  SilcClientEntry client;

  SILC_LOG_DEBUG(("Start"));

  if (packet->src_id_type != SILC_ID_CLIENT ||
      packet->dst_id_type != SILC_ID_CLIENT || !packet->dst_id)
    return;

  /* Get the route to the client */
  dst_sock = silc_server_get_client_route(server, packet->dst_id,
					  packet->dst_id_len, NULL,
					  &idata, &client);
  if (!dst_sock) {
    SilcBuffer idp;
    unsigned char error;

    if (client && client->mode & SILC_UMODE_DETACHED) {
      SILC_LOG_DEBUG(("Client is detached, discarding packet"));
      return;
    }

    /* Send SILC_NOTIFY_TYPE_ERROR to indicate that such destination ID
       does not exist or is invalid. */
    idp = silc_id_payload_encode_data(packet->dst_id,
				      packet->dst_id_len,
				      packet->dst_id_type);
    if (!idp)
      return;

    error = SILC_STATUS_ERR_NO_SUCH_CLIENT_ID;
    if (packet->src_id_type == SILC_ID_CLIENT) {
      SilcClientID *client_id = silc_id_str2id(packet->src_id,
					       packet->src_id_len,
					       packet->src_id_type);
      silc_server_send_notify_dest(server, sock, FALSE,
				   client_id, SILC_ID_CLIENT,
				   SILC_NOTIFY_TYPE_ERROR, 2,
				   &error, 1,
				   idp->data, idp->len);
      silc_free(client_id);
    } else {
      silc_server_send_notify(server, sock, FALSE,
			      SILC_NOTIFY_TYPE_ERROR, 2,
			      &error, 1,
			      idp->data, idp->len);
    }

    silc_buffer_free(idp);
    return;
  }

  /* Check whether destination client wishes to receive private messages */
  if (client && !(packet->flags & SILC_PACKET_FLAG_PRIVMSG_KEY) &&
      client->mode & SILC_UMODE_BLOCK_PRIVMSG) {
    SILC_LOG_DEBUG(("Client blocks private messages, discarding packet"));
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
					  packet->dst_id_len, NULL,
					  &idata, NULL);
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
  SilcChannelClientEntry chl;
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
      SilcBuffer idp;
      unsigned char error;

      /* Send SILC_NOTIFY_TYPE_ERROR to indicate that such destination ID
	 does not exist or is invalid. */
      idp = silc_id_payload_encode_data(packet->dst_id,
					packet->dst_id_len,
					packet->dst_id_type);
      if (!idp)
	goto out;

      error = SILC_STATUS_ERR_NO_SUCH_CHANNEL_ID;
      if (packet->src_id_type == SILC_ID_CLIENT) {
	SilcClientID *client_id = silc_id_str2id(packet->src_id,
						 packet->src_id_len,
						 packet->src_id_type);
	silc_server_send_notify_dest(server, sock, FALSE,
				     client_id, SILC_ID_CLIENT,
				     SILC_NOTIFY_TYPE_ERROR, 2,
				     &error, 1, idp->data, idp->len);
	silc_free(client_id);
      } else {
	silc_server_send_notify(server, sock, FALSE,
				SILC_NOTIFY_TYPE_ERROR, 2,
				&error, 1, idp->data, idp->len);
      }

      silc_buffer_free(idp);
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
							channel, &chl)) {
      SILC_LOG_DEBUG(("Client not on channel"));
      goto out;
    }

    /* If channel is moderated check that client is allowed to send
       messages. */
    if (channel->mode & SILC_CHANNEL_MODE_SILENCE_USERS &&
	!(chl->mode & SILC_CHANNEL_UMODE_CHANOP) &&
	!(chl->mode & SILC_CHANNEL_UMODE_CHANFO)) {
      SILC_LOG_DEBUG(("Channel is silenced from normal users"));
      goto out;
    }
    if (channel->mode & SILC_CHANNEL_MODE_SILENCE_OPERS &&
	chl->mode & SILC_CHANNEL_UMODE_CHANOP &&
	!(chl->mode & SILC_CHANNEL_UMODE_CHANFO)) {
      SILC_LOG_DEBUG(("Channel is silenced from operators"));
      goto out;
    }
    if (chl->mode & SILC_CHANNEL_UMODE_QUIET) {
      SILC_LOG_DEBUG(("Sender is quieted on the channel"));
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
      (server->server_type == SILC_ROUTER && !server->backup_router &&
       sock->type == SILC_SOCKET_TYPE_ROUTER))
    return;

  /* Save the channel key */
  channel = silc_server_save_channel_key(server, buffer, NULL);
  if (!channel) {
    SILC_LOG_ERROR(("Bad channel key from %s (%s)",
		    sock->hostname, sock->ip));
    return;
  }

  /* Distribute the key to everybody who is on the channel. If we are router
     we will also send it to locally connected servers. */
  silc_server_send_channel_key(server, sock, channel, FALSE);

  if (server->server_type != SILC_BACKUP_ROUTER) {
    /* Distribute to local cell backup routers. */
    silc_server_backup_send(server, sock->user_data,
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
  SilcIDListData idata;
  char *username = NULL, *realname = NULL;
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
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_NOT_AUTHENTICATED, NULL);
    if (sock->user_data)
      silc_server_free_sock_user_data(server, sock, NULL);
    return NULL;
  }

  /* Make sure this client hasn't registered already */
  if (idata->status & SILC_IDLIST_STATUS_REGISTERED) {
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_OPERATION_ALLOWED,
				  "Too many registrations");
    if (sock->user_data)
      silc_server_free_sock_user_data(server, sock, NULL);
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
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
				  NULL);
    if (sock->user_data)
      silc_server_free_sock_user_data(server, sock, NULL);
    return NULL;
  }

  if (!username) {
    silc_free(username);
    silc_free(realname);
    SILC_LOG_ERROR(("Client %s (%s) did not send its username, closing "
		    "connection", sock->hostname, sock->ip));
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
				  NULL);
    if (sock->user_data)
      silc_server_free_sock_user_data(server, sock, NULL);
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
				    SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
				    NULL);
      if (sock->user_data)
	silc_server_free_sock_user_data(server, sock, NULL);
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
				    SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
				    NULL);
      if (sock->user_data)
	silc_server_free_sock_user_data(server, sock, NULL);
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
    if (nickfail > 9) {
      silc_server_disconnect_remote(server, sock,
				    SILC_STATUS_ERR_BAD_NICKNAME, NULL);
      if (sock->user_data)
	silc_server_free_sock_user_data(server, sock, NULL);
      return NULL;
    }
    snprintf(&nickname[strlen(nickname) - 1], 1, "%d", nickfail);
  }

  /* If client marked as anonymous, scramble the username and hostname */
  if (client->mode & SILC_UMODE_ANONYMOUS) {
    char *scramble;

    if (strlen(username) >= 2) {
      username[0] = silc_rng_get_byte_fast(server->rng);
      username[1] = silc_rng_get_byte_fast(server->rng);
    }

    scramble = silc_hash_babbleprint(server->sha1hash, username,
				     strlen(username));
    scramble[5] = '@';
    scramble[11] = '.';
    memcpy(&scramble[16], ".silc", 5);
    scramble[21] = '\0';
    silc_free(username);
    username = scramble;
  }

  /* Update client entry */
  idata->status |= SILC_IDLIST_STATUS_REGISTERED;
  client->nickname = nickname;
  client->username = username;
  client->userinfo = realname ? realname : strdup(username);
  client->id = client_id;
  id_len = silc_id_get_len(client_id, SILC_ID_CLIENT);

  /* Add the client again to the ID cache */
  silc_idcache_add(server->local_list->clients, client->nickname,
		   client_id, client, 0, NULL);

  /* Notify our router about new client on the SILC network */
  silc_server_send_new_id(server, SILC_PRIMARY_ROUTE(server),
			  SILC_BROADCAST(server), client->id,
			  SILC_ID_CLIENT, id_len);

  /* Distribute to backup routers */
  if (server->server_type == SILC_ROUTER) {
    SilcBuffer idp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
    silc_server_backup_send(server, sock->user_data, SILC_PACKET_NEW_ID, 0,
			    idp->data, idp->len, FALSE, TRUE);
    silc_buffer_free(idp);
  }

  /* Send the new client ID to the client. */
  silc_server_send_new_id(server, sock, FALSE, client->id, SILC_ID_CLIENT,
			  silc_id_get_len(client->id, SILC_ID_CLIENT));

  /* Send some nice info to the client */
  silc_server_send_connect_notifys(server, sock, client);

  /* Check if anyone is watching this nickname */
  if (server->server_type == SILC_ROUTER)
    silc_server_check_watcher_list(server, client, NULL, 0);

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

  /* Statistics */
  if (server->server_type == SILC_ROUTER)
    server->stat.cell_servers++;

  /* Remove the old cache entry */
  if (!silc_idcache_del_by_context(server->local_list->servers, new_server)) {
    if (!silc_idcache_del_by_context(server->global_list->servers,
				     new_server)) {
      SILC_LOG_INFO(("Unauthenticated %s attempted to register to "
		     "network", (sock->type == SILC_SOCKET_TYPE_SERVER ?
				 "server" : "router")));
      silc_server_disconnect_remote(server, sock,
				    SILC_STATUS_ERR_NOT_AUTHENTICATED, NULL);
      if (sock->user_data)
	silc_server_free_sock_user_data(server, sock, NULL);
      return NULL;
    }
    local = FALSE;
  }

  /* Make sure this server hasn't registered already */
  if (idata->status & SILC_IDLIST_STATUS_REGISTERED) {
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_OPERATION_ALLOWED,
				  "Too many registrations");
    if (sock->user_data)
      silc_server_free_sock_user_data(server, sock, NULL);
    return NULL;
  }

  /* Parse the incoming packet */
  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI16_NSTRING_ALLOC(&id_string, &id_len),
			     SILC_STR_UI16_NSTRING_ALLOC(&server_name,
							 &name_len),
			     SILC_STR_END);
  if (ret == -1) {
    silc_free(id_string);
    silc_free(server_name);
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
				  NULL);
    if (sock->user_data)
      silc_server_free_sock_user_data(server, sock, NULL);
    return NULL;
  }

  if (id_len > buffer->len) {
    silc_free(id_string);
    silc_free(server_name);
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
				  NULL);
    if (sock->user_data)
      silc_server_free_sock_user_data(server, sock, NULL);
    return NULL;
  }

  if (name_len > 256)
    server_name[255] = '\0';

  /* Get Server ID */
  server_id = silc_id_str2id(id_string, id_len, SILC_ID_SERVER);
  if (!server_id) {
    silc_free(id_string);
    silc_free(server_name);
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
				  NULL);
    if (sock->user_data)
      silc_server_free_sock_user_data(server, sock, NULL);
    return NULL;
  }
  silc_free(id_string);

  /* Check for valid server ID */
  if (!silc_id_is_valid_server_id(server, server_id, sock)) {
    SILC_LOG_INFO(("Invalid server ID sent by %s (%s)",
		   sock->ip, sock->hostname));
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_BAD_SERVER_ID, NULL);
    if (sock->user_data)
      silc_server_free_sock_user_data(server, sock, NULL);
    silc_free(server_name);
    return NULL;
  }

  /* Check that we do not have this ID already */
  server_entry = silc_idlist_find_server_by_id(server->local_list,
					       server_id, TRUE, NULL);
  if (server_entry) {
    if (SILC_IS_LOCAL(server_entry)) {
      silc_server_disconnect_remote(server, sock,
				    SILC_STATUS_ERR_OPERATION_ALLOWED,
				    "Too many registrations");
      if (sock->user_data)
	silc_server_free_sock_user_data(server, sock, NULL);
      return NULL;
    } else {
      silc_idcache_del_by_context(server->local_list->servers, server_entry);
    }
  } else {
    server_entry = silc_idlist_find_server_by_id(server->global_list,
						 server_id, TRUE, NULL);
    if (server_entry) {
      if (SILC_IS_LOCAL(server_entry)) {
	silc_server_disconnect_remote(server, sock,
				      SILC_STATUS_ERR_OPERATION_ALLOWED,
				      "Too many registrations");
	if (sock->user_data)
	  silc_server_free_sock_user_data(server, sock, NULL);
	return NULL;
      } else {
	silc_idcache_del_by_context(server->global_list->servers,
				    server_entry);
      }
    }
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
      SILC_PRIMARY_ROUTE(server) != sock)
    silc_server_send_new_id(server, SILC_PRIMARY_ROUTE(server),
			    TRUE, new_server->id, SILC_ID_SERVER,
			    silc_id_get_len(server_id, SILC_ID_SERVER));

  if (server->server_type == SILC_ROUTER) {
    /* Distribute to backup routers */
    SilcBuffer idp = silc_id_payload_encode(new_server->id, SILC_ID_SERVER);
    silc_server_backup_send(server, sock->user_data, SILC_PACKET_NEW_ID, 0,
			    idp->data, idp->len, FALSE, TRUE);
    silc_buffer_free(idp);
  }

  /* Check whether this router connection has been replaced by an
     backup router. If it has been then we'll disable the server and will
     ignore everything it will send until the backup router resuming
     protocol has been completed. */
  if (sock->type == SILC_SOCKET_TYPE_ROUTER &&
      silc_server_backup_replaced_get(server, server_id, NULL)) {
    /* Send packet to the router indicating that it cannot use this
       connection as it has been replaced by backup router. */
    SILC_LOG_DEBUG(("Remote router has been replaced by backup router, "
		    "disabling its connection"));

    silc_server_backup_send_replaced(server, sock);

    /* Mark the router disabled. The data sent earlier will go but nothing
       after this goes to this connection. */
    idata->status |= SILC_IDLIST_STATUS_DISABLED;
  } else {
    /* If it is router announce our stuff to it. */
    if (sock->type == SILC_SOCKET_TYPE_ROUTER &&
	server->server_type == SILC_ROUTER) {
      silc_server_announce_servers(server, FALSE, 0, sock);
      silc_server_announce_clients(server, 0, sock);
      silc_server_announce_channels(server, 0, sock);
    }

    /* Announce our information to backup router */
    if (new_server->server_type == SILC_BACKUP_ROUTER &&
	sock->type == SILC_SOCKET_TYPE_SERVER &&
	server->server_type == SILC_ROUTER) {
      silc_server_announce_servers(server, TRUE, 0, sock);
      silc_server_announce_clients(server, 0, sock);
      silc_server_announce_channels(server, 0, sock);
    }

    /* If backup router, mark it as one of ours.  This server is considered
       to be backup router after this setting. */
    if (new_server->server_type == SILC_BACKUP_ROUTER) {
      SilcServerConfigRouter *backup;
      backup = silc_server_config_find_backup_conn(server, sock->ip);
      if (!backup)
	backup = silc_server_config_find_backup_conn(server, sock->hostname);
      if (backup) {
	/* Add as our backup router */
	silc_server_backup_add(server, new_server, backup->backup_replace_ip,
			       backup->backup_replace_port,
			       backup->backup_local);
      }
    }

    /* By default the servers connected to backup router are disabled
       until backup router has become the primary */
    if (server->server_type == SILC_BACKUP_ROUTER &&
	sock->type == SILC_SOCKET_TYPE_SERVER)
      idata->status |= SILC_IDLIST_STATUS_DISABLED;
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
      router_sock = server->router ? SILC_PRIMARY_ROUTE(server) : sock;
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

      /* Check if anyone is watching this nickname */
      if (server->server_type == SILC_ROUTER && id_list == server->local_list)
	silc_server_check_watcher_list(server, entry, NULL, 0);

      if (server->server_type == SILC_ROUTER) {
	/* Add the client's public key to hash table or get the key with
	   GETKEY command. */
        if (entry->data.public_key)
	  silc_hash_table_add(server->pk_hash, entry->data.public_key, entry);
	else
	  silc_server_send_command(server, router_sock,
				   SILC_COMMAND_GETKEY, ++server->cmd_ident,
				   1, 1, buffer->data, buffer->len);
      }
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
  if (broadcast && server->server_type == SILC_ROUTER &&
      sock->type == SILC_SOCKET_TYPE_SERVER &&
      !(packet->flags & SILC_PACKET_FLAG_BROADCAST)) {
    SILC_LOG_DEBUG(("Broadcasting received New ID packet"));
    silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			    packet->type,
			    packet->flags | SILC_PACKET_FLAG_BROADCAST,
			    buffer->data, buffer->len, FALSE);
    silc_server_backup_send(server, sock->user_data,
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
  if (server->server_type == SILC_ROUTER &&
      sock->type == SILC_SOCKET_TYPE_SERVER &&
      !(packet->flags & SILC_PACKET_FLAG_BROADCAST)) {
    SILC_LOG_DEBUG(("Broadcasting received New ID List packet"));
    silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			    packet->type,
			    packet->flags | SILC_PACKET_FLAG_BROADCAST,
			    packet->buffer->data,
			    packet->buffer->len, FALSE);
    silc_server_backup_send(server, sock->user_data,
			    packet->type, packet->flags,
			    packet->buffer->data, packet->buffer->len,
			    FALSE, TRUE);
  }

  /* Make copy of the original packet context, except for the actual
     data buffer, which we will here now fetch from the original buffer. */
  new_id = silc_packet_context_alloc();
  new_id->type = SILC_PACKET_NEW_ID;
  new_id->flags = packet->flags & (~SILC_PACKET_FLAG_LIST);
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
  SilcUInt32 id_len, cipher_len;
  SilcServerEntry server_entry;
  SilcChannelEntry channel;
  const char *cipher;

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

      channel =
	silc_idlist_add_channel(server->global_list, strdup(channel_name),
				0, channel_id, sock->user_data, NULL, NULL, 0);
      if (!channel) {
	silc_channel_payload_free(payload);
	silc_free(channel_id);
	return;
      }
      channel->disabled = TRUE;    /* Disabled until someone JOINs */

      server->stat.channels++;
      if (server->server_type == SILC_ROUTER)
	channel->users_resolved = TRUE;
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
      SILC_LOG_DEBUG(("Channel is new to us"));

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
	  silc_channel_payload_free(payload);
	  silc_free(channel_id);
	  silc_free(tmp);
	}

	/* Wait that server re-announces this channel */
	return;
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
      channel->disabled = TRUE;    /* Disabled until someone JOINs */

#if 0 /* We assume that CMODE_CHANGE notify is sent to us after this. */

      /* XXX Dunno if this is supposed to be set in any server type.  If set
	 here the CMODE_CHANGE that may follow sets mode that we already
	 have, and we may loose data from the CMODE_CHANGE notify. */
      if (server_entry->server_type != SILC_BACKUP_ROUTER)
	channel->mode = silc_channel_get_mode(payload);
#endif

      /* Send the new channel key to the server */
      id = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
      id_len = silc_id_get_len(channel->id, SILC_ID_CHANNEL);
      cipher = silc_cipher_get_name(channel->channel_key);
      cipher_len = strlen(cipher);
      chk = silc_channel_key_payload_encode(id_len, id,
					    cipher_len, cipher,
					    channel->key_len / 8,
					    channel->key);
      silc_server_packet_send(server, sock, SILC_PACKET_CHANNEL_KEY, 0,
			      chk->data, chk->len, FALSE);
      silc_buffer_free(chk);
      silc_free(id);
    } else {
      /* The channel exist by that name, check whether the ID's match.
	 If they don't then we'll force the server to use the ID we have.
	 We also create a new key for the channel. */
      SilcBuffer modes = NULL, users = NULL, users_modes = NULL;

      SILC_LOG_DEBUG(("Channel already exists"));

      if (!SILC_ID_CHANNEL_COMPARE(channel_id, channel->id)) {
	/* They don't match, send CHANNEL_CHANGE notify to the server to
	   force the ID change. */
	SILC_LOG_DEBUG(("Forcing the server to change Channel ID"));
	silc_server_send_notify_channel_change(server, sock, FALSE,
					       channel_id, channel->id);
	silc_channel_payload_free(payload);
	silc_free(channel_id);

	/* Wait that server re-announces this channel */
	return;
      }

#if 0 /* We will announce our CMODE anyway for this channel, so no need
	 to check it (implicit enforce). */

      /* If the mode is different from what we have then enforce the
	 mode change. */
      mode = silc_channel_get_mode(payload);
      if (channel->mode != mode) {
	SILC_LOG_DEBUG(("Forcing the server to change channel mode"));
	silc_server_send_notify_cmode(server, sock, FALSE, channel,
				      channel->mode, server->id,
				      SILC_ID_SERVER, channel->cipher,
				      channel->hmac_name,
				      channel->passphrase,
				      channel->founder_key);
      }
#endif

      /* Create new key for the channel and send it to the server and
	 everybody else possibly on the channel. */
      if (!(channel->mode & SILC_CHANNEL_MODE_PRIVKEY)) {

	if (silc_hash_table_count(channel->user_list)) {
	  if (!silc_server_create_channel_key(server, channel, 0)) {
	    silc_channel_payload_free(payload);
	    silc_free(channel_id);
	    return;
	  }

	  /* Send to the channel */
	  silc_server_send_channel_key(server, sock, channel, FALSE);
	}

	/* Send to the server */
	id = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
	id_len = silc_id_get_len(channel->id, SILC_ID_CHANNEL);
	cipher = silc_cipher_get_name(channel->channel_key);
	cipher_len = strlen(cipher);
	chk = silc_channel_key_payload_encode(id_len, id,
					      cipher_len, cipher,
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
      silc_server_announce_get_channel_users(server, channel, &modes, &users,
					     &users_modes);
      if (users) {
	silc_buffer_push(users, users->data - users->head);
	silc_server_packet_send(server, sock,
				SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
				users->data, users->len, FALSE);
	silc_buffer_free(users);
      }
      if (modes) {
	silc_buffer_push(modes, modes->data - modes->head);
	silc_server_packet_send_dest(server, sock,
				     SILC_PACKET_NOTIFY, SILC_PACKET_FLAG_LIST,
				     channel->id, SILC_ID_CHANNEL,
				     modes->data, modes->len, FALSE);
	silc_buffer_free(modes);
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
      if (channel->topic) {
	silc_server_send_notify_topic_set(server, sock,
					  server->server_type == SILC_ROUTER ?
					  TRUE : FALSE, channel,
					  server->id, SILC_ID_SERVER,
					  channel->topic);
      }
    }
  }

  /* If the sender of this packet is server and we are router we need to
     broadcast this packet to other routers in the network. Broadcast
     this list packet instead of multiple New Channel packets. */
  if (server->server_type == SILC_ROUTER &&
      sock->type == SILC_SOCKET_TYPE_SERVER &&
      !(packet->flags & SILC_PACKET_FLAG_BROADCAST)) {
    SILC_LOG_DEBUG(("Broadcasting received New Channel packet"));
    silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			    packet->type,
			    packet->flags | SILC_PACKET_FLAG_BROADCAST,
			    packet->buffer->data,
			    packet->buffer->len, FALSE);
    silc_server_backup_send(server, sock->user_data,
			    packet->type, packet->flags,
			    packet->buffer->data, packet->buffer->len,
			    FALSE, TRUE);
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

  /* Make copy of the original packet context, except for the actual
     data buffer, which we will here now fetch from the original buffer. */
  new = silc_packet_context_alloc();
  new->type = SILC_PACKET_NEW_CHANNEL;
  new->flags = packet->flags & (~SILC_PACKET_FLAG_LIST);
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
					  packet->dst_id_len, NULL,
					  &idata, NULL);
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

  if (packet->src_id_type && packet->src_id_type != SILC_ID_CLIENT) {
    SILC_LOG_DEBUG(("Request not from client"));
    return;
  }

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

  SILC_LOG_DEBUG(("Authentication method is [%s]",
		  (auth_meth == SILC_AUTH_NONE ? "None" :
		   auth_meth == SILC_AUTH_PASSWORD ? "Passphrase" :
		   "Digital signatures")));

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

  SILC_LOG_DEBUG(("Received rekey request"));

  /* If we have other protocol executing we have no other choice but to
     not execute rekey. XXX This is very bad thing.  Let's hope this
     doesn't happen often. */
  if (sock->protocol) {
    SILC_LOG_WARNING(("Cannot execute REKEY protocol because other protocol "
		      "is executing at the same time"));
    return;
  }

  /* Allocate internal protocol context. This is sent as context
     to the protocol. */
  proto_ctx = silc_calloc(1, sizeof(*proto_ctx));
  proto_ctx->server = (void *)server;
  proto_ctx->sock = silc_socket_dup(sock);
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
					  packet->dst_id_len, NULL,
					  &idata, NULL);
  if (!dst_sock)
    return;

  /* Relay the packet */
  silc_server_relay_packet(server, dst_sock, idata->send_key,
			   idata->hmac_send, idata->psn_send++,
			   packet, FALSE);
}

typedef struct {
  SilcServer server;
  SilcSocketConnection sock;
  SilcPacketContext *packet;
  void *data;
} *SilcServerResumeResolve;

SILC_SERVER_CMD_FUNC(resume_resolve)
{
  SilcServerResumeResolve r = (SilcServerResumeResolve)context;
  SilcServer server = r->server;
  SilcSocketConnection sock = r->sock;
  SilcServerCommandReplyContext reply = context2;
  SilcClientEntry client;

  SILC_LOG_DEBUG(("Start"));

  if (!reply || !silc_command_get_status(reply->payload, NULL, NULL)) {
    SILC_LOG_ERROR(("Client %s (%s) tried to resume unknown client, "
		    "closing connection", sock->hostname, sock->ip));
    silc_server_disconnect_remote(server, sock,
				  SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
				  "Resuming not possible");
    if (sock->user_data)
      silc_server_free_sock_user_data(server, sock, NULL);
    goto out;
  }

  if (reply && silc_command_get(reply->payload) == SILC_COMMAND_WHOIS) {
    /* Get entry to the client, and resolve it if we don't have it. */
    client = silc_idlist_find_client_by_id(server->local_list,
					   r->data, TRUE, NULL);
    if (!client) {
      client = silc_idlist_find_client_by_id(server->global_list,
					     r->data, TRUE, NULL);
      if (!client) {
	SILC_LOG_ERROR(("Client %s (%s) tried to resume unknown client, "
			"closing connection", sock->hostname, sock->ip));
	silc_server_disconnect_remote(server, sock,
				      SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
				      "Resuming not possible");
	if (sock->user_data)
	  silc_server_free_sock_user_data(server, sock, NULL);
	goto out;
      }
    }

    if (!(client->mode & SILC_UMODE_DETACHED)) {
      SILC_LOG_ERROR(("Client %s (%s) tried to resume un-detached client, "
		      "closing connection", sock->hostname, sock->ip));
      silc_server_disconnect_remote(server, sock,
				    SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
				    "Resuming not possible");
      if (sock->user_data)
	silc_server_free_sock_user_data(server, sock, NULL);
      goto out;
    }

    client->data.status |= SILC_IDLIST_STATUS_RESUME_RES;
  }

  /* Reprocess the packet */
  silc_server_resume_client(server, sock, r->packet);

 out:
  silc_socket_free(r->sock);
  silc_packet_context_free(r->packet);
  silc_free(r->data);
  silc_free(r);
}

/* Received client resuming packet.  This is used to resume detached
   client session.  It can be sent by the client who wishes to resume
   but this is also sent by servers and routers to notify other routers
   that the client is not detached anymore. */

void silc_server_resume_client(SilcServer server,
			       SilcSocketConnection sock,
			       SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer, buf;
  SilcIDListData idata;
  SilcIDCacheEntry id_cache = NULL;
  SilcClientEntry detached_client;
  SilcClientID *client_id = NULL;
  unsigned char *id_string, *auth = NULL;
  SilcUInt16 id_len, auth_len = 0;
  int ret, nickfail = 0;
  bool resolved, local, nick_change = FALSE, resolve = FALSE;
  SilcChannelEntry channel;
  SilcHashTableList htl;
  SilcChannelClientEntry chl;
  SilcServerResumeResolve r;
  const char *cipher;

  ret = silc_buffer_unformat(buffer,
			     SILC_STR_UI16_NSTRING(&id_string, &id_len),
			     SILC_STR_END);
  if (ret != -1)
    client_id = silc_id_str2id(id_string, id_len, SILC_ID_CLIENT);

  if (sock->type == SILC_SOCKET_TYPE_CLIENT) {
    /* Client send this and is attempting to resume to old client session */
    SilcClientEntry client;
    SilcBuffer keyp;

    if (ret != -1) {
      silc_buffer_pull(buffer, 2 + id_len);
      auth = buffer->data;
      auth_len = buffer->len;
      silc_buffer_push(buffer, 2 + id_len);
    }

    if (!client_id || auth_len < 128) {
      SILC_LOG_ERROR(("Client %s (%s) sent incomplete resume information, "
		      "closing connection", sock->hostname, sock->ip));
      silc_server_disconnect_remote(server, sock,
				    SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
				    "Resuming not possible");
      if (sock->user_data)
	silc_server_free_sock_user_data(server, sock, NULL);
      silc_free(client_id);
      return;
    }

    /* Take client entry of this connection */
    client = (SilcClientEntry)sock->user_data;
    idata = (SilcIDListData)client;

    /* Get entry to the client, and resolve it if we don't have it. */
    detached_client = silc_server_query_client(server, client_id, FALSE,
					       &resolved);
    if (!detached_client) {
      if (resolved) {
	/* The client info is being resolved. Reprocess this packet after
	   receiving the reply to the query. */
	SILC_LOG_DEBUG(("Resolving client"));
	r = silc_calloc(1, sizeof(*r));
	if (!r)
	  return;
	r->server = server;
	r->sock = silc_socket_dup(sock);
	r->packet = silc_packet_context_dup(packet);
	r->data = client_id;
	silc_server_command_pending(server, SILC_COMMAND_WHOIS,
				    server->cmd_ident,
				    silc_server_command_resume_resolve, r);
      } else {
	SILC_LOG_ERROR(("Client %s (%s) tried to resume unknown client, "
			"closing connection", sock->hostname, sock->ip));
	silc_server_disconnect_remote(server, sock,
				      SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
				      "Resuming not possible");
	if (sock->user_data)
	  silc_server_free_sock_user_data(server, sock, NULL);
	silc_free(client_id);
      }
      return;
    }

    if (detached_client->data.status & SILC_IDLIST_STATUS_RESUMED) {
      SILC_LOG_ERROR(("Client %s (%s) tried to attach more than once, "
 	              "closing connection", sock->hostname, sock->ip));
      silc_server_disconnect_remote(server, sock,
                                    SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
 	                            "Resuming not possible");
      if (sock->user_data)
	silc_server_free_sock_user_data(server, sock, NULL);
      silc_free(client_id);

      return;
    }

    if (detached_client->resuming_client &&
	detached_client->resuming_client != client) {
      SILC_LOG_ERROR(("Client %s (%s) tried to attach more than once, "
 	              "closing connection", sock->hostname, sock->ip));
      silc_server_disconnect_remote(server, sock,
                                    SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
 	                            "Resuming not possible");
      if (sock->user_data)
	silc_server_free_sock_user_data(server, sock, NULL);
      silc_free(client_id);

      return;
    }

    if (!detached_client->resuming_client)
      detached_client->resuming_client = client;

    if (!(detached_client->mode & SILC_UMODE_DETACHED))
      resolve = TRUE;
    if (!silc_hash_table_count(detached_client->channels) &&
	detached_client->router)
      resolve = TRUE;
    if (!detached_client->nickname)
      resolve = TRUE;
    if (detached_client->data.status & SILC_IDLIST_STATUS_RESUME_RES)
      resolve = FALSE;

    if (resolve) {
      if (server->server_type == SILC_SERVER && !server->standalone) {
	/* The client info is being resolved. Reprocess this packet after
	   receiving the reply to the query. */
	SILC_LOG_DEBUG(("Resolving client info"));
	silc_server_query_client(server, client_id, TRUE, NULL);
	r = silc_calloc(1, sizeof(*r));
	if (!r)
	  return;
	r->server = server;
	r->sock = silc_socket_dup(sock);
	r->packet = silc_packet_context_dup(packet);
	r->data = client_id;
	silc_server_command_pending(server, SILC_COMMAND_WHOIS,
				    server->cmd_ident,
				    silc_server_command_resume_resolve, r);
	return;
      }
      if (server->server_type == SILC_SERVER) {
	SILC_LOG_ERROR(("Client %s (%s) tried to resume un-detached client, "
			"closing connection", sock->hostname, sock->ip));
	silc_server_disconnect_remote(server, sock,
				      SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
				      "Resuming not possible");
	if (sock->user_data)
	  silc_server_free_sock_user_data(server, sock, NULL);
	silc_free(client_id);
	return;
      }
    }

    /* Check that we have the public key of the client, if not then we must
       resolve it first. */
    if (!detached_client->data.public_key) {
      if (server->server_type == SILC_SERVER && server->standalone) {
	SILC_LOG_ERROR(("Detached client's public key not present, "
			"closing connection"));
	silc_server_disconnect_remote(server, sock,
				      SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
				      "Resuming not possible");
	if (sock->user_data)
	  silc_server_free_sock_user_data(server, sock, NULL);
	silc_free(client_id);
      } else {
	/* We must retrieve the detached client's public key by sending
	   GETKEY command. Reprocess this packet after receiving the key */
	SilcBuffer idp = silc_id_payload_encode(client_id, SILC_ID_CLIENT);
	SilcSocketConnection dest_sock =
	  silc_server_get_client_route(server, NULL, 0, client_id, NULL, NULL);

	SILC_LOG_DEBUG(("Resolving client public key"));

	silc_server_send_command(server, dest_sock ? dest_sock :
				 SILC_PRIMARY_ROUTE(server),
				 SILC_COMMAND_GETKEY, ++server->cmd_ident,
				 1, 1, idp->data, idp->len);

	r = silc_calloc(1, sizeof(*r));
	if (!r) {
	  silc_free(client_id);
	  return;
	}

	r->server = server;
	r->sock = silc_socket_dup(sock);
	r->packet = silc_packet_context_dup(packet);
	silc_server_command_pending(server, SILC_COMMAND_GETKEY,
				    server->cmd_ident,
				    silc_server_command_resume_resolve, r);

	silc_buffer_free(idp);
      }
      silc_free(client_id);
      return;
    } else if (!silc_pkcs_public_key_compare(detached_client->data.public_key,
					     idata->public_key)) {
      /* We require that the connection and resuming authentication data
	 must be using same key pair. */
      SILC_LOG_ERROR(("Resuming attempted with wrong public key, "
		      "closing connection"));
      silc_server_disconnect_remote(server, sock,
				    SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
				    "Resuming not possible");
      if (sock->user_data)
	silc_server_free_sock_user_data(server, sock, NULL);
      silc_free(client_id);
      return;
    }

    /* Verify the authentication payload.  This has to be successful in
       order to allow the resuming */
    if (!idata->hash ||
	!silc_auth_verify_data(auth, auth_len, SILC_AUTH_PUBLIC_KEY,
			       detached_client->data.public_key, 0,
			       idata->hash, detached_client->id,
			       SILC_ID_CLIENT)) {
      SILC_LOG_ERROR(("Client %s (%s) resume authentication failed, "
		      "closing connection", sock->hostname, sock->ip));
      silc_server_disconnect_remote(server, sock,
				    SILC_STATUS_ERR_INCOMPLETE_INFORMATION,
				    "Resuming not possible");
      if (sock->user_data)
	silc_server_free_sock_user_data(server, sock, NULL);
      silc_free(client_id);
      return;
    }

    /* If the ID is not based in our ID then change it */
    if (!SILC_ID_COMPARE(detached_client->id, server->id, 
			 server->id->ip.data_len)) {
      silc_free(client_id);
      while (!silc_id_create_client_id(server, server->id, server->rng,
				       server->md5hash,
				       detached_client->nickname,
				       &client_id)) {
	nickfail++;
	if (nickfail > 9) {
	  silc_server_disconnect_remote(server, sock,
					SILC_STATUS_ERR_BAD_NICKNAME,
					"Resuming not possible");
	  if (sock->user_data)
	    silc_server_free_sock_user_data(server, sock, NULL);
	  return;
	}
	snprintf(&detached_client->
		 nickname[strlen(detached_client->nickname) - 1], 1,
		 "%d", nickfail);
      }
      nick_change = TRUE;
    }

    /* Now resume the client to the network */

    silc_schedule_task_del_by_context(server->schedule, detached_client);
    sock->user_data = detached_client;
    detached_client->connection = sock;

    if (detached_client->data.public_key)
      silc_hash_table_del_by_context(server->pk_hash,
	                             detached_client->data.public_key,
				     detached_client);
    if (idata->public_key)
      silc_hash_table_del_by_context(server->pk_hash,
				     idata->public_key, idata);

    /* Take new keys and stuff into use in the old entry */
    silc_idlist_del_data(detached_client);
    silc_idlist_add_data(detached_client, idata);

    if (detached_client->data.public_key)
      silc_hash_table_add(server->pk_hash,
			  detached_client->data.public_key, detached_client);

    detached_client->data.status |= SILC_IDLIST_STATUS_REGISTERED;
    detached_client->data.status |= SILC_IDLIST_STATUS_RESUMED;
    detached_client->data.status |= SILC_IDLIST_STATUS_LOCAL;
    detached_client->data.status &= ~SILC_IDLIST_STATUS_RESUME_RES;
    detached_client->mode &= ~SILC_UMODE_DETACHED;
    server->stat.my_detached--;

    /* We are finished - reset resuming client */
    detached_client->resuming_client = NULL;

    /* Check if anyone is watching this client */
    if (server->server_type == SILC_ROUTER)
      silc_server_check_watcher_list(server, detached_client, NULL,
				     SILC_NOTIFY_TYPE_UMODE_CHANGE);

    /* Delete this current client entry since we're resuming to old one. */
    server->stat.my_clients--;
    server->stat.clients--;
    if (server->stat.cell_clients)
      server->stat.cell_clients--;
    silc_server_remove_from_channels(server, NULL, client, FALSE,
				     NULL, FALSE, FALSE);
    silc_server_del_from_watcher_list(server, client);
    if (!silc_idlist_del_client(server->local_list, client))
      silc_idlist_del_client(server->global_list, client);
    client = detached_client;
    silc_free(client->servername);
    client->servername = strdup(server->server_name);

    /* Send the RESUME_CLIENT packet to our primary router so that others
       know this client isn't detached anymore. */
    buf = silc_buffer_alloc_size(2 + id_len);
    silc_buffer_format(buf,
		       SILC_STR_UI_SHORT(id_len),
		       SILC_STR_UI_XNSTRING(id_string, id_len),
		       SILC_STR_END);

    /* Send to primary router */
    silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			    SILC_PACKET_RESUME_CLIENT, 0,
			    buf->data, buf->len, TRUE);
    silc_server_backup_send(server, client->router,
			    SILC_PACKET_RESUME_CLIENT, 0,
			    buf->data, buf->len, TRUE, TRUE);

    /* As router we must deliver this packet directly to the original
       server whom this client was earlier. */
    if (server->server_type == SILC_ROUTER && client->router &&
	client->router->server_type != SILC_ROUTER)
      silc_server_packet_send(server, client->router->connection,
			      SILC_PACKET_RESUME_CLIENT, 0,
			      buf->data, buf->len, TRUE);
    silc_buffer_free(buf);
    client->router = NULL;

    if (nick_change) {
      /* Notify about Client ID change, nickname doesn't actually change. */
      silc_server_send_notify_nick_change(server, SILC_PRIMARY_ROUTE(server),
					  SILC_BROADCAST(server),
					  client->id, client_id,
					  client->nickname);
    }

    /* Resolve users on those channels that client has joined but we
       haven't resolved user list yet. */
    if (server->server_type == SILC_SERVER && !server->standalone) {
      silc_hash_table_list(client->channels, &htl);
      while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
	channel = chl->channel;
	SILC_LOG_DEBUG(("Resolving users for %s channel",
			channel->channel_name));
	if (channel->disabled || !channel->users_resolved) {
	  silc_server_send_command(server, SILC_PRIMARY_ROUTE(server),
				   SILC_COMMAND_USERS, ++server->cmd_ident,
				   1, 2, channel->channel_name,
				   strlen(channel->channel_name));
	}
      }
      silc_hash_table_list_reset(&htl);
    }

    /* Send the new client ID to the client. After this client may start
       receiving other packets, and may start sending packets too. */
    silc_server_send_new_id(server, sock, FALSE, client_id, SILC_ID_CLIENT,
			    silc_id_get_len(client_id, SILC_ID_CLIENT));

    if (nick_change) {
      /* Send NICK change notify to channels as well. */
      SilcBuffer oidp, nidp;
      oidp = silc_id_payload_encode(client->id, SILC_ID_CLIENT);
      nidp = silc_id_payload_encode(client_id, SILC_ID_CLIENT);
      silc_server_send_notify_on_channels(server, NULL, client,
					  SILC_NOTIFY_TYPE_NICK_CHANGE, 3,
					  oidp->data, oidp->len,
					  nidp->data, nidp->len,
					  client->nickname,
					  strlen(client->nickname));
      silc_buffer_free(oidp);
      silc_buffer_free(nidp);
    }

    /* Add the client again to the ID cache to get it to correct list */
    if (!silc_idcache_del_by_context(server->local_list->clients, client))
      silc_idcache_del_by_context(server->global_list->clients, client);
    silc_free(client->id);
    client->id = client_id;
    client_id = NULL;
    silc_idcache_add(server->local_list->clients, client->nickname,
		     client->id, client, 0, NULL);

    /* Send some nice info to the client */
    silc_server_send_connect_notifys(server, sock, client);

    /* Send all channel keys of channels the client has joined */
    silc_hash_table_list(client->channels, &htl);
    while (silc_hash_table_get(&htl, NULL, (void *)&chl)) {
      bool created = FALSE;
      channel = chl->channel;

      if (channel->mode & SILC_CHANNEL_MODE_PRIVKEY)
	continue;

      /* If we don't have channel key, then create one */
      if (!channel->channel_key) {
	if (!silc_server_create_channel_key(server, channel, 0))
	  continue;
	created = TRUE;
      }

      id_string = silc_id_id2str(channel->id, SILC_ID_CHANNEL);
      cipher = silc_cipher_get_name(channel->channel_key);
      keyp =
	silc_channel_key_payload_encode(silc_id_get_len(channel->id,
							SILC_ID_CHANNEL),
					id_string,
					strlen(cipher), cipher,
					channel->key_len / 8, channel->key);
      silc_free(id_string);

      /* Send the channel key to the client */
      silc_server_packet_send(server, sock, SILC_PACKET_CHANNEL_KEY, 0,
			      keyp->data, keyp->len, FALSE);

      /* Distribute the channel key to channel */
      if (created) {
	silc_server_send_channel_key(server, NULL, channel,
				     server->server_type == SILC_ROUTER ?
				     FALSE : !server->standalone);
	silc_server_backup_send(server, NULL, SILC_PACKET_CHANNEL_KEY, 0,
				keyp->data, keyp->len, FALSE, TRUE);
      }

      silc_buffer_free(keyp);
    }
    silc_hash_table_list_reset(&htl);

  } else if (sock->type != SILC_SOCKET_TYPE_CLIENT) {
    /* Server or router sent this to us to notify that that a client has
       been resumed. */
    SilcServerEntry server_entry;
    SilcServerID *server_id;

    if (!client_id) {
      SILC_LOG_DEBUG(("Malformed resuming packet"));
      return;
    }

    /* Get entry to the client, and resolve it if we don't have it. */
    detached_client = silc_idlist_find_client_by_id(server->local_list,
						    client_id, TRUE,
						    &id_cache);
    if (!detached_client) {
      detached_client = silc_idlist_find_client_by_id(server->global_list,
						      client_id, TRUE,
						      &id_cache);
      if (!detached_client) {
	SILC_LOG_DEBUG(("Resuming client is unknown"));
	silc_free(client_id);
	return;
      }
    }

    /* Check that the client has not been resumed already because it is
       protocol error to attempt to resume more than once.  The client
       will be killed if this protocol error occurs. */
    if (detached_client->data.status & SILC_IDLIST_STATUS_RESUMED &&
	!(detached_client->mode & SILC_UMODE_DETACHED)) {
      /* The client is clearly attempting to resume more than once and
	 perhaps playing around by resuming from several different places
	 at the same time. */
      SILC_LOG_DEBUG(("Attempting to re-resume client, killing both"));
      silc_server_kill_client(server, detached_client, NULL,
			      server->id, SILC_ID_SERVER);
      silc_free(client_id);
      return;
    }

    /* Check whether client is detached at all */
    if (!(detached_client->mode & SILC_UMODE_DETACHED)) {
      SILC_LOG_DEBUG(("Client is not detached"));
      silc_free(client_id);
      return;
    }

    SILC_LOG_DEBUG(("Resuming detached client"));

    /* If the sender of this packet is server and we are router we need to
       broadcast this packet to other routers in the network. */
    if (server->server_type == SILC_ROUTER &&
	sock->type == SILC_SOCKET_TYPE_SERVER &&
	!(packet->flags & SILC_PACKET_FLAG_BROADCAST)) {
      SILC_LOG_DEBUG(("Broadcasting received Resume Client packet"));
      silc_server_packet_send(server, SILC_PRIMARY_ROUTE(server),
			      packet->type,
			      packet->flags | SILC_PACKET_FLAG_BROADCAST,
			      buffer->data, buffer->len, FALSE);
      silc_server_backup_send(server, sock->user_data,
			      packet->type, packet->flags,
			      packet->buffer->data, packet->buffer->len,
			      FALSE, TRUE);
    }

    /* Client is detached, and now it is resumed.  Remove the detached
       mode and mark that it is resumed. */

    if (detached_client->data.public_key)
      silc_hash_table_del_by_context(server->pk_hash,
	                             detached_client->data.public_key,
				     detached_client);

    silc_idlist_del_data(detached_client);
    detached_client->mode &= ~SILC_UMODE_DETACHED;
    detached_client->data.status |= SILC_IDLIST_STATUS_RESUMED;
    detached_client->data.status &= ~SILC_IDLIST_STATUS_LOCAL;
    id_cache->expire = 0;

    /* Check if anyone is watching this client */
    if (server->server_type == SILC_ROUTER)
      silc_server_check_watcher_list(server, detached_client, NULL,
				     SILC_NOTIFY_TYPE_UMODE_CHANGE);

    silc_schedule_task_del_by_context(server->schedule, detached_client);

    /* Get the new owner of the resumed client */
    server_id = silc_id_str2id(packet->src_id, packet->src_id_len,
			       packet->src_id_type);
    if (!server_id) {
      silc_free(client_id);
      return;
    }

    /* Get server entry */
    server_entry = silc_idlist_find_server_by_id(server->global_list,
						 server_id, TRUE, NULL);
    local = FALSE;
    if (!server_entry) {
      server_entry = silc_idlist_find_server_by_id(server->local_list,
						   server_id, TRUE, NULL);
      local = TRUE;
      if (!server_entry) {
	silc_free(server_id);
	silc_free(client_id);
	return;
      }
    }

    if (server->server_type == SILC_ROUTER &&
	sock->type == SILC_SOCKET_TYPE_ROUTER &&
	server_entry->server_type == SILC_ROUTER)
      local = FALSE;

    /* Change the client to correct list. */
    if (!silc_idcache_del_by_context(server->local_list->clients,
				     detached_client))
      silc_idcache_del_by_context(server->global_list->clients,
				  detached_client);
    silc_idcache_add(local && server->server_type == SILC_ROUTER ?
		     server->local_list->clients :
		     server->global_list->clients,
		     detached_client->nickname,
		     detached_client->id, detached_client, FALSE, NULL);

    /* Change the owner of the client */
    detached_client->router = server_entry;

    /* Update channel information regarding global clients on channel. */
    if (server->server_type != SILC_ROUTER) {
      silc_hash_table_list(detached_client->channels, &htl);
      while (silc_hash_table_get(&htl, NULL, (void *)&chl))
	chl->channel->global_users =
	  silc_server_channel_has_global(chl->channel);
      silc_hash_table_list_reset(&htl);
    }

    silc_free(server_id);
  }

  silc_free(client_id);
}
