/*

  packet_receive.c

  Author: Pekka Riikonen <priikone@poseidon.pspt.fi>

  Copyright (C) 1997 - 2000 Pekka Riikonen

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

/* Received private message. This resolves the destination of the message 
   and sends the packet. This is used by both server and router.  If the
   destination is our locally connected client this sends the packet to
   the client. This may also send the message for further routing if
   the destination is not in our server (or router). */

void silc_server_private_message(SilcServer server,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet)
{
  SilcClientID *id;
  SilcServerEntry router;
  SilcSocketConnection dst_sock;
  SilcClientEntry client;
  SilcIDListData idata;

  SILC_LOG_DEBUG(("Start"));

  if (!packet->dst_id) {
    SILC_LOG_ERROR(("Bad Client ID in private message packet, dropped"));
    goto err;
  }

  /* Decode destination Client ID */
  id = silc_id_str2id(packet->dst_id, SILC_ID_CLIENT);
  if (!id) {
    SILC_LOG_ERROR(("Could not decode destination Client ID, dropped"));
    goto err;
  }

  /* If the destination belongs to our server we don't have to route
     the message anywhere but to send it to the local destination. */
  client = silc_idlist_find_client_by_id(server->local_list, id);
  if (client) {
    /* It exists, now deliver the message to the destination */
    dst_sock = (SilcSocketConnection)client->connection;

    /* If we are router and the client has router then the client is in
       our cell but not directly connected to us. */
    if (server->server_type == SILC_ROUTER && client->router) {
      /* We are of course in this case the client's router thus the real
	 "router" of the client is the server who owns the client. Thus
	 we will send the packet to that server. */
      router = (SilcServerEntry)dst_sock->user_data;
      idata = (SilcIDListData)router;
      //      assert(client->router == server->id_entry);

      silc_server_send_private_message(server, dst_sock,
				       idata->send_key,
				       idata->hmac,
				       packet);
      return;
    }

    /* Seems that client really is directly connected to us */
    idata = (SilcIDListData)client;
    silc_server_send_private_message(server, dst_sock, 
				     idata->send_key,
				     idata->hmac, packet);
    return;
  }

  /* Destination belongs to someone not in this server. If we are normal
     server our action is to send the packet to our router. */
  if (server->server_type == SILC_SERVER && !server->standalone) {
    router = server->router;

    /* Send to primary route */
    if (router) {
      dst_sock = (SilcSocketConnection)router->connection;
      idata = (SilcIDListData)router;
      silc_server_send_private_message(server, dst_sock, 
				       idata->send_key,
				       idata->hmac, packet);
    }
    return;
  }

  /* We are router and we will perform route lookup for the destination 
     and send the message to fastest route. */
  if (server->server_type == SILC_ROUTER && !server->standalone) {
    dst_sock = silc_server_get_route(server, id, SILC_ID_CLIENT);
    router = (SilcServerEntry)dst_sock->user_data;
    idata = (SilcIDListData)router;

    /* Get fastest route and send packet. */
    if (router)
      silc_server_send_private_message(server, dst_sock, 
				       idata->send_key,
				       idata->hmac, packet);
    return;
  }

 err:
  silc_server_send_error(server, sock, 
			 "No such nickname: Private message not sent");
}

/* Relays received command reply packet to the correct destination. The
   destination must be one of our locally connected client or the packet
   will be ignored. This is called when server has forwarded one of
   client's command request to router and router has now replied to the 
   command. */

void silc_server_packet_relay_command_reply(SilcServer server,
					    SilcSocketConnection sock,
					    SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcClientEntry client;
  SilcClientID *id;
  SilcSocketConnection dst_sock;
  SilcIDListData idata;

  SILC_LOG_DEBUG(("Start"));

  /* Source must be server or router */
  if (packet->src_id_type != SILC_ID_SERVER &&
      sock->type != SILC_SOCKET_TYPE_ROUTER)
    return;

  /* Destination must be client */
  if (packet->dst_id_type != SILC_ID_CLIENT)
    return;

  /* Execute command reply locally for the command */
  silc_server_command_reply_process(server, sock, buffer);

  id = silc_id_str2id(packet->dst_id, SILC_ID_CLIENT);

  /* Destination must be one of ours */
  client = silc_idlist_find_client_by_id(server->local_list, id);
  if (!client) {
    SILC_LOG_ERROR(("Cannot relay command reply to unknown client"));
    silc_free(id);
    return;
  }

  /* Relay the packet to the client */

  dst_sock = (SilcSocketConnection)client->connection;
  silc_buffer_push(buffer, SILC_PACKET_HEADER_LEN + packet->src_id_len 
		   + packet->dst_id_len + packet->padlen);

  silc_packet_send_prepare(dst_sock, 0, 0, buffer->len);
  silc_buffer_put(dst_sock->outbuf, buffer->data, buffer->len);

  idata = (SilcIDListData)client;

  /* Encrypt packet */
  silc_packet_encrypt(idata->send_key, idata->hmac, dst_sock->outbuf, 
		      buffer->len);
    
  /* Send the packet */
  silc_server_packet_send_real(server, dst_sock, TRUE);

  silc_free(id);
}

/* Process received channel message. The message can be originated from
   client or server. */

void silc_server_channel_message(SilcServer server,
				 SilcSocketConnection sock,
				 SilcPacketContext *packet)
{
  SilcChannelEntry channel = NULL;
  SilcChannelClientEntry chl;
  SilcChannelID *id = NULL;
  void *sender = NULL;

  SILC_LOG_DEBUG(("Processing channel message"));

  /* Sanity checks */
  if (packet->dst_id_type != SILC_ID_CHANNEL) {
    SILC_LOG_ERROR(("Received bad message for channel, dropped"));
    SILC_LOG_DEBUG(("Received bad message for channel, dropped"));
    goto out;
  }

  /* Find channel entry */
  id = silc_id_str2id(packet->dst_id, SILC_ID_CHANNEL);
  channel = silc_idlist_find_channel_by_id(server->local_list, id);
  if (!channel) {
    SILC_LOG_DEBUG(("Could not find channel"));
    goto out;
  }

  /* See that this client is on the channel. If the message is coming
     from router we won't do the check as the message is from client that
     we don't know about. Also, if the original sender is not client
     (as it can be server as well) we don't do the check. */
  sender = silc_id_str2id(packet->src_id, packet->src_id_type);
  if (sock->type != SILC_SOCKET_TYPE_ROUTER && 
      packet->src_id_type == SILC_ID_CLIENT) {
    silc_list_start(channel->user_list);
    while ((chl = silc_list_get(channel->user_list)) != SILC_LIST_END) {
      if (chl->client && !SILC_ID_CLIENT_COMPARE(chl->client->id, sender))
	break;
    }
    if (chl == SILC_LIST_END)
      goto out;
  }

  /* Distribute the packet to our local clients. This will send the
     packet for further routing as well, if needed. */
  silc_server_packet_relay_to_channel(server, sock, channel, sender,
				      packet->src_id_type,
				      packet->buffer->data,
				      packet->buffer->len, FALSE);

 out:
  if (sender)
    silc_free(sender);
  if (id)
    silc_free(id);
}

/* Received channel key packet. We distribute the key to all of our locally
   connected clients on the channel. */

void silc_server_channel_key(SilcServer server,
			     SilcSocketConnection sock,
			     SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcChannelKeyPayload payload = NULL;
  SilcChannelID *id = NULL;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  unsigned char *tmp;
  unsigned int tmp_len;
  char *cipher;
  int exist = FALSE;

  if (packet->src_id_type != SILC_ID_SERVER)
    goto out;

  /* Decode channel key payload */
  payload = silc_channel_key_payload_parse(buffer);
  if (!payload) {
    SILC_LOG_ERROR(("Bad channel key payload, dropped"));
    goto out;
  }

  /* Get channel ID */
  tmp = silc_channel_key_get_id(payload, &tmp_len);
  id = silc_id_payload_parse_id(tmp, tmp_len);
  if (!id)
    goto out;

  /* Get the channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list, id);
  if (!channel) {
    SILC_LOG_ERROR(("Received key for non-existent channel"));
    goto out;
  }

  tmp = silc_channel_key_get_key(payload, &tmp_len);
  if (!tmp)
    goto out;

  cipher = silc_channel_key_get_cipher(payload, NULL);;
  if (!cipher)
    goto out;

  /* Remove old key if exists */
  if (channel->key) {
    memset(channel->key, 0, channel->key_len);
    silc_free(channel->key);
    silc_cipher_free(channel->channel_key);
    exist = TRUE;
  }

  /* Create new cipher */
  if (!silc_cipher_alloc(cipher, &channel->channel_key))
    goto out;

  /* Save the key */
  channel->key_len = tmp_len * 8;
  channel->key = silc_calloc(tmp_len, sizeof(unsigned char));
  memcpy(channel->key, tmp, tmp_len);
  channel->channel_key->cipher->set_key(channel->channel_key->context, 
					tmp, tmp_len);

  /* Distribute the key to everybody who is on the channel. If we are router
     we will also send it to locally connected servers. */
  silc_server_send_channel_key(server, channel, FALSE);

 out:
  if (id)
    silc_free(id);
  if (payload)
    silc_channel_key_payload_free(payload);
}

/* Received packet to replace a ID. This checks that the requested ID
   exists and replaces it with the new one. */

void silc_server_replace_id(SilcServer server,
			    SilcSocketConnection sock,
			    SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  unsigned char *old_id = NULL, *new_id = NULL;
  SilcIdType old_id_type, new_id_type;
  unsigned short old_id_len, new_id_len;
  void *id = NULL, *id2 = NULL;

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      packet->src_id_type == SILC_ID_CLIENT)
    return;

  SILC_LOG_DEBUG(("Replacing ID"));

  silc_buffer_unformat(buffer,
		       SILC_STR_UI_SHORT(&old_id_type),
		       SILC_STR_UI16_NSTRING_ALLOC(&old_id, &old_id_len),
		       SILC_STR_UI_SHORT(&new_id_type),
		       SILC_STR_UI16_NSTRING_ALLOC(&new_id, &new_id_len),
		       SILC_STR_END);

  if (old_id_type != new_id_type)
    goto out;

  if (old_id_len != silc_id_get_len(old_id_type) ||
      new_id_len != silc_id_get_len(new_id_type))
    goto out;

  id = silc_id_str2id(old_id, old_id_type);
  if (!id)
    goto out;

  id2 = silc_id_str2id(new_id, new_id_type);
  if (!id2)
    goto out;

  /* If we are router and this packet is not already broadcast packet
     we will broadcast it. The sending socket really cannot be router or
     the router is buggy. If this packet is coming from router then it must
     have the broadcast flag set already and we won't do anything. */
  if (server->server_type == SILC_ROUTER &&
      sock->type == SILC_SOCKET_TYPE_SERVER &&
      !(packet->flags & SILC_PACKET_FLAG_BROADCAST)) {
    SILC_LOG_DEBUG(("Broadcasting received Replace ID packet"));
    silc_server_packet_send(server, server->router->connection, packet->type,
			    packet->flags | SILC_PACKET_FLAG_BROADCAST, 
			    buffer->data, buffer->len, FALSE);
  }

  /* Replace the old ID */
  switch(old_id_type) {
  case SILC_ID_CLIENT:
    if (silc_idlist_replace_client_id(server->local_list, id, id2) == NULL)
      if (server->server_type == SILC_ROUTER)
	silc_idlist_replace_client_id(server->global_list, id, id2);
    break;

  case SILC_ID_SERVER:
    if (silc_idlist_replace_server_id(server->local_list, id, id2) == NULL)
      if (server->server_type == SILC_ROUTER)
	silc_idlist_replace_server_id(server->global_list, id, id2);
    break;

  case SILC_ID_CHANNEL:
    /* XXX Hmm... Basically this cannot occur. Channel ID's cannot be
       re-generated. */
    silc_free(id2);
    break;

  default:
    silc_free(id2);
    break;
  }

 out:
  if (id)
    silc_free(id);
  if (old_id)
    silc_free(old_id);
  if (new_id)
    silc_free(new_id);
}


/* Received New Client packet and processes it.  Creates Client ID for the
   client. Client becomes registered after calling this functions. */

SilcClientEntry silc_server_new_client(SilcServer server,
				       SilcSocketConnection sock,
				       SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcClientEntry client;
  SilcIDCacheEntry cache;
  SilcClientID *client_id;
  SilcBuffer reply;
  SilcIDListData idata;
  char *username = NULL, *realname = NULL, *id_string;

  SILC_LOG_DEBUG(("Creating new client"));

  if (sock->type != SILC_SOCKET_TYPE_CLIENT)
    return NULL;

  /* Take client entry */
  client = (SilcClientEntry)sock->user_data;
  idata = (SilcIDListData)client;

  /* Fetch the old client cache entry so that we can update it. */
  if (!silc_idcache_find_by_context(server->local_list->clients,
				    sock->user_data, &cache)) {
    SILC_LOG_ERROR(("Lost client's cache entry - bad thing"));
    return NULL;
  }

  /* Parse incoming packet */
  silc_buffer_unformat(buffer,
		       SILC_STR_UI16_STRING_ALLOC(&username),
		       SILC_STR_UI16_STRING_ALLOC(&realname),
		       SILC_STR_END);

  /* Create Client ID */
  silc_id_create_client_id(server->id, server->rng, server->md5hash,
			   username, &client_id);

  /* Update client entry */
  idata->registered = TRUE;
  client->nickname = strdup(username);
  client->username = username;
  client->userinfo = realname;
  client->id = client_id;

  /* Update the cache entry */
  cache->id = (void *)client_id;
  cache->type = SILC_ID_CLIENT;
  cache->data = username;
  silc_idcache_sort_by_data(server->local_list->clients);

  /* Notify our router about new client on the SILC network */
  if (!server->standalone)
    silc_server_send_new_id(server, (SilcSocketConnection) 
			    server->router->connection, 
			    server->server_type == SILC_ROUTER ? TRUE : FALSE,
			    client->id, SILC_ID_CLIENT, SILC_ID_CLIENT_LEN);
  
  /* Send the new client ID to the client. */
  id_string = silc_id_id2str(client->id, SILC_ID_CLIENT);
  reply = silc_buffer_alloc(2 + 2 + SILC_ID_CLIENT_LEN);
  silc_buffer_pull_tail(reply, SILC_BUFFER_END(reply));
  silc_buffer_format(reply,
		     SILC_STR_UI_SHORT(SILC_ID_CLIENT),
		     SILC_STR_UI_SHORT(SILC_ID_CLIENT_LEN),
		     SILC_STR_UI_XNSTRING(id_string, SILC_ID_CLIENT_LEN),
		     SILC_STR_END);
  silc_server_packet_send(server, sock, SILC_PACKET_NEW_ID, 0, 
			  reply->data, reply->len, FALSE);
  silc_free(id_string);
  silc_buffer_free(reply);

  /* Send some nice info to the client */
  SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			  ("Welcome to the SILC Network %s@%s",
			   username, sock->hostname));
  SILC_SERVER_SEND_NOTIFY(server, sock, SILC_NOTIFY_TYPE_NONE,
			  ("Your host is %s, running version %s",
			   server->config->server_info->server_name,
			   server_version));
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
  SilcServerEntry new_server;
  SilcIDCacheEntry cache;
  SilcServerID *server_id;
  SilcIDListData idata;
  unsigned char *server_name, *id_string;
  unsigned short id_len;

  SILC_LOG_DEBUG(("Creating new server"));

  if (sock->type != SILC_SOCKET_TYPE_SERVER &&
      sock->type != SILC_SOCKET_TYPE_ROUTER)
    return NULL;

  /* Take server entry */
  new_server = (SilcServerEntry)sock->user_data;
  idata = (SilcIDListData)new_server;

  /* Fetch the old server cache entry so that we can update it. */
  if (!silc_idcache_find_by_context(server->local_list->servers,
				    sock->user_data, &cache)) {
    SILC_LOG_ERROR(("Lost server's cache entry - bad thing"));
    return NULL;
  }

  /* Parse the incoming packet */
  silc_buffer_unformat(buffer,
		       SILC_STR_UI16_NSTRING_ALLOC(&id_string, &id_len),
		       SILC_STR_UI16_STRING_ALLOC(&server_name),
		       SILC_STR_END);

  if (id_len > buffer->len) {
    silc_free(id_string);
    silc_free(server_name);
    return NULL;
  }

  /* Get Server ID */
  server_id = silc_id_str2id(id_string, SILC_ID_SERVER);
  silc_free(id_string);

  /* Update client entry */
  idata->registered = TRUE;
  new_server->server_name = server_name;
  new_server->id = server_id;

  /* Update the cache entry */
  cache->id = (void *)server_id;
  cache->type = SILC_ID_SERVER;
  cache->data = server_name;
  silc_idcache_sort_by_data(server->local_list->servers);

  /* Distribute the information about new server in the SILC network
     to our router. If we are normal server we won't send anything
     since this connection must be our router connection. */
  if (server->server_type == SILC_ROUTER && !server->standalone &&
      server->router->connection != sock)
    silc_server_send_new_id(server, server->router->connection,
			    TRUE, new_server->id, SILC_ID_SERVER, 
			    SILC_ID_SERVER_LEN);

  return new_server;
}

/* Processes incoming New ID packet. New ID Payload is used to distribute
   information about newly registered clients and servers. */

void silc_server_new_id(SilcServer server, SilcSocketConnection sock,
			SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  SilcIDList id_list;
  SilcServerEntry tmpserver, router;
  SilcSocketConnection router_sock;
  SilcIDPayload idp;
  SilcIdType id_type;
  void *id, *tmpid;

  SILC_LOG_DEBUG(("Processing new ID"));

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      server->server_type == SILC_SERVER ||
      packet->src_id_type != SILC_ID_SERVER)
    return;

  idp = silc_id_payload_parse(buffer);
  if (!idp)
    return;

  id_type = silc_id_payload_get_type(idp);

  /* Normal server cannot have other normal server connections */
  if (id_type == SILC_ID_SERVER && sock->type == SILC_SOCKET_TYPE_SERVER)
    goto out;

  id = silc_id_payload_get_id(idp);
  if (!id)
    goto out;

  /* If the sender of this packet is server and we are router we need to
     broadcast this packet to other routers in the network. */
  if (!server->standalone && server->server_type == SILC_ROUTER &&
      sock->type == SILC_SOCKET_TYPE_SERVER &&
      !(packet->flags & SILC_PACKET_FLAG_BROADCAST)) {
    SILC_LOG_DEBUG(("Broadcasting received New ID packet"));
    silc_server_packet_send(server, server->router->connection,
			    packet->type, 
			    packet->flags | SILC_PACKET_FLAG_BROADCAST,
			    buffer->data, buffer->len, FALSE);
  }

  /* If the packet is originated from the one who sent it to us we know
     that the ID belongs to our cell, unless the sender was router. */
  tmpid = silc_id_str2id(packet->src_id, SILC_ID_SERVER);
  tmpserver = (SilcServerEntry)sock->user_data;

  if (!SILC_ID_SERVER_COMPARE(tmpid, tmpserver->id) &&
      sock->type == SILC_SOCKET_TYPE_SERVER) {
    id_list = server->local_list;
    router_sock = sock;
    router = sock->user_data;
    /*    router = server->id_entry; */
  } else {
    id_list = server->global_list;
    router_sock = (SilcSocketConnection)server->router->connection;
    router = server->router;
  }

  silc_free(tmpid);

  switch(id_type) {
  case SILC_ID_CLIENT:
    SILC_LOG_DEBUG(("New client id(%s) from [%s] %s",
		    silc_id_render(id, SILC_ID_CLIENT),
		    sock->type == SILC_SOCKET_TYPE_SERVER ?
		    "Server" : "Router", sock->hostname));
    
    /* Add the client to our local list. We are router and we keep
       cell specific local database of all clients in the cell. */
    silc_idlist_add_client(id_list, NULL, NULL, NULL, id, router, router_sock);
    break;

  case SILC_ID_SERVER:
    SILC_LOG_DEBUG(("New server id(%s) from [%s] %s",
		    silc_id_render(id, SILC_ID_SERVER),
		    sock->type == SILC_SOCKET_TYPE_SERVER ?
		    "Server" : "Router", sock->hostname));
    
    /* Add the server to our local list. We are router and we keep
       cell specific local database of all servers in the cell. */
    silc_idlist_add_server(id_list, NULL, 0, id, router, router_sock);
    break;

  case SILC_ID_CHANNEL:
    SILC_LOG_ERROR(("Channel cannot be registered with NEW_ID packet"));
    break;

  default:
    break;
  }

 out:
  silc_id_payload_free(idp);
}

/* Received Remove Channel User packet to remove a user from a channel. 
   Routers notify other routers that user has left a channel. Client must
   not send this packet.. Normal server may send this packet but must not
   receive it. */

void silc_server_remove_channel_user(SilcServer server,
				     SilcSocketConnection sock,
				     SilcPacketContext *packet)
{
  SilcBuffer buffer = packet->buffer;
  unsigned char *tmp1 = NULL, *tmp2 = NULL;
  SilcClientID *client_id = NULL;
  SilcChannelID *channel_id = NULL;
  SilcChannelEntry channel;
  SilcClientEntry client;

  SILC_LOG_DEBUG(("Removing user from channel"));

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      server->server_type == SILC_SERVER)
    return;

  silc_buffer_unformat(buffer,
		       SILC_STR_UI16_STRING_ALLOC(&tmp1),
		       SILC_STR_UI16_STRING_ALLOC(&tmp2),
		       SILC_STR_END);

  if (!tmp1 || !tmp2)
    goto out;

  client_id = silc_id_str2id(tmp1, SILC_ID_CLIENT);
  channel_id = silc_id_str2id(tmp2, SILC_ID_CHANNEL);
  if (!client_id || !channel_id)
    goto out;

  /* If we are router and this packet is not already broadcast packet
     we will broadcast it. The sending socket really cannot be router or
     the router is buggy. If this packet is coming from router then it must
     have the broadcast flag set already and we won't do anything. */
  if (!server->standalone && server->server_type == SILC_ROUTER &&
      sock->type == SILC_SOCKET_TYPE_SERVER &&
      !(packet->flags & SILC_PACKET_FLAG_BROADCAST)) {
    SILC_LOG_DEBUG(("Broadcasting received Remove Channel User packet"));
    silc_server_packet_send(server, server->router->connection, packet->type,
			    packet->flags | SILC_PACKET_FLAG_BROADCAST, 
			    buffer->data, buffer->len, FALSE);
  }

  /* XXX routers should check server->global_list as well */
  /* Get channel entry */
  channel = silc_idlist_find_channel_by_id(server->local_list, channel_id);
  if (!channel)
    goto out;
  
  /* XXX routers should check server->global_list as well */
  /* Get client entry */
  client = silc_idlist_find_client_by_id(server->local_list, client_id);
  if (!client)
    goto out;

  /* Remove from channel */
  silc_server_remove_from_one_channel(server, sock, channel, client, FALSE);

 out:
  if (tmp1)
    silc_free(tmp1);
  if (tmp2)
    silc_free(tmp2);
  if (client_id)
    silc_free(client_id);
  if (channel_id)
    silc_free(channel_id);
}

/* Received New Channel packet. Information about new channels in the 
   network are distributed using this packet. Save the information about
   the new channel. */

void silc_server_new_channel(SilcServer server,
			     SilcSocketConnection sock,
			     SilcPacketContext *packet)
{
  unsigned char *id;
  SilcChannelID *channel_id;
  unsigned short channel_id_len;
  char *channel_name;

  SILC_LOG_DEBUG(("Processing New Channel"));

  if (sock->type != SILC_SOCKET_TYPE_ROUTER ||
      server->server_type == SILC_SERVER ||
      packet->src_id_type != SILC_ID_SERVER)
    return;

  /* Parse payload */
  if (!silc_buffer_unformat(packet->buffer, 
			    SILC_STR_UI16_STRING_ALLOC(&channel_name),
			    SILC_STR_UI16_NSTRING_ALLOC(&id, &channel_id_len),
			    SILC_STR_END))
    return;
    
  if (!channel_name || !id)
    return;

  /* Decode the channel ID */
  channel_id = silc_id_str2id(id, SILC_ID_CHANNEL);
  if (!channel_id)
    return;
  silc_free(id);

  SILC_LOG_DEBUG(("New channel id(%s) from [Router] %s",
		  silc_id_render(channel_id, SILC_ID_CHANNEL), 
		  sock->hostname));

  /* Add the new channel. Add it always to global list since if we receive
     this packet then it cannot be created by ourselves but some other 
     router hence global channel. */
  silc_idlist_add_channel(server->global_list, channel_name, 0, channel_id, 
			  server->router->connection, NULL);
}

/* Received notify packet. Server can receive notify packets from router. 
   Server then relays the notify messages to clients if needed. */

void silc_server_notify(SilcServer server,
			SilcSocketConnection sock,
			SilcPacketContext *packet)
{
  SilcNotifyPayload payload;
  SilcNotifyType type;
  SilcArgumentPayload args;
  SilcChannelID *channel_id;
  SilcChannelEntry channel;

  SILC_LOG_DEBUG(("Start"));

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      packet->src_id_type != SILC_ID_SERVER)
    return;

  /* XXX: For now we expect that the we are normal server and that the
     sender is router. Server could send (protocol allows it) notify to
     router but we don't support it yet. */
  if (server->server_type != SILC_SERVER &&
      sock->type != SILC_SOCKET_TYPE_ROUTER)
    return;

  payload = silc_notify_payload_parse(packet->buffer);
  if (!payload)
    return;

  type = silc_notify_get_type(payload);
  args = silc_notify_get_args(payload);
  if (!args)
    goto out;

  switch(type) {
  case SILC_NOTIFY_TYPE_JOIN:
    /* 
     * Distribute the notify to local clients on the channel
     */

    channel_id = silc_id_str2id(packet->dst_id, packet->dst_id_type);
    if (!channel_id)
      goto out;

    /* Get channel entry */
    channel = silc_idlist_find_channel_by_id(server->local_list, channel_id);
    if (!channel) {
      silc_free(channel_id);
      goto out;
    }

    /* Send to channel */
    silc_server_packet_send_to_channel(server, channel, packet->type, FALSE,
				       packet->buffer->data, 
				       packet->buffer->len, FALSE);
    break;

  case SILC_NOTIFY_TYPE_LEAVE:
    break;

  case SILC_NOTIFY_TYPE_SIGNOFF:
    break;

    /* Ignore rest notify types for now */
  case SILC_NOTIFY_TYPE_NONE:
  case SILC_NOTIFY_TYPE_INVITE:
  case SILC_NOTIFY_TYPE_TOPIC_SET:
  case SILC_NOTIFY_TYPE_CMODE_CHANGE:
  case SILC_NOTIFY_TYPE_CUMODE_CHANGE:
  case SILC_NOTIFY_TYPE_MOTD:
  default:
    break;
  }

 out:
  silc_notify_payload_free(payload);
}

/* Received new channel user packet. Information about new users on a
   channel are distributed between routers using this packet.  The
   router receiving this will redistribute it and also sent JOIN notify
   to local clients on the same channel. Normal server sends JOIN notify
   to its local clients on the channel. */

void silc_server_new_channel_user(SilcServer server,
				  SilcSocketConnection sock,
				  SilcPacketContext *packet)
{
  unsigned char *tmpid1, *tmpid2;
  SilcClientID *client_id = NULL;
  SilcChannelID *channel_id = NULL;
  unsigned short channel_id_len;
  unsigned short client_id_len;
  SilcClientEntry client;
  SilcChannelEntry channel;
  SilcChannelClientEntry chl;
  SilcIDList id_list;
  SilcServerEntry tmpserver, router;
  SilcSocketConnection router_sock;
  SilcBuffer clidp;
  void *tmpid;

  SILC_LOG_DEBUG(("Start"));

  if (sock->type == SILC_SOCKET_TYPE_CLIENT ||
      server->server_type != SILC_ROUTER ||
      packet->src_id_type != SILC_ID_SERVER)
    return;

  /* Parse payload */
  if (!silc_buffer_unformat(packet->buffer, 
			    SILC_STR_UI16_NSTRING_ALLOC(&tmpid1, 
							&channel_id_len),
			    SILC_STR_UI16_NSTRING_ALLOC(&tmpid2, 
							&client_id_len),
			    SILC_STR_END))
    return;

  if (!tmpid1 || !tmpid2)
    return;

  /* Decode the channel ID */
  channel_id = silc_id_str2id(tmpid1, SILC_ID_CHANNEL);
  if (!channel_id)
    goto out;

  /* Decode the client ID */
  client_id = silc_id_str2id(tmpid1, SILC_ID_CLIENT);
  if (!client_id)
    goto out;

  /* If the packet is originated from the one who sent it to us we know
     that the ID belongs to our cell, unless the sender was router. */
  tmpid = silc_id_str2id(packet->src_id, SILC_ID_SERVER);
  tmpserver = (SilcServerEntry)sock->user_data;

  if (!SILC_ID_SERVER_COMPARE(tmpid, tmpserver->id) &&
      sock->type == SILC_SOCKET_TYPE_SERVER) {
    id_list = server->local_list;
    router_sock = sock;
    router = sock->user_data;
  } else {
    id_list = server->global_list;
    router_sock = (SilcSocketConnection)server->router->connection;
    router = server->router;
  }
  silc_free(tmpid);

  /* Find the channel */
  channel = silc_idlist_find_channel_by_id(id_list, channel_id);
  if (!channel) {
    SILC_LOG_ERROR(("Received channel user for non-existent channel"));
    goto out;
  }

  /* If we are router and this packet is not already broadcast packet
     we will broadcast it. */
  if (!server->standalone && server->server_type == SILC_ROUTER &&
      !(packet->flags & SILC_PACKET_FLAG_BROADCAST)) {
    SILC_LOG_DEBUG(("Broadcasting received New Channel User packet"));
    silc_server_packet_send(server, server->router->connection, packet->type,
			    packet->flags | SILC_PACKET_FLAG_BROADCAST, 
			    packet->buffer->data, packet->buffer->len, FALSE);
  }

  /* Get client entry */
  client = silc_idlist_find_client_by_id(id_list, client_id);
  if (!client) {
    /* This is new client to us, add entry to ID list */
    client = silc_idlist_add_client(id_list, NULL, NULL, NULL, 
				    client_id, router, router_sock);
    if (!client)
      goto out;
  }

  /* Join the client to the channel by adding it to channel's user list.
     Add also the channel to client entry's channels list for fast cross-
     referencing. */
  chl = silc_calloc(1, sizeof(*chl));
  chl->client = client;
  chl->channel = channel;
  silc_list_add(channel->user_list, chl);
  silc_list_add(client->channels, chl);

  /* Send JOIN notify to local clients on the channel. As we are router
     it is assured that this is sent only to our local clients and locally
     connected servers if needed. */
  clidp = silc_id_payload_encode(client_id, SILC_ID_CLIENT);
  silc_server_send_notify_to_channel(server, channel, FALSE,
				     SILC_NOTIFY_TYPE_JOIN, 
				     1, clidp->data, clidp->len);
  silc_buffer_free(clidp);

  client_id = NULL;

 out:
  if (client_id)
    silc_free(client_id);
  if (channel_id)
    silc_free(channel_id);
  silc_free(tmpid1);
  silc_free(tmpid2);
}
