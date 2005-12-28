/*

  server_util.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2005 Pekka Riikonen

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
#include "silcserver.h"
#include "server_internal.h"

SilcBool silc_server_check_watcher_list(SilcServer server,
				    SilcClientEntry client,
				    const char *new_nick,
				    SilcNotifyType notify)
{
  return TRUE;
}

/* This function is used to send the notify packets and motd to the
   incoming client connection. */

void silc_server_send_welcome(SilcServerAccept ac, SilcClientEntry client)
{
  SilcServer server = ac->thread->server;
  SilcPacketStream stream = client->stream;

  SILC_LOG_DEBUG(("Send welcome notifys"));

  /* Send some nice info to the client */
  SILC_SERVER_SEND_NOTIFY(server, stream, SILC_NOTIFY_TYPE_NONE,
			  ("Welcome to the SILC Network %s",
			   client->username));
  SILC_SERVER_SEND_NOTIFY(server, stream, SILC_NOTIFY_TYPE_NONE,
			  ("Your host is %s, running version %s",
			   server->server_name, SILC_DIST_VERSION_STRING));

  if (server->server_type == SILC_ROUTER) {
    SILC_SERVER_SEND_NOTIFY(server, stream, SILC_NOTIFY_TYPE_NONE,
			    ("There are %d clients, %d servers and %d "
			     "routers in SILC Network",
			     server->stat.clients, server->stat.servers,
			     server->stat.routers));
  } else {
    if (server->stat.clients && server->stat.servers + 1)
      SILC_SERVER_SEND_NOTIFY(server, stream, SILC_NOTIFY_TYPE_NONE,
			      ("There are %d clients, %d servers and %d "
			       "routers in SILC Network",
			       server->stat.clients, server->stat.servers,
			       (server->standalone ? 0 :
				!server->stat.routers ? 1 :
				server->stat.routers)));
  }

  if (server->stat.cell_clients && server->stat.cell_servers + 1)
    SILC_SERVER_SEND_NOTIFY(server, stream, SILC_NOTIFY_TYPE_NONE,
			    ("There are %d clients on %d servers in our cell",
			     server->stat.cell_clients,
			     server->stat.cell_servers));
  if (server->server_type == SILC_ROUTER) {
    SILC_SERVER_SEND_NOTIFY(server, stream, SILC_NOTIFY_TYPE_NONE,
			    ("I have %d clients, %d channels, %d servers and "
			     "%d routers",
			     server->stat.my_clients,
			     server->stat.my_channels,
			     server->stat.my_servers,
			     server->stat.my_routers));
  } else {
    SILC_SERVER_SEND_NOTIFY(server, stream, SILC_NOTIFY_TYPE_NONE,
			    ("I have %d clients and %d channels formed",
			     server->stat.my_clients,
			     server->stat.my_channels));
  }

  if (server->stat.server_ops || server->stat.router_ops)
    SILC_SERVER_SEND_NOTIFY(server, stream, SILC_NOTIFY_TYPE_NONE,
			    ("There are %d server operators and %d router "
			     "operators online",
			     server->stat.server_ops,
			     server->stat.router_ops));
  if (server->stat.my_router_ops + server->stat.my_server_ops)
    SILC_SERVER_SEND_NOTIFY(server, stream, SILC_NOTIFY_TYPE_NONE,
			    ("I have %d operators online",
			     server->stat.my_router_ops +
			     server->stat.my_server_ops));

  SILC_SERVER_SEND_NOTIFY(server, stream, SILC_NOTIFY_TYPE_NONE,
			  ("Your connection is secured with %s cipher, "
			   "key length %d bits",
			   silc_cipher_get_name(ac->prop->cipher),
			   silc_cipher_get_key_len(ac->prop->cipher)));
  SILC_SERVER_SEND_NOTIFY(server, stream, SILC_NOTIFY_TYPE_NONE,
			  ("Your current nickname is %s",
			   client->nickname));

  /* Send motd */
  silc_server_send_motd(server, stream);
}

/* Creates new Client ID. */

SilcBool silc_server_create_client_id(SilcServer server, char *nickname,
				      SilcClientID *new_id)
{
  unsigned char hash[16];
  SilcBool finding = FALSE;

  SILC_LOG_DEBUG(("Creating new Client ID"));

  /* Create hash of the nickname (it's already checked as valid identifier
     string). */
  silc_hash_make(server->md5hash, nickname, strlen(nickname), hash);

  /* Create the ID */
  memcpy(new_id->ip.data, server->id.ip.data, server->id.ip.data_len);
  new_id->ip.data_len = server->id.ip.data_len;
  new_id->rnd = silc_rng_get_byte(server->rng);
  memcpy(new_id->hash, hash, CLIENTID_HASH_LEN);

  /* Assure that the ID does not exist already */
  while (1) {
    if (!silc_server_find_client_by_id(server, new_id, FALSE, NULL))
      break;

    /* The ID exists, start increasing the rnd from 0 until we find a
       ID that does not exist. If we wrap and it still exists then we
       will return FALSE and the caller must send some other nickname
       since this cannot be used anymore. */
    new_id->rnd++;

    if (finding && new_id->rnd == 0)
      return FALSE;

    if (!finding) {
      new_id->rnd = 0;
      finding = TRUE;
    }
  }

  SILC_LOG_DEBUG(("New ID (%s)", silc_id_render(new_id, SILC_ID_CLIENT)));

  return TRUE;
}

/* Creates a Server ID. */

SilcBool silc_server_create_server_id(SilcServer server,
				      const char *ip, SilcUInt16 port,
				      SilcServerID *new_id)
{
  SILC_LOG_DEBUG(("Creating new Server ID"));

  if (!new_id)
    return FALSE;

  /* Create the ID */

  if (!silc_net_addr2bin(ip, new_id->ip.data, sizeof(new_id->ip.data)))
    return FALSE;

  new_id->ip.data_len = silc_net_is_ip4(ip) ? 4 : 16;
  new_id->port = SILC_SWAB_16(port);
  new_id->rnd = silc_rng_get_rn16(server->rng);

  SILC_LOG_DEBUG(("New ID (%s)", silc_id_render(new_id, SILC_ID_SERVER)));

  return TRUE;
}

/* Checks whether the `server_id' is valid.  It must be based to the
   IP address provided in the `remote' socket connection. */

SilcBool silc_server_check_server_id(const char *ip_address,
				     SilcServerID *server_id)
{
  unsigned char ip[16];

  if (!silc_net_addr2bin(ip_address, ip, sizeof(ip)))
    return FALSE;

  if (silc_net_is_ip4(ip_address)) {
    if (!memcmp(server_id->ip.data, ip, 4))
      return TRUE;
  } else {
    if (!memcmp(server_id->ip.data, ip, 16))
      return TRUE;
  }

  return FALSE;
}
