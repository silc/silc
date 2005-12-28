/*

  server_params.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#include "silc.h"
#include "silcserver.h"
#include "server_internal.h"

/************************** Types and definitions ***************************/

/* Default values */
#define SILC_SERVER_PARAM_RETRY_COUNT        7	  /* Max retry count */
#define SILC_SERVER_PARAM_RETRY_MULTIPLIER   2	  /* Interval growth */
#define SILC_SERVER_PARAM_RETRY_RANDOMIZER   2	  /* timeout += rnd % 2 */
#define SILC_SERVER_PARAM_RETRY_INTERVAL_MIN 10	  /* Min retry timeout */
#define SILC_SERVER_PARAM_RETRY_INTERVAL_MAX 600  /* Max generated timeout */
#define SILC_SERVER_PARAM_REKEY              3600 /* Session rekey interval */
#define SILC_SERVER_PARAM_KEEPALIVE          300  /* Heartbeat interval */
#define SILC_SERVER_PARAM_MAX_CONNS          1000 /* Max connections */
#define SILC_SERVER_PARAM_MAX_CONNS_SINGLE   1000 /* Max conns per host */
#define SILC_SERVER_PARAM_CONN_PER_THREAD    30	  /* Connections per thread */
#define SILC_SERVER_PARAM_CHANNEL_REKEY      3600 /* Channel rekey interval */
#define SILC_SERVER_PARAM_SKE_TIMEOUT        60	  /* SKE timeout */
#define SILC_SERVER_PARAM_CONNAUTH_TIMEOUT   60	  /* CONN_AUTH timeout */
#define SILC_SERVER_PARAM_QOS_RATE_LIMIT     10	  /* QoS rate limit */
#define SILC_SERVER_PARAM_QOS_BYTES_LIMIT    2048 /* QoS bytes limit */
#define SILC_SERVER_PARAM_QOS_LIMIT_SEC      0    /* QoS limit sec */
#define SILC_SERVER_PARAM_QOS_LIMIT_USEC     500000 /* QoS limit usec */
#define SILC_SERVER_PARAM_CH_JOIN_LIMIT      50	  /* Join limit */


/************************ Static utility functions **************************/

/* Sets connection parameter defaults */

static void
silc_server_param_set_param_defaults(SilcServerParamConnParams params,
				     SilcServerParamConnParams defaults)
{
#define SET_PARAM_DEFAULT(p, d)	params->p =				\
  (params->p ? params->p : (defaults && defaults->p ? defaults->p : d))

  SET_PARAM_DEFAULT(connections_max, SILC_SERVER_PARAM_MAX_CONNS);
  SET_PARAM_DEFAULT(connections_max_per_host,
		    SILC_SERVER_PARAM_MAX_CONNS_SINGLE);
  SET_PARAM_DEFAULT(keepalive_secs, SILC_SERVER_PARAM_KEEPALIVE);
  SET_PARAM_DEFAULT(reconnect_count, SILC_SERVER_PARAM_RETRY_COUNT);
  SET_PARAM_DEFAULT(reconnect_interval, SILC_SERVER_PARAM_RETRY_INTERVAL_MIN);
  SET_PARAM_DEFAULT(reconnect_interval_max,
		    SILC_SERVER_PARAM_RETRY_INTERVAL_MAX);
  SET_PARAM_DEFAULT(key_exchange_rekey, SILC_SERVER_PARAM_REKEY);
  SET_PARAM_DEFAULT(qos_rate_limit, SILC_SERVER_PARAM_QOS_RATE_LIMIT);
  SET_PARAM_DEFAULT(qos_bytes_limit, SILC_SERVER_PARAM_QOS_BYTES_LIMIT);
  SET_PARAM_DEFAULT(qos_limit_sec, SILC_SERVER_PARAM_QOS_LIMIT_SEC);
  SET_PARAM_DEFAULT(qos_limit_usec, SILC_SERVER_PARAM_QOS_LIMIT_USEC);
  SET_PARAM_DEFAULT(chlimit, SILC_SERVER_PARAM_CH_JOIN_LIMIT);

#undef SET_PARAM_DEFAULT
}


/***************************** Retrieval API ********************************/

/* Returns the denied connection configuration entry by host. */

SilcServerParamDeny
silc_server_params_find_denied(SilcServer server, char *ip, char *host)
{
  SilcServerParams params = server->params;
  SilcServerParamDeny deny;

  if (ip) {
    silc_list_start(params->denied);
    while ((deny = silc_list_get(params->denied)) != SILC_LIST_END) {
      if (deny->host && !silc_string_compare(deny->host, ip))
	continue;
      return deny;
    }
  }

  if (host) {
    silc_list_start(params->denied);
    while ((deny = silc_list_get(params->denied)) != SILC_LIST_END) {
      if (deny->host && !silc_string_compare(deny->host, host))
	continue;
      return deny;
    }
  }

  return NULL;
}

/* Returns client connection information from configuration file by host
   (name or ip) */

SilcServerParamClient
silc_server_params_find_client(SilcServer server, char *ip, char *host)
{
  SilcServerParams params = server->params;
  SilcServerParamClient client;

  if (ip) {
    silc_list_start(params->clients);
    while ((client = silc_list_get(params->clients)) != SILC_LIST_END) {
      if (client->host && !silc_string_compare(client->host, ip))
	continue;
      return client;
    }
  }

  if (host) {
    silc_list_start(params->clients);
    while ((client = silc_list_get(params->clients)) != SILC_LIST_END) {
      if (client->host && !silc_string_compare(client->host, host))
	continue;
      return client;
    }
  }

  return NULL;
}

/* Returns server connection info from server configuartion by host
   (name or ip). */

SilcServerParamServer
silc_server_params_find_server(SilcServer server, char *ip, char *host)
{
  SilcServerParams params = server->params;
  SilcServerParamServer serv;

  if (ip) {
    silc_list_start(params->servers);
    while ((serv = silc_list_get(params->servers)) != SILC_LIST_END) {
      if (serv->host && !silc_string_compare(serv->host, ip))
	continue;
      return serv;
    }
  }

  if (host) {
    silc_list_start(params->servers);
    while ((serv = silc_list_get(params->servers)) != SILC_LIST_END) {
      if (serv->host && !silc_string_compare(serv->host, host))
	continue;
      return serv;
    }
  }

  return NULL;
}

/* Returns router connection info from server configuration by
   host (name or ip). */

SilcServerParamRouter
silc_server_params_find_router(SilcServer server, char *ip,
			       char *host, int port)
{
  SilcServerParams params = server->params;
  SilcServerParamRouter serv;

  if (ip) {
    silc_list_start(params->routers);
    while ((serv = silc_list_get(params->routers)) != SILC_LIST_END) {
      if (serv->host && !silc_string_compare(serv->host, ip))
	continue;
      if (port && serv->port && serv->port != port)
	continue;
      return serv;
    }
  }

  if (host) {
    silc_list_start(params->routers);
    while ((serv = silc_list_get(params->routers)) != SILC_LIST_END) {
      if (serv->host && !silc_string_compare(serv->host, host))
        continue;
      if (port && serv->port && serv->port != port)
	continue;
      return serv;
    }
  }

  return NULL;
}

/* Find backup router connection by host (name or ip) */

SilcServerParamRouter
silc_server_params_find_backup(SilcServer server, char *host, char *ip)
{
  SilcServerParams params = server->params;
  SilcServerParamRouter serv;

  if (ip) {
    silc_list_start(params->routers);
    while ((serv = silc_list_get(params->routers)) != SILC_LIST_END) {
      if (!serv->backup_router)
	continue;
      if (!silc_string_compare(serv->host, ip))
	continue;
      return serv;
    }
  }

  if (host) {
    silc_list_start(params->routers);
    while ((serv = silc_list_get(params->routers)) != SILC_LIST_END) {
      if (!serv->backup_router)
	continue;
      if (!silc_string_compare(serv->host, host))
        continue;
      return serv;
    }
  }

  return NULL;
}


/******************************* Public API *********************************/

/* Allocate parameters context */

SilcServerParams silc_server_params_alloc(void)
{
  SilcServerParams params;

  params = silc_calloc(1, sizeof(*params));
  if (!params)
    return NULL;

  /* Init lists */
  silc_list_init(params->cipher, struct SilcServerParamCipherStruct, next);
  silc_list_init(params->hash, struct SilcServerParamHashStruct, next);
  silc_list_init(params->hmac, struct SilcServerParamHmacStruct, next);
  silc_list_init(params->pkcs, struct SilcServerParamPkcsStruct, next);
  silc_list_init(params->clients, struct SilcServerParamClientStruct, next);
  silc_list_init(params->servers, struct SilcServerParamServerStruct, next);
  silc_list_init(params->routers, struct SilcServerParamRouterStruct, next);
  silc_list_init(params->conn_params, SilcServerParamConnParamsStruct, next);
  silc_list_init(params->denied, struct SilcServerParamDenyStruct, next);
  silc_list_init(params->admins, struct SilcServerParamAdminStruct, next);

  /* Set default values */
  silc_server_param_set_param_defaults(&params->param, NULL);
  params->channel_rekey_secs = SILC_SERVER_PARAM_CHANNEL_REKEY;
  params->key_exchange_timeout = SILC_SERVER_PARAM_SKE_TIMEOUT;
  params->conn_auth_timeout = SILC_SERVER_PARAM_CONNAUTH_TIMEOUT;
  params->connections_per_thread = SILC_SERVER_PARAM_CONN_PER_THREAD;

  return params;
}

/* Frees parameters context */

void silc_server_params_free(SilcServerParams params)
{
  silc_free(params);
}

/* Allocate server info context */

SilcServerParamServerInfo silc_server_params_serverinfo_alloc(void)
{
  SilcServerParamServerInfo server_info;

  server_info = silc_calloc(1, sizeof(*server_info));
  if (!server_info)
    return NULL;

  silc_list_init(server_info->interfaces,
		 struct SilcServerParamInterfaceStruct, next);

  return server_info;
}

/* Set server info */

void silc_server_params_set_serverinfo(SilcServerParams params,
				       SilcServerParamServerInfo server_info)
{
  params->server_info = server_info;
}

/* Add interface */

void silc_server_params_serverinfo_add_iface(SilcServerParamServerInfo info,
					     SilcServerParamInterface iface)
{
  silc_list_add(info->interfaces, iface);
}

/* Add cipher */

void silc_server_params_add_cipher(SilcServerParams params,
				   SilcServerParamCipher cipher)
{
  silc_list_add(params->cipher, cipher);
}

/* Add hash */

void silc_server_params_add_hash(SilcServerParams params,
				 SilcServerParamHash hash)
{
  silc_list_add(params->hash, hash);
}

/* Add HMAC */

void silc_server_params_add_hmac(SilcServerParams params,
				 SilcServerParamHmac hmac)
{
  silc_list_add(params->hmac, hmac);
}

/* Add PKCS */

void silc_server_params_add_pkcs(SilcServerParams params,
				 SilcServerParamPkcs pkcs)
{
  silc_list_add(params->pkcs, pkcs);
}

/* Add client */

void silc_server_params_add_client(SilcServerParams params,
				   SilcServerParamClient client)
{
  silc_list_add(params->clients, client);
}

/* Add server */

void silc_server_params_add_server(SilcServerParams params,
				   SilcServerParamServer server)
{
  silc_list_add(params->servers, server);
}

/* Add router */

void silc_server_params_add_router(SilcServerParams params,
				   SilcServerParamRouter router)
{
  silc_list_add(params->routers, router);
}

/* Add connection parameters */

void silc_server_params_add_connparam(SilcServerParams params,
				      SilcServerParamConnParams param)
{
  silc_list_add(params->conn_params, param);
}

/* Add deny */

void silc_server_params_add_deny(SilcServerParams params,
				 SilcServerParamDeny deny)
{
  silc_list_add(params->denied, deny);
}

/* Add admin */

void silc_server_params_add_admin(SilcServerParams params,
				  SilcServerParamAdmin admin)
{
  silc_list_add(params->admins, admin);
}
