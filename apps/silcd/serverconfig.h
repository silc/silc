/*

  serverconfig.h

  Author: Johnny Mnemonic <johnny@themnemonic.org>

  Copyright (C) 1997 - 2002 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/

#ifndef SERVERCONFIG_H
#define SERVERCONFIG_H

typedef struct SilcServerConfigCipherStruct {
  char *name;
  char *module;
  SilcUInt32 key_length;
  SilcUInt32 block_length;
  struct SilcServerConfigCipherStruct *next;
} SilcServerConfigCipher;

typedef struct SilcServerConfigHashStruct {
  char *name;
  char *module;
  SilcUInt32 block_length;
  SilcUInt32 digest_length;
  struct SilcServerConfigHashStruct *next;
} SilcServerConfigHash;

typedef struct SilcServerConfigHmacStruct {
  char *name;
  char *hash;
  SilcUInt32 mac_length;
  struct SilcServerConfigHmacStruct *next;
} SilcServerConfigHmac;

typedef struct SilcServerConfigPkcsStruct {
  char *name;
  struct SilcServerConfigPkcsStruct *next;
} SilcServerConfigPkcs;

typedef struct SilcServerConfigServerInfoStruct {
  char *server_name;
  char *server_ip;
  SilcUInt16 port;
  char *server_type;	/* E.g. "Test Server" */
  char *location;	/* geographic location */
  char *admin;		/* admin full name */
  char *email;		/* admin's email address */
  char *user;		/* userid the server should be runned at */
  char *group;		/* ditto, but about groupid */
  SilcPublicKey public_key;
  SilcPrivateKey private_key;
  char *motd_file;	/* path to text motd file (reading only) */
  char *pid_file;	/* path to the pid file (for reading and writing) */
} SilcServerConfigServerInfo;

typedef struct SilcServerConfigLoggingStruct {
  char *file;
  SilcUInt32 maxsize;
} SilcServerConfigLogging;

/* Connection parameters */
typedef struct SilcServerConfigConnParams {
  char *name;
  SilcUInt32 connections_max;
  SilcUInt32 connections_max_per_host;
  SilcUInt32 keepalive_secs;
  SilcUInt32 reconnect_count;
  SilcUInt32 reconnect_interval;
  SilcUInt32 reconnect_interval_max;
  bool reconnect_keep_trying;
  SilcUInt32 key_exchange_rekey;
  bool key_exchange_pfs;
  char *version_protocol;
  char *version_software;
  char *version_software_vendor;
  struct SilcServerConfigConnParams *next;
} SilcServerConfigConnParams;

/* Holds all client authentication data from config file */
typedef struct SilcServerConfigClientStruct {
  char *host;
  unsigned char *passphrase;
  SilcUInt32 passphrase_len;
  SilcHashTable publickeys;
  SilcServerConfigConnParams *param;
  struct SilcServerConfigClientStruct *next;
} SilcServerConfigClient;

/* Holds all server's administrators authentication data from config file */
typedef struct SilcServerConfigAdminStruct {
  char *host;
  char *user;
  char *nick;
  unsigned char *passphrase;
  SilcUInt32 passphrase_len;
  SilcHashTable publickeys;
  struct SilcServerConfigAdminStruct *next;
} SilcServerConfigAdmin;

/* Holds all configured denied connections from config file */
typedef struct SilcServerConfigDenyStruct {
  char *host;
  char *reason;
  struct SilcServerConfigDenyStruct *next;
} SilcServerConfigDeny;

/* Holds all configured server connections from config file */
typedef struct SilcServerConfigServerStruct {
  char *host;
  unsigned char *passphrase;
  SilcUInt32 passphrase_len;
  SilcHashTable publickeys;
  SilcServerConfigConnParams *param;
  bool backup_router;
  struct SilcServerConfigServerStruct *next;
} SilcServerConfigServer;

/* Holds all configured router connections from config file */
typedef struct SilcServerConfigRouterStruct {
  char *host;
  unsigned char *passphrase;
  SilcUInt32 passphrase_len;
  SilcHashTable publickeys;
  SilcUInt16 port;
  SilcServerConfigConnParams *param;
  bool initiator;
  bool backup_router;
  char *backup_replace_ip;
  SilcUInt16 backup_replace_port;
  bool backup_local;
  struct SilcServerConfigRouterStruct *next;
} SilcServerConfigRouter;

/* define the SilcServerConfig object */
typedef struct {
  void *tmp;

  /* Reference count (when this reaches zero, config object is destroyed) */
  SilcInt32 refcount;

  /* The General section */
  char *module_path;
  bool prefer_passphrase_auth;
  bool require_reverse_lookup;
  SilcUInt32 channel_rekey_secs;
  SilcUInt32 key_exchange_timeout;
  SilcUInt32 conn_auth_timeout;
  SilcServerConfigConnParams param;
  bool logging_quick;
  long logging_flushdelay;

  /* Other configuration sections */
  SilcServerConfigCipher *cipher;
  SilcServerConfigHash *hash;
  SilcServerConfigHmac *hmac;
  SilcServerConfigPkcs *pkcs;
  SilcServerConfigLogging *logging_info;
  SilcServerConfigLogging *logging_warnings;
  SilcServerConfigLogging *logging_errors;
  SilcServerConfigLogging *logging_fatals;
  SilcServerConfigServerInfo *server_info;
  SilcServerConfigConnParams *conn_params;
  SilcServerConfigClient *clients;
  SilcServerConfigAdmin *admins;
  SilcServerConfigDeny *denied;
  SilcServerConfigServer *servers;
  SilcServerConfigRouter *routers;
} *SilcServerConfig;

typedef struct {
  SilcServerConfig config;
  void *ref_ptr;
} SilcServerConfigRef;

/* Prototypes */

/* Basic config operations */
SilcServerConfig silc_server_config_alloc(const char *filename);
void silc_server_config_destroy(SilcServerConfig config);
void silc_server_config_ref(SilcServerConfigRef *ref, SilcServerConfig config,
			    void *ref_ptr);
void silc_server_config_unref(SilcServerConfigRef *ref);

/* Algorithm registering and reset functions */
bool silc_server_config_register_ciphers(SilcServer server);
bool silc_server_config_register_hashfuncs(SilcServer server);
bool silc_server_config_register_hmacs(SilcServer server);
bool silc_server_config_register_pkcs(SilcServer server);
void silc_server_config_setlogfiles(SilcServer server);

/* Run-time config access functions */
SilcServerConfigClient *
silc_server_config_find_client(SilcServer server, char *host);
SilcServerConfigAdmin *
silc_server_config_find_admin(SilcServer server, char *host, char *user,
			      char *nick);
SilcServerConfigDeny *
silc_server_config_find_denied(SilcServer server, char *host);
SilcServerConfigServer *
silc_server_config_find_server_conn(SilcServer server, char *host);
SilcServerConfigRouter *
silc_server_config_find_router_conn(SilcServer server, char *host, int port);
bool silc_server_config_is_primary_route(SilcServer server);
SilcServerConfigRouter *
silc_server_config_get_primary_router(SilcServer server);

#endif	/* !SERVERCONFIG_H */
