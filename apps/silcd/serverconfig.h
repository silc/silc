/*

  serverconfig.h

  Author: Johnny Mnemonic <johnny@themnemonic.org>

  Copyright (C) 1997 - 2002 Johnny Mnemonic

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

typedef struct SilcServerConfigSectionCipherStruct {
  char *name;
  char *module;
  uint32 key_length;
  uint32 block_length;
  struct SilcServerConfigSectionCipherStruct *next;
} SilcServerConfigSectionCipher;

typedef struct SilcServerConfigSectionHashStruct {
  char *name;
  char *module;
  uint32 block_length;
  uint32 digest_length;
  struct SilcServerConfigSectionHashStruct *next;
} SilcServerConfigSectionHash;

typedef struct SilcServerConfigSectionHmacStruct {
  char *name;
  char *hash;
  uint32 mac_length;
  struct SilcServerConfigSectionHmacStruct *next;
} SilcServerConfigSectionHmac;

typedef struct SilcServerConfigSectionPkcsStruct {
  char *name;
  struct SilcServerConfigSectionPkcsStruct *next;
} SilcServerConfigSectionPkcs;

typedef struct SilcServerConfigSectionServerInfoStruct {
  char *server_name;
  char *server_ip;
  uint16 port;
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
} SilcServerConfigSectionServerInfo;

typedef struct SilcServerConfigSectionLoggingStruct {
  char *file;
  uint32 maxsize;
} SilcServerConfigSectionLogging;

/* Holds all configured connection classes */
/* typedef struct SilcServerConfigSectionClassStruct {
  uint32 class;
  uint32 ping_freq;
  uint32 connect_freq;
  uint32 max_links;
  struct SilcServerConfigSectionClassStruct *next;
} SilcServerConfigSectionClass; */

/* Holds all client authentication data from config file */
typedef struct SilcServerConfigSectionClientStruct {
  char *host;
  unsigned char *passphrase;
  uint32 passphrase_len;
  void *publickey;
  uint16 port;
  uint32 class;
  struct SilcServerConfigSectionClientStruct *next;
} SilcServerConfigSectionClient;

/* Holds all server's administrators authentication data from config file */
typedef struct SilcServerConfigSectionAdminStruct {
  char *host;
  char *user;
  char *nick;
  unsigned char *passphrase;
  uint32 passphrase_len;
  void *publickey;
  struct SilcServerConfigSectionAdminStruct *next;
} SilcServerConfigSectionAdmin;

/* Holds all configured denied connections from config file */
typedef struct SilcServerConfigSectionDenyStruct {
  char *host;
  uint16 port;
  char *reason;
  struct SilcServerConfigSectionDenyStruct *next;
} SilcServerConfigSectionDeny;

/* Holds all configured server connections from config file */
typedef struct SilcServerConfigSectionServerStruct {
  char *host;
  unsigned char *passphrase;
  uint32 passphrase_len;
  void *publickey;
  char *version;
  uint32 class;
  bool backup_router;
  struct SilcServerConfigSectionServerStruct *next;
} SilcServerConfigSectionServer;

/* Holds all configured router connections from config file */
typedef struct SilcServerConfigSectionRouterStruct {
  char *host;
  unsigned char *passphrase;
  uint32 passphrase_len;
  void *publickey;
  uint16 port;
  char *version;
  uint32 class;
  bool initiator;
  bool backup_router;
  char *backup_replace_ip;
  uint16 backup_replace_port;
  bool backup_local;
  struct SilcServerConfigSectionRouterStruct *next;
} SilcServerConfigSectionRouter;

/* define the SilcServerConfig object */
typedef struct {
  void *tmp;
  char *module_path;
  bool prefer_passphrase_auth;

  SilcServerConfigSectionCipher *cipher;
  SilcServerConfigSectionHash *hash;
  SilcServerConfigSectionHmac *hmac;
  SilcServerConfigSectionPkcs *pkcs;
  SilcServerConfigSectionLogging *logging_info;
  SilcServerConfigSectionLogging *logging_warnings;
  SilcServerConfigSectionLogging *logging_errors;
  SilcServerConfigSectionLogging *logging_fatals;
  SilcServerConfigSectionServerInfo *server_info;
/*SilcServerConfigSectionClass *conn_class; */
  SilcServerConfigSectionClient *clients;
  SilcServerConfigSectionAdmin *admins;
  SilcServerConfigSectionDeny *denied;
  SilcServerConfigSectionServer *servers;
  SilcServerConfigSectionRouter *routers;
} *SilcServerConfig;

/* Prototypes */

/* Basic config operations */
SilcServerConfig silc_server_config_alloc(char *filename);
void silc_server_config_destroy(SilcServerConfig config);

/* Algorithm registering and reset functions */
bool silc_server_config_register_ciphers(SilcServer server);
bool silc_server_config_register_hashfuncs(SilcServer server);
bool silc_server_config_register_hmacs(SilcServer server);
bool silc_server_config_register_pkcs(SilcServer server);
void silc_server_config_setlogfiles(SilcServer server);

/* Run-time config access functions */
SilcServerConfigSectionClient *
silc_server_config_find_client(SilcServer server, char *host, int port);
SilcServerConfigSectionAdmin *
silc_server_config_find_admin(SilcServer server, char *host, char *user, 
			      char *nick);
SilcServerConfigSectionDeny *
silc_server_config_find_denied(SilcServer server, char *host, uint16 port);
SilcServerConfigSectionServer *
silc_server_config_find_server_conn(SilcServer server, char *host);
SilcServerConfigSectionRouter *
silc_server_config_find_router_conn(SilcServer server, char *host, int port);
bool silc_server_config_is_primary_route(SilcServer server);
SilcServerConfigSectionRouter *
silc_server_config_get_primary_router(SilcServer server);

#endif	/* !SERVERCONFIG_H */
