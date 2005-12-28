/*

  silcserver_params.h

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

#ifndef SILCSERVER_PARAMS_H
#define SILCSERVER_PARAMS_H

typedef struct SilcServerParamCipherStruct {
  char *name;
  char *module;
  SilcUInt32 key_length;
  SilcUInt32 block_length;
  struct SilcServerParamCipherStruct *next;
} *SilcServerParamCipher;

typedef struct SilcServerParamHashStruct {
  char *name;
  char *module;
  SilcUInt32 block_length;
  SilcUInt32 digest_length;
  struct SilcServerParamHashStruct *next;
} *SilcServerParamHash;

typedef struct SilcServerParamHmacStruct {
  char *name;
  char *hash;
  SilcUInt32 mac_length;
  struct SilcServerParamHmacStruct *next;
} *SilcServerParamHmac;

typedef struct SilcServerParamPkcsStruct {
  char *name;
  struct SilcServerParamPkcsStruct *next;
} *SilcServerParamPkcs;

typedef struct SilcServerParamInterfaceStruct {
  char *ip;				/* IP address */
  SilcUInt16 port;			/* Port */
  struct SilcServerParamInterfaceStruct *next;
} *SilcServerParamInterface;

typedef struct SilcServerParamServerInfoStruct {
  char *server_name;			/* Server name */
  SilcList interfaces;			/* SilcServerParamInterface */
  char *server_type;			/* E.g. "Test Server" */
  char *location;			/* Geographic location */
  char *admin;				/* Admin's full name */
  char *email;				/* Admin's email address */
  char *user;				/* Userid the server use */
  char *group;				/* Groupid the server use  */
  char *motd_file;			/* Path to text MOTD file */
  char *pid_file;			/* Path to the PID file */
  SilcPublicKey public_key;		/* Server's public key */
  SilcPrivateKey private_key;		/* Server's private key */
} *SilcServerParamServerInfo;

typedef struct SilcServerParamLoggingStruct {
  char *file;
  SilcUInt32 maxsize;
} *SilcServerParamLogging;

/* Connection parameters */
typedef struct SilcServerParamConnParamsObject {
  struct SilcServerParamConnParams *next;
  char *name;
  char *version_protocol;
  char *version_software;
  char *version_software_vendor;
  SilcUInt32 connections_max;
  SilcUInt32 connections_max_per_host;
  SilcUInt32 keepalive_secs;
  SilcUInt32 reconnect_count;
  SilcUInt32 reconnect_interval;
  SilcUInt32 reconnect_interval_max;
  SilcUInt32 key_exchange_rekey;
  SilcUInt32 qos_rate_limit;
  SilcUInt32 qos_bytes_limit;
  SilcUInt32 qos_limit_sec;
  SilcUInt32 qos_limit_usec;
  SilcUInt32 chlimit;
  unsigned int key_exchange_pfs      : 1;
  unsigned int reconnect_keep_trying : 1;
  unsigned int anonymous             : 1;
  unsigned int qos                   : 1;
} *SilcServerParamConnParams, SilcServerParamConnParamsStruct;

/* Holds all client authentication data from config file */
typedef struct SilcServerParamClientStruct {
  char *host;
  unsigned char *passphrase;
  SilcUInt32 passphrase_len;
  SilcHashTable publickeys;
  SilcBool pubkey_auth;
  SilcServerParamConnParams param;
  struct SilcServerParamClientStruct *next;
} *SilcServerParamClient;

/* Holds all server's administrators authentication data from config file */
typedef struct SilcServerParamAdminStruct {
  char *host;
  char *user;
  char *nick;
  unsigned char *passphrase;
  SilcUInt32 passphrase_len;
  SilcHashTable publickeys;
  struct SilcServerParamAdminStruct *next;
} *SilcServerParamAdmin;

/* Holds all configured denied connections from config file */
typedef struct SilcServerParamDenyStruct {
  char *host;
  char *reason;
  struct SilcServerParamDenyStruct *next;
} *SilcServerParamDeny;

/* Holds all configured server connections from config file */
typedef struct SilcServerParamServerStruct {
  char *host;
  unsigned char *passphrase;
  SilcUInt32 passphrase_len;
  SilcHashTable publickeys;
  SilcBool pubkey_auth;
  SilcServerParamConnParams param;
  SilcBool backup_router;
  struct SilcServerParamServerStruct *next;
} *SilcServerParamServer;

/* Holds all configured router connections from config file */
typedef struct SilcServerParamRouterStruct {
  char *host;
  unsigned char *passphrase;
  SilcUInt32 passphrase_len;
  SilcHashTable publickeys;
  SilcBool pubkey_auth;
  SilcUInt16 port;
  SilcServerParamConnParams param;
  SilcBool initiator;
  SilcBool backup_router;
  char *backup_replace_ip;
  SilcUInt16 backup_replace_port;
  SilcBool backup_local;
  struct SilcServerParamRouterStruct *next;
} *SilcServerParamRouter;

typedef struct {
  /* Server information */
  SilcServerParamServerInfo server_info;

  /* Global flags */
  unsigned int prefer_passphrase_auth   : 1;
  unsigned int require_reverse_lookup   : 1;
  unsigned int detach_disabled          : 1;

  /* Threads support */
  unsigned int use_threads              : 1;
  SilcUInt32 connections_per_thread;

  /* Default connection parameters */
  SilcServerParamConnParamsStruct param;

  SilcUInt32 channel_rekey_secs;
  SilcUInt32 key_exchange_timeout;
  SilcUInt32 conn_auth_timeout;
  SilcUInt32 detach_timeout;
  SilcBool logging_timestamp;
  SilcBool logging_quick;
  long logging_flushdelay;
  char *debug_string;

  /* Supported ciphers, hashes, hmacs and PKCS's */
  SilcList cipher;		       /* SilcServerParamCipher */
  SilcList hash;		       /* SilcServerParamHash */
  SilcList hmac;		       /* SilcServerParamHmac */
  SilcList pkcs;		       /* SilcServerParamPkcs */

  /* Configured client, server and router connections */
  SilcList clients;		       /* SilcServerParamClient */
  SilcList servers;		       /* SilcServerParamServer */
  SilcList routers;		       /* SilcServerParamRouter */

  /* Configured connections parameters */
  SilcList conn_params;		       /* SilcServerParamConnParams */

  /* Denied connections */
  SilcList denied;		       /* SilcServerParamDeny */

  /* Configured server administrators */
  SilcList admins;		       /* SilcServerParamAdmin */

  SilcServerParamLogging *logging_info;
  SilcServerParamLogging *logging_warnings;
  SilcServerParamLogging *logging_errors;
  SilcServerParamLogging *logging_fatals;

  SilcUInt8 refcnt;		       /* Reference counter */
} *SilcServerParams;

/****f* silcserver/SilcServerParamsAPI/silc_server_params_alloc
 *
 * SYNOPSIS
 *
 *    SilcServerParams silc_server_params_alloc(void);
 *
 * DESCRIPTION
 *
 *    Allocates server parameters context.
 *
 ***/
SilcServerParams silc_server_params_alloc(void);

/****f* silcserver/SilcServerParamsAPI/silc_server_params_free
 *
 * SYNOPSIS
 *
 *    void silc_server_params_free(SilcServerParams params);
 *
 * DESCRIPTION
 *
 *    Frees server parameters and all allocated resources in it.
 *
 ***/
void silc_server_params_free(SilcServerParams params);

/****f* silcserver/SilcServerParamsAPI/silc_server_params_serverinfo_alloc
 *
 * SYNOPSIS
 *
 *    SilcServerParamServerInfo silc_server_params_serverinfo_alloc(void);
 *
 * DESCRIPTION
 *
 *    Allocates server information context.  This does not have to be freed
 *    by the caller.  It is freed when the server parameters are freed.
 *
 ***/
SilcServerParamServerInfo silc_server_params_serverinfo_alloc(void);

/****f* silcserver/SilcServerParamsAPI/silc_server_params_serverinfo_alloc
 *
 * SYNOPSIS
 *
 *    void
 *    silc_server_params_serverinfo_add_iface(SilcServerParamServerInfo info,
 *                                            SilcServerParamInterface iface);
 *
 * DESCRIPTION
 *
 *    Adds interface to server information parameters.  The first added
 *    interface is the primary interface.
 *
 ***/
void silc_server_params_serverinfo_add_iface(SilcServerParamServerInfo info,
					     SilcServerParamInterface iface);

/****f* silcserver/SilcServerParamsAPI/silc_server_params_set_serverinfo
 *
 * SYNOPSIS
 *
 *    void
 *    silc_server_params_set_serverinfo(SilcServerParams params,
 *                                      SilcServerParamServerInfo
 *                                                       server_info);
 *
 * DESCRIPTION
 *
 *    Set server's information to server parameters.
 *
 ***/
void silc_server_params_set_serverinfo(SilcServerParams params,
				       SilcServerParamServerInfo server_info);

/****f* silcserver/SilcServerParamsAPI/silc_server_params_add_cipher
 *
 * SYNOPSIS
 *
 *    void silc_server_params_add_cipher(SilcServerParams params,
 *                                       SilcServerParamCipher cipher);
 *
 * DESCRIPTION
 *
 *    Adds a cipher to server parameters.
 *
 ***/
void silc_server_params_add_cipher(SilcServerParams params,
				   SilcServerParamCipher cipher);

/****f* silcserver/SilcServerParamsAPI/silc_server_params_add_hash
 *
 * SYNOPSIS
 *
 *    void silc_server_params_add_hash(SilcServerParams params,
 *                                     SilcServerParamHash hash);
 *
 * DESCRIPTION
 *
 *    Adds a hash function to server parameters.
 *
 ***/
void silc_server_params_add_hash(SilcServerParams params,
				 SilcServerParamHash hash);

/****f* silcserver/SilcServerParamsAPI/silc_server_params_add_hmac
 *
 * SYNOPSIS
 *
 *    void silc_server_params_add_hmac(SilcServerParams params,
 *                                     SilcServerParamHmac hmac);
 *
 * DESCRIPTION
 *
 *    Adds a HMAC to server parameters.
 *
 ***/
void silc_server_params_add_hmac(SilcServerParams params,
				 SilcServerParamHmac hmac);

/****f* silcserver/SilcServerParamsAPI/silc_server_params_add_pkcs
 *
 * SYNOPSIS
 *
 *    void silc_server_params_add_pkcs(SilcServerParams params,
 *                                     SilcServerParamPkcs pkcs);
 *
 * DESCRIPTION
 *
 *    Adds a HMAC to server parameters.
 *
 ***/
void silc_server_params_add_pkcs(SilcServerParams params,
				 SilcServerParamPkcs pkcs);

/****f* silcserver/SilcServerParamsAPI/silc_server_params_add_client
 *
 * SYNOPSIS
 *
 *    void silc_server_params_add_client(SilcServerParams params,
 *                                       SilcServerParamClient client);
 *
 * DESCRIPTION
 *
 *    Adds a client connection to server parameters.
 *
 ***/
void silc_server_params_add_client(SilcServerParams params,
				   SilcServerParamClient client);

/****f* silcserver/SilcServerParamsAPI/silc_server_params_add_server
 *
 * SYNOPSIS
 *
 *    void silc_server_params_add_server(SilcServerParams params,
 *                                       SilcServerParamServer server);
 *
 * DESCRIPTION
 *
 *    Adds a server connection to server parameters.
 *
 ***/
void silc_server_params_add_server(SilcServerParams params,
				   SilcServerParamServer server);

/****f* silcserver/SilcServerParamsAPI/silc_server_params_add_router
 *
 * SYNOPSIS
 *
 *    void silc_server_params_add_router(SilcServerParams params,
 *                                       SilcServerParamRouter router);
 *
 * DESCRIPTION
 *
 *    Adds a router connection to server parameters.
 *
 ***/
void silc_server_params_add_router(SilcServerParams params,
				   SilcServerParamRouter router);

/****f* silcserver/SilcServerParamsAPI/silc_server_params_add_connparam
 *
 * SYNOPSIS
 *
 *    void silc_server_params_add_connparam(SilcServerParams params,
 *                                          SilcServerParamConnParams param);
 *
 * DESCRIPTION
 *
 *    Adds a connection parameters to server parameters.
 *
 ***/
void silc_server_params_add_connparam(SilcServerParams params,
				      SilcServerParamConnParams param);

/****f* silcserver/SilcServerParamsAPI/silc_server_params_add_deny
 *
 * SYNOPSIS
 *
 *    void silc_server_params_add_deny(SilcServerParams params,
 *                                     SilcServerParamDeny deny);
 *
 * DESCRIPTION
 *
 *    Adds a denied connection to server parameters.
 *
 ***/
void silc_server_params_add_deny(SilcServerParams params,
				 SilcServerParamDeny deny);

/****f* silcserver/SilcServerParamsAPI/silc_server_params_add_admin
 *
 * SYNOPSIS
 *
 *    void silc_server_params_add_admin(SilcServerParams params,
 *                                      SilcServerParamAdmin admin);
 *
 * DESCRIPTION
 *
 *    Adds an server administrator to server parameters.
 *
 ***/
void silc_server_params_add_admin(SilcServerParams params,
				  SilcServerParamAdmin admin);

#endif	/* SILCSERVER_PARAMS_H */
