/*

  serverconfig.h

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

#ifndef SERVERCONFIG_H
#define SERVERCONFIG_H

/* Holds information of configured algorithms */
typedef struct SilcServerConfigSectionAlgStruct {
  char *alg_name;
  char *sim_name;
  uint32 block_len;
  uint32 key_len;
  struct SilcServerConfigSectionAlgStruct *next;
  struct SilcServerConfigSectionAlgStruct *prev;
#define SILC_CONFIG_SERVER_MODNAME "builtin"
} SilcServerConfigSectionAlg;

/* Holds server keys from config file */
typedef struct {
  SilcPublicKey public_key;
  SilcPrivateKey private_key;
} SilcServerConfigSectionServerKeys;

/* Holds server information from config file */
typedef struct {
  char *server_name;
  char *server_ip;
  char *location;
  uint16 port;
} SilcServerConfigSectionServerInfo;

/* Holds server's administrative information from config file */
typedef struct {
  char *location;
  char *server_type;
  char *admin_name;
  char *admin_email;
} SilcServerConfigSectionAdminInfo;

/* Holds all the ports the server is listenning on */
typedef struct SilcServerConfigSectionListenPortStruct {
  char *host;
  char *remote_ip;
  uint16 port;
  struct SilcServerConfigSectionListenPortStruct *next;
  struct SilcServerConfigSectionListenPortStruct *prev;
} SilcServerConfigSectionListenPort;

/* Holds server's execution identity, or the user and group which
   to change from root when server starts */
typedef struct {
 char *user;
 char *group;
} SilcServerConfigSectionIdentity;

/* Holds all the configured log files. */
typedef struct SilcServerConfigSectionLoggingStruct {
  char *logtype;
  char *filename;
  uint32 maxsize;
  struct SilcServerConfigSectionLoggingStruct *next;
  struct SilcServerConfigSectionLoggingStruct *prev;

/* Allowed <Logging> section types */
#define SILC_CONFIG_SERVER_LF_INFO "infologfile"
#define SILC_CONFIG_SERVER_LF_WARNING "warninglogfile"
#define SILC_CONFIG_SERVER_LF_ERROR "errorlogfile"
#define SILC_CONFIG_SERVER_LF_FATAL "fatallogfile"
} SilcServerConfigSectionLogging;

/* Holds all configured connection classes */
typedef struct SilcServerConfigSectionConnectionClassStruct {
  uint32 class;
  uint32 ping_freq;
  uint32 connect_freq;
  uint32 max_links;
  struct SilcServerConfigSectionConnectionClassStruct *next;
  struct SilcServerConfigSectionConnectionClassStruct *prev;
} SilcServerConfigSectionConnectionClass;

#define SILC_CONFIG_SERVER_AUTH_METH_PASSWD "passwd"
#define SILC_CONFIG_SERVER_AUTH_METH_PUBKEY "pubkey"

/* Holds all client authentication data from config file */
typedef struct SilcServerConfigSectionClientConnectionStruct {
  char *host;
  SilcAuthMethod auth_meth;
  void *auth_data;
  uint32 auth_data_len;
  uint16 port;
  uint32 class;
  struct SilcServerConfigSectionClientConnectionStruct *next;
  struct SilcServerConfigSectionClientConnectionStruct *prev;
} SilcServerConfigSectionClientConnection;

/* Hols all server's administrators authentication data from config file */
typedef struct SilcServerConfigSectionAdminConnectionStruct {
  char *host;
  char *username;
  char *nickname;
  SilcAuthMethod auth_meth;
  void *auth_data;
  uint32 auth_data_len;
  struct SilcServerConfigSectionAdminConnectionStruct *next;
  struct SilcServerConfigSectionAdminConnectionStruct *prev;
} SilcServerConfigSectionAdminConnection;

/* Holds all configured server/router connections from config file */
typedef struct SilcServerConfigSectionServerConnectionStruct {
  char *host;
  SilcAuthMethod auth_meth;
  void *auth_data;
  uint32 auth_data_len;
  uint16 port;
  char *version;
  uint32 class;
  bool initiator;
  struct SilcServerConfigSectionServerConnectionStruct *next;
  struct SilcServerConfigSectionServerConnectionStruct *prev;
} SilcServerConfigSectionServerConnection;

/* Holds all configured denied connections from config file */
typedef struct SilcServerConfigSectionDenyConnectionStruct {
  char *host;
  char *comment;
  uint16 port;
  struct SilcServerConfigSectionDenyConnectionStruct *next;
  struct SilcServerConfigSectionDenyConnectionStruct *prev;
} SilcServerConfigSectionDenyConnection;

/* Holds motd file */
typedef struct {
  char *motd_file;
} SilcServerConfigSectionMotd;

/* 
   SILC Server Config object. 

   This object holds all the data parsed from the SILC server configuration
   file. This is mainly used at the initialization of the server.

*/
typedef struct {
  /* Pointer back to the server */
  void *server;

  /* Filename of the configuration file */
  char *filename;

  /* Configuration sections */
  SilcServerConfigSectionAlg *cipher;
  SilcServerConfigSectionAlg *pkcs;
  SilcServerConfigSectionAlg *hash_func;
  SilcServerConfigSectionAlg *hmac;
  SilcServerConfigSectionServerKeys *server_keys;
  SilcServerConfigSectionServerInfo *server_info;
  SilcServerConfigSectionAdminInfo *admin_info;
  SilcServerConfigSectionListenPort *listen_port;
  SilcServerConfigSectionIdentity *identity;
  SilcServerConfigSectionLogging *logging;
  SilcServerConfigSectionConnectionClass *conn_class;
  SilcServerConfigSectionClientConnection *clients;
  SilcServerConfigSectionServerConnection *servers;
  SilcServerConfigSectionServerConnection *routers;
  SilcServerConfigSectionAdminConnection *admins;
  SilcServerConfigSectionDenyConnection *denied;
  SilcServerConfigSectionMotd *motd;
} SilcServerConfigObject;

typedef SilcServerConfigObject *SilcServerConfig;

/* Configuration section type enumerations. */
typedef enum {
  SILC_CONFIG_SERVER_SECTION_TYPE_NONE = 0,
  SILC_CONFIG_SERVER_SECTION_TYPE_CIPHER,
  SILC_CONFIG_SERVER_SECTION_TYPE_PKCS,
  SILC_CONFIG_SERVER_SECTION_TYPE_HASH_FUNCTION,
  SILC_CONFIG_SERVER_SECTION_TYPE_HMAC,
  SILC_CONFIG_SERVER_SECTION_TYPE_SERVER_KEYS,
  SILC_CONFIG_SERVER_SECTION_TYPE_SERVER_INFO,
  SILC_CONFIG_SERVER_SECTION_TYPE_ADMIN_INFO,
  SILC_CONFIG_SERVER_SECTION_TYPE_LISTEN_PORT,
  SILC_CONFIG_SERVER_SECTION_TYPE_IDENTITY,
  SILC_CONFIG_SERVER_SECTION_TYPE_LOGGING,
  SILC_CONFIG_SERVER_SECTION_TYPE_CONNECTION_CLASS,
  SILC_CONFIG_SERVER_SECTION_TYPE_CLIENT_CONNECTION,
  SILC_CONFIG_SERVER_SECTION_TYPE_SERVER_CONNECTION,
  SILC_CONFIG_SERVER_SECTION_TYPE_ROUTER_CONNECTION,
  SILC_CONFIG_SERVER_SECTION_TYPE_ADMIN_CONNECTION,
  SILC_CONFIG_SERVER_SECTION_TYPE_DENY_CONNECTION,
  SILC_CONFIG_SERVER_SECTION_TYPE_MOTD,
} SilcServerConfigSectionType;

/* SILC Configuration Section structure. */
typedef struct {
  const char *section;
  SilcServerConfigSectionType type;
  int maxfields;
} SilcServerConfigSection;

/* LIst of all possible config sections in SILC server. */
extern SilcServerConfigSection silc_server_config_sections[];

/* Structure used in parsing the configuration lines. The line is read
   from a file to this structure before parsing it further. */
typedef struct SilcServerConfigParseStruct {
  SilcBuffer line;
  int linenum;
  SilcServerConfigSection *section;
  struct SilcServerConfigParseStruct *next;
  struct SilcServerConfigParseStruct *prev;
} *SilcServerConfigParse;

/* Macros */

/* Allocates list entries for configuration sections. Used by all
   config sections as this is common. */
#define SILC_SERVER_CONFIG_LIST_ALLOC(x)		\
do {							\
  if (!(x)) {						\
    (x) = silc_calloc(1, sizeof(*(x)));			\
    (x)->next = NULL;					\
    (x)->prev = NULL;					\
  } else {						\
    if (!(x)->next) {					\
      (x)->next = silc_calloc(1, sizeof(*(x)->next));	\
      (x)->next->next = NULL;				\
      (x)->next->prev = (x);				\
      (x) = (x)->next;					\
    }							\
  }							\
} while(0)

/* Prototypes */
SilcServerConfig silc_server_config_alloc(char *filename);
void silc_server_config_free(SilcServerConfig config);
int silc_server_config_parse(SilcServerConfig config, SilcBuffer buffer,
			     SilcServerConfigParse *return_config);
int silc_server_config_parse_lines(SilcServerConfig config, 
				   SilcServerConfigParse parse_config);
int silc_server_config_check_sections(uint32 checkmask);
void silc_server_config_setlogfiles(SilcServerConfig config);
void silc_server_config_register_ciphers(SilcServerConfig config);
void silc_server_config_register_pkcs(SilcServerConfig config);
void silc_server_config_register_hashfuncs(SilcServerConfig config);
void silc_server_config_register_hmacs(SilcServerConfig config);
SilcServerConfigSectionClientConnection *
silc_server_config_find_client_conn(SilcServerConfig config, 
				    char *host, int port);
SilcServerConfigSectionServerConnection *
silc_server_config_find_server_conn(SilcServerConfig config, 
				    char *host, int port);
SilcServerConfigSectionServerConnection *
silc_server_config_find_router_conn(SilcServerConfig config, 
				    char *host, int port);
bool silc_server_config_is_primary_route(SilcServerConfig config);
SilcServerConfigSectionAdminConnection *
silc_server_config_find_admin(SilcServerConfig config,
			      char *host, char *username, char *nickname);
SilcServerConfigSectionDenyConnection *
silc_server_config_denied_conn(SilcServerConfig config, char *host,
			       int port);

#endif
