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
typedef struct SilcConfigServerSectionAlgStruct {
  char *alg_name;
  char *sim_name;
  unsigned int block_len;
  unsigned int key_len;
  struct SilcConfigServerSectionAlgStruct *next;
  struct SilcConfigServerSectionAlgStruct *prev;
#define SILC_CONFIG_SERVER_MODNAME "builtin"
} SilcConfigServerSectionAlg;

/* Holds server information from config file */
typedef struct {
  char *server_name;
  char *server_ip;
  char *location;
  unsigned short port;
} SilcConfigServerSectionServerInfo;

/* Holds server's administrative information from config file */
typedef struct {
  char *location;
  char *server_type;
  char *admin_name;
  char *admin_email;
} SilcConfigServerSectionAdminInfo;

/* Holds all the ports the server is listenning on */
typedef struct SilcConfigServerSectionListenPortStruct {
  char *host;
  char *remote_ip;
  unsigned short port;
  struct SilcConfigServerSectionListenPortStruct *next;
  struct SilcConfigServerSectionListenPortStruct *prev;
} SilcConfigServerSectionListenPort;

/* Holds server's execution identity, or the user and group which
   to change from root when server starts */
typedef struct {
 char *user;
 char *group;
} SilcConfigServerSectionIdentity;

/* Holds all the configured log files. */
typedef struct SilcConfigServerSectionLoggingStruct {
  char *logtype;
  char *filename;
  unsigned int maxsize;
  struct SilcConfigServerSectionLoggingStruct *next;
  struct SilcConfigServerSectionLoggingStruct *prev;

/* Allowed <Logging> section types */
#define SILC_CONFIG_SERVER_LF_INFO "infologfile"
#define SILC_CONFIG_SERVER_LF_WARNING "warninglogfile"
#define SILC_CONFIG_SERVER_LF_ERROR "errorlogfile"
#define SILC_CONFIG_SERVER_LF_FATAL "fatalogfile"
} SilcConfigServerSectionLogging;

/* Holds all configured connection classes */
typedef struct SilcConfigServerSectionConnectionClassStruct {
  unsigned int class;
  unsigned int ping_freq;
  unsigned int connect_freq;
  unsigned int max_links;
  struct SilcConfigServerSectionConnectionClassStruct *next;
  struct SilcConfigServerSectionConnectionClassStruct *prev;
} SilcConfigServerSectionConnectionClass;

#define SILC_CONFIG_SERVER_AUTH_METH_PASSWD "passwd"
#define SILC_CONFIG_SERVER_AUTH_METH_PUBKEY "pubkey"

/* Holds all client authentication data from config file */
typedef struct SilcConfigServerSectionClientConnectionStruct {
  char *host;
  int auth_meth;
  char *auth_data;
  unsigned short port;
  unsigned int class;
  struct SilcConfigServerSectionClientConnectionStruct *next;
  struct SilcConfigServerSectionClientConnectionStruct *prev;
} SilcConfigServerSectionClientConnection;

/* Hols all server's administrators authentication data from config file */
typedef struct SilcConfigServerSectionAdminConnectionStruct {
  char *host;
  int auth_meth;
  char *auth_data;
  char *nickname;
  unsigned int class;
  struct SilcConfigServerSectionAdminConnectionStruct *next;
  struct SilcConfigServerSectionAdminConnectionStruct *prev;
} SilcConfigServerSectionAdminConnection;

/* Holds all configured server/router connections from config file */
typedef struct SilcConfigServerSectionServerConnectionStruct {
  char *host;
  int auth_meth;
  char *auth_data;
  unsigned short port;
  char *version;
  unsigned int class;
  int initiator;
  struct SilcConfigServerSectionServerConnectionStruct *next;
  struct SilcConfigServerSectionServerConnectionStruct *prev;
} SilcConfigServerSectionServerConnection;

/* Holds all configured denied connections from config file */
typedef struct {
  char *host;
  char *time;
  char *comment;
  unsigned short port;
} SilcConfigServerSectionDenyConnection;

/* Holds all client redirections from config file */
typedef struct {
  char *host;
  unsigned short port;
} SilcConfigServerSectionRedirectClient;

/* Holds motd file */
typedef struct {
  char *motd_file;
} SilcConfigServerSectionMotd;

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
  SilcConfigServerSectionAlg *cipher;
  SilcConfigServerSectionAlg *pkcs;
  SilcConfigServerSectionAlg *hash_func;
  SilcConfigServerSectionServerInfo *server_info;
  SilcConfigServerSectionAdminInfo *admin_info;
  SilcConfigServerSectionListenPort *listen_port;
  SilcConfigServerSectionIdentity *identity;
  SilcConfigServerSectionLogging *logging;
  SilcConfigServerSectionConnectionClass *conn_class;
  SilcConfigServerSectionClientConnection *clients;
  SilcConfigServerSectionServerConnection *servers;
  SilcConfigServerSectionServerConnection *routers;
  SilcConfigServerSectionAdminConnection *admins;
  SilcConfigServerSectionDenyConnection *denied;
  SilcConfigServerSectionRedirectClient *redirect;
  SilcConfigServerSectionMotd *motd;
} SilcConfigServerObject;

typedef SilcConfigServerObject *SilcConfigServer;

/* Configuration section type enumerations. */
typedef enum {
  SILC_CONFIG_SERVER_SECTION_TYPE_NONE = 0,
  SILC_CONFIG_SERVER_SECTION_TYPE_CIPHER,
  SILC_CONFIG_SERVER_SECTION_TYPE_PKCS,
  SILC_CONFIG_SERVER_SECTION_TYPE_HASH_FUNCTION,
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
  SILC_CONFIG_SERVER_SECTION_TYPE_REDIRECT_CLIENT,
  SILC_CONFIG_SERVER_SECTION_TYPE_MOTD,
} SilcConfigServerSectionType;

/* SILC Configuration Section structure. */
typedef struct {
  const char *section;
  SilcConfigServerSectionType type;
  unsigned int maxfields;
} SilcConfigServerSection;

/* LIst of all possible config sections in SILC server. */
extern SilcConfigServerSection silc_config_server_sections[];

/* Structure used in parsing the configuration lines. The line is read
   from a file to this structure before parsing it further. */
typedef struct SilcConfigServerParseStruct {
  SilcBuffer line;
  unsigned int linenum;
  SilcConfigServerSection *section;
  struct SilcConfigServerParseStruct *next;
  struct SilcConfigServerParseStruct *prev;
} *SilcConfigServerParse;

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
SilcConfigServer silc_config_server_alloc(char *filename);
void silc_config_server_free(SilcConfigServer config);
int silc_config_server_parse(SilcConfigServer config, SilcBuffer buffer,
			     SilcConfigServerParse *return_config);
int silc_config_server_parse_lines(SilcConfigServer config, 
				   SilcConfigServerParse parse_config);
int silc_config_server_check_sections(unsigned int checkmask);
void silc_config_server_setlogfiles(SilcConfigServer config);
void silc_config_server_register_ciphers(SilcConfigServer config);
void silc_config_server_register_pkcs(SilcConfigServer config);
void silc_config_server_register_hashfuncs(SilcConfigServer config);
SilcConfigServerSectionClientConnection *
silc_config_server_find_client_conn(SilcConfigServer config, 
				    char *host, int port);
SilcConfigServerSectionServerConnection *
silc_config_server_find_server_conn(SilcConfigServer config, 
				    char *host, int port);
SilcConfigServerSectionServerConnection *
silc_config_server_find_router_conn(SilcConfigServer config, 
				    char *host, int port);
void silc_config_server_print();

#endif
