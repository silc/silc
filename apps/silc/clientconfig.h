/*

  clientconfig.h

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

#ifndef CLIENTCONFIG_H
#define CLIENTCONFIG_H

/* Holds information of configured algorithms */
typedef struct SilcClientConfigSectionAlgStruct {
  char *alg_name;
  char *sim_name;
  uint32 block_len;
  uint32 key_len;
  struct SilcClientConfigSectionAlgStruct *next;
  struct SilcClientConfigSectionAlgStruct *prev;
#define SILC_CLIENT_CONFIG_MODNAME "builtin"
} SilcClientConfigSectionAlg;

/* Holds all server connections from config file */
typedef struct SilcClientConfigSectionConnectionStruct {
  char *host;
  int auth_meth;
  char *auth_data;
  uint16 port;
  struct SilcClientConfigSectionConnectionStruct *next;
  struct SilcClientConfigSectionConnectionStruct *prev;
#define SILC_CLIENT_CONFIG_AUTH_METH_PASSWD "passwd"
#define SILC_CLIENT_CONFIG_AUTH_METH_PUBKEY "pubkey"
} SilcClientConfigSectionConnection;

/* Holds all given commands from config file */
typedef struct SilcClientConfigSectionCommandStruct {
  char *command;
  struct SilcClientConfigSectionCommandStruct *next;
  struct SilcClientConfigSectionCommandStruct *prev;
} SilcClientConfigSectionCommand;

/* 
   SILC Client Config object.

   This object holds all the data parsed from the SILC client configuration
   file. This is mainly used at the initialization of the client.

*/
typedef struct {
  /* Pointer back to the client */
  void *client;

  /* Filename of the configuration file */
  char *filename;

  /* Configuration sections */
  SilcClientConfigSectionAlg *cipher;
  SilcClientConfigSectionAlg *pkcs;
  SilcClientConfigSectionAlg *hash_func;
  SilcClientConfigSectionAlg *hmac;
  SilcClientConfigSectionConnection *conns;
  SilcClientConfigSectionCommand *commands;
} SilcClientConfigObject;

typedef SilcClientConfigObject *SilcClientConfig;

/* Configuration section type enumerations. */
typedef enum {
  SILC_CLIENT_CONFIG_SECTION_TYPE_NONE = 0,
  SILC_CLIENT_CONFIG_SECTION_TYPE_CIPHER,
  SILC_CLIENT_CONFIG_SECTION_TYPE_PKCS,
  SILC_CLIENT_CONFIG_SECTION_TYPE_HASH_FUNCTION,
  SILC_CLIENT_CONFIG_SECTION_TYPE_HMAC,
  SILC_CLIENT_CONFIG_SECTION_TYPE_CONNECTION,
  SILC_CLIENT_CONFIG_SECTION_TYPE_COMMAND = 253, /* Special section */
} SilcClientConfigSectionType;

/* SILC Configuration Section structure. */
typedef struct {
  const char *section;
  SilcClientConfigSectionType type;
  int maxfields;
} SilcClientConfigSection;

/* List of all possible config sections in SILC client */
extern SilcClientConfigSection silc_client_config_sections[];

/* Structure used in parsing the configuration lines. The line is read
   from a file to this structure before parsing it further. */
typedef struct SilcClientConfigParseStruct {
  SilcBuffer line;
  int linenum;
  SilcClientConfigSection *section;
  struct SilcClientConfigParseStruct *next;
  struct SilcClientConfigParseStruct *prev;
} *SilcClientConfigParse;

/* Prototypes */
SilcClientConfig silc_client_config_alloc(char *filename);
void silc_client_config_free(SilcClientConfig config);
int silc_client_config_parse(SilcClientConfig config, SilcBuffer buffer,
			     SilcClientConfigParse *return_config);
int silc_client_config_parse_lines(SilcClientConfig config, 
				   SilcClientConfigParse parse_config);
int silc_client_config_check_sections(uint32 checkmask);
void silc_client_config_setlogfiles(SilcClientConfig config);
void silc_client_config_register_ciphers(SilcClientConfig config);
void silc_client_config_register_pkcs(SilcClientConfig config);
void silc_client_config_register_hashfuncs(SilcClientConfig config);
void silc_client_config_register_hmacs(SilcClientConfig config);
SilcClientConfigSectionConnection *
silc_client_config_find_connection(SilcClientConfig config, 
				   char *host, int port);

#endif
