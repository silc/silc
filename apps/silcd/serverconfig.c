/*

  serverconfig.c

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
/* $Id$ */

#include "serverincludes.h"
#include "server_internal.h"

#if 0
#define SERVER_CONFIG_DEBUG(fmt) SILC_LOG_DEBUG(fmt)
#else
#define SERVER_CONFIG_DEBUG(fmt)
#endif

/* auto-declare needed variables for the common list parsing */
#define SILC_SERVER_CONFIG_SECTION_INIT(__type__)			\
  SilcServerConfig config = (SilcServerConfig) context;			\
  __type__ *findtmp, *tmp = (__type__ *) config->tmp;			\
  int got_errno = 0

/* append the tmp field to the specified list */
#define SILC_SERVER_CONFIG_LIST_APPENDTMP(__list__)			\
  if (!__list__) {							\
    __list__ = tmp;							\
  } else {								\
    for (findtmp = __list__; findtmp->next; findtmp = findtmp->next);	\
    findtmp->next = tmp;						\
  }

/* loops all elements in a list and provides a di struct pointer of the
 * specified type containing the current element */
#define SILC_SERVER_CONFIG_LIST_DESTROY(__type__, __list__)		\
  for (tmp = (void *) __list__; tmp;) {					\
    __type__ *di = (__type__ *) tmp;					\
    tmp = (void *) di->next;

/* Set EDOUBLE error value and bail out if necessary */
#define CONFIG_IS_DOUBLE(__x__)						\
  if ((__x__)) {							\
    got_errno = SILC_CONFIG_EDOUBLE; 					\
    goto got_err;							\
  }

/* Free the authentication fields in the specified struct
 * Expands to two instructions */
#define CONFIG_FREE_AUTH(__section__)					\
  silc_free(__section__->passphrase);					\
  silc_pkcs_public_key_free(__section__->publickey)

/* Set default values to those parameters that have not been defined */
static void 
my_set_param_defaults(SilcServerConfigConnParams *params,
		      SilcServerConfigConnParams *defaults)
{
#define SET_PARAM_DEFAULT(p, d)						\
  (params->p ? params->p : (defaults && defaults->p ? defaults->p : d))

  params->connections_max = 
    SET_PARAM_DEFAULT(connections_max, SILC_SERVER_MAX_CONNECTIONS);
  params->connections_max_per_host = 
    SET_PARAM_DEFAULT(connections_max_per_host, 
		      SILC_SERVER_MAX_CONNECTIONS_SINGLE);
  params->keepalive_secs = 
    SET_PARAM_DEFAULT(keepalive_secs, SILC_SERVER_KEEPALIVE);
  params->reconnect_count = 
    SET_PARAM_DEFAULT(reconnect_count, SILC_SERVER_RETRY_COUNT);
  params->reconnect_interval = 
    SET_PARAM_DEFAULT(reconnect_interval, SILC_SERVER_RETRY_INTERVAL_MIN);
  params->reconnect_interval_max = 
    SET_PARAM_DEFAULT(reconnect_interval_max, SILC_SERVER_RETRY_INTERVAL_MAX);
  params->key_exchange_rekey = 
    SET_PARAM_DEFAULT(key_exchange_rekey, SILC_SERVER_REKEY);
}

/* Find connection parameters by the parameter block name. */
static SilcServerConfigConnParams *
my_find_param(SilcServerConfig config, const char *name, uint32 line)
{
  SilcServerConfigConnParams *param;

  for (param = config->conn_params; param; param = param->next) {
    if (!strcasecmp(param->name, name))
      return param;
  }

  fprintf(stderr, "\nError while parsing config file at line %lu: "
	  "Cannot find Param \"%s\".\n", line, name);

  return NULL;
}

/* parse an authdata according to its auth method */
static bool my_parse_authdata(SilcAuthMethod auth_meth, char *p, uint32 line,
			      void **auth_data, uint32 *auth_data_len)
{
  if (auth_meth == SILC_AUTH_PASSWORD) {
    /* p is a plain text password */
    if (auth_data)
      *auth_data = (void *) strdup(p);
    if (auth_data_len)
      *auth_data_len = (uint32) strlen(p);
  } else if (auth_meth == SILC_AUTH_PUBLIC_KEY) {
    /* p is a public key */
    SilcPublicKey public_key;

    if (!silc_pkcs_load_public_key(p, &public_key, SILC_PKCS_FILE_PEM))
      if (!silc_pkcs_load_public_key(p, &public_key, SILC_PKCS_FILE_BIN)) {
	fprintf(stderr, "\nError while parsing config file at line %lu: "
		"Could not load public key file!\n", line);
	return FALSE;
      }
    if (auth_data)
      *auth_data = (void *) public_key;
    if (auth_data_len)
      *auth_data_len = 0;
  } else {
    fprintf(stderr, "\nError while parsing config file at line %lu: "
	    "Unknown authentication method.\n", line);
    return FALSE;
  }
  return TRUE;
}

/* Callbacks */

SILC_CONFIG_CALLBACK(fetch_generic)
{
  SilcServerConfig config = (SilcServerConfig) context;
  int got_errno = 0;

  if (!strcmp(name, "module_path")) {
    CONFIG_IS_DOUBLE(config->module_path);
    config->module_path = (*(char *)val ? strdup((char *) val) : NULL);
  }
  else if (!strcmp(name, "prefer_passphrase_auth")) {
    config->prefer_passphrase_auth = *(bool *)val;
  }
  else if (!strcmp(name, "require_reverse_lookup")) {
    config->require_reverse_lookup = *(bool *)val;
  }
  else if (!strcmp(name, "connections_max")) {
    config->param.connections_max = (uint32) *(int *)val;
  }
  else if (!strcmp(name, "connections_max_per_host")) {
    config->param.connections_max_per_host = (uint32) *(int *)val;
  }
  else if (!strcmp(name, "keepalive_secs")) {
    config->param.keepalive_secs = (uint32) *(int *)val;
  }
  else if (!strcmp(name, "reconnect_count")) {
    config->param.reconnect_count = (uint32) *(int *)val;
  }
  else if (!strcmp(name, "reconnect_interval")) {
    config->param.reconnect_interval = (uint32) *(int *)val;
  }
  else if (!strcmp(name, "reconnect_interval_max")) {
    config->param.reconnect_interval_max = (uint32) *(int *)val;
  }
  else if (!strcmp(name, "reconnect_keep_trying")) {
    config->param.reconnect_keep_trying = *(bool *)val;
  }
  else if (!strcmp(name, "key_exchange_rekey")) {
    config->param.key_exchange_rekey = (uint32) *(int *)val;
  }
  else if (!strcmp(name, "key_exchange_pfs")) {
    config->param.key_exchange_pfs = *(bool *)val;
  }
  else if (!strcmp(name, "channel_rekey_secs")) {
    config->channel_rekey_secs = (uint32) *(int *)val;
  }
  else if (!strcmp(name, "key_exchange_timeout")) {
    config->key_exchange_timeout = (uint32) *(int *)val;
  }
  else if (!strcmp(name, "conn_auth_timeout")) {
    config->conn_auth_timeout = (uint32) *(int *)val;
  }
  else
    return SILC_CONFIG_EINTERNAL;

  return SILC_CONFIG_OK;

 got_err:
  return got_errno;
}

SILC_CONFIG_CALLBACK(fetch_cipher)
{
  SILC_SERVER_CONFIG_SECTION_INIT(SilcServerConfigCipher);

  SERVER_CONFIG_DEBUG(("Received CIPHER type=%d name=\"%s\" (val=%x)",
		       type, name, context));
  if (type == SILC_CONFIG_ARG_BLOCK) {
    /* check the temporary struct's fields */
    if (!tmp) /* empty sub-block? */
      return SILC_CONFIG_OK;
    if (!tmp->name) {
      got_errno = SILC_CONFIG_EMISSFIELDS;
      goto got_err;
    }
    /* the temporary struct is ok, append it to the list */
    SILC_SERVER_CONFIG_LIST_APPENDTMP(config->cipher);
    config->tmp = NULL;
    return SILC_CONFIG_OK;
  }
  /* if there isn't a temporary struct alloc one */
  if (!tmp) {
    config->tmp = silc_calloc(1, sizeof(*findtmp));
    tmp = (SilcServerConfigCipher *) config->tmp;
  }

  /* Identify and save this value */
  if (!strcmp(name, "name")) {
    CONFIG_IS_DOUBLE(tmp->name);
    tmp->name = strdup((char *) val);
  }
  else if (!strcmp(name, "module")) {
    CONFIG_IS_DOUBLE(tmp->module);
    tmp->module = (*(char *)val ? strdup((char *) val) : NULL);
  }
  else if (!strcmp(name, "keylength")) {
    tmp->key_length = *(uint32 *)val;
  }
  else if (!strcmp(name, "blocklength")) {
    tmp->block_length = *(uint32 *)val;
  }
  else
    return SILC_CONFIG_EINTERNAL;
  return SILC_CONFIG_OK;

 got_err:
  silc_free(tmp->name);
  silc_free(tmp->module);
  silc_free(tmp);
  config->tmp = NULL;
  return got_errno;
}

SILC_CONFIG_CALLBACK(fetch_hash)
{
  SILC_SERVER_CONFIG_SECTION_INIT(SilcServerConfigHash);

  SERVER_CONFIG_DEBUG(("Received HASH type=%d name=%s (val=%x)",
		       type, name, context));
  if (type == SILC_CONFIG_ARG_BLOCK) {
    /* check the temporary struct's fields */
    if (!tmp) /* empty sub-block? */
      return SILC_CONFIG_OK;
    if (!tmp->name || (tmp->block_length == 0) || (tmp->digest_length == 0)) {
      got_errno = SILC_CONFIG_EMISSFIELDS;
      goto got_err;
    }
    /* the temporary struct in tmp is ok */
    SILC_SERVER_CONFIG_LIST_APPENDTMP(config->hash);
    config->tmp = NULL;
    return SILC_CONFIG_OK;
  }

  /* if there isn't a temporary struct alloc one */
  if (!tmp) {
    config->tmp = silc_calloc(1, sizeof(*findtmp));
    tmp = (SilcServerConfigHash *) config->tmp;
  }

  /* Identify and save this value */
  if (!strcmp(name, "name")) {
    CONFIG_IS_DOUBLE(tmp->name);
    tmp->name = strdup((char *) val);
  }
  else if (!strcmp(name, "module")) {
    CONFIG_IS_DOUBLE(tmp->module);
    tmp->module = (*(char *)val ? strdup((char *) val) : NULL);
  }
  else if (!strcmp(name, "blocklength")) {
    tmp->block_length = *(int *)val;
  }
  else if (!strcmp(name, "digestlength")) {
    tmp->digest_length = *(int *)val;
  }
  else
    return SILC_CONFIG_EINTERNAL;
  return SILC_CONFIG_OK;

 got_err:
  silc_free(tmp->name);
  silc_free(tmp->module);
  silc_free(tmp);
  config->tmp = NULL;
  return got_errno;
}

SILC_CONFIG_CALLBACK(fetch_hmac)
{
  SILC_SERVER_CONFIG_SECTION_INIT(SilcServerConfigHmac);

  SERVER_CONFIG_DEBUG(("Received HMAC type=%d name=\"%s\" (val=%x)",
		       type, name, context));
  if (type == SILC_CONFIG_ARG_BLOCK) {
    /* check the temporary struct's fields */
    if (!tmp) /* empty sub-block? */
      return SILC_CONFIG_OK;
    if (!tmp->name || !tmp->hash || (tmp->mac_length == 0)) {
      got_errno = SILC_CONFIG_EMISSFIELDS;
      goto got_err;
    }
    /* the temporary struct is ok, append it to the list */
    SILC_SERVER_CONFIG_LIST_APPENDTMP(config->hmac);
    config->tmp = NULL;
    return SILC_CONFIG_OK;
  }
  /* if there isn't a temporary struct alloc one */
  if (!tmp) {
    config->tmp = silc_calloc(1, sizeof(*findtmp));
    tmp = (SilcServerConfigHmac *) config->tmp;
  }

  /* Identify and save this value */
  if (!strcmp(name, "name")) {
    CONFIG_IS_DOUBLE(tmp->name);
    tmp->name = strdup((char *) val);
  }
  else if (!strcmp(name, "hash")) {
    CONFIG_IS_DOUBLE(tmp->hash);
    tmp->hash = strdup((char *) val);
  }
  else if (!strcmp(name, "maclength")) {
    tmp->mac_length = *(int *)val;
  }
  else
    return SILC_CONFIG_EINTERNAL;
  return SILC_CONFIG_OK;

 got_err:
  silc_free(tmp->name);
  silc_free(tmp->hash);
  silc_free(tmp);
  config->tmp = NULL;
  return got_errno;
}

SILC_CONFIG_CALLBACK(fetch_pkcs)
{
  SILC_SERVER_CONFIG_SECTION_INIT(SilcServerConfigPkcs);

  SERVER_CONFIG_DEBUG(("Received PKCS type=%d name=\"%s\" (val=%x)", 
		       type, name, context));
  if (type == SILC_CONFIG_ARG_BLOCK) {
    /* check the temporary struct's fields */
    if (!tmp) /* empty sub-block? */
      return SILC_CONFIG_OK;
    if (!tmp->name) {
      got_errno = SILC_CONFIG_EMISSFIELDS;
      goto got_err;
    }
    /* the temporary struct is ok, append it to the list */
    SILC_SERVER_CONFIG_LIST_APPENDTMP(config->pkcs);
    config->tmp = NULL;
    return SILC_CONFIG_OK;
  }
  /* if there isn't a temporary struct alloc one */
  if (!tmp) {
    config->tmp = silc_calloc(1, sizeof(*findtmp));
    tmp = (SilcServerConfigPkcs *) config->tmp;
  }

  /* Identify and save this value */
  if (!strcmp(name, "name")) {
    CONFIG_IS_DOUBLE(tmp->name);
    tmp->name = strdup((char *) val);
  }
  else
    return SILC_CONFIG_EINTERNAL;
  return SILC_CONFIG_OK;

 got_err:
  silc_free(tmp->name);
  silc_free(tmp);
  config->tmp = NULL;
  return got_errno;
}

SILC_CONFIG_CALLBACK(fetch_serverinfo)
{
  SilcServerConfig config = (SilcServerConfig) context;
  SilcServerConfigServerInfo *server_info = config->server_info;
  int got_errno = 0;

  /* if there isn't the struct alloc it */
  if (!server_info)
    config->server_info = server_info = (SilcServerConfigServerInfo *)
		silc_calloc(1, sizeof(*server_info));

  if (type == SILC_CONFIG_ARG_BLOCK) {
    /* check for mandatory inputs */
    return SILC_CONFIG_OK;
  }
  if (!strcmp(name, "hostname")) {
    CONFIG_IS_DOUBLE(server_info->server_name);
    server_info->server_name = strdup((char *) val);
  }
  else if (!strcmp(name, "ip")) {
    CONFIG_IS_DOUBLE(server_info->server_ip);
    server_info->server_ip = strdup((char *) val);
  }
  else if (!strcmp(name, "port")) {
    int port = *(int *)val;
    if ((port <= 0) || (port > 65535)) {
      fprintf(stderr, "Invalid port number!\n");
      return SILC_CONFIG_ESILENT;
    }
    server_info->port = (uint16) port;
  }
  else if (!strcmp(name, "servertype")) {
    CONFIG_IS_DOUBLE(server_info->server_type);
    server_info->server_type = strdup((char *) val);
  }
  else if (!strcmp(name, "admin")) {
    CONFIG_IS_DOUBLE(server_info->admin);
    server_info->admin = strdup((char *) val);
  }
  else if (!strcmp(name, "adminemail")) {
    CONFIG_IS_DOUBLE(server_info->email);
    server_info->email = strdup((char *) val);
  }
  else if (!strcmp(name, "location")) {
    CONFIG_IS_DOUBLE(server_info->location);
    server_info->location = strdup((char *) val);
  }
  else if (!strcmp(name, "user")) {
    CONFIG_IS_DOUBLE(server_info->user);
    server_info->user = strdup((char *) val);
  }
  else if (!strcmp(name, "group")) {
    CONFIG_IS_DOUBLE(server_info->group);
    server_info->group = strdup((char *) val);
  }
  else if (!strcmp(name, "motdfile")) {
    CONFIG_IS_DOUBLE(server_info->motd_file);
    server_info->motd_file = strdup((char *) val);
  }
  else if (!strcmp(name, "pidfile")) {
    CONFIG_IS_DOUBLE(server_info->pid_file);
    server_info->pid_file = strdup((char *) val);
  }
  else if (!strcmp(name, "publickey")) {
    char *tmp = (char *) val;

    /* try to load specified file, if fail stop config parsing */
    if (!silc_pkcs_load_public_key(tmp, &server_info->public_key,
				   SILC_PKCS_FILE_PEM))
      if (!silc_pkcs_load_public_key(tmp, &server_info->public_key,
				     SILC_PKCS_FILE_BIN)) {
	fprintf(stderr, "\nError: Could not load public key file.");
	fprintf(stderr, "\n  line %lu: file \"%s\"\n", line, tmp);
	return SILC_CONFIG_ESILENT;
      }
  }
  else if (!strcmp(name, "privatekey")) {
    char *tmp = (char *) val;

    /* try to load specified file, if fail stop config parsing */
    if (!silc_pkcs_load_private_key(tmp, &server_info->private_key,
				    SILC_PKCS_FILE_BIN))
      if (!silc_pkcs_load_private_key(tmp, &server_info->private_key,
				      SILC_PKCS_FILE_PEM)) {
	fprintf(stderr, "\nError: Could not load private key file.");
	fprintf(stderr, "\n  line %lu: file \"%s\"\n", line, tmp);
	return SILC_CONFIG_ESILENT;
      }
  }
  else
    return SILC_CONFIG_EINTERNAL;
  return SILC_CONFIG_OK;

 got_err:
  return got_errno;
}

SILC_CONFIG_CALLBACK(fetch_logging)
{
  SilcServerConfig config = (SilcServerConfig) context;
  SilcServerConfigLogging *tmp =
	(SilcServerConfigLogging *) config->tmp;
  int got_errno;

  if (!strcmp(name, "quicklogs")) {
    silc_log_quick = *(bool *)val;
  }
  else if (!strcmp(name, "flushdelay")) {
    int flushdelay = *(int *)val;
    if (flushdelay < 2) { /* this value was taken from silclog.h (min delay) */
      fprintf(stderr, "Error: line %lu: invalid flushdelay value, use "
		"quicklogs if you want real-time logging.\n", line);
      return SILC_CONFIG_ESILENT;
    }
    silc_log_flushdelay = (long) flushdelay;
  }
#define FETCH_LOGGING_CHAN(__chan__, __member__)		\
  else if (!strcmp(name, __chan__)) {				\
    if (!tmp) return SILC_CONFIG_OK;				\
    if (!tmp->file) {						\
      got_errno = SILC_CONFIG_EMISSFIELDS; goto got_err;	\
    }								\
    config->__member__ = tmp;					\
    config->tmp = NULL;						\
  }
  FETCH_LOGGING_CHAN("info", logging_info)
  FETCH_LOGGING_CHAN("warnings", logging_warnings)
  FETCH_LOGGING_CHAN("errors", logging_errors)
  FETCH_LOGGING_CHAN("fatals", logging_fatals)
#undef FETCH_LOGGING_CHAN
  else if (!strcmp(name, "file")) {
    if (!tmp) { /* FIXME: what the fuck is this? */
      config->tmp = silc_calloc(1, sizeof(*tmp));
      tmp = (SilcServerConfigLogging *) config->tmp;
    }
    if (tmp->file) {
      got_errno = SILC_CONFIG_EMISSFIELDS; goto got_err;
    }
    tmp->file = strdup((char *) val);
  }
  else if (!strcmp(name, "size")) {
    if (!tmp) {
      config->tmp = silc_calloc(1, sizeof(*tmp));
      tmp = (SilcServerConfigLogging *) config->tmp;
    }
    tmp->maxsize = *(uint32 *) val;
  }
  else
    return SILC_CONFIG_EINTERNAL;
  return SILC_CONFIG_OK;

 got_err:
  silc_free(tmp->file);
  silc_free(tmp);
  config->tmp = NULL;
  return got_errno;
}

SILC_CONFIG_CALLBACK(fetch_connparam)
{
  SILC_SERVER_CONFIG_SECTION_INIT(SilcServerConfigConnParams);

  SERVER_CONFIG_DEBUG(("Received CONNPARAM type=%d name=\"%s\" (val=%x)", 
		       type, name, context));

  if (type == SILC_CONFIG_ARG_BLOCK) {
    if (!tmp)
      return SILC_CONFIG_OK;

    if (!tmp->name) {
      got_errno = SILC_CONFIG_EMISSFIELDS;
      goto got_err;
    }

    /* Set defaults */
    my_set_param_defaults(tmp, &config->param);

    SILC_SERVER_CONFIG_LIST_APPENDTMP(config->conn_params);
    config->tmp = NULL;
    return SILC_CONFIG_OK;
  }

  /* if there isn't a temporary struct alloc one */
  if (!tmp) {
    config->tmp = silc_calloc(1, sizeof(*findtmp));
    tmp = (SilcServerConfigConnParams *) config->tmp;
  }

  if (!strcmp(name, "name")) {
    CONFIG_IS_DOUBLE(tmp->name);
    tmp->name = (*(char *)val ? strdup((char *) val) : NULL);
  }
  else if (!strcmp(name, "connections_max")) {
    tmp->connections_max = *(uint32 *)val;
  }
  else if (!strcmp(name, "connections_max_per_host")) {
    tmp->connections_max_per_host = *(uint32 *)val;
  }
  else if (!strcmp(name, "keepalive_secs")) {
    tmp->keepalive_secs = *(uint32 *)val;
  }
  else if (!strcmp(name, "reconnect_count")) {
    tmp->reconnect_count = *(uint32 *)val;
  }
  else if (!strcmp(name, "reconnect_interval")) {
    tmp->reconnect_interval = *(uint32 *)val;
  }
  else if (!strcmp(name, "reconnect_interval_max")) {
    tmp->reconnect_interval_max = *(uint32 *)val;
  }
  else if (!strcmp(name, "reconnect_keep_trying")) {
    tmp->reconnect_keep_trying = *(bool *)val;
  }
  else if (!strcmp(name, "key_exchange_rekey")) {
    tmp->key_exchange_rekey = *(uint32 *)val;
  }
  else if (!strcmp(name, "key_exchange_pfs")) {
    tmp->key_exchange_pfs = *(bool *)val;
  }
  else
    return SILC_CONFIG_EINTERNAL;

  return SILC_CONFIG_OK;

 got_err:
  silc_free(tmp->name);
  silc_free(tmp);
  config->tmp = NULL;
  return got_errno;
}

SILC_CONFIG_CALLBACK(fetch_client)
{
  SILC_SERVER_CONFIG_SECTION_INIT(SilcServerConfigClient);

  SERVER_CONFIG_DEBUG(("Received CLIENT type=%d name=\"%s\" (val=%x)",
		       type, name, context));

  /* alloc tmp before block checking (empty sub-blocks are welcome here) */
  if (!tmp) {
    config->tmp = silc_calloc(1, sizeof(*findtmp));
    tmp = (SilcServerConfigClient *) config->tmp;
  }

  if (type == SILC_CONFIG_ARG_BLOCK) {
    /* closing the block */
    SILC_SERVER_CONFIG_LIST_APPENDTMP(config->clients);
    config->tmp = NULL;
    return SILC_CONFIG_OK;
  }

  /* Identify and save this value */
  if (!strcmp(name, "host")) {
    CONFIG_IS_DOUBLE(tmp->host);
    tmp->host = (*(char *)val ? strdup((char *) val) : NULL);
  }
  else if (!strcmp(name, "passphrase")) {
    if (!my_parse_authdata(SILC_AUTH_PASSWORD, (char *) val, line,
			   (void **)&tmp->passphrase,
			   &tmp->passphrase_len)) {
      got_errno = SILC_CONFIG_ESILENT;
      goto got_err;
    }
  }
  else if (!strcmp(name, "publickey")) {
    if (!my_parse_authdata(SILC_AUTH_PUBLIC_KEY, (char *) val, line,
			   &tmp->publickey, NULL)) {
      got_errno = SILC_CONFIG_ESILENT;
      goto got_err;
    }
  }
  else if (!strcmp(name, "params")) {
    CONFIG_IS_DOUBLE(tmp->param);
    tmp->param = my_find_param(config, (char *) val, line);
    if (!tmp->param) { /* error already output */
      got_errno = SILC_CONFIG_ESILENT;
      goto got_err;
    }
  }
  else
    return SILC_CONFIG_EINTERNAL;
  return SILC_CONFIG_OK;

 got_err:
  silc_free(tmp->host);
  CONFIG_FREE_AUTH(tmp);
  silc_free(tmp);
  config->tmp = NULL;
  return got_errno;
}

SILC_CONFIG_CALLBACK(fetch_admin)
{
  SILC_SERVER_CONFIG_SECTION_INIT(SilcServerConfigAdmin);

  SERVER_CONFIG_DEBUG(("Received CLIENT type=%d name=\"%s\" (val=%x)",
		       type, name, context));

  if (type == SILC_CONFIG_ARG_BLOCK) {
    /* check the temporary struct's fields */
    if (!tmp) /* empty sub-block? */
      return SILC_CONFIG_OK;

    SILC_SERVER_CONFIG_LIST_APPENDTMP(config->admins);
    config->tmp = NULL;
    return SILC_CONFIG_OK;
  }

  /* if there isn't a temporary struct alloc one */
  if (!tmp) {
    config->tmp = silc_calloc(1, sizeof(*findtmp));
    tmp = (SilcServerConfigAdmin *) config->tmp;
  }

  /* Identify and save this value */
  if (!strcmp(name, "host")) {
    CONFIG_IS_DOUBLE(tmp->host);
    tmp->host = (*(char *)val ? strdup((char *) val) : NULL);
  }
  else if (!strcmp(name, "user")) {
    CONFIG_IS_DOUBLE(tmp->user);
    tmp->user = (*(char *)val ? strdup((char *) val) : NULL);
  }
  else if (!strcmp(name, "nick")) {
    CONFIG_IS_DOUBLE(tmp->nick);
    tmp->nick = (*(char *)val ? strdup((char *) val) : NULL);
  }
  else if (!strcmp(name, "passphrase")) {
    if (!my_parse_authdata(SILC_AUTH_PASSWORD, (char *) val, line,
			   (void **)&tmp->passphrase,
			   &tmp->passphrase_len)) {
      got_errno = SILC_CONFIG_ESILENT;
      goto got_err;
    }
  }
  else if (!strcmp(name, "publickey")) {
    if (!my_parse_authdata(SILC_AUTH_PUBLIC_KEY, (char *) val, line,
			   &tmp->publickey, NULL)) {
      got_errno = SILC_CONFIG_ESILENT;
      goto got_err;
    }
  }
  else
    return SILC_CONFIG_EINTERNAL;
  return SILC_CONFIG_OK;

 got_err:
  silc_free(tmp->host);
  silc_free(tmp->user);
  silc_free(tmp->nick);
  CONFIG_FREE_AUTH(tmp);
  silc_free(tmp);
  config->tmp = NULL;
  return got_errno;
}

SILC_CONFIG_CALLBACK(fetch_deny)
{
  SILC_SERVER_CONFIG_SECTION_INIT(SilcServerConfigDeny);

  SERVER_CONFIG_DEBUG(("Received DENY type=%d name=\"%s\" (val=%x)",
		       type, name, context));
  if (type == SILC_CONFIG_ARG_BLOCK) {
    /* check the temporary struct's fields */
    if (!tmp) /* empty sub-block? */
      return SILC_CONFIG_OK;
    if (!tmp->reason) {
      got_errno = SILC_CONFIG_EMISSFIELDS;
      goto got_err;
    }
    SILC_SERVER_CONFIG_LIST_APPENDTMP(config->denied);
    config->tmp = NULL;
    return SILC_CONFIG_OK;
  }
  /* if there isn't a temporary struct alloc one */
  if (!tmp) {
    config->tmp = silc_calloc(1, sizeof(*findtmp));
    tmp = (SilcServerConfigDeny *) config->tmp;
  }

  /* Identify and save this value */
  if (!strcmp(name, "host")) {
    CONFIG_IS_DOUBLE(tmp->host);
    tmp->host = (*(char *)val ? strdup((char *) val) : strdup("*"));
  }
  else if (!strcmp(name, "reason")) {
    CONFIG_IS_DOUBLE(tmp->reason);
    tmp->reason = strdup((char *) val);
  }
  else
    return SILC_CONFIG_EINTERNAL;
  return SILC_CONFIG_OK;

 got_err:
  silc_free(tmp->host);
  silc_free(tmp->reason);
  silc_free(tmp);
  config->tmp = NULL;
  return got_errno;
}

SILC_CONFIG_CALLBACK(fetch_server)
{
  SILC_SERVER_CONFIG_SECTION_INIT(SilcServerConfigServer);

  SERVER_CONFIG_DEBUG(("Received SERVER type=%d name=\"%s\" (val=%x)",
		       type, name, context));

  if (type == SILC_CONFIG_ARG_BLOCK) {
    /* check the temporary struct's fields */
    if (!tmp) /* empty sub-block? */
      return SILC_CONFIG_OK;

    /* the temporary struct is ok, append it to the list */
    SILC_SERVER_CONFIG_LIST_APPENDTMP(config->servers);
    config->tmp = NULL;
    return SILC_CONFIG_OK;
  }

  /* if there isn't a temporary struct alloc one */
  if (!tmp) {
    config->tmp = silc_calloc(1, sizeof(*findtmp));
    tmp = (SilcServerConfigServer *) config->tmp;
  }

  /* Identify and save this value */
  if (!strcmp(name, "host")) {
    CONFIG_IS_DOUBLE(tmp->host);
    tmp->host = (*(char *)val ? strdup((char *) val) : strdup("*"));
  }
  else if (!strcmp(name, "passphrase")) {
    if (!my_parse_authdata(SILC_AUTH_PASSWORD, (char *) val, line,
			   (void **)&tmp->passphrase,
			   &tmp->passphrase_len)) {
      got_errno = SILC_CONFIG_ESILENT;
      goto got_err;
    }
  }
  else if (!strcmp(name, "publickey")) {
    if (!my_parse_authdata(SILC_AUTH_PUBLIC_KEY, (char *) val, line,
			   &tmp->publickey, NULL)) {
      got_errno = SILC_CONFIG_ESILENT;
      goto got_err;
    }
  }
  else if (!strcmp(name, "versionid")) {
    CONFIG_IS_DOUBLE(tmp->version);
    tmp->version = strdup((char *) val);
  }
  else if (!strcmp(name, "params")) {
    CONFIG_IS_DOUBLE(tmp->param);
    tmp->param = my_find_param(config, (char *) val, line);
    if (!tmp->param) { /* error already output */
      got_errno = SILC_CONFIG_ESILENT;
      goto got_err;
    }
  }
  else if (!strcmp(name, "backup")) {
    tmp->backup_router = *(bool *)val;
  }
  else
    return SILC_CONFIG_EINTERNAL;

  return SILC_CONFIG_OK;

 got_err:
  silc_free(tmp->host);
  silc_free(tmp->version);
  CONFIG_FREE_AUTH(tmp);
  silc_free(tmp);
  config->tmp = NULL;
  return got_errno;
}

SILC_CONFIG_CALLBACK(fetch_router)
{
  SILC_SERVER_CONFIG_SECTION_INIT(SilcServerConfigRouter);

  SERVER_CONFIG_DEBUG(("Received ROUTER type=%d name=\"%s\" (val=%x)",
		       type, name, context));

  if (type == SILC_CONFIG_ARG_BLOCK) {
    if (!tmp) /* empty sub-block? */
      return SILC_CONFIG_OK;

    /* the temporary struct is ok, append it to the list */
    SILC_SERVER_CONFIG_LIST_APPENDTMP(config->routers);
    config->tmp = NULL;
    return SILC_CONFIG_OK;
  }

  /* if there isn't a temporary struct alloc one */
  if (!tmp) {
    config->tmp = silc_calloc(1, sizeof(*findtmp));
    tmp = (SilcServerConfigRouter *) config->tmp;
  }

  /* Identify and save this value */
  if (!strcmp(name, "host")) {
    CONFIG_IS_DOUBLE(tmp->host);
    tmp->host = strdup((char *) val);
  }
  else if (!strcmp(name, "port")) {
    int port = *(int *)val;
    if ((port <= 0) || (port > 65535)) {
      fprintf(stderr, "Invalid port number!\n");
      return SILC_CONFIG_ESILENT;
    }
    tmp->port = (uint16) port;
  }
  else if (!strcmp(name, "passphrase")) {
    if (!my_parse_authdata(SILC_AUTH_PASSWORD, (char *) val, line,
			   (void **)&tmp->passphrase,
			   &tmp->passphrase_len)) {
      got_errno = SILC_CONFIG_ESILENT;
      goto got_err;
    }
  }
  else if (!strcmp(name, "publickey")) {
    if (!my_parse_authdata(SILC_AUTH_PUBLIC_KEY, (char *) val, line,
			   &tmp->publickey, NULL)) {
      got_errno = SILC_CONFIG_ESILENT;
      goto got_err;
    }
  }
  else if (!strcmp(name, "versionid")) {
    CONFIG_IS_DOUBLE(tmp->version);
    tmp->version = strdup((char *) val);
  }
  else if (!strcmp(name, "params")) {
    CONFIG_IS_DOUBLE(tmp->param);
    tmp->param = my_find_param(config, (char *) val, line);
    if (!tmp->param) { /* error already output */
      got_errno = SILC_CONFIG_ESILENT;
      goto got_err;
    }
  }
  else if (!strcmp(name, "initiator")) {
    tmp->initiator = *(bool *)val;
  }
  else if (!strcmp(name, "backuphost")) {
    CONFIG_IS_DOUBLE(tmp->backup_replace_ip);
    tmp->backup_replace_ip = (*(char *)val ? strdup((char *) val) :
			      strdup("*"));
  }
  else if (!strcmp(name, "backupport")) {
    int port = *(int *)val;
    if ((port <= 0) || (port > 65535)) {
      fprintf(stderr, "Invalid port number!\n");
      return SILC_CONFIG_ESILENT;
    }
    tmp->backup_replace_port = (uint16) port;
  }
  else if (!strcmp(name, "backuplocal")) {
    tmp->backup_local = *(bool *)val;
  }
  else
    return SILC_CONFIG_EINTERNAL;

  return SILC_CONFIG_OK;

 got_err:
  silc_free(tmp->host);
  silc_free(tmp->version);
  silc_free(tmp->backup_replace_ip);
  CONFIG_FREE_AUTH(tmp);
  silc_free(tmp);
  config->tmp = NULL;
  return got_errno;
}

/* known config options tables */
static const SilcConfigTable table_general[] = {
  { "module_path",		SILC_CONFIG_ARG_STRE,	fetch_generic,	NULL },
  { "prefer_passphrase_auth",	SILC_CONFIG_ARG_TOGGLE,	fetch_generic,	NULL },
  { "require_reverse_lookup",	SILC_CONFIG_ARG_TOGGLE,	fetch_generic,	NULL },
  { "connections_max",		SILC_CONFIG_ARG_INT,	fetch_generic,	NULL },
  { "connections_max_per_host", SILC_CONFIG_ARG_INT,    fetch_generic,	NULL },
  { "keepalive_secs",		SILC_CONFIG_ARG_INT,	fetch_generic,	NULL },
  { "reconnect_count",		SILC_CONFIG_ARG_INT,	fetch_generic,	NULL },
  { "reconnect_interval",      	SILC_CONFIG_ARG_INT,	fetch_generic,	NULL },
  { "reconnect_interval_max",   SILC_CONFIG_ARG_INT,	fetch_generic,	NULL },
  { "reconnect_keep_trying",	SILC_CONFIG_ARG_TOGGLE,	fetch_generic,	NULL },
  { "key_exchange_rekey",	SILC_CONFIG_ARG_INT,	fetch_generic,	NULL },
  { "key_exchange_pfs",		SILC_CONFIG_ARG_TOGGLE,	fetch_generic,	NULL },
  { "channel_rekey_secs",	SILC_CONFIG_ARG_INT,	fetch_generic,	NULL },
  { "key_exchange_timeout",   	SILC_CONFIG_ARG_INT,	fetch_generic,	NULL },
  { "conn_auth_timeout",   	SILC_CONFIG_ARG_INT,	fetch_generic,	NULL },
  { 0, 0, 0, 0 }
};

static const SilcConfigTable table_cipher[] = {
  { "name",		SILC_CONFIG_ARG_STR,	fetch_cipher,	NULL },
  { "module",		SILC_CONFIG_ARG_STRE,	fetch_cipher,	NULL },
  { "keylength",	SILC_CONFIG_ARG_INT,	fetch_cipher,	NULL },
  { "blocklength",	SILC_CONFIG_ARG_INT,	fetch_cipher,	NULL },
  { 0, 0, 0, 0 }
};

static const SilcConfigTable table_hash[] = {
  { "name",		SILC_CONFIG_ARG_STR,	fetch_hash,	NULL },
  { "module",		SILC_CONFIG_ARG_STRE,	fetch_hash,	NULL },
  { "blocklength",	SILC_CONFIG_ARG_INT,	fetch_hash,	NULL },
  { "digestlength",	SILC_CONFIG_ARG_INT,	fetch_hash,	NULL },
  { 0, 0, 0, 0 }
};

static const SilcConfigTable table_hmac[] = {
  { "name",		SILC_CONFIG_ARG_STR,	fetch_hmac,	NULL },
  { "hash",		SILC_CONFIG_ARG_STR,	fetch_hmac,	NULL },
  { "maclength",	SILC_CONFIG_ARG_INT,	fetch_hmac,	NULL },
  { 0, 0, 0, 0 }
};

static const SilcConfigTable table_pkcs[] = {
  { "name",		SILC_CONFIG_ARG_STR,	fetch_pkcs,	NULL },
  { 0, 0, 0, 0 }
};

static const SilcConfigTable table_serverinfo[] = {
  { "hostname",		SILC_CONFIG_ARG_STR,	fetch_serverinfo, NULL},
  { "ip",		SILC_CONFIG_ARG_STR,	fetch_serverinfo, NULL},
  { "port",		SILC_CONFIG_ARG_INT,	fetch_serverinfo, NULL},
  { "servertype",	SILC_CONFIG_ARG_STR,	fetch_serverinfo, NULL},
  { "location",		SILC_CONFIG_ARG_STR,	fetch_serverinfo, NULL},
  { "admin",		SILC_CONFIG_ARG_STR,	fetch_serverinfo, NULL},
  { "adminemail",	SILC_CONFIG_ARG_STR,	fetch_serverinfo, NULL},
  { "user",		SILC_CONFIG_ARG_STR,	fetch_serverinfo, NULL},
  { "group",		SILC_CONFIG_ARG_STR,	fetch_serverinfo, NULL},
  { "publickey",	SILC_CONFIG_ARG_STR,	fetch_serverinfo, NULL},
  { "privatekey",	SILC_CONFIG_ARG_STR,	fetch_serverinfo, NULL},
  { "motdfile",		SILC_CONFIG_ARG_STRE,	fetch_serverinfo, NULL},
  { "pidfile",		SILC_CONFIG_ARG_STRE,	fetch_serverinfo, NULL},
  { 0, 0, 0, 0 }
};

static const SilcConfigTable table_logging_c[] = {
  { "file",		SILC_CONFIG_ARG_STR,	fetch_logging,	NULL },
  { "size",		SILC_CONFIG_ARG_SIZE,	fetch_logging,	NULL },
/*{ "quicklog",		SILC_CONFIG_ARG_NONE,	fetch_logging,	NULL }, */
  { 0, 0, 0, 0 }
};

static const SilcConfigTable table_logging[] = {
  { "quicklogs",	SILC_CONFIG_ARG_TOGGLE,	fetch_logging,	NULL },
  { "flushdelay",	SILC_CONFIG_ARG_INT,	fetch_logging,	NULL },
  { "info",		SILC_CONFIG_ARG_BLOCK,	fetch_logging,	table_logging_c },
  { "warnings",		SILC_CONFIG_ARG_BLOCK,	fetch_logging,	table_logging_c },
  { "errors",		SILC_CONFIG_ARG_BLOCK,	fetch_logging,	table_logging_c },
  { "fatals",		SILC_CONFIG_ARG_BLOCK,	fetch_logging,	table_logging_c },
  { 0, 0, 0, 0 }
};

static const SilcConfigTable table_connparam[] = {
  { "name",		       SILC_CONFIG_ARG_STR,    fetch_connparam, NULL },
  { "require_reverse_lookup",  SILC_CONFIG_ARG_TOGGLE, fetch_connparam,	NULL },
  { "connections_max",	       SILC_CONFIG_ARG_INT,    fetch_connparam, NULL },
  { "connections_max_per_host",SILC_CONFIG_ARG_INT,    fetch_connparam, NULL },
  { "keepalive_secs",	       SILC_CONFIG_ARG_INT,    fetch_connparam, NULL },
  { "reconnect_count",	       SILC_CONFIG_ARG_INT,    fetch_connparam, NULL },
  { "reconnect_interval",      SILC_CONFIG_ARG_INT,    fetch_connparam,	NULL },
  { "reconnect_interval_max",  SILC_CONFIG_ARG_INT,    fetch_connparam,	NULL },
  { "reconnect_keep_trying",   SILC_CONFIG_ARG_TOGGLE, fetch_connparam,	NULL },
  { "key_exchange_rekey",      SILC_CONFIG_ARG_INT,    fetch_connparam,	NULL },
  { "key_exchange_pfs",	       SILC_CONFIG_ARG_TOGGLE, fetch_connparam,	NULL },
  { 0, 0, 0, 0 }
};

static const SilcConfigTable table_client[] = {
  { "host",		SILC_CONFIG_ARG_STRE,	fetch_client,	NULL },
  { "passphrase",	SILC_CONFIG_ARG_STR,	fetch_client,	NULL },
  { "publickey",	SILC_CONFIG_ARG_STR,	fetch_client,	NULL },
  { "params",		SILC_CONFIG_ARG_STR,	fetch_client,	NULL },
  { 0, 0, 0, 0 }
};

static const SilcConfigTable table_admin[] = {
  { "host",		SILC_CONFIG_ARG_STRE,	fetch_admin,	NULL },
  { "user",		SILC_CONFIG_ARG_STRE,	fetch_admin,	NULL },
  { "nick",		SILC_CONFIG_ARG_STRE,	fetch_admin,	NULL },
  { "passphrase",	SILC_CONFIG_ARG_STR,	fetch_admin,	NULL },
  { "publickey",	SILC_CONFIG_ARG_STR,	fetch_admin,	NULL },
  { "port",		SILC_CONFIG_ARG_INT,	fetch_admin,	NULL },
  { "params",		SILC_CONFIG_ARG_STR,	fetch_admin,	NULL },
  { 0, 0, 0, 0 }
};

static const SilcConfigTable table_deny[] = {
  { "host",		SILC_CONFIG_ARG_STRE,	fetch_deny,	NULL },
  { "reason",		SILC_CONFIG_ARG_STR,	fetch_deny,	NULL },
  { 0, 0, 0, 0 }
};

static const SilcConfigTable table_serverconn[] = {
  { "host",		SILC_CONFIG_ARG_STRE,	fetch_server,	NULL },
  { "passphrase",	SILC_CONFIG_ARG_STR,	fetch_server,	NULL },
  { "publickey",	SILC_CONFIG_ARG_STR,	fetch_server,	NULL },
  { "versionid",	SILC_CONFIG_ARG_STR,	fetch_server,	NULL },
  { "params",		SILC_CONFIG_ARG_STR,	fetch_server,	NULL },
  { "backup",		SILC_CONFIG_ARG_TOGGLE,	fetch_server,	NULL },
  { 0, 0, 0, 0 }
};

static const SilcConfigTable table_routerconn[] = {
  { "host",		SILC_CONFIG_ARG_STRE,	fetch_router,	NULL },
  { "port",		SILC_CONFIG_ARG_INT,	fetch_router,	NULL },
  { "passphrase",	SILC_CONFIG_ARG_STR,	fetch_router,	NULL },
  { "publickey",	SILC_CONFIG_ARG_STR,	fetch_router,	NULL },
  { "versionid",	SILC_CONFIG_ARG_STR,	fetch_router,	NULL },
  { "params",		SILC_CONFIG_ARG_STR,	fetch_router,	NULL },
  { "initiator",	SILC_CONFIG_ARG_TOGGLE,	fetch_router,	NULL },
  { "backuphost",	SILC_CONFIG_ARG_STRE,	fetch_router,	NULL },
  { "backupport",	SILC_CONFIG_ARG_INT,	fetch_router,	NULL },
  { "backuplocal",	SILC_CONFIG_ARG_TOGGLE,	fetch_router,	NULL },
  { 0, 0, 0, 0 }
};

static const SilcConfigTable table_main[] = {
  { "general",		SILC_CONFIG_ARG_BLOCK,	NULL,	       table_general },
  { "cipher",		SILC_CONFIG_ARG_BLOCK,	fetch_cipher,  table_cipher },
  { "hash",		SILC_CONFIG_ARG_BLOCK,	fetch_hash,    table_hash },
  { "hmac",		SILC_CONFIG_ARG_BLOCK,	fetch_hmac,    table_hmac },
  { "pkcs",		SILC_CONFIG_ARG_BLOCK,	fetch_pkcs,    table_pkcs },
  { "serverinfo",	SILC_CONFIG_ARG_BLOCK,	fetch_serverinfo, table_serverinfo },
  { "logging",		SILC_CONFIG_ARG_BLOCK,	NULL,	       table_logging },
  { "connectionparams",	SILC_CONFIG_ARG_BLOCK,	fetch_connparam, table_connparam },
  { "client",		SILC_CONFIG_ARG_BLOCK,	fetch_client,  table_client },
  { "admin",		SILC_CONFIG_ARG_BLOCK,	fetch_admin,   table_admin },
  { "deny",		SILC_CONFIG_ARG_BLOCK,	fetch_deny,    table_deny },
  { "serverconnection",	SILC_CONFIG_ARG_BLOCK,	fetch_server,  table_serverconn },
  { "routerconnection",	SILC_CONFIG_ARG_BLOCK,	fetch_router,  table_routerconn },
  { 0, 0, 0, 0 }
};

/* Allocates a new configuration object, opens configuration file and
 * parses it. The parsed data is returned to the newly allocated
 * configuration object. */

SilcServerConfig silc_server_config_alloc(char *filename)
{
  SilcServerConfig config;
  SilcConfigEntity ent;
  SilcConfigFile *file;
  int ret;
  SILC_LOG_DEBUG(("Loading config data from `%s'", filename));

  /* alloc a config object */
  config = (SilcServerConfig) silc_calloc(1, sizeof(*config));
  /* obtain a config file object */
  file = silc_config_open(filename);
  if (!file) {
    fprintf(stderr, "\nError: can't open config file `%s'\n", filename);
    return NULL;
  }
  /* obtain a SilcConfig entity, we can use it to start the parsing */
  ent = silc_config_init(file);
  /* load the known configuration options, give our empty object as context */
  silc_config_register_table(ent, table_main, (void *) config);
  /* enter the main parsing loop.  When this returns, we have the parsing
   * result and the object filled (or partially, in case of errors). */
  ret = silc_config_main(ent);
  SILC_LOG_DEBUG(("Parser returned [ret=%d]: %s", ret, 
		  silc_config_strerror(ret)));

  /* Check if the parser returned errors */
  if (ret) {
    /* handle this special error return which asks to quietly return */
    if (ret != SILC_CONFIG_ESILENT) {
      char *linebuf, *filename = silc_config_get_filename(file);
      uint32 line = silc_config_get_line(file);
      fprintf(stderr, "\nError while parsing config file: %s.\n",
		silc_config_strerror(ret));
      linebuf = silc_config_read_line(file, line);
      fprintf(stderr, "  file %s line %lu:  %s\n\n", filename, line, linebuf);
      silc_free(linebuf);
    }
    return NULL;
  }
  /* close (destroy) the file object */
  silc_config_close(file);

  /* XXX FIXME: check for missing mandatory fields */
  if (!config->server_info) {
    fprintf(stderr, "\nError: Missing mandatory block `server_info'\n");
    return NULL;
  }
  return config;
}

/* ... */

void silc_server_config_destroy(SilcServerConfig config)
{
  void *tmp;
  silc_free(config->module_path);

  /* Destroy Logging channels */
  if (config->logging_info)
    silc_free(config->logging_info->file);
  if (config->logging_warnings)
    silc_free(config->logging_warnings->file);
  if (config->logging_errors)
    silc_free(config->logging_errors->file);
  if (config->logging_fatals)
    silc_free(config->logging_fatals->file);

  /* Destroy the ServerInfo struct */
  if (config->server_info) {
    register SilcServerConfigServerInfo *si = config->server_info;
    silc_free(si->server_name);
    silc_free(si->server_ip);
    silc_free(si->server_type);
    silc_free(si->location);
    silc_free(si->admin);
    silc_free(si->email);
    silc_free(si->user);
    silc_free(si->group);
    silc_free(si->motd_file);
    silc_free(si->pid_file);
  }

  /* Now let's destroy the lists */

  SILC_SERVER_CONFIG_LIST_DESTROY(SilcServerConfigCipher,
				  config->cipher)
    silc_free(di->name);
    silc_free(di->module);
    silc_free(di);
  }
  SILC_SERVER_CONFIG_LIST_DESTROY(SilcServerConfigHash, config->hash)
    silc_free(di->name);
    silc_free(di->module);
    silc_free(di);
  }
  SILC_SERVER_CONFIG_LIST_DESTROY(SilcServerConfigHmac, config->hmac)
    silc_free(di->name);
    silc_free(di->hash);
    silc_free(di);
  }
  SILC_SERVER_CONFIG_LIST_DESTROY(SilcServerConfigPkcs, config->pkcs)
    silc_free(di->name);
    silc_free(di);
  }
  SILC_SERVER_CONFIG_LIST_DESTROY(SilcServerConfigClient,
				  config->clients)
    silc_free(di->host);
    CONFIG_FREE_AUTH(di);
    silc_free(di);
  }
  SILC_SERVER_CONFIG_LIST_DESTROY(SilcServerConfigAdmin, config->admins)
    silc_free(di->host);
    silc_free(di->user);
    silc_free(di->nick);
    CONFIG_FREE_AUTH(di);
    silc_free(di);
  }
  SILC_SERVER_CONFIG_LIST_DESTROY(SilcServerConfigDeny, config->denied)
    silc_free(di->host);
    silc_free(di->reason);
    silc_free(di);
  }
  SILC_SERVER_CONFIG_LIST_DESTROY(SilcServerConfigServer,
				  config->servers)
    silc_free(di->host);
    silc_free(di->version);
    CONFIG_FREE_AUTH(di);
    silc_free(di);
  }
  SILC_SERVER_CONFIG_LIST_DESTROY(SilcServerConfigRouter,
				  config->routers)
    silc_free(di->host);
    silc_free(di->version);
    silc_free(di->backup_replace_ip);
    CONFIG_FREE_AUTH(di);
    silc_free(di);
  }
}

/* Registers configured ciphers. These can then be allocated by the
   server when needed. */

bool silc_server_config_register_ciphers(SilcServer server)
{
  SilcServerConfig config = server->config;
  SilcServerConfigCipher *cipher = config->cipher;
  char *module_path = config->module_path;

  SILC_LOG_DEBUG(("Registering configured ciphers"));

  if (!cipher) /* any cipher in the config file? */
    return FALSE;

  while (cipher) {
    /* if there isn't a module_path OR there isn't a module sim name try to
     * use buil-in functions */
    if (!module_path || !cipher->module) {
      int i;
      for (i = 0; silc_default_ciphers[i].name; i++)
	if (!strcmp(silc_default_ciphers[i].name, cipher->name)) {
	  silc_cipher_register(&silc_default_ciphers[i]);
	  break;
	}
      if (!silc_cipher_is_supported(cipher->name)) {
	SILC_LOG_ERROR(("Unknown cipher `%s'", cipher->name));
	silc_server_stop(server);
	exit(1);
      }
    } else {
#ifdef SILC_SIM
      /* Load (try at least) the crypto SIM module */
      char buf[1023], *alg_name;
      SilcCipherObject cipher_obj;
      SilcSimContext *sim;

      memset(&cipher_obj, 0, sizeof(cipher_obj));
      cipher_obj.name = cipher->name;
      cipher_obj.block_len = cipher->block_length;
      cipher_obj.key_len = cipher->key_length * 8;

      /* build the libname */
      snprintf(buf, sizeof(buf), "%s/%s", config->module_path,
		cipher->module);
      sim = silc_sim_alloc();
      sim->type = SILC_SIM_CIPHER;
      sim->libname = buf;

      alg_name = strdup(cipher->name);
      if (strchr(alg_name, '-'))
	*strchr(alg_name, '-') = '\0';

      if (silc_sim_load(sim)) {
	cipher_obj.set_key =
	  silc_sim_getsym(sim, silc_sim_symname(alg_name,
						SILC_CIPHER_SIM_SET_KEY));
	SILC_LOG_DEBUG(("set_key=%p", cipher_obj.set_key));
	cipher_obj.set_key_with_string =
	  silc_sim_getsym(sim, 
	    silc_sim_symname(alg_name,
	      SILC_CIPHER_SIM_SET_KEY_WITH_STRING));
	SILC_LOG_DEBUG(("set_key_with_string=%p", 
	  cipher_obj.set_key_with_string));
	cipher_obj.encrypt =
	  silc_sim_getsym(sim, silc_sim_symname(alg_name,
						SILC_CIPHER_SIM_ENCRYPT_CBC));
	SILC_LOG_DEBUG(("encrypt_cbc=%p", cipher_obj.encrypt));
        cipher_obj.decrypt =
	  silc_sim_getsym(sim, silc_sim_symname(alg_name,
						SILC_CIPHER_SIM_DECRYPT_CBC));
	SILC_LOG_DEBUG(("decrypt_cbc=%p", cipher_obj.decrypt));
        cipher_obj.context_len =
	  silc_sim_getsym(sim, silc_sim_symname(alg_name,
						SILC_CIPHER_SIM_CONTEXT_LEN));
	SILC_LOG_DEBUG(("context_len=%p", cipher_obj.context_len));

	/* Put the SIM to the list of all SIM's in server */
	silc_dlist_add(server->sim, sim);

	silc_free(alg_name);
      } else {
	SILC_LOG_ERROR(("Error configuring ciphers"));
	silc_server_stop(server);
	exit(1);
      }

      /* Register the cipher */
      silc_cipher_register(&cipher_obj);
#else
      SILC_LOG_ERROR(("Dynamic module support not compiled, "
			"can't load modules!"));
      silc_server_stop(server);
      exit(1);
#endif
    }
    cipher = cipher->next;
  } /* while */

  return TRUE;
}

/* Registers configured hash functions. These can then be allocated by the
   server when needed. */

bool silc_server_config_register_hashfuncs(SilcServer server)
{
  SilcServerConfig config = server->config;
  SilcServerConfigHash *hash = config->hash;
  char *module_path = config->module_path;

  SILC_LOG_DEBUG(("Registering configured hash functions"));

  if (!hash) /* any hash func in the config file? */
    return FALSE;

  while (hash) {
    /* if there isn't a module_path OR there isn't a module sim name try to
     * use buil-in functions */
    if (!module_path || !hash->module) {
      int i;
      for (i = 0; silc_default_hash[i].name; i++)
	if (!strcmp(silc_default_hash[i].name, hash->name)) {
	  silc_hash_register(&silc_default_hash[i]);
	  break;
	}
      if (!silc_hash_is_supported(hash->name)) {
	SILC_LOG_ERROR(("Unknown hash funtion `%s'", hash->name));
	silc_server_stop(server);
	exit(1);
      }
    } else {
#ifdef SILC_SIM
      /* Load (try at least) the hash SIM module */
      SilcHashObject hash_obj;
      SilcSimContext *sim;

      memset(&hash_obj, 0, sizeof(hash_obj));
      hash_obj.name = hash->name;
      hash_obj.block_len = hash->block_length;
      hash_obj.hash_len = hash->digest_length;

      sim = silc_sim_alloc();
      sim->type = SILC_SIM_HASH;
      sim->libname = hash->module;

      if ((silc_sim_load(sim))) {
	hash_obj.init =
	  silc_sim_getsym(sim, silc_sim_symname(hash->name,
						SILC_HASH_SIM_INIT));
	SILC_LOG_DEBUG(("init=%p", hash_obj.init));
	hash_obj.update =
	  silc_sim_getsym(sim, silc_sim_symname(hash->name,
						SILC_HASH_SIM_UPDATE));
	SILC_LOG_DEBUG(("update=%p", hash_obj.update));
        hash_obj.final =
	  silc_sim_getsym(sim, silc_sim_symname(hash->name,
						SILC_HASH_SIM_FINAL));
	SILC_LOG_DEBUG(("final=%p", hash_obj.final));
        hash_obj.context_len =
	  silc_sim_getsym(sim, silc_sim_symname(hash->name,
						SILC_HASH_SIM_CONTEXT_LEN));
	SILC_LOG_DEBUG(("context_len=%p", hash_obj.context_len));

	/* Put the SIM to the table of all SIM's in server */
	silc_dlist_add(server->sim, sim);
      } else {
	SILC_LOG_ERROR(("Error configuring hash functions"));
	silc_server_stop(server);
	exit(1);
      }

      /* Register the hash function */
      silc_hash_register(&hash_obj);
#else
      SILC_LOG_ERROR(("Dynamic module support not compiled, "
			"can't load modules!"));
      silc_server_stop(server);
      exit(1);
#endif
    }
    hash = hash->next;
  } /* while */

  return TRUE;
}

/* Registers configure HMACs. These can then be allocated by the server
   when needed. */

bool silc_server_config_register_hmacs(SilcServer server)
{
  SilcServerConfig config = server->config;
  SilcServerConfigHmac *hmac = config->hmac;

  SILC_LOG_DEBUG(("Registering configured HMACs"));

  if (!hmac)
    return FALSE;

  while (hmac) {
    SilcHmacObject hmac_obj;
    if (!silc_hash_is_supported(hmac->hash)) {
      SILC_LOG_ERROR(("Unknown hash function `%s'", hmac->hash));
      silc_server_stop(server);
      exit(1);
    }
    /* Register the HMAC */
    memset(&hmac_obj, 0, sizeof(hmac_obj));
    hmac_obj.name = hmac->name;
    hmac_obj.len = hmac->mac_length;
    silc_hmac_register(&hmac_obj);

    hmac = hmac->next;
  } /* while */

  return TRUE;
}

/* Registers configured PKCS's. */

bool silc_server_config_register_pkcs(SilcServer server)
{
  SilcServerConfig config = server->config;
  SilcServerConfigPkcs *pkcs = config->pkcs;

  SILC_LOG_DEBUG(("Registering configured PKCS"));

  if (!pkcs)
    return FALSE;

  while (pkcs) {
    int i;
    for (i = 0; silc_default_pkcs[i].name; i++)
      if (!strcmp(silc_default_pkcs[i].name, pkcs->name)) {
	silc_pkcs_register(&silc_default_pkcs[i]);
	break;
      }
    if (!silc_pkcs_is_supported(pkcs->name)) {
      SILC_LOG_ERROR(("Unknown PKCS `%s'", pkcs->name));
      silc_server_stop(server);
      exit(1);
    }
    pkcs = pkcs->next;
  } /* while */

  return TRUE;
}

/* Sets log files where log messages are saved by the server logger. */

void silc_server_config_setlogfiles(SilcServer server)
{
  SilcServerConfig config = server->config;
  SilcServerConfigLogging *this;

  SILC_LOG_DEBUG(("Setting configured log file names"));

  if ((this = config->logging_info))
    silc_log_set_file(SILC_LOG_INFO, this->file, this->maxsize, 
		      server->schedule);
  if ((this = config->logging_warnings))
    silc_log_set_file(SILC_LOG_WARNING, this->file, this->maxsize, 
		      server->schedule);
  if ((this = config->logging_errors))
    silc_log_set_file(SILC_LOG_ERROR, this->file, this->maxsize,
		      server->schedule);
  if ((this = config->logging_fatals))
    silc_log_set_file(SILC_LOG_FATAL, this->file, this->maxsize, 
		      server->schedule);
}

/* Returns client authentication information from configuration file by host
   (name or ip) */

SilcServerConfigClient *
silc_server_config_find_client(SilcServer server, char *host)
{
  SilcServerConfig config = server->config;
  SilcServerConfigClient *client;

  if (!config || !host)
    return NULL;

  for (client = config->clients; client; client = client->next) {
    if (client->host && !silc_string_compare(client->host, host))
      continue;
    break;
  }

  /* if none matched, then client is already NULL */
  return client;
}

/* Returns admin connection configuration by host, username and/or
   nickname. */

SilcServerConfigAdmin *
silc_server_config_find_admin(SilcServer server, char *host, char *user, 
			      char *nick)
{
  SilcServerConfig config = server->config;
  SilcServerConfigAdmin *admin;

  /* make sure we have a value for the matching parameters */
  if (!host)
    host = "*";
  if (!user)
    user = "*";
  if (!nick)
    nick = "*";

  for (admin = config->admins; admin; admin = admin->next) {
    if (admin->host && !silc_string_compare(admin->host, host))
      continue;
    if (admin->user && !silc_string_compare(admin->user, user))
      continue;
    if (admin->nick && !silc_string_compare(admin->nick, nick))
      continue;
    /* no checks failed -> this entry matches */
    break;
  }

  /* if none matched, then admin is already NULL */
  return admin;
}

/* Returns the denied connection configuration entry by host. */

SilcServerConfigDeny *
silc_server_config_find_denied(SilcServer server, char *host)
{
  SilcServerConfig config = server->config;
  SilcServerConfigDeny *deny;

  /* make sure we have a value for the matching parameters */
  if (!config || !host)
    return NULL;

  for (deny = config->denied; deny; deny = deny->next) {
    if (deny->host && !silc_string_compare(deny->host, host))
      continue;
    break;
  }

  /* if none matched, then deny is already NULL */
  return deny;
}

/* Returns server connection info from server configuartion by host
   (name or ip). */

SilcServerConfigServer *
silc_server_config_find_server_conn(SilcServer server, char *host)
{
  SilcServerConfig config = server->config;
  SilcServerConfigServer *serv = NULL;

  if (!host)
    return NULL;

  if (!config->servers)
    return NULL;

  for (serv = config->servers; serv; serv = serv->next) {
    if (!silc_string_compare(serv->host, host))
      continue;
    break;
  }

  return serv;
}

/* Returns router connection info from server configuration by
   host (name or ip). */

SilcServerConfigRouter *
silc_server_config_find_router_conn(SilcServer server, char *host, int port)
{
  SilcServerConfig config = server->config;
  SilcServerConfigRouter *serv = NULL;

  if (!host)
    return NULL;

  if (!config->routers)
    return NULL;

  for (serv = config->routers; serv; serv = serv->next) {
    if (!silc_string_compare(serv->host, host))
      continue;
    if (port && serv->port && serv->port != port)
      continue;
    break;
  }

  return serv;
}

/* Returns TRUE if configuration for a router connection that we are
   initiating exists. */

bool silc_server_config_is_primary_route(SilcServer server)
{
  SilcServerConfig config = server->config;
  SilcServerConfigRouter *serv = NULL;
  int i;
  bool found = FALSE;

  serv = config->routers;
  for (i = 0; serv; i++) {
    if (serv->initiator == TRUE && serv->backup_router == FALSE) {
      found = TRUE;
      break;
    }

    serv = serv->next;
  }

  return found;
}

/* Returns our primary connection configuration or NULL if we do not
   have primary router configured. */

SilcServerConfigRouter *
silc_server_config_get_primary_router(SilcServer server)
{
  SilcServerConfig config = server->config;
  SilcServerConfigRouter *serv = NULL;
  int i;

  serv = config->routers;
  for (i = 0; serv; i++) {
    if (serv->initiator == TRUE && serv->backup_router == FALSE)
      return serv;
    serv = serv->next;
  }

  return NULL;
}

/* Set default values to stuff that was not configured. */

bool silc_server_config_set_defaults(SilcServer server)
{
  SilcServerConfig config = server->config;

  my_set_param_defaults(&config->param, NULL);

  config->channel_rekey_secs = (config->channel_rekey_secs ? 
				config->channel_rekey_secs :
				SILC_SERVER_CHANNEL_REKEY);
  config->key_exchange_timeout = (config->key_exchange_timeout ? 
				  config->key_exchange_timeout :
				  SILC_SERVER_SKE_TIMEOUT);
  config->conn_auth_timeout = (config->conn_auth_timeout ? 
			       config->conn_auth_timeout :
			       SILC_SERVER_CONNAUTH_TIMEOUT);

  return TRUE;
}
