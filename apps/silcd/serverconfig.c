/*

  serverconfig.c

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
/* $Id$ */

#include "serverincludes.h"
#include "server_internal.h"

/*  XXX
   All possible configuration sections for SILC server. 

   <Cipher>

       Format:

       +<Cipher name>:<SIM path>

   <PKCS>

       Format:

       +<PKCS name>:<key length>

   <HashFunction>

       Format:

       +<Hash function name>:<SIM path>

   <ServerInfo>

       This section is used to set the server informations.

       Format:

       +<Server DNS name>:<Server IP>:<Geographic location>:<Port>

   <AdminInfo>

       This section is used to set the server's administrative information.

       Format:

       +<Location>:<Server type>:<Admin's name>:<Admin's email address>

   <ListenPort>

       This section is used to set ports the server is listenning.

       Format:

       +<Local IP/UNIX socket path>:<Remote IP>:<Port>

   <Identity>

       This section is used to set both the user and group which silcd
       sets itself upon starting.

       Format:

       <user>:<group>

   <Logging>

       This section is used to set various logging files, their paths
       and maximum sizes. All the other directives except those defined
       below are ignored in this section. Log files are purged after they
       reach the maximum set byte size.

       Format:

       +infologfile:<path>:<max byte size>
       +errorlogfile:<path>:<max byte size>

   <ConnectionClass>

       This section is used to define connection classes. These can be
       used to optimize the server and the connections.

       Format:

       +<Class number>:<Ping freq>:<Connect freq>:<Max links>

   <ClientAuth>

       This section is used to define client authentications.

       Format:

       +<Remote address or name>:<auth method>:<password/cert/key/???>:<Port>:<Class>

   <AdminAuth>

       This section is used to define the server's administration 
       authentications.

       Format:

       +<Hostname>:<auth method>:<password/cert/key/???>:<Nickname hash>:<Class>

   <ServerConnection>

       This section is used to define the server connections to this
       server/router. Only routers can have normal server connections.
       Normal servers leave this section epmty. The remote server cannot be
       older than specified Version ID.

       Format:

       +<Remote address or name>:<auth method>:<password/key/???>:<Port>:<Version ID>:<Class>

   <RouterConnection>

       This section is used to define the router connections to this
       server/router. Both normal server and router can have router
       connections. Normal server usually has only one connection while
       a router can have multiple. The remote server cannot be older than
       specified Version ID.

       Format:

       +<Remote address or name>:<auth method>:<password/key/???>:
       <Port>:<Version ID>:<Class>:<Initiator>

   <DenyConnection>

       This section is used to deny specific connections to your server. This
       can be used to deny both clients and servers.

       Format:

       +<Remote address or name or nickname>:<Time interval>:<Comment>:<Port>

   <RedirectClient>

       This section is used to set the alternate servers that clients will be
       redirected to when our server is full.

       Format:

       +<Remote address or name>:<Port>

*/
SilcServerConfigSection silc_server_config_sections[] = {
  { "[Cipher]", 
    SILC_CONFIG_SERVER_SECTION_TYPE_CIPHER, 4 },
  { "[PKCS]", 
    SILC_CONFIG_SERVER_SECTION_TYPE_PKCS, 2 },
  { "[HashFunction]", 
    SILC_CONFIG_SERVER_SECTION_TYPE_HASH_FUNCTION, 4 },
  { "[ServerInfo]", 
    SILC_CONFIG_SERVER_SECTION_TYPE_SERVER_INFO, 4 },
  { "[AdminInfo]", 
    SILC_CONFIG_SERVER_SECTION_TYPE_ADMIN_INFO, 4 },
  { "[ListenPort]", 
    SILC_CONFIG_SERVER_SECTION_TYPE_LISTEN_PORT, 3 },
  { "[Identity]", 
    SILC_CONFIG_SERVER_SECTION_TYPE_IDENTITY, 2 },
  { "[Logging]", 
    SILC_CONFIG_SERVER_SECTION_TYPE_LOGGING, 3 },
  { "[ConnectionClass]", 
    SILC_CONFIG_SERVER_SECTION_TYPE_CONNECTION_CLASS, 4 },
  { "[ClientConnection]", 
    SILC_CONFIG_SERVER_SECTION_TYPE_CLIENT_CONNECTION, 5 },
  { "[ServerConnection]", 
    SILC_CONFIG_SERVER_SECTION_TYPE_SERVER_CONNECTION, 6 },
  { "[RouterConnection]", 
    SILC_CONFIG_SERVER_SECTION_TYPE_ROUTER_CONNECTION, 7 },
  { "[AdminConnection]", 
    SILC_CONFIG_SERVER_SECTION_TYPE_ADMIN_CONNECTION, 5 },
  { "[DenyConnection]", 
    SILC_CONFIG_SERVER_SECTION_TYPE_DENY_CONNECTION, 4 },
  { "[RedirectClient]", 
    SILC_CONFIG_SERVER_SECTION_TYPE_REDIRECT_CLIENT, 2 },
  { "[motd]", 
    SILC_CONFIG_SERVER_SECTION_TYPE_MOTD, 1 },
  
  { NULL, SILC_CONFIG_SERVER_SECTION_TYPE_NONE, 0 }
};

/* Allocates a new configuration object, opens configuration file and
   parses the file. The parsed data is returned to the newly allocated
   configuration object. */

SilcServerConfig silc_server_config_alloc(char *filename)
{
  SilcServerConfig new;
  SilcBuffer buffer;
  SilcServerConfigParse config_parse;

  SILC_LOG_DEBUG(("Allocating new configuration object"));

  new = silc_calloc(1, sizeof(*new));
  if (!new) {
    fprintf(stderr, "Could not allocate new configuration object");
    return NULL;
  }

  new->filename = filename;

  /* Open configuration file and parse it */
  config_parse = NULL;
  buffer = NULL;
  silc_config_open(filename, &buffer);
  if (!buffer)
    goto fail;
  if ((silc_server_config_parse(new, buffer, &config_parse)) == FALSE)
    goto fail;
  if ((silc_server_config_parse_lines(new, config_parse)) == FALSE)
    goto fail;

  silc_free(buffer);

  return new;

 fail:
  silc_free(new);
  return NULL;
}

/* Free's a configuration object. */

void silc_server_config_free(SilcServerConfig config)
{
  if (config) {
    silc_free(config->filename);
    silc_free(config->server_info);
    silc_free(config->admin_info);
    silc_free(config->listen_port);
    silc_free(config->identity);
    silc_free(config->conn_class);
    silc_free(config->clients);
    silc_free(config->admins);
    silc_free(config->servers);
    silc_free(config->routers);
    silc_free(config->denied);
    silc_free(config->redirect);
    silc_free(config->motd);
    silc_free(config);
  }
}

/* Parses the the buffer and returns the parsed lines into return_config
   argument. The return_config argument doesn't have to be initialized 
   before calling this. It will be initialized during the parsing. The
   buffer sent as argument can be safely free'd after this function has
   succesfully returned. */

int silc_server_config_parse(SilcServerConfig config, SilcBuffer buffer, 
			     SilcServerConfigParse *return_config)
{
  int i, begin;
  unsigned int linenum;
  char line[1024], *cp;
  SilcServerConfigSection *cptr = NULL;
  SilcServerConfigParse parse = *return_config, first = NULL;

  SILC_LOG_DEBUG(("Parsing configuration file"));

  begin = 0;
  linenum = 0;
  while((begin = silc_gets(line, sizeof(line), 
			   buffer->data, buffer->len, begin)) != EOF) {
    cp = line;
    linenum++;

    /* Check for bad line */
    if (silc_check_line(cp))
      continue;

    /* Remove tabs and whitespaces from the line */
    if (strchr(cp, '\t')) {
      i = 0;
      while(strchr(cp + i, '\t')) {
	*strchr(cp + i, '\t') = ' ';
	i++;
      }
    }
    for (i = 0; i < strlen(cp); i++) {
      if (cp[i] != ' ') {
	if (i)
	  cp++;
	break;
      }
      cp++;
    }

    /* Parse line */
    switch(cp[0]) {
    case '[':
      /*
       * Start of a section
       */

      /* Remove new line sign */
      if (strchr(cp, '\n'))
	*strchr(cp, '\n') = '\0';
      
      /* Check for matching sections */
      for (cptr = silc_server_config_sections; cptr->section; cptr++)
	if (!strncasecmp(cp, cptr->section, strlen(cptr->section)))
	  break;

      if (!cptr->section) {
	fprintf(stderr, "%s:%d: Unknown section `%s'\n", 
			config->filename, linenum, cp);
	return FALSE;
      }

      break;
    default:
      /*
       * Start of a configuration line
       */

      if (cptr->type != SILC_CONFIG_SERVER_SECTION_TYPE_NONE) {
	
	if (strchr(cp, '\n'))
	    *strchr(cp, '\n') = ':';

	if (parse == NULL) {
	  parse = silc_calloc(1, sizeof(*parse));
	  parse->line = NULL;
	  parse->section = NULL;
	  parse->next = NULL;
	  parse->prev = NULL;
	} else {
	  if (parse->next == NULL) {
	    parse->next = silc_calloc(1, sizeof(*parse->next));
	    parse->next->line = NULL;
	    parse->next->section = NULL;
	    parse->next->next = NULL;
	    parse->next->prev = parse;
	    parse = parse->next;
	  }
	}
	
	if (first == NULL)
	  first = parse;

	/* Add the line to parsing structure for further parsing. */
	if (parse) {
	  parse->section = cptr;
	  parse->line = silc_buffer_alloc(strlen(cp) + 1);
	  parse->linenum = linenum;
	  silc_buffer_pull_tail(parse->line, strlen(cp));
	  silc_buffer_put(parse->line, cp, strlen(cp));
	}
      }
      break;
    }
  }
  
  /* Set the return_config argument to its first value so that further
     parsing can be started from the first line. */
  *return_config = first;

  return TRUE;
}

/* Parses the lines earlier read from configuration file. The config object
   must not be initialized, it will be initialized in this function. The
   parse_config argument is uninitialized automatically during this
   function. */

int silc_server_config_parse_lines(SilcServerConfig config, 
				   SilcServerConfigParse parse_config)
{
  int ret, check = FALSE;
  unsigned int checkmask;
  char *tmp;
  SilcServerConfigParse pc = parse_config;
  SilcBuffer line;

  SILC_LOG_DEBUG(("Parsing configuration lines"));
  
  if (!config)
    return FALSE;
  
  checkmask = 0;
  while(pc) {
    check = FALSE;
    line = pc->line;

    /* Get number of tokens in line */
    ret = silc_config_check_num_token(line);
    if (ret != pc->section->maxfields) {
      /* Bad line */
      fprintf(stderr, "%s:%d: Missing tokens, %d tokens (should be %d)\n",
	      config->filename, pc->linenum, ret, 
	      pc->section->maxfields);
      break;
    }

    /* Parse the line */
    switch(pc->section->type) {
    case SILC_CONFIG_SERVER_SECTION_TYPE_CIPHER:

      SILC_SERVER_CONFIG_LIST_ALLOC(config->cipher);

      /* Get cipher name */
      ret = silc_config_get_token(line, &config->cipher->alg_name);
      if (ret < 0)
	break;
      if (ret == 0) {
	fprintf(stderr, "%s:%d: Cipher name not defined\n",
		config->filename, pc->linenum);
	break;
      }

      /* Get module name */
      config->cipher->sim_name = NULL;
      ret = silc_config_get_token(line, &config->cipher->sim_name);
      if (ret < 0)
	break;

      /* Get block length */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret == 0) {
	fprintf(stderr, "%s:%d: Cipher block length not defined\n",
		config->filename, pc->linenum);
	break;
      }
      config->cipher->block_len = atoi(tmp);
      silc_free(tmp);

      /* Get key length */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret == 0) {
	fprintf(stderr, "%s:%d: Cipher key length not defined\n",
		config->filename, pc->linenum);
	break;
      }
      config->cipher->key_len = atoi(tmp);
      silc_free(tmp);

      check = TRUE;
      checkmask |= (1L << pc->section->type);
      break;

    case SILC_CONFIG_SERVER_SECTION_TYPE_PKCS:

      SILC_SERVER_CONFIG_LIST_ALLOC(config->pkcs);

      /* Get PKCS name */
      ret = silc_config_get_token(line, &config->pkcs->alg_name);
      if (ret < 0)
	break;
      if (ret == 0) {
	fprintf(stderr, "%s:%d: PKCS name not defined\n",
		config->filename, pc->linenum);
	break;
      }

      /* Get key length */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret == 0) {
	fprintf(stderr, "%s:%d: PKCS key length not defined\n",
		config->filename, pc->linenum);
	break;
      }
      config->pkcs->key_len = atoi(tmp);
      silc_free(tmp);

      check = TRUE;
      checkmask |= (1L << pc->section->type);
      break;

    case SILC_CONFIG_SERVER_SECTION_TYPE_HASH_FUNCTION:

      SILC_SERVER_CONFIG_LIST_ALLOC(config->hash_func);

      /* Get Hash function name */
      ret = silc_config_get_token(line, &config->hash_func->alg_name);
      if (ret < 0)
	break;
      if (ret == 0) {
	fprintf(stderr, "%s:%d: Hash function name not defined\n",
		config->filename, pc->linenum);
	break;
      }
      
      /* Get Hash function module name */
      config->hash_func->sim_name = NULL;
      ret = silc_config_get_token(line, &config->hash_func->sim_name);
      if (ret < 0)
	break;

      /* Get block length */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret == 0) {
	fprintf(stderr, "%s:%d: Hash function block length not defined\n",
		config->filename, pc->linenum);
	break;
      }
      config->hash_func->block_len = atoi(tmp);
      silc_free(tmp);

      /* Get hash length */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret == 0) {
	fprintf(stderr, "%s:%d: Hash function hash length not defined\n",
		config->filename, pc->linenum);
	break;
      }
      config->hash_func->key_len = atoi(tmp);
      silc_free(tmp);

      check = TRUE;
      checkmask |= (1L << pc->section->type);
      break;

    case SILC_CONFIG_SERVER_SECTION_TYPE_SERVER_INFO:

      if (!config->server_info)
	config->server_info = silc_calloc(1, sizeof(*config->server_info));

      /* Get server name */
      ret = silc_config_get_token(line, &config->server_info->server_name);
      if (ret < 0)
	break;
      if (ret == 0) {
	/* Server name not defined */

      }
      
      /* Get server IP */
      ret = silc_config_get_token(line, &config->server_info->server_ip);
      if (ret < 0)
	break;
      if (ret == 0) {
	/* Server IP not defined */

      }

      /* Get server location */
      ret = silc_config_get_token(line, &config->server_info->location);
      if (ret < 0)
	break;

      /* Get server port */
      /* XXX: Need port here??? */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret == 0) {
	/* Port not defined */

      }
      config->server_info->port = atoi(tmp);
      silc_free(tmp);

      check = TRUE;
      checkmask |= (1L << pc->section->type);
      break;

    case SILC_CONFIG_SERVER_SECTION_TYPE_ADMIN_INFO:

      if (!config->admin_info)
	config->admin_info = silc_calloc(1, sizeof(*config->admin_info));

      /* Get location */
      ret = silc_config_get_token(line, &config->admin_info->location);
      if (ret < 0)
	break;

      /* Get server type */
      ret = silc_config_get_token(line, &config->admin_info->server_type);
      if (ret < 0)
	break;

      /* Get admins name */
      ret = silc_config_get_token(line, &config->admin_info->admin_name);
      if (ret < 0)
	break;

      /* Get admins email address */
      ret = silc_config_get_token(line, &config->admin_info->admin_email);
      if (ret < 0)
	break;

      check = TRUE;
      checkmask |= (1L << pc->section->type);
      break;

    case SILC_CONFIG_SERVER_SECTION_TYPE_LISTEN_PORT:

      SILC_SERVER_CONFIG_LIST_ALLOC(config->listen_port);

      /* Get host */
      ret = silc_config_get_token(line, &config->listen_port->host);
      if (ret < 0)
	break;

      /* Get remote IP */
      ret = silc_config_get_token(line, &config->listen_port->remote_ip);
      if (ret < 0)
	break;

      /* Get port */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret == 0) {
	/* Any port */
	config->listen_port->port = 0;
      } else {
	config->listen_port->port = atoi(tmp);
	silc_free(tmp);
      }

      check = TRUE;
      checkmask |= (1L << pc->section->type);
      break;

    case SILC_CONFIG_SERVER_SECTION_TYPE_IDENTITY:

      if (!config->identity)
        config->identity = silc_calloc(1, sizeof(*config->identity));

      /* Get user */
      ret = silc_config_get_token(line, &config->identity->user);
      if (ret < 0)
        break;
      /* Get group */
      ret = silc_config_get_token(line, &config->identity->group);
      if (ret < 0)
        break;

      check = TRUE;
      checkmask |= (1L << pc->section->type);

    case SILC_CONFIG_SERVER_SECTION_TYPE_CONNECTION_CLASS:

      SILC_SERVER_CONFIG_LIST_ALLOC(config->conn_class);

      /* Get class number */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret == 0) {
	/* Class number not defined */

      }
      config->conn_class->class = atoi(tmp);
      silc_free(tmp);

      /* Get ping frequency */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      config->conn_class->ping_freq = atoi(tmp);
      silc_free(tmp);

      /* Get connect frequency */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      config->conn_class->connect_freq = atoi(tmp);
      silc_free(tmp);

      /* Get max links */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      config->conn_class->max_links = atoi(tmp);
      silc_free(tmp);

      check = TRUE;
      checkmask |= (1L << pc->section->type);
      break;

    case SILC_CONFIG_SERVER_SECTION_TYPE_LOGGING:

      SILC_SERVER_CONFIG_LIST_ALLOC(config->logging);

      /* Get log section type and check it */
      ret = silc_config_get_token(line, &config->logging->logtype);
      if (ret < 0)
	break;
      if (ret == 0) {
	fprintf(stderr, "%s:%d: Log file section not defined\n", 
		config->filename, pc->linenum);
	break;
      }
      if (strcmp(config->logging->logtype, SILC_CONFIG_SERVER_LF_INFO)
	  && strcmp(config->logging->logtype, SILC_CONFIG_SERVER_LF_WARNING)
	  && strcmp(config->logging->logtype, SILC_CONFIG_SERVER_LF_ERROR)
	  && strcmp(config->logging->logtype, SILC_CONFIG_SERVER_LF_FATAL)) {
	fprintf(stderr, "%s:%d: Unknown log file section '%s'\n",
		config->filename, pc->linenum, config->logging->logtype);
	break;
      }

      /* Get log filename */
      ret = silc_config_get_token(line, &config->logging->filename);
      if (ret < 0)
	break;
      if (ret == 0) {
	fprintf(stderr, "%s:%d: Log file name not defined\n",
		config->filename, pc->linenum);
	break;
      }

      /* Get max byte size */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret) {
	config->logging->maxsize = atoi(tmp);
	silc_free(tmp);
      }

      check = TRUE;
      checkmask |= (1L << pc->section->type);
      break;

    case SILC_CONFIG_SERVER_SECTION_TYPE_CLIENT_CONNECTION:

      SILC_SERVER_CONFIG_LIST_ALLOC(config->clients);

      /* Get host */
      ret = silc_config_get_token(line, &config->clients->host);
      if (ret < 0)
	break;
      if (ret == 0)
	/* Any host */
	config->clients->host = strdup("*");

      /* Get authentication method */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret) {
	if (strcmp(tmp, SILC_CONFIG_SERVER_AUTH_METH_PASSWD) &&
	    strcmp(tmp, SILC_CONFIG_SERVER_AUTH_METH_PUBKEY)) {
	  fprintf(stderr, "%s:%d: Unknown authentication method '%s'\n",
		  config->filename, pc->linenum, tmp);
	  break;
	}

	if (!strcmp(tmp, SILC_CONFIG_SERVER_AUTH_METH_PASSWD))
	  config->clients->auth_meth = SILC_AUTH_PASSWORD;

	if (!strcmp(tmp, SILC_CONFIG_SERVER_AUTH_METH_PUBKEY))
	  config->clients->auth_meth = SILC_AUTH_PUBLIC_KEY;

	silc_free(tmp);
      }

      /* Get authentication data */
      ret = silc_config_get_token(line, &config->clients->auth_data);
      if (ret < 0)
	break;
      if (ret == 0)
	/* Any host */
	config->clients->host = strdup("*");

      /* Get port */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret == 0) {
	config->clients->port = atoi(tmp);
	silc_free(tmp);
      }

      /* Get class number */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret) {
	config->clients->class = atoi(tmp);
	silc_free(tmp);
      }

      check = TRUE;
      checkmask |= (1L << pc->section->type);
      break;

    case SILC_CONFIG_SERVER_SECTION_TYPE_SERVER_CONNECTION:

      SILC_SERVER_CONFIG_LIST_ALLOC(config->servers);

      /* Get host */
      ret = silc_config_get_token(line, &config->servers->host);
      if (ret < 0)
	break;
      if (ret == 0)
	/* Any host */
	config->servers->host = strdup("*");

      /* Get authentication method */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret) {
	if (strcmp(tmp, SILC_CONFIG_SERVER_AUTH_METH_PASSWD) &&
	    strcmp(tmp, SILC_CONFIG_SERVER_AUTH_METH_PUBKEY)) {
	  fprintf(stderr, "%s:%d: Unknown authentication method '%s'\n",
		  config->filename, pc->linenum, tmp);
	  break;
	}

	if (!strcmp(tmp, SILC_CONFIG_SERVER_AUTH_METH_PASSWD))
	  config->servers->auth_meth = SILC_AUTH_PASSWORD;

	if (!strcmp(tmp, SILC_CONFIG_SERVER_AUTH_METH_PUBKEY))
	  config->servers->auth_meth = SILC_AUTH_PUBLIC_KEY;

	silc_free(tmp);
      }

      /* Get authentication data */
      ret = silc_config_get_token(line, &config->servers->auth_data);
      if (ret < 0)
	break;

      /* Get port */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret) {
	config->servers->port = atoi(tmp);
	silc_free(tmp);
      }

      /* Get version */
      ret = silc_config_get_token(line, &config->servers->version);
      if (ret < 0)
	break;

      /* Get class number */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret) {
	config->servers->class = atoi(tmp);
	silc_free(tmp);
      }

      check = TRUE;
      checkmask |= (1L << pc->section->type);
      break;

    case SILC_CONFIG_SERVER_SECTION_TYPE_ROUTER_CONNECTION:

      SILC_SERVER_CONFIG_LIST_ALLOC(config->routers);

      /* Get host */
      ret = silc_config_get_token(line, &config->routers->host);
      if (ret < 0)
	break;
      //      if (ret == 0)
      ///* Any host */
      //	config->routers->host = strdup("*");

      /* Get authentication method */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret) {
	if (strcmp(tmp, SILC_CONFIG_SERVER_AUTH_METH_PASSWD) &&
	    strcmp(tmp, SILC_CONFIG_SERVER_AUTH_METH_PUBKEY)) {
	  fprintf(stderr, "%s:%d: Unknown authentication method '%s'\n",
		  config->filename, pc->linenum, tmp);
	  break;
	}

	if (!strcmp(tmp, SILC_CONFIG_SERVER_AUTH_METH_PASSWD))
	  config->routers->auth_meth = SILC_AUTH_PASSWORD;

	if (!strcmp(tmp, SILC_CONFIG_SERVER_AUTH_METH_PUBKEY))
	  config->routers->auth_meth = SILC_AUTH_PUBLIC_KEY;

	silc_free(tmp);
      }

      /* Get authentication data */
      ret = silc_config_get_token(line, &config->routers->auth_data);
      if (ret < 0)
	break;

      /* Get port */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret) {
	config->routers->port = atoi(tmp);
	silc_free(tmp);
      }

      /* Get version */
      ret = silc_config_get_token(line, &config->routers->version);
      if (ret < 0)
	break;

      /* Get class number */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret) {
	config->routers->class = atoi(tmp);
	silc_free(tmp);
      }

      /* Get whether we are initiator or not */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret) {
	config->routers->initiator = atoi(tmp);
	if (config->routers->initiator != 0)
	  config->routers->initiator = TRUE;
	silc_free(tmp);
      }

      check = TRUE;
      checkmask |= (1L << pc->section->type);
      break;

    case SILC_CONFIG_SERVER_SECTION_TYPE_ADMIN_CONNECTION:

      SILC_SERVER_CONFIG_LIST_ALLOC(config->admins);

      /* Get host */
      ret = silc_config_get_token(line, &config->admins->host);
      if (ret < 0)
	break;
      if (ret == 0)
	/* Any host */
	config->admins->host = strdup("*");

      /* Get authentication method */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret) {
	if (strcmp(tmp, SILC_CONFIG_SERVER_AUTH_METH_PASSWD) &&
	    strcmp(tmp, SILC_CONFIG_SERVER_AUTH_METH_PUBKEY)) {
	  fprintf(stderr, "%s:%d: Unknown authentication method '%s'\n",
		  config->filename, pc->linenum, tmp);
	  break;
	}

	if (!strcmp(tmp, SILC_CONFIG_SERVER_AUTH_METH_PASSWD))
	  config->admins->auth_meth = SILC_AUTH_PASSWORD;

	if (!strcmp(tmp, SILC_CONFIG_SERVER_AUTH_METH_PUBKEY))
	  config->admins->auth_meth = SILC_AUTH_PUBLIC_KEY;

	silc_free(tmp);
      }

      /* Get authentication data */
      ret = silc_config_get_token(line, &config->admins->auth_data);
      if (ret < 0)
	break;

      /* Get nickname */
      ret = silc_config_get_token(line, &config->admins->nickname);
      if (ret < 0)
	break;

      /* Get class number */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret) {
	config->admins->class = atoi(tmp);
	silc_free(tmp);
      }

      check = TRUE;
      checkmask |= (1L << pc->section->type);
      break;

    case SILC_CONFIG_SERVER_SECTION_TYPE_DENY_CONNECTION:
      /* Not implemented yet */
      check = TRUE;
      break;

    case SILC_CONFIG_SERVER_SECTION_TYPE_REDIRECT_CLIENT:
      /* Not implemented yet */
      check = TRUE;
      break;

    case SILC_CONFIG_SERVER_SECTION_TYPE_MOTD:

      if (!config->motd)
	config->motd = silc_calloc(1, sizeof(*config->motd));

      /* Get motd file */
      ret = silc_config_get_token(line, &config->motd->motd_file);
      if (ret < 0)
	break;

      check = TRUE;
      checkmask |= (1L << pc->section->type);
      break;

    case SILC_CONFIG_SERVER_SECTION_TYPE_NONE:
    default:
      /* Error */
      break;
    }

    /* Check for error */
    if (check == FALSE) {
      /* Line could not be parsed */
      fprintf(stderr, "%s:%d: Parse error\n", config->filename, pc->linenum);
      break;
    }

    pc = pc->next;
    /* XXXX */
    //    silc_free(pc->prev);
    //    pc->prev = NULL;
  }

  if (check == FALSE)
    return FALSE;;

  /* Check that all mandatory sections really were found. If not, the server
     cannot function and we return error. */
  ret = silc_server_config_check_sections(checkmask);
  if (ret == FALSE) {
    /* XXX */

  }
  
  /* Before returning all the lists in the config object must be set
     to their first values (the last value is first here). */
  while (config->cipher && config->cipher->prev)
    config->cipher = config->cipher->prev;
  while (config->pkcs && config->pkcs->prev)
    config->pkcs = config->pkcs->prev;
  while (config->hash_func && config->hash_func->prev)
    config->hash_func = config->hash_func->prev;
  while (config->listen_port && config->listen_port->prev)
    config->listen_port = config->listen_port->prev;
  while (config->logging && config->logging->prev)
    config->logging = config->logging->prev;
  while (config->conn_class && config->conn_class->prev)
    config->conn_class = config->conn_class->prev;
  while (config->clients && config->clients->prev)
    config->clients = config->clients->prev;
  while (config->servers && config->servers->prev)
    config->servers = config->servers->prev;
  while (config->routers && config->routers->prev)
    config->routers = config->routers->prev;
  
  SILC_LOG_DEBUG(("Done"));
  
  return TRUE;
}

/* This function checks that the mask sent as argument includes all the 
   sections that are mandatory in SILC server. */

int silc_server_config_check_sections(unsigned int checkmask)
{
  if (!(checkmask & (1L << SILC_CONFIG_SERVER_SECTION_TYPE_SERVER_INFO))) {
    
    return FALSE;
  }
  if (!(checkmask & (1L << SILC_CONFIG_SERVER_SECTION_TYPE_ADMIN_INFO))) {
    
    return FALSE;
  }
  if (!(checkmask & (1L << SILC_CONFIG_SERVER_SECTION_TYPE_LISTEN_PORT))) {
    
    return FALSE;
  }
  if (!(checkmask & (1L << SILC_CONFIG_SERVER_SECTION_TYPE_CLIENT_CONNECTION))) {
    
    return FALSE;
  }
  if (!(checkmask 
	& (1L << SILC_CONFIG_SERVER_SECTION_TYPE_SERVER_CONNECTION))) {
    
    return FALSE;
  }
  if (!(checkmask 
	& (1L << SILC_CONFIG_SERVER_SECTION_TYPE_ROUTER_CONNECTION))) {
    
    return FALSE;
  }

  return TRUE;
}

/* Sets log files where log messages is saved by the server. */

void silc_server_config_setlogfiles(SilcServerConfig config)
{
  SilcServerConfigSectionLogging *log;
  char *info, *warning, *error, *fatal;
  unsigned int info_size, warning_size, error_size, fatal_size;

  SILC_LOG_DEBUG(("Setting configured log file names"));

  /* Set default files before checking configuration */
  info = SILC_LOG_FILE_INFO;
  warning = SILC_LOG_FILE_WARNING;
  error = SILC_LOG_FILE_ERROR;
  fatal = SILC_LOG_FILE_FATAL;
  info_size = 0;
  warning_size = 0;
  error_size = 0;
  fatal_size = 0;

  log = config->logging;
  while(log) {
    if (!strcmp(log->logtype, SILC_CONFIG_SERVER_LF_INFO)) {
      info = log->filename;
      info_size = log->maxsize;
    }
    if (!strcmp(log->logtype, SILC_CONFIG_SERVER_LF_WARNING)) {
      warning = log->filename;
      warning_size = log->maxsize;
    }
    if (!strcmp(log->logtype, SILC_CONFIG_SERVER_LF_ERROR)) {
      error = log->filename;
      error_size = log->maxsize;
    }
    if (!strcmp(log->logtype, SILC_CONFIG_SERVER_LF_FATAL)) {
      fatal = log->filename;
      fatal_size = log->maxsize;
    }

    log = log->next;
  }

  silc_log_set_files(info, info_size, warning, warning_size,
		     error, error_size, fatal, fatal_size);
}

/* Registers configured ciphers. These can then be allocated by the
   server when needed. */

void silc_server_config_register_ciphers(SilcServerConfig config)
{
  SilcServerConfigSectionAlg *alg;
  SilcServer server = (SilcServer)config->server;

  SILC_LOG_DEBUG(("Registering configured ciphers"));

  alg = config->cipher;
  while(alg) {

    if (!alg->sim_name) {
      /* Crypto module is supposed to be built in. Nothing to be done
	 here except to test that the cipher really is built in. */
      SilcCipher tmp = NULL;

      if (silc_cipher_alloc(alg->alg_name, &tmp) == FALSE) {
	SILC_LOG_ERROR(("Unsupported cipher `%s'", alg->alg_name));
	silc_server_stop(server);
	exit(1);
      }
      silc_cipher_free(tmp);

#ifdef SILC_SIM
    } else {
      /* Load (try at least) the crypto SIM module */
      SilcCipherObject cipher;
      SilcSimContext *sim;

      memset(&cipher, 0, sizeof(cipher));
      cipher.name = alg->alg_name;
      cipher.block_len = alg->block_len;
      cipher.key_len = alg->key_len * 8;

      sim = silc_sim_alloc();
      sim->type = SILC_SIM_CIPHER;
      sim->libname = alg->sim_name;

      if ((silc_sim_load(sim))) {
	cipher.set_key = 
	  silc_sim_getsym(sim, silc_sim_symname(alg->alg_name, 
						SILC_CIPHER_SIM_SET_KEY));
	SILC_LOG_DEBUG(("set_key=%p", cipher.set_key));
	cipher.set_key_with_string = 
	  silc_sim_getsym(sim, silc_sim_symname(alg->alg_name, 
						SILC_CIPHER_SIM_SET_KEY_WITH_STRING));
	SILC_LOG_DEBUG(("set_key_with_string=%p", cipher.set_key_with_string));
	cipher.encrypt = 
	  silc_sim_getsym(sim, silc_sim_symname(alg->alg_name,
						SILC_CIPHER_SIM_ENCRYPT_CBC));
	SILC_LOG_DEBUG(("encrypt_cbc=%p", cipher.encrypt));
        cipher.decrypt = 
	  silc_sim_getsym(sim, silc_sim_symname(alg->alg_name,
						SILC_CIPHER_SIM_DECRYPT_CBC));
	SILC_LOG_DEBUG(("decrypt_cbc=%p", cipher.decrypt));
        cipher.context_len = 
	  silc_sim_getsym(sim, silc_sim_symname(alg->alg_name,
						SILC_CIPHER_SIM_CONTEXT_LEN));
	SILC_LOG_DEBUG(("context_len=%p", cipher.context_len));

	/* Put the SIM to the list of all SIM's in server */
	silc_dlist_add(server->sim, sim);
      } else {
	SILC_LOG_ERROR(("Error configuring ciphers"));
	silc_server_stop(server);
	exit(1);
      }

      /* Register the cipher */
      silc_cipher_register(&cipher);
#endif
    }

    alg = alg->next;
  }
}

/* Registers configured PKCS's. */
/* XXX: This really doesn't do anything now since we have statically
   registered our PKCS's. This should be implemented when PKCS works
   as SIM's. This checks now only that the PKCS user requested is 
   really out there. */

void silc_server_config_register_pkcs(SilcServerConfig config)
{
  SilcServerConfigSectionAlg *alg = config->pkcs;
  SilcServer server = (SilcServer)config->server;
  SilcPKCS tmp = NULL;

  SILC_LOG_DEBUG(("Registering configured PKCS"));

  while(alg) {

    if (silc_pkcs_alloc(alg->alg_name, &tmp) == FALSE) {
      SILC_LOG_ERROR(("Unsupported PKCS `%s'", alg->alg_name));
      silc_server_stop(server);
      exit(1);
    }
    silc_free(tmp);

    alg = alg->next;
  }
}

/* Registers configured hash functions. These can then be allocated by the
   server when needed. */

void silc_server_config_register_hashfuncs(SilcServerConfig config)
{
  SilcServerConfigSectionAlg *alg;
  SilcServer server = (SilcServer)config->server;

  SILC_LOG_DEBUG(("Registering configured hash functions"));

  alg = config->hash_func;
  while(alg) {

    if (!alg->sim_name) {
      /* Hash module is supposed to be built in. Nothing to be done
	 here except to test that the hash function really is built in. */
      SilcHash tmp = NULL;

      if (silc_hash_alloc(alg->alg_name, &tmp) == FALSE) {
	SILC_LOG_ERROR(("Unsupported hash function `%s'", alg->alg_name));
	silc_server_stop(server);
	exit(1);
      }
      silc_free(tmp);

#ifdef SILC_SIM
    } else {
      /* Load (try at least) the hash SIM module */
      SilcHashObject hash;
      SilcSimContext *sim;

      memset(&hash, 0, sizeof(hash));
      hash.name = alg->alg_name;
      hash.block_len = alg->block_len;
      hash.hash_len = alg->key_len;

      sim = silc_sim_alloc();
      sim->type = SILC_SIM_HASH;
      sim->libname = alg->sim_name;

      if ((silc_sim_load(sim))) {
	hash.init = 
	  silc_sim_getsym(sim, silc_sim_symname(alg->alg_name, 
						SILC_HASH_SIM_INIT));
	SILC_LOG_DEBUG(("init=%p", hash.init));
	hash.update = 
	  silc_sim_getsym(sim, silc_sim_symname(alg->alg_name,
						SILC_HASH_SIM_UPDATE));
	SILC_LOG_DEBUG(("update=%p", hash.update));
        hash.final = 
	  silc_sim_getsym(sim, silc_sim_symname(alg->alg_name,
						SILC_HASH_SIM_FINAL));
	SILC_LOG_DEBUG(("final=%p", hash.final));
        hash.context_len = 
	  silc_sim_getsym(sim, silc_sim_symname(alg->alg_name,
						SILC_HASH_SIM_CONTEXT_LEN));
	SILC_LOG_DEBUG(("context_len=%p", hash.context_len));

	/* Put the SIM to the table of all SIM's in server */
	silc_dlist_add(server->sim, sim);
      } else {
	SILC_LOG_ERROR(("Error configuring hash functions"));
	silc_server_stop(server);
	exit(1);
      }

      /* Register the cipher */
      silc_hash_register(&hash);
#endif
    }

    alg = alg->next;
  }
}

/* Returns client authentication information from server configuration
   by host (name or ip). */

SilcServerConfigSectionClientConnection *
silc_server_config_find_client_conn(SilcServerConfig config, 
				    char *host, int port)
{
  int i;
  SilcServerConfigSectionClientConnection *client = NULL;

  if (!host)
    return NULL;

  if (!config->clients)
    return NULL;

  client = config->clients;

  for (i = 0; client; i++) {
    if (silc_string_compare(client->host, host))
      break;
    client = client->next;
  }

  if (!client)
    return NULL;

  return client;
}

/* Returns server connection info from server configuartion by host 
   (name or ip). */

SilcServerConfigSectionServerConnection *
silc_server_config_find_server_conn(SilcServerConfig config, 
				    char *host, int port)
{
  int i;
  SilcServerConfigSectionServerConnection *serv = NULL;

  if (!host)
    return NULL;

  if (!config->servers)
    return NULL;

  serv = config->servers;
  for (i = 0; serv; i++) {
    if (silc_string_compare(serv->host, host))
      break;
    serv = serv->next;
  }

  if (!serv)
    return NULL;

  return serv;
}

/* Returns router connection info from server configuartion by
   host (name or ip). */

SilcServerConfigSectionServerConnection *
silc_server_config_find_router_conn(SilcServerConfig config, 
				    char *host, int port)
{
  int i;
  SilcServerConfigSectionServerConnection *serv = NULL;

  if (!host)
    return NULL;

  if (!config->routers)
    return NULL;

  serv = config->routers;
  for (i = 0; serv; i++) {
    if (silc_string_compare(serv->host, host))
      break;
    serv = serv->next;
  }

  if (!serv)
    return NULL;

  return serv;
}

/* Prints out example configuration file with default built in
   configuration values. */

void silc_server_config_print()
{
  char *buf;

  buf = "\
#\n\
# Automatically generated example SILCd configuration file with default\n\
# built in values. Use this as a guide to configure your SILCd configuration\n\
# file for your system. For detailed description of different configuration\n\
# sections refer to silcd(8) manual page.\n\
#\n";
  /*
#<Cipher>
#+blowfish
#+twofish
#+rc5
#+rc6
#+3des

#<HashFunction>
#+md5
#+sha1

<ServerInfo>
+lassi.kuo.fi.ssh.com:10.2.1.6:Kuopio, Finland:1333

<AdminInfo>
+Mun huone:Mun servo:Pekka Riikonen:priikone@poseidon.pspt.fi

<ListenPort>
+10.2.1.6:10.2.1.6:1333

<Logging>
+infologfile:silcd.log:10000
#+warninglogfile:/var/log/silcd_warning.log:10000
#+errorlogfile:ERROR.log:10000
#+fatallogfile:/var/log/silcd_error.log:

<ConnectionClass>
	  	+1:100:100:100
			+2:200:300:400

<ClientAuth>
+10.2.1.199:priikone:333:1

<AdminAuth>
+10.2.1.199:priikone:priikone:1

<ServerConnection>

<RouterConnection>

<DenyConnection>
<RedirectClient>
  */

  fprintf(stdout, "%s\n", buf);
}
