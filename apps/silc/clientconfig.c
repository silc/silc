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

#include "clientincludes.h"
#include "clientconfig.h"

/* 
   All possible configuration sections for SILC client.
*/
SilcClientConfigSection silc_client_config_sections[] = {
  { "[cipher]", 
    SILC_CLIENT_CONFIG_SECTION_TYPE_CIPHER, 4 },
  { "[pkcs]", 
    SILC_CLIENT_CONFIG_SECTION_TYPE_PKCS, 2 },
  { "[hash]", 
    SILC_CLIENT_CONFIG_SECTION_TYPE_HASH_FUNCTION, 4 },
  { "[connection]", 
    SILC_CLIENT_CONFIG_SECTION_TYPE_CONNECTION, 4 },
  { "[commands]", 
    SILC_CLIENT_CONFIG_SECTION_TYPE_COMMAND, 0 },
  
  { NULL, SILC_CLIENT_CONFIG_SECTION_TYPE_NONE, 0 }
};

/* Allocates a new configuration object, opens configuration file and
   parses the file. The parsed data is returned to the newly allocated
   configuration object. */

SilcClientConfig silc_client_config_alloc(char *filename)
{
  SilcClientConfig new;
  SilcBuffer buffer;
  SilcClientConfigParse config_parse;

  SILC_LOG_DEBUG(("Allocating new configuration object"));

  new = silc_calloc(1, sizeof(*new));
  new->filename = filename;

  /* Open configuration file and parse it */
  config_parse = NULL;
  buffer = NULL;
  silc_config_open(filename, &buffer);
  if (!buffer)
    goto fail;
  if ((silc_client_config_parse(new, buffer, &config_parse)) == FALSE)
    goto fail;
  if ((silc_client_config_parse_lines(new, config_parse)) == FALSE)
    goto fail;

  silc_free(buffer);

  return new;

 fail:
  silc_free(new);
  return NULL;
}

/* Free's a configuration object. */

void silc_client_config_free(SilcClientConfig config)
{
  if (config) {

    silc_free(config);
  }
}

/* Parses the the buffer and returns the parsed lines into return_config
   argument. The return_config argument doesn't have to be initialized 
   before calling this. It will be initialized during the parsing. The
   buffer sent as argument can be safely free'd after this function has
   succesfully returned. */

int silc_client_config_parse(SilcClientConfig config, SilcBuffer buffer, 
			     SilcClientConfigParse *return_config)
{
  int i, begin;
  unsigned int linenum;
  char line[1024], *cp;
  SilcClientConfigSection *cptr = NULL;
  SilcClientConfigParse parse = *return_config, first = NULL;

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
      for (cptr = silc_client_config_sections; cptr->section; cptr++)
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

      /* Handle config section */
      if (cptr->type != SILC_CLIENT_CONFIG_SECTION_TYPE_NONE) {
	
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

int silc_client_config_parse_lines(SilcClientConfig config, 
				   SilcClientConfigParse parse_config)
{
  int ret, check = FALSE;
  char *tmp;
  SilcClientConfigParse pc = parse_config;
  SilcBuffer line;

  SILC_LOG_DEBUG(("Parsing configuration lines"));
  
  if (!config)
    return FALSE;
  
  while(pc) {
    check = FALSE;
    line = pc->line;

    /* Get number of tokens in line (command section is handeled
       specially and has no tokens at all). */
    ret = silc_config_check_num_token(line);
    if (ret != pc->section->maxfields && 
	pc->section->type != SILC_CLIENT_CONFIG_SECTION_TYPE_COMMAND) {
      /* Bad line */
      fprintf(stderr, "%s:%d: Missing tokens, %d tokens (should be %d)\n",
	      config->filename, pc->linenum, ret, 
	      pc->section->maxfields);
      break;
    }

    /* Parse the line */
    switch(pc->section->type) {
    case SILC_CLIENT_CONFIG_SECTION_TYPE_CIPHER:

      if (!config->cipher) {
	config->cipher = silc_calloc(1, sizeof(*config->cipher));
	config->cipher->next = NULL;
	config->cipher->prev = NULL;
      } else {
	if (!config->cipher->next) {
	  config->cipher->next = 
	    silc_calloc(1, sizeof(*config->cipher->next));
	  config->cipher->next->next = NULL;
	  config->cipher->next->prev = config->cipher;
	  config->cipher = config->cipher->next;
	}
      }

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
      break;

    case SILC_CLIENT_CONFIG_SECTION_TYPE_PKCS:

      if (!config->pkcs) {
	config->pkcs = silc_calloc(1, sizeof(*config->pkcs));
	config->pkcs->next = NULL;
	config->pkcs->prev = NULL;
      } else {
	if (!config->pkcs->next) {
	  config->pkcs->next = 
	    silc_calloc(1, sizeof(*config->pkcs->next));
	  config->pkcs->next->next = NULL;
	  config->pkcs->next->prev = config->pkcs;
	  config->pkcs = config->pkcs->next;
	}
      }

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
      break;

    case SILC_CLIENT_CONFIG_SECTION_TYPE_HASH_FUNCTION:

      if (!config->hash_func) {
	config->hash_func = silc_calloc(1, sizeof(*config->hash_func));
	config->hash_func->next = NULL;
	config->hash_func->prev = NULL;
      } else {
	if (!config->hash_func->next) {
	  config->hash_func->next = 
	    silc_calloc(1, sizeof(*config->hash_func->next));
	  config->hash_func->next->next = NULL;
	  config->hash_func->next->prev = config->hash_func;
	  config->hash_func = config->hash_func->next;
	}
      }

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
      break;

    case SILC_CLIENT_CONFIG_SECTION_TYPE_CONNECTION:

      if (!config->conns) {
	config->conns = silc_calloc(1, sizeof(*config->conns));
	config->conns->next = NULL;
	config->conns->prev = NULL;
      } else {
	if (!config->conns->next) {
	  config->conns->next = silc_calloc(1, sizeof(*config->conns));
	  config->conns->next->next = NULL;
	  config->conns->next->prev = config->conns;
	  config->conns = config->conns->next;
	}
      }
      
      /* Get host */
      ret = silc_config_get_token(line, &config->conns->host);
      if (ret < 0)
	break;
      if (ret == 0)
	/* Any host */
	config->conns->host = strdup("*");

      /* Get authentication method */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret) {
	if (strcmp(tmp, SILC_CLIENT_CONFIG_AUTH_METH_PASSWD) &&
	    strcmp(tmp, SILC_CLIENT_CONFIG_AUTH_METH_PUBKEY)) {
	  fprintf(stderr, "%s:%d: Unknown authentication method '%s'\n",
		  config->filename, pc->linenum, tmp);
	  break;
	}

	if (!strcmp(tmp, SILC_CLIENT_CONFIG_AUTH_METH_PASSWD))
	  config->conns->auth_meth = SILC_AUTH_PASSWORD;

	if (!strcmp(tmp, SILC_CLIENT_CONFIG_AUTH_METH_PUBKEY))
	  config->conns->auth_meth = SILC_AUTH_PUBLIC_KEY;

	silc_free(tmp);
      }

      /* Get authentication data */
      ret = silc_config_get_token(line, &config->conns->auth_data);
      if (ret < 0)
	break;

      /* Get port */
      ret = silc_config_get_token(line, &tmp);
      if (ret < 0)
	break;
      if (ret) {
	config->conns->port = atoi(tmp);
	silc_free(tmp);
      }

      check = TRUE;
      break;

    case SILC_CLIENT_CONFIG_SECTION_TYPE_COMMAND:

      if (!config->commands) {
	config->commands = silc_calloc(1, sizeof(*config->commands));
	config->commands->next = NULL;
	config->commands->prev = NULL;
      } else {
	if (!config->commands->next) {
	  config->commands->next = silc_calloc(1, sizeof(*config->commands));
	  config->commands->next->next = NULL;
	  config->commands->next->prev = config->commands;
	  config->commands = config->commands->next;
	}
      }
      
      /* Get command line (this may include parameters as well. They
	 will be parsed later with standard command parser when
	 executing particular command.) */
      config->commands->command = silc_calloc(strlen(line->data), 
					      sizeof(char));
      memcpy(config->commands->command, line->data, strlen(line->data) - 1);
      if (ret < 0)
	break;

      check = TRUE;
      break;

    case SILC_CLIENT_CONFIG_SECTION_TYPE_NONE:
    default:
      break;
    }

    /* Check for error */
    if (check == FALSE) {
      /* Line could not be parsed */
      fprintf(stderr, "%s:%d: Parse error\n", config->filename, pc->linenum);
      break;
    }

    pc = pc->next;
  }

  if (check == FALSE)
    return FALSE;;

  /* Before returning all the lists in the config object must be set
     to their first values (the last value is first here). */
  while (config->cipher && config->cipher->prev)
    config->cipher = config->cipher->prev;
  while (config->pkcs && config->pkcs->prev)
    config->pkcs = config->pkcs->prev;
  while (config->hash_func && config->hash_func->prev)
    config->hash_func = config->hash_func->prev;
  while (config->conns && config->conns->prev)
    config->conns = config->conns->prev;
  while (config->commands && config->commands->prev)
    config->commands = config->commands->prev;
  
  SILC_LOG_DEBUG(("Done"));
  
  return TRUE;
}

/* Registers configured ciphers. These can then be allocated by the
   client when needed. */

void silc_client_config_register_ciphers(SilcClientConfig config)
{
  SilcClientConfigSectionAlg *alg;
  SilcClientInternal app = (SilcClientInternal)config->client;
  SilcClient client = app->client;

  SILC_LOG_DEBUG(("Registering configured ciphers"));

  alg = config->cipher;
  while(alg) {

    if (!alg->sim_name) {
      /* Crypto module is supposed to be built in. Nothing to be done
	 here except to test that the cipher really is built in. */
      SilcCipher tmp = NULL;

      if (silc_cipher_alloc(alg->alg_name, &tmp) == FALSE) {
	SILC_LOG_ERROR(("Unsupported cipher `%s'", alg->alg_name));
	silc_client_stop(client);
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

	/* Put the SIM to the table of all SIM's in client */
	app->sim = silc_realloc(app->sim,
				   sizeof(*app->sim) * 
				   (app->sim_count + 1));
	app->sim[app->sim_count] = sim;
	app->sim_count++;
      } else {
	SILC_LOG_ERROR(("Error configuring ciphers"));
	silc_client_stop(client);
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

void silc_client_config_register_pkcs(SilcClientConfig config)
{
  SilcClientConfigSectionAlg *alg = config->pkcs;
  SilcClientInternal app = (SilcClientInternal)config->client;
  SilcClient client = app->client;
  SilcPKCS tmp = NULL;

  SILC_LOG_DEBUG(("Registering configured PKCS"));

  while(alg) {

    if (silc_pkcs_alloc(alg->alg_name, &tmp) == FALSE) {
      SILC_LOG_ERROR(("Unsupported PKCS `%s'", alg->alg_name));
      silc_client_stop(client);
      exit(1);
    }
    silc_free(tmp);

    alg = alg->next;
  }
}

/* Registers configured hash functions. These can then be allocated by the
   client when needed. */

void silc_client_config_register_hashfuncs(SilcClientConfig config)
{
  SilcClientConfigSectionAlg *alg;
  SilcClientInternal app = (SilcClientInternal)config->client;
  SilcClient client = app->client;

  SILC_LOG_DEBUG(("Registering configured hash functions"));

  alg = config->hash_func;
  while(alg) {

    if (!alg->sim_name) {
      /* Hash module is supposed to be built in. Nothing to be done
	 here except to test that the hash function really is built in. */
      SilcHash tmp = NULL;

      if (silc_hash_alloc(alg->alg_name, &tmp) == FALSE) {
	SILC_LOG_ERROR(("Unsupported hash function `%s'", alg->alg_name));
	silc_client_stop(client);
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

	/* Put the SIM to the table of all SIM's in client */
	app->sim = silc_realloc(app->sim,
				   sizeof(*app->sim) * 
				   (app->sim_count + 1));
	app->sim[app->sim_count] = sim;
	app->sim_count++;
      } else {
	SILC_LOG_ERROR(("Error configuring hash functions"));
	silc_client_stop(client);
	exit(1);
      }

      /* Register the cipher */
      silc_hash_register(&hash);
#endif
    }

    alg = alg->next;
  }
}


SilcClientConfigSectionConnection *
silc_client_config_find_connection(SilcClientConfig config, 
				   char *host, int port)
{
  int i;
  SilcClientConfigSectionConnection *conn = NULL;

  SILC_LOG_DEBUG(("Finding connection"));

  if (!host)
    return NULL;

  if (!config->conns)
    return NULL;

  conn = config->conns;
  for (i = 0; conn; i++) {
    if (silc_string_compare(conn->host, host))
      break;
    conn = conn->next;
  }

  if (!conn)
    return NULL;

  SILC_LOG_DEBUG(("Found match"));

  return conn;
}
