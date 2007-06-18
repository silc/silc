/*

  silcapputil.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2007 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silc.h"

static char *silc_create_pk_identifier(void)
{
  char *username = NULL, *realname = NULL;
  char *hostname, email[256];
  char *ident;

  /* Get realname */
  realname = silc_get_real_name();

  /* Get hostname */
  hostname = silc_net_localhost();
  if (!hostname)
    return NULL;

  /* Get username (mandatory) */
  username = silc_get_username();
  if (!username)
    return NULL;

  /* Create default email address, whether it is right or not */
  silc_snprintf(email, sizeof(email), "%s@%s", username, hostname);

  ident = silc_pkcs_silc_encode_identifier(username, hostname, realname,
					   email, NULL, NULL, NULL);
  if (realname)
    silc_free(realname);
  silc_free(hostname);
  silc_free(username);

  return ident;
}

/* Generate key pair */

SilcBool silc_create_key_pair(const char *pkcs_name,
			      SilcUInt32 key_len_bits,
			      const char *pub_filename,
			      const char *prv_filename,
			      const char *pub_identifier,
			      const char *passphrase,
			      SilcPublicKey *return_public_key,
			      SilcPrivateKey *return_private_key,
			      SilcBool interactive)
{
  SilcRng rng;
  char line[256];
  char *pkfile = pub_filename ? strdup(pub_filename) : NULL;
  char *prvfile = prv_filename ? strdup(prv_filename) : NULL;
  char *alg = pkcs_name ? strdup(pkcs_name) : NULL;
  char *identifier = pub_identifier ? strdup(pub_identifier) : NULL;
  char *pass = passphrase ? strdup(passphrase) : NULL;
  SilcPublicKey public_key;
  SilcPrivateKey private_key;

  if (interactive && (!alg || !pub_filename || !prv_filename))
    printf("\
New pair of keys will be created.  Please, answer to following questions.\n\
");

  if (!alg) {
    if (interactive) {
      while (!alg) {
	alg = silc_get_input("PKCS name (l to list names) [rsa]: ", FALSE);
	if (!alg)
	  alg = strdup("rsa");

	if (*alg == 'l' || *alg == 'L') {
	  char *list = silc_pkcs_get_supported();
	  printf("%s\n", list);
	  silc_free(list);
	  silc_free(alg);
	  alg = NULL;
	}
      }
    } else {
      alg = strdup("rsa");
    }
  }

  if (!silc_pkcs_find_algorithm(alg, NULL)) {
    fprintf(stderr, "Unknown PKCS algorithm `%s' or crypto library"
	    "is not initialized", alg);
    return FALSE;
  }

  if (!key_len_bits) {
    if (interactive) {
      char *length = NULL;
      length = silc_get_input("Key length in key_len_bits [2048]: ", FALSE);
      if (length)
	key_len_bits = atoi(length);
      silc_free(length);
    }
    if (!key_len_bits)
      key_len_bits = 2048;
  }

  if (!identifier) {
    char *def = silc_create_pk_identifier();

    if (interactive) {
      memset(line, 0, sizeof(line));
      if (def)
	silc_snprintf(line, sizeof(line), "Identifier [%s]: ", def);
      else
	silc_snprintf(line, sizeof(line),
	       "Identifier (eg. UN=jon, HN=jon.dummy.com, "
	       "RN=Jon Johnson, E=jon@dummy.com): ");

      while (!identifier) {
	identifier = silc_get_input(line, FALSE);
	if (!identifier && def)
	  identifier = strdup(def);
      }
    } else {
      if (!def) {
	fprintf(stderr, "Could not create public key identifier: %s\n",
		strerror(errno));
	return FALSE;
      }
      identifier = strdup(def);
    }

    silc_free(def);
  }

  if (!strstr(identifier, "UN=") || !strstr(identifier, "HN=")) {
    fprintf(stderr, "Invalid public key identifier.  You must specify both "
	    "UN and HN\n");
    return FALSE;
  }

  rng = silc_rng_alloc();
  silc_rng_init(rng);
  silc_rng_global_init(rng);

  if (!pkfile) {
    if (interactive) {
      memset(line, 0, sizeof(line));
      silc_snprintf(line, sizeof(line), "Public key filename [public_key.pub]: ");
      pkfile = silc_get_input(line, FALSE);
    }
    if (!pkfile)
      pkfile = strdup("public_key.pub");
  }

  if (!prvfile) {
    if (interactive) {
      memset(line, 0, sizeof(line));
      silc_snprintf(line, sizeof(line), "Private key filename [private_key.prv]: ");
      prvfile = silc_get_input(line, FALSE);
    }
    if (!prvfile)
      prvfile = strdup("private_key.prv");
  }

  if (!pass) {
    while (TRUE) {
      char *pass2 = NULL;
      pass = silc_get_input("Private key passphrase: ", TRUE);
      if (!pass) {
        pass = strdup("");
	break;
      } else {
	SilcBool match;
	printf("\n");
	pass2 = silc_get_input("Retype private key passphrase: ", TRUE);
	if (!pass2)
	  pass2 = strdup("");
	match = !strcmp(pass, pass2);
	silc_free(pass2);
	if (match)
	  break;
	fprintf(stderr, "\nPassphrases do not match\n\n");
      }
    }
  }

  if (interactive)
    printf("\nGenerating the key pair...\n");

  /* Generate keys */
  if (!silc_pkcs_silc_generate_key(alg, key_len_bits,
				   identifier, rng, &public_key,
				   &private_key))
    return FALSE;

  /* Save public key into file */
  if (!silc_pkcs_save_public_key(pkfile, public_key, SILC_PKCS_FILE_BASE64))
    return FALSE;

  /* Save private key into file */
  if (!silc_pkcs_save_private_key(prvfile, private_key,
				  (const unsigned char *)pass, strlen(pass),
				  SILC_PKCS_FILE_BIN, rng))
    return FALSE;

  if (return_public_key)
    *return_public_key = public_key;
  else
    silc_pkcs_public_key_free(public_key);

  if (return_private_key)
    *return_private_key = private_key;
  else
    silc_pkcs_private_key_free(private_key);

  printf("Public key has been saved into `%s'.\n", pkfile);
  printf("Private key has been saved into `%s'.\n", prvfile);
  if (interactive) {
    printf("Press <Enter> to continue...\n");
    getchar();
  }

  silc_rng_free(rng);
  silc_free(alg);
  silc_free(pkfile);
  silc_free(prvfile);
  silc_free(identifier);
  memset(pass, 0, strlen(pass));
  silc_free(pass);

  return TRUE;
}

/* Load key pair */

SilcBool silc_load_key_pair(const char *pub_filename,
			    const char *prv_filename,
			    const char *passphrase,
			    SilcPublicKey *return_public_key,
			    SilcPrivateKey *return_private_key)
{
  char *pass = passphrase ? strdup(passphrase) : NULL;

  SILC_LOG_DEBUG(("Loading public and private keys"));

  if (!silc_pkcs_load_public_key(pub_filename, return_public_key)) {
    if (pass)
      memset(pass, 0, strlen(pass));
    silc_free(pass);
    return FALSE;
  }

  if (!pass) {
    pass = silc_get_input("Private key passphrase: ", TRUE);
    if (!pass)
      pass = strdup("");
  }

  if (!silc_pkcs_load_private_key(prv_filename,
				  (const unsigned char *)pass, strlen(pass),
				  return_private_key)) {
    silc_pkcs_public_key_free(*return_public_key);
    *return_public_key = NULL;
    memset(pass, 0, strlen(pass));
    silc_free(pass);
    return FALSE;
  }

  memset(pass, 0, strlen(pass));
  silc_free(pass);
  return TRUE;
}

/* Dump public key into stdout */

SilcBool silc_show_public_key(SilcPublicKey public_key)
{
  SilcSILCPublicKey silc_pubkey;
  SilcPublicKeyIdentifier ident;
  char *fingerprint, *babbleprint;
  unsigned char *pk;
  SilcUInt32 pk_len;
  SilcUInt32 key_len = 0;

  silc_pubkey = silc_pkcs_get_context(SILC_PKCS_SILC, public_key);
  if (!silc_pubkey)
    return FALSE;

  ident = &silc_pubkey->identifier;
  key_len = silc_pkcs_public_key_get_len(public_key);
  pk = silc_pkcs_public_key_encode(public_key, &pk_len);
  if (!pk)
    return FALSE;
  fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
  babbleprint = silc_hash_babbleprint(NULL, pk, pk_len);

  printf("Algorithm          : %s\n", silc_pkcs_get_name(public_key));
  if (key_len)
    printf("Key length (bits)  : %d\n", (unsigned int)key_len);
  if (ident->version)
    printf("Version            : %s\n", ident->version);
  if (ident->realname)
    printf("Real name          : %s\n", ident->realname);
  if (ident->username)
    printf("Username           : %s\n", ident->username);
  if (ident->host)
    printf("Hostname           : %s\n", ident->host);
  if (ident->email)
    printf("Email              : %s\n", ident->email);
  if (ident->org)
    printf("Organization       : %s\n", ident->org);
  if (ident->country)
    printf("Country            : %s\n", ident->country);
  printf("Fingerprint (SHA1) : %s\n", fingerprint);
  printf("Babbleprint (SHA1) : %s\n", babbleprint);

  fflush(stdout);

  silc_free(fingerprint);
  silc_free(babbleprint);
  silc_free(pk);

  return TRUE;
}

/* Dump public key into stdout */

SilcBool silc_show_public_key_file(const char *pub_filename)
{
  SilcPublicKey public_key;
  SilcBool ret;

  if (!silc_pkcs_load_public_key((char *)pub_filename, &public_key)) {
    fprintf(stderr, "Could not load public key file `%s'\n", pub_filename);
    return FALSE;
  }

  printf("Public key file    : %s\n", pub_filename);
  ret = silc_show_public_key(public_key);
  silc_pkcs_public_key_free(public_key);

  return ret;
}

/* Change private key passphrase */

SilcBool silc_change_private_key_passphrase(const char *prv_filename,
					    const char *old_passphrase,
					    const char *new_passphrase)
{
  SilcPrivateKey private_key;
  char *pass;
  SilcRng rng;

  pass = old_passphrase ? strdup(old_passphrase) : NULL;
  if (!pass) {
    pass = silc_get_input("Old passphrase: ", TRUE);
    if (!pass)
      pass = strdup("");
  }

  if (!silc_pkcs_load_private_key(prv_filename,
				  (const unsigned char *)pass, strlen(pass),
				  &private_key)) {
    memset(pass, 0, strlen(pass));
    silc_free(pass);
    fprintf(stderr, "Could not load private key `%s' file\n", prv_filename);
    return FALSE;
  }

  memset(pass, 0, strlen(pass));
  silc_free(pass);

  pass = new_passphrase ? strdup(new_passphrase) : NULL;
  if (!pass) {
    char *pass2 = NULL;
    fprintf(stdout, "\n");
    pass = silc_get_input("New passphrase: ", TRUE);
    if (!pass) {
      pass = strdup("");
    } else {
      while (TRUE) {
	printf("\n");
	pass2 = silc_get_input("Retype new passphrase: ", TRUE);
	if (!pass2)
	  pass2 = strdup("");
	if (!strcmp(pass, pass2))
	  break;
	fprintf(stderr, "\nPassphrases do not match");
      }
      silc_free(pass2);
    }
  }

  rng = silc_rng_alloc();
  silc_rng_init(rng);

  silc_pkcs_save_private_key((char *)prv_filename, private_key,
			     (unsigned char *)pass, strlen(pass),
			     SILC_PKCS_FILE_BIN, rng);

  fprintf(stdout, "\nPassphrase changed\n");

  memset(pass, 0, strlen(pass));
  silc_free(pass);

  silc_pkcs_private_key_free(private_key);
  silc_rng_free(rng);

  return TRUE;
}

/* Checks that the 'identifier' string is valid identifier string
   and does not contain any unassigned or prohibited character.  This
   function is used to check for valid nicknames, channel names,
   server names, usernames, hostnames, service names, algorithm names,
   other security property names, and SILC Public Key name. */

unsigned char *silc_identifier_check(const unsigned char *identifier,
				     SilcUInt32 identifier_len,
				     SilcStringEncoding identifier_encoding,
				     SilcUInt32 max_allowed_length,
				     SilcUInt32 *out_len)
{
  unsigned char *utf8s;
  SilcUInt32 utf8s_len;
  SilcStringprepStatus status;

  if (!identifier || !identifier_len)
    return NULL;

  if (max_allowed_length && identifier_len > max_allowed_length)
    return NULL;

  status = silc_stringprep(identifier, identifier_len,
			   identifier_encoding, SILC_IDENTIFIER_PREP, 0,
			   &utf8s, &utf8s_len, SILC_STRING_UTF8);
  if (status != SILC_STRINGPREP_OK) {
    SILC_LOG_DEBUG(("silc_stringprep() status error %d", status));
    return NULL;
  }

  if (out_len)
    *out_len = utf8s_len;

  return utf8s;
}

/* Same as above but does not allocate memory, just checks the
   validity of the string. */

SilcBool silc_identifier_verify(const unsigned char *identifier,
				SilcUInt32 identifier_len,
				SilcStringEncoding identifier_encoding,
				SilcUInt32 max_allowed_length)
{
  SilcStringprepStatus status;

  if (!identifier || !identifier_len)
    return FALSE;

  if (max_allowed_length && identifier_len > max_allowed_length)
    return FALSE;

  status = silc_stringprep(identifier, identifier_len,
			   identifier_encoding, SILC_IDENTIFIER_PREP, 0,
			   NULL, NULL, SILC_STRING_UTF8);
  if (status != SILC_STRINGPREP_OK) {
    SILC_LOG_DEBUG(("silc_stringprep() status error %d", status));
    return FALSE;
  }

  return TRUE;
}

unsigned char *silc_channel_name_check(const unsigned char *identifier,
				       SilcUInt32 identifier_len,
				       SilcStringEncoding identifier_encoding,
				       SilcUInt32 max_allowed_length,
				       SilcUInt32 *out_len)
{
  unsigned char *utf8s;
  SilcUInt32 utf8s_len;
  SilcStringprepStatus status;

  if (!identifier || !identifier_len)
    return NULL;

  if (max_allowed_length && identifier_len > max_allowed_length)
    return NULL;

  status = silc_stringprep(identifier, identifier_len,
			   identifier_encoding, SILC_IDENTIFIER_CH_PREP, 0,
			   &utf8s, &utf8s_len, SILC_STRING_UTF8);
  if (status != SILC_STRINGPREP_OK) {
    SILC_LOG_DEBUG(("silc_stringprep() status error %d", status));
    return NULL;
  }

  if (out_len)
    *out_len = utf8s_len;

  return utf8s;
}

/* Same as above but does not allocate memory, just checks the
   validity of the string. */

SilcBool silc_channel_name_verify(const unsigned char *identifier,
				  SilcUInt32 identifier_len,
				  SilcStringEncoding identifier_encoding,
				  SilcUInt32 max_allowed_length)
{
  SilcStringprepStatus status;

  if (!identifier || !identifier_len)
    return FALSE;

  if (max_allowed_length && identifier_len > max_allowed_length)
    return FALSE;

  status = silc_stringprep(identifier, identifier_len,
			   identifier_encoding, SILC_IDENTIFIER_CH_PREP, 0,
			   NULL, NULL, SILC_STRING_UTF8);
  if (status != SILC_STRINGPREP_OK) {
    SILC_LOG_DEBUG(("silc_stringprep() status error %d", status));
    return FALSE;
  }

  return TRUE;
}

/* Return mode list */

SilcBool silc_get_mode_list(SilcBuffer mode_list, SilcUInt32 mode_list_count,
			    SilcUInt32 **list)
{
  int i;

  if (silc_buffer_len(mode_list) / 4 != mode_list_count)
    return FALSE;

  *list = silc_calloc(mode_list_count, sizeof(**list));

  for (i = 0; i < mode_list_count; i++) {
    SILC_GET32_MSB((*list)[i], mode_list->data);
    silc_buffer_pull(mode_list, 4);
  }

  silc_buffer_push(mode_list, mode_list->data - mode_list->head);

  return TRUE;
}

/* Status message structure. Messages are defined below. */
typedef struct {
  SilcStatus status;
  const char *message;
} SilcStatusMessage;

#define STAT(x) SILC_STATUS_ERR_##x
static const SilcStatusMessage silc_status_messages[] = {

  { STAT(NO_SUCH_NICK),      "There was no such nickname" },
  { STAT(NO_SUCH_CHANNEL),   "There was no such channel" },
  { STAT(NO_SUCH_SERVER),    "There was no such server" },
  { STAT(INCOMPLETE_INFORMATION),  "Incomplete registration information" },
  { STAT(NO_RECIPIENT),      "No recipient given" },
  { STAT(UNKNOWN_COMMAND),   "Unknown command" },
  { STAT(WILDCARDS),         "Wilcrads not allowed" },
  { STAT(NO_CLIENT_ID),      "No Client ID given" },
  { STAT(NO_CHANNEL_ID),     "No Channel ID given" },
  { STAT(NO_SERVER_ID),      "No Server ID given" },
  { STAT(BAD_CLIENT_ID),     "Bad Client ID" },
  { STAT(BAD_CHANNEL_ID),    "Bad Channel ID" },
  { STAT(NO_SUCH_CLIENT_ID), "There is no such client" },
  { STAT(NO_SUCH_CHANNEL_ID),"There is no such channel" },
  { STAT(NICKNAME_IN_USE),   "Nickname already exists" },
  { STAT(NOT_ON_CHANNEL),    "You are not on that channel" },
  { STAT(USER_NOT_ON_CHANNEL),"They are not on the channel" },
  { STAT(USER_ON_CHANNEL),   "User already on the channel" },
  { STAT(NOT_REGISTERED),    "You have not registered" },
  { STAT(NOT_ENOUGH_PARAMS), "Not enough parameters" },
  { STAT(TOO_MANY_PARAMS),   "Too many parameters" },
  { STAT(PERM_DENIED),       "Permission denied" },
  { STAT(BANNED_FROM_SERVER),"You are not allowed to connect" },
  { STAT(BAD_PASSWORD),      "Cannot join channel. Incorrect password" },
  { STAT(CHANNEL_IS_FULL),   "Cannot join channel. Channel is full" },
  { STAT(NOT_INVITED),     "Cannot join channel. You have not been invited" },
  { STAT(BANNED_FROM_CHANNEL), "Cannot join channel. You have been banned" },
  { STAT(UNKNOWN_MODE),    "Unknown mode" },
  { STAT(NOT_YOU),         "Cannot change mode for other users" },
  { STAT(NO_CHANNEL_PRIV), "Permission denied. You are not channel operator" },
  { STAT(NO_CHANNEL_FOPRIV),"Permission denied. You are not channel founder" },
  { STAT(NO_SERVER_PRIV),  "Permission denied. You are not server operator" },
  { STAT(NO_ROUTER_PRIV),  "Permission denied. You are not SILC operator" },
  { STAT(BAD_NICKNAME),    "Bad nickname" },
  { STAT(BAD_CHANNEL),     "Bad channel name" },
  { STAT(AUTH_FAILED),     "Authentication failed" },
  { STAT(UNKNOWN_ALGORITHM), "Unsupported algorithm" },
  { STAT(NO_SUCH_SERVER_ID), "No such Server ID" },
  { STAT(RESOURCE_LIMIT), "No more free resources" },
  { STAT(NO_SUCH_SERVICE), "Service doesn't exist" },
  { STAT(NOT_AUTHENTICATED), "You have not been authenticated" },
  { STAT(BAD_SERVER_ID), "Server ID is not valid" },
  { STAT(KEY_EXCHANGE_FAILED), "Key exchange failed" },
  { STAT(BAD_VERSION), "Bad version" },
  { STAT(TIMEDOUT), "Service timed out" },
  { STAT(UNSUPPORTED_PUBLIC_KEY), "Unsupported public key type" },
  { STAT(OPERATION_ALLOWED), "Operation is not allowed" },
  { STAT(BAD_SERVER), "Bad server name" },
  { STAT(BAD_USERNAME), "Bad user name" },
  { STAT(NO_SUCH_PUBLIC_KEY), "Unknown public key" },

  { 0, NULL }
};

/* Returns status message string */

const char *silc_get_status_message(unsigned char status)
{
  int i;

  for (i = 0; silc_status_messages[i].message; i++) {
    if (silc_status_messages[i].status == status)
      break;
  }

  if (silc_status_messages[i].message == NULL)
    return "";

  return silc_status_messages[i].message;
}

static const char *packet_name[] = {
  "NONE",
  "DISCONNECT",
  "SUCCESS",
  "FAILURE",
  "REJECT",
  "NOTIFY",
  "ERROR",
  "CHANNEL MESSAGE",
  "CHANNEL KEY",
  "PRIVATE MESSAGE",
  "PRIVATE MESSAGE KEY",
  "COMMAND",
  "COMMAND REPLY",
  "KEY EXCHANGE",
  "KEY EXCHANGE 1",
  "KEY EXCHANGE 2",
  "CONNECTION AUTH REQUEST",
  "CONNECTION AUTH",
  "NEW ID",
  "NEW CLIENT",
  "NEW SERVER",
  "NEW CHANNEL",
  "REKEY",
  "REKEY_DONE",
  "HEARTBEAT",
  "KEY AGREEMENT",
  "RESUME ROUTER",
  "FTP",
  "RESUME CLIENT",
};

/* Returns packet type name */

const char *silc_get_packet_name(unsigned char type)
{
  if (type >= SILC_PACKET_MAX)
    return "RESERVED";
  if (type >= SILC_PACKET_PRIVATE)
    return "PRIVATE RANGE";
  if (type > (sizeof(packet_name) / sizeof(*packet_name)))
    return "UNKNOWN";
  return packet_name[type];
}

static const char *command_name[] = {
  "NONE",
  "WHOIS",
  "WHOWAS",
  "IDENTIFY",
  "NICK",
  "LIST",
  "TOPIC",
  "INVITE",
  "QUIT",
  "KILL",
  "INFO",
  "STATS",
  "PING",
  "OPER",
  "JOIN",
  "MOTD",
  "UMODE",
  "CMODE",
  "CUMODE",
  "KICK",
  "BAN",
  "DETACH",
  "WATCH",
  "SILCOPER",
  "LEAVE",
  "USERS",
  "GETKEY",
  "SERVICE",
};

/* Returns command name */

const char *silc_get_command_name(unsigned char command)
{
  if (command >= SILC_COMMAND_RESERVED)
    return "RESERVED";
  if (command >= SILC_COMMAND_PRIVATE)
    return "PRIVATE RANGE";
  if (command > (sizeof(command_name) / sizeof(*command_name)))
    return "UNKNOWN";
  return command_name[command];
}

/* Parses SILC protocol style version string. */

SilcBool silc_parse_version_string(const char *version,
				   SilcUInt32 *protocol_version,
				   char **protocol_version_string,
				   SilcUInt32 *software_version,
				   char **software_version_string,
				   char **vendor_version)
{
  char *cp, buf[32];
  int maj = 0, min = 0;

  if (!strstr(version, "SILC-"))
    return FALSE;

  cp = (char *)version + 5;
  if (!cp || !(*cp))
    return FALSE;

  /* Take protocol version */

  maj = atoi(cp);
  if (!strchr(cp, '.'))
    return FALSE;
  cp = strchr(cp, '.') + 1;
  if (!cp || !(*cp))
    return FALSE;
  min = atoi(cp);

  memset(buf, 0, sizeof(buf));
  silc_snprintf(buf, sizeof(buf) - 1, "%d%d", maj, min);
  if (protocol_version)
    *protocol_version = atoi(buf);
  memset(buf, 0, sizeof(buf));
  silc_snprintf(buf, sizeof(buf) - 1, "%d.%d", maj, min);
  if (protocol_version_string)
    *protocol_version_string = strdup(buf);

  /* Take software version */

  maj = 0;
  min = 0;
  if (!strchr(cp, '-'))
    return FALSE;
  cp = strchr(cp, '-') + 1;
  if (!cp || !(*cp))
    return FALSE;

  maj = atoi(cp);
  if (strchr(cp, '.')) {
    cp = strchr(cp, '.') + 1;
    if (cp && *cp)
      min = atoi(cp);
  }

  memset(buf, 0, sizeof(buf));
  silc_snprintf(buf, sizeof(buf) - 1, "%d%d", maj, min);
  if (software_version)
    *software_version = atoi(buf);
  memset(buf, 0, sizeof(buf));
  silc_snprintf(buf, sizeof(buf) - 1, "%d.%d", maj, min);
  if (software_version_string)
    *software_version_string = strdup(buf);

  /* Take vendor string */

  if (strchr(cp, '.')) {
    cp = strchr(cp, '.') + 1;
    if (cp && *cp && vendor_version)
      *vendor_version = strdup(cp);
  } else if (strchr(cp, ' ')) {
    cp = strchr(cp, ' ') + 1;
    if (cp && *cp && vendor_version)
      *vendor_version = strdup(cp);
  }

  return TRUE;
}

/* Converts version string x.x into number representation. */

SilcUInt32 silc_version_to_num(const char *version)
{
  int maj = 0, min = 0;
  char *cp, buf[32];

  if (!version)
    return 0;

  cp = (char *)version;
  maj = atoi(cp);
  cp = strchr(cp, '.');
  if (cp)
    min = atoi(cp + 1);

  memset(buf, 0, sizeof(buf));
  silc_snprintf(buf, sizeof(buf) - 1, "%d%d", maj, min);
  return (SilcUInt32)atoi(buf);
}

/* Parses mode mask and returns the mode as string. */

char *silc_client_chmode(SilcUInt32 mode, const char *cipher, const char *hmac)
{
  char string[100];

  if (!mode)
    return NULL;

  memset(string, 0, sizeof(string));

  if (mode & SILC_CHANNEL_MODE_PRIVATE)
    strncat(string, "p", 1);

  if (mode & SILC_CHANNEL_MODE_SECRET)
    strncat(string, "s", 1);

  if (mode & SILC_CHANNEL_MODE_PRIVKEY)
    strncat(string, "k", 1);

  if (mode & SILC_CHANNEL_MODE_INVITE)
    strncat(string, "i", 1);

  if (mode & SILC_CHANNEL_MODE_TOPIC)
    strncat(string, "t", 1);

  if (mode & SILC_CHANNEL_MODE_ULIMIT)
    strncat(string, "l", 1);

  if (mode & SILC_CHANNEL_MODE_PASSPHRASE)
    strncat(string, "a", 1);

  if (mode & SILC_CHANNEL_MODE_FOUNDER_AUTH)
    strncat(string, "f", 1);

  if (mode & SILC_CHANNEL_MODE_CHANNEL_AUTH)
    strncat(string, "C", 1);

  if (mode & SILC_CHANNEL_MODE_SILENCE_USERS)
    strncat(string, "m", 1);

  if (mode & SILC_CHANNEL_MODE_SILENCE_OPERS)
    strncat(string, "M", 1);

  if (mode & SILC_CHANNEL_MODE_CIPHER)
    strncat(string, "c", 1);

  if (mode & SILC_CHANNEL_MODE_HMAC)
    strncat(string, "h", 1);

  if (mode & SILC_CHANNEL_MODE_CIPHER) {
    if (strlen(cipher) + strlen(string) + 1< sizeof(string)) {
      strncat(string, " ", 1);
      strncat(string, cipher, strlen(cipher));
    }
  }

  if (mode & SILC_CHANNEL_MODE_HMAC) {
    if (strlen(hmac) + strlen(string) + 1< sizeof(string)) {
      strncat(string, " ", 1);
      strncat(string, hmac, strlen(hmac));
    }
  }

  /* Rest of mode is ignored */

  return strdup(string);
}

/* Parses channel user mode mask and returns te mode as string */

char *silc_client_chumode(SilcUInt32 mode)
{
  char string[64];

  if (!mode)
    return NULL;

  memset(string, 0, sizeof(string));

  if (mode & SILC_CHANNEL_UMODE_CHANFO)
    strncat(string, "f", 1);

  if (mode & SILC_CHANNEL_UMODE_CHANOP)
    strncat(string, "o", 1);

  if (mode & SILC_CHANNEL_UMODE_BLOCK_MESSAGES)
    strncat(string, "b", 1);

  if (mode & SILC_CHANNEL_UMODE_BLOCK_MESSAGES_USERS)
    strncat(string, "u", 1);

  if (mode & SILC_CHANNEL_UMODE_BLOCK_MESSAGES_ROBOTS)
    strncat(string, "r", 1);

  if (mode & SILC_CHANNEL_UMODE_QUIET)
    strncat(string, "q", 1);

  return strdup(string);
}

/* Parses channel user mode and returns it as special mode character. */

char *silc_client_chumode_char(SilcUInt32 mode)
{
  char string[64];

  if (!mode)
    return NULL;

  memset(string, 0, sizeof(string));

  if (mode & SILC_CHANNEL_UMODE_CHANFO)
    strncat(string, "*", 1);

  if (mode & SILC_CHANNEL_UMODE_CHANOP)
    strncat(string, "@", 1);

  if (mode & SILC_CHANNEL_UMODE_QUIET)
    strncat(string, "&", 1);

  return strdup(string);
}

/* Renders ID to suitable to print for example to log file. */

static char rid[256];
#define _PUT_STRING(__d__, __s__)					\
do {									\
  int __sp = sizeof(__d__) - 1 - strlen(__d__);				\
  if (__sp < strlen(__s__)) {						\
    if (__sp)								\
      strncat(__d__, __s__, (sizeof(__d__) - 1) - strlen(__d__));	\
  } else {								\
    strncat(__d__, __s__, strlen(__s__));				\
  }									\
} while(0)

char *silc_id_render(void *id, SilcIdType id_type)
{
  char tmp[100];
  unsigned char tmps[2];
  char *cp;

  memset(rid, 0, sizeof(rid));
  switch(id_type) {
  case SILC_ID_SERVER:
    {
      SilcServerID *server_id = (SilcServerID *)id;
      if (server_id->ip.data_len > 4) {
#ifdef HAVE_IPV6
	struct sockaddr_in6 ipv6;
	memset(&ipv6, 0, sizeof(ipv6));
	ipv6.sin6_family = AF_INET6;
	memmove(&ipv6.sin6_addr, server_id->ip.data, sizeof(ipv6.sin6_addr));
	if (!getnameinfo((struct sockaddr *)&ipv6, sizeof(ipv6),
			 tmp, sizeof(tmp) - 1, NULL, 0, NI_NUMERICHOST))
	  _PUT_STRING(rid, tmp);
#endif
      } else {
	struct in_addr ipv4;
	memmove(&ipv4.s_addr, server_id->ip.data, 4);
	cp = inet_ntoa(ipv4);
	if (cp)
	  _PUT_STRING(rid, cp);
      }

      memset(tmp, 0, sizeof(tmp));
      silc_snprintf(tmp, sizeof(tmp) - 1, ",%d,", ntohs(server_id->port));
      _PUT_STRING(rid, tmp);
      SILC_PUT16_MSB(server_id->rnd, tmps);
      memset(tmp, 0, sizeof(tmp));
      silc_snprintf(tmp, sizeof(tmp) - 1, "[%02x %02x]", tmps[0], tmps[1]);
      _PUT_STRING(rid, tmp);
    }
    break;
  case SILC_ID_CLIENT:
    {
      SilcClientID *client_id = (SilcClientID *)id;
      if (client_id->ip.data_len > 4) {
#ifdef HAVE_IPV6
	struct sockaddr_in6 ipv6;
	memset(&ipv6, 0, sizeof(ipv6));
	ipv6.sin6_family = AF_INET6;
	memmove(&ipv6.sin6_addr, client_id->ip.data, sizeof(ipv6.sin6_addr));
	if (!getnameinfo((struct sockaddr *)&ipv6, sizeof(ipv6),
			 tmp, sizeof(tmp) - 1, NULL, 0, NI_NUMERICHOST))
	  _PUT_STRING(rid, tmp);
#endif
      } else {
	struct in_addr ipv4;
	memmove(&ipv4.s_addr, client_id->ip.data, 4);
	cp = inet_ntoa(ipv4);
	if (cp)
	  _PUT_STRING(rid, cp);
      }

      memset(tmp, 0, sizeof(tmp));
      silc_snprintf(tmp, sizeof(tmp) - 1, ",%02x,", client_id->rnd);
      _PUT_STRING(rid, tmp);
      memset(tmp, 0, sizeof(tmp));
      silc_snprintf(tmp, sizeof(tmp) - 1, "[%02x %02x %02x %02x...]",
	       client_id->hash[0], client_id->hash[1],
	       client_id->hash[2], client_id->hash[3]);
      _PUT_STRING(rid, tmp);
    }
    break;
  case SILC_ID_CHANNEL:
    {
      SilcChannelID *channel_id = (SilcChannelID *)id;
      if (channel_id->ip.data_len > 4) {
#ifdef HAVE_IPV6
	struct sockaddr_in6 ipv6;
	memset(&ipv6, 0, sizeof(ipv6));
	ipv6.sin6_family = AF_INET6;
	memmove(&ipv6.sin6_addr, channel_id->ip.data, sizeof(ipv6.sin6_addr));
	if (!getnameinfo((struct sockaddr *)&ipv6, sizeof(ipv6),
			 tmp, sizeof(tmp) - 1, NULL, 0, NI_NUMERICHOST))
	  _PUT_STRING(rid, tmp);
#endif
      } else {
	struct in_addr ipv4;
	memmove(&ipv4.s_addr, channel_id->ip.data, 4);
	cp = inet_ntoa(ipv4);
	if (cp)
	  _PUT_STRING(rid, cp);
      }

      memset(tmp, 0, sizeof(tmp));
      silc_snprintf(tmp, sizeof(tmp) - 1, ",%d,", ntohs(channel_id->port));
      _PUT_STRING(rid, tmp);
      SILC_PUT16_MSB(channel_id->rnd, tmps);
      memset(tmp, 0, sizeof(tmp));
      silc_snprintf(tmp, sizeof(tmp) - 1, "[%02x %02x]", tmps[0], tmps[1]);
      _PUT_STRING(rid, tmp);
    }
    break;
  }

  return rid;
}
#undef _PUT_STRING
