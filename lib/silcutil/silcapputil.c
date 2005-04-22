/*

  silcapputil.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 2002 - 2005 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "silcincludes.h"

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
  snprintf(email, sizeof(email), "%s@%s", username, hostname);

  ident = silc_pkcs_encode_identifier(username, hostname, realname, email,
				      NULL, NULL);
  if (realname)
    silc_free(realname);
  silc_free(hostname);
  silc_free(username);

  return ident;
}

/* Generate key pair */

bool silc_create_key_pair(const char *pkcs_name,
			  SilcUInt32 key_len_bits,
			  const char *pub_filename,
			  const char *prv_filename,
			  const char *pub_identifier,
			  const char *passphrase,
			  SilcPKCS *return_pkcs,
			  SilcPublicKey *return_public_key,
			  SilcPrivateKey *return_private_key,
			  bool interactive)
{
  SilcPKCS pkcs;
  SilcPublicKey pub_key;
  SilcPrivateKey prv_key;
  SilcRng rng;
  unsigned char *key;
  SilcUInt32 key_len;
  char line[256];
  char *pkfile = pub_filename ? strdup(pub_filename) : NULL;
  char *prvfile = prv_filename ? strdup(prv_filename) : NULL;
  char *alg = pkcs_name ? strdup(pkcs_name) : NULL;
  char *identifier = pub_identifier ? strdup(pub_identifier) : NULL;
  char *pass = passphrase ? strdup(passphrase) : NULL;

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

  if (!silc_pkcs_is_supported(alg)) {
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
	snprintf(line, sizeof(line), "Identifier [%s]: ", def);
      else
	snprintf(line, sizeof(line),
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

  rng = silc_rng_alloc();
  silc_rng_init(rng);
  silc_rng_global_init(rng);

  if (!pkfile) {
    if (interactive) {
      memset(line, 0, sizeof(line));
      snprintf(line, sizeof(line), "Public key filename [public_key.pub]: ");
      pkfile = silc_get_input(line, FALSE);
    }
    if (!pkfile)
      pkfile = strdup("public_key.pub");
  }

  if (!prvfile) {
    if (interactive) {
      memset(line, 0, sizeof(line));
      snprintf(line, sizeof(line), "Private key filename [private_key.prv]: ");
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
	bool match;
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

  /* Generate keys */
  silc_pkcs_alloc(alg, &pkcs);
  silc_pkcs_generate_key(pkcs, key_len_bits, rng);

  /* Save public key into file */
  key = silc_pkcs_get_public_key(pkcs, &key_len);
  pub_key = silc_pkcs_public_key_alloc(silc_pkcs_get_name(pkcs),
				       identifier, key, key_len);
  silc_pkcs_save_public_key(pkfile, pub_key, SILC_PKCS_FILE_PEM);
  if (return_public_key)
    *return_public_key = pub_key;
  else
    silc_pkcs_public_key_free(pub_key);
  memset(key, 0, key_len);
  silc_free(key);

  /* Save private key into file */
  key = silc_pkcs_get_private_key(pkcs, &key_len);
  prv_key = silc_pkcs_private_key_alloc(silc_pkcs_get_name(pkcs),
					key, key_len);
  silc_pkcs_save_private_key(prvfile, prv_key,
			     (unsigned char *)pass, strlen(pass),
			     SILC_PKCS_FILE_BIN);
  if (return_private_key)
    *return_private_key = prv_key;
  else
    silc_pkcs_private_key_free(prv_key);
  memset(key, 0, key_len);
  silc_free(key);

  printf("Public key has been saved into `%s'.\n", pkfile);
  printf("Private key has been saved into `%s'.\n", prvfile);
  if (interactive) {
    printf("Press <Enter> to continue...\n");
    getchar();
  }

  if (return_pkcs)
    *return_pkcs = pkcs;
  else
    silc_pkcs_free(pkcs);

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

bool silc_load_key_pair(const char *pub_filename,
			const char *prv_filename,
			const char *passphrase,
			SilcPKCS *return_pkcs,
			SilcPublicKey *return_public_key,
			SilcPrivateKey *return_private_key)
{
  char *pass = passphrase ? strdup(passphrase) : NULL;

  SILC_LOG_DEBUG(("Loading public and private keys"));

  if (silc_pkcs_load_public_key((char *)pub_filename, return_public_key,
				SILC_PKCS_FILE_PEM) == FALSE)
    if (silc_pkcs_load_public_key((char *)pub_filename, return_public_key,
				  SILC_PKCS_FILE_BIN) == FALSE) {
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

  if (silc_pkcs_load_private_key((char *)prv_filename, return_private_key,
				 (unsigned char *)pass, strlen(pass),
				 SILC_PKCS_FILE_BIN) == FALSE)
    if (silc_pkcs_load_private_key((char *)prv_filename, return_private_key,
				   (unsigned char *)pass, strlen(pass),
				   SILC_PKCS_FILE_PEM) == FALSE) {
      memset(pass, 0, strlen(pass));
      silc_free(pass);
      return FALSE;
    }

  if (return_pkcs) {
    silc_pkcs_alloc((*return_public_key)->name, return_pkcs);
    silc_pkcs_public_key_set(*return_pkcs, *return_public_key);
    silc_pkcs_private_key_set(*return_pkcs, *return_private_key);
  }

  memset(pass, 0, strlen(pass));
  silc_free(pass);
  return TRUE;
}

/* Dump public key into stdout */

bool silc_show_public_key(const char *pub_filename)
{
  SilcPublicKey public_key;
  SilcPublicKeyIdentifier ident;
  char *fingerprint, *babbleprint;
  unsigned char *pk;
  SilcUInt32 pk_len;
  SilcPKCS pkcs;
  SilcUInt32 key_len = 0;

  if (silc_pkcs_load_public_key((char *)pub_filename, &public_key,
				SILC_PKCS_FILE_PEM) == FALSE)
    if (silc_pkcs_load_public_key((char *)pub_filename, &public_key,
				  SILC_PKCS_FILE_BIN) == FALSE) {
      fprintf(stderr, "Could not load public key file `%s'\n", pub_filename);
      return FALSE;
    }

  ident = silc_pkcs_decode_identifier(public_key->identifier);

  pk = silc_pkcs_public_key_encode(public_key, &pk_len);
  fingerprint = silc_hash_fingerprint(NULL, pk, pk_len);
  babbleprint = silc_hash_babbleprint(NULL, pk, pk_len);

  if (silc_pkcs_alloc(public_key->name, &pkcs)) {
    key_len = silc_pkcs_public_key_set(pkcs, public_key);
    silc_pkcs_free(pkcs);
  }

  printf("Public key file    : %s\n", pub_filename);
  printf("Algorithm          : %s\n", public_key->name);
  if (key_len)
    printf("Key length (bits)  : %d\n", (unsigned int)key_len);
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
  silc_pkcs_public_key_free(public_key);
  silc_pkcs_free_identifier(ident);

  return TRUE;
}

/* Change private key passphrase */

bool silc_change_private_key_passphrase(const char *prv_filename,
					const char *old_passphrase,
					const char *new_passphrase)
{
  SilcPrivateKey private_key;
  bool base64 = FALSE;
  char *pass;

  pass = old_passphrase ? strdup(old_passphrase) : NULL;
  if (!pass) {
    pass = silc_get_input("Old passphrase: ", TRUE);
    if (!pass)
      pass = strdup("");
  }

  if (silc_pkcs_load_private_key((char *)prv_filename, &private_key,
				 (unsigned char *)pass, strlen(pass),
				 SILC_PKCS_FILE_BIN) == FALSE) {
    base64 = TRUE;
    if (silc_pkcs_load_private_key((char *)prv_filename, &private_key,
				   (unsigned char *)pass, strlen(pass),
				   SILC_PKCS_FILE_PEM) == FALSE) {
      memset(pass, 0, strlen(pass));
      silc_free(pass);
      fprintf(stderr, "Could not load private key `%s' file\n", prv_filename);
      return FALSE;
    }
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

  silc_pkcs_save_private_key((char *)prv_filename, private_key,
			     (unsigned char *)pass, strlen(pass),
			     base64 ? SILC_PKCS_FILE_PEM : SILC_PKCS_FILE_BIN);

  fprintf(stdout, "\nPassphrase changed\n");

  memset(pass, 0, strlen(pass));
  silc_free(pass);

  silc_pkcs_private_key_free(private_key);
  return TRUE;
}
