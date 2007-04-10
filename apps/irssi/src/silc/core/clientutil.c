/*

  client.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2006 Pekka Riikonen

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; version 2 of the License.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

*/
/* $Id$ */

#include "module.h"

#include "net-nonblock.h"
#include "net-sendbuffer.h"
#include "signals.h"
#include "servers.h"
#include "commands.h"
#include "levels.h"
#include "modules.h"
#include "rawlog.h"
#include "misc.h"
#include "settings.h"

#include "channels-setup.h"

#include "silc-servers.h"
#include "silc-channels.h"
#include "silc-queries.h"
#include "silc-nicklist.h"
#include "window-item-def.h"

#include "fe-common/core/printtext.h"
#include "fe-common/core/keyboard.h"
#include "fe-common/silc/module-formats.h"

#include "core.h"

#ifdef SILC_PLUGIN
void silc_client_print_list(char *list)
{
  char **items;
  int i=0;

  items = g_strsplit(list, ",", -1);
  
  while (items[i] != NULL)
    printformat_module("fe-common/silc", NULL, NULL,
		       MSGLEVEL_CRAP, SILCTXT_CONFIG_LIST,
		       items[i++]);

  g_strfreev(items);
}
#endif

/* Lists supported ciphers */

void silc_client_list_ciphers()
{
  char *ciphers = silc_cipher_get_supported();
#ifdef SILC_PLUGIN
  printformat_module("fe-common/silc", NULL, NULL,
		     MSGLEVEL_CRAP, SILCTXT_CONFIG_ALGOS,
		     "cipher");
  silc_client_print_list(ciphers);
#else
  fprintf(stdout, "%s\n", ciphers);
#endif
  silc_free(ciphers);
}

/* Lists supported hash functions */

void silc_client_list_hash_funcs()
{
  char *hash = silc_hash_get_supported();
#ifdef SILC_PLUGIN
  printformat_module("fe-common/silc", NULL, NULL,
		     MSGLEVEL_CRAP, SILCTXT_CONFIG_ALGOS,
		     "hash");
  silc_client_print_list(hash);
#else
  fprintf(stdout, "%s\n", hash);
#endif
  silc_free(hash);
}

/* Lists supported hash functions */

void silc_client_list_hmacs()
{
  char *hash = silc_hmac_get_supported();
#ifdef SILC_PLUGIN
  printformat_module("fe-common/silc", NULL, NULL,
		     MSGLEVEL_CRAP, SILCTXT_CONFIG_ALGOS,
		     "hmac");
  silc_client_print_list(hash);
#else
  fprintf(stdout, "%s\n", hash);
#endif
  silc_free(hash);
}

/* Lists supported PKCS algorithms */

void silc_client_list_pkcs()
{
  char *pkcs = silc_pkcs_get_supported();
#ifdef SILC_PLUGIN
  printformat_module("fe-common/silc", NULL, NULL,
		     MSGLEVEL_CRAP, SILCTXT_CONFIG_ALGOS,
		     "pkcs");
  silc_client_print_list(pkcs);
#else
  fprintf(stdout, "%s\n", pkcs);
#endif
  silc_free(pkcs);
}

/* This checks stats for various SILC files and directories. First it
   checks if ~/.silc directory exist and is owned by the correct user. If
   it doesn't exist, it will create the directory. After that it checks if
   user's Public and Private key files exists. If they doesn't exist they
   will be created after return. */

int silc_client_check_silc_dir()
{
  char filename[256], file_public_key[256], file_private_key[256];
  char servfilename[256], clientfilename[256], friendsfilename[256];
  struct stat st;
  struct passwd *pw;

  SILC_LOG_DEBUG(("Checking ~./silc directory"));

  memset(filename, 0, sizeof(filename));
  memset(file_public_key, 0, sizeof(file_public_key));
  memset(file_private_key, 0, sizeof(file_private_key));

  pw = getpwuid(getuid());
  if (!pw) {
    fprintf(stderr, "silc: %s\n", strerror(errno));
    return FALSE;
  }

  /* We'll take home path from /etc/passwd file to be sure. */
  snprintf(filename, sizeof(filename) - 1, "%s/", get_irssi_dir());
  snprintf(servfilename, sizeof(servfilename) - 1, "%s/serverkeys",
	   get_irssi_dir());
  snprintf(clientfilename, sizeof(clientfilename) - 1, "%s/clientkeys",
	   get_irssi_dir());
  snprintf(friendsfilename, sizeof(friendsfilename) - 1, "%s/friends",
	   get_irssi_dir());

  /*
   * Check ~/.silc directory
   */
  if ((stat(filename, &st)) == -1) {
    /* If dir doesn't exist */
    if (errno == ENOENT) {
      if (pw->pw_uid == geteuid()) {
	if ((mkdir(filename, 0755)) == -1) {
	  fprintf(stderr, "Couldn't create `%s' directory\n", filename);
	  return FALSE;
	}
      } else {
	fprintf(stderr, "Couldn't create `%s' directory due to a wrong uid!\n",
		filename);
	return FALSE;
      }
    } else {
      fprintf(stderr, "%s\n", strerror(errno));
      return FALSE;
    }
  } else {

    /* Check the owner of the dir */
    if (st.st_uid != 0 && st.st_uid != pw->pw_uid) {
      fprintf(stderr, "You don't seem to own `%s' directory\n",
	      filename);
      return FALSE;
    }

#if 0
    /* Check the permissions of the dir */
    if ((st.st_mode & 0777) != 0755) {
      if ((chmod(filename, 0755)) == -1) {
	fprintf(stderr, "Permissions for `%s' directory must be 0755\n",
		filename);
	return FALSE;
      }
    }
#endif
  }

  /*
   * Check ~./silc/serverkeys directory
   */
  if ((stat(servfilename, &st)) == -1) {
    /* If dir doesn't exist */
    if (errno == ENOENT) {
      if (pw->pw_uid == geteuid()) {
	if ((mkdir(servfilename, 0755)) == -1) {
	  fprintf(stderr, "Couldn't create `%s' directory\n", servfilename);
	  return FALSE;
	}
      } else {
	fprintf(stderr, "Couldn't create `%s' directory due to a wrong uid!\n",
		servfilename);
	return FALSE;
      }
    } else {
      fprintf(stderr, "%s\n", strerror(errno));
      return FALSE;
    }
  }

  /*
   * Check ~./silc/clientkeys directory
   */
  if ((stat(clientfilename, &st)) == -1) {
    /* If dir doesn't exist */
    if (errno == ENOENT) {
      if (pw->pw_uid == geteuid()) {
	if ((mkdir(clientfilename, 0755)) == -1) {
	  fprintf(stderr, "Couldn't create `%s' directory\n", clientfilename);
	  return FALSE;
	}
      } else {
	fprintf(stderr, "Couldn't create `%s' directory due to a wrong uid!\n",
		clientfilename);
	return FALSE;
      }
    } else {
      fprintf(stderr, "%s\n", strerror(errno));
      return FALSE;
    }
  }

  /*
   * Check ~./silc/friends directory
   */
  if ((stat(friendsfilename, &st)) == -1) {
    /* If dir doesn't exist */
    if (errno == ENOENT) {
      if (pw->pw_uid == geteuid()) {
	if ((mkdir(friendsfilename, 0755)) == -1) {
	  fprintf(stderr, "Couldn't create `%s' directory\n", friendsfilename);
	  return FALSE;
	}
      } else {
	fprintf(stderr, "Couldn't create `%s' directory due to a wrong uid!\n",
		friendsfilename);
	return FALSE;
      }
    } else {
      fprintf(stderr, "%s\n", strerror(errno));
      return FALSE;
    }
  }

  /*
   * Check Public and Private keys
   */
  snprintf(file_public_key, sizeof(file_public_key) - 1, "%s%s",
	   filename, SILC_CLIENT_PUBLIC_KEY_NAME);
  snprintf(file_private_key, sizeof(file_private_key) - 1, "%s%s",
	   filename, SILC_CLIENT_PRIVATE_KEY_NAME);

  if ((stat(file_public_key, &st)) == -1) {
    /* If file doesn't exist */
    if (errno == ENOENT) {
      fprintf(stdout, "Running SILC for the first time\n");
      silc_create_key_pair(SILC_CLIENT_DEF_PKCS,
			   SILC_CLIENT_DEF_PKCS_LEN,
			   file_public_key, file_private_key,
			   NULL, NULL, NULL, NULL, FALSE);
      printf("Press <Enter> to continue...\n");
      getchar();
    } else {
      fprintf(stderr, "%s\n", strerror(errno));
      return FALSE;
    }
  }

  /* Check the owner of the public key */
  if (st.st_uid != 0 && st.st_uid != pw->pw_uid) {
    fprintf(stderr, "You don't seem to own your public key!?\n");
    return FALSE;
  }

  if ((stat(file_private_key, &st)) == -1) {
    /* If file doesn't exist */
    if (errno == ENOENT) {
      fprintf(stdout, "Your private key doesn't exist\n");
      silc_create_key_pair(SILC_CLIENT_DEF_PKCS,
			   SILC_CLIENT_DEF_PKCS_LEN,
			   file_public_key, file_private_key,
			   NULL, NULL, NULL, NULL, FALSE);
      printf("Press <Enter> to continue...\n");
      getchar();
    } else {
      fprintf(stderr, "%s\n", strerror(errno));
      return FALSE;
    }
  }

  /* Check the owner of the private key */
  if (st.st_uid != 0 && st.st_uid != pw->pw_uid) {
    fprintf(stderr, "You don't seem to own your private key!?\n");
    return FALSE;
  }

  /* Check the permissions for the private key */
  if ((st.st_mode & 0777) != 0600) {
    fprintf(stderr, "Wrong permissions in your private key file `%s'!\n"
	    "Trying to change them ... ", file_private_key);
    if ((chmod(file_private_key, 0600)) == -1) {
      fprintf(stderr,
	      "Failed to change permissions for private key file!\n"
	      "Permissions for your private key file must be 0600.\n");
      return FALSE;
    }
    fprintf(stderr, "Done.\n\n");
  }

  return TRUE;
}

/* Loads public and private key from files. */

int silc_client_load_keys(SilcClient client)
{
  char pub[256], prv[256];
  struct passwd *pw;
  bool ret;

  SILC_LOG_DEBUG(("Loading public and private keys"));

  pw = getpwuid(getuid());
  if (!pw)
    return FALSE;

  memset(prv, 0, sizeof(prv));
  snprintf(prv, sizeof(prv) - 1, "%s/%s",
	   get_irssi_dir(), SILC_CLIENT_PRIVATE_KEY_NAME);

  memset(pub, 0, sizeof(pub));
  snprintf(pub, sizeof(pub) - 1, "%s/%s",
	   get_irssi_dir(), SILC_CLIENT_PUBLIC_KEY_NAME);

  /* Try loading first with "" passphrase, for those that didn't set
     passphrase for private key, and only if that fails let it prompt
     for passphrase. */
  ret = silc_load_key_pair(pub, prv, "", &irssi_pubkey, &irssi_privkey);
  if (!ret)
    ret = silc_load_key_pair(pub, prv, NULL, &irssi_pubkey, &irssi_privkey);

  if (!ret)
    SILC_LOG_ERROR(("Could not load key pair"));

  return ret;
}

#ifdef SILC_PLUGIN
void create_key_passphrase(const char *answer, CREATE_KEY_REC *rec)
{
  char priv_key_file[128], pub_key_file[128];

  signal_stop();

  if ((rec->passphrase == NULL) && (answer) && (*answer != '\0')) {
    rec->passphrase = g_strdup(answer);
    keyboard_entry_redirect((SIGNAL_FUNC) create_key_passphrase,
		            format_get_text("fe-common/silc", NULL, NULL,
				            NULL, SILCTXT_CONFIG_PASS_ASK2),
			    ENTRY_REDIRECT_FLAG_HIDDEN, rec);
    return;
  }

  if ((answer) && (*answer != '\0') && (rec->passphrase != NULL)) {
    if (strcmp(answer, rec->passphrase)) {
      printformat_module("fe-common/silc", NULL, NULL,
		         MSGLEVEL_CRAP, SILCTXT_CONFIG_PASSMISMATCH);
      g_free(rec->pkcs);
      g_free(rec->passphrase);
      g_free(rec);
      return;
    }
  }

  memset(priv_key_file, 0, sizeof(priv_key_file));
  memset(pub_key_file, 0, sizeof(pub_key_file));
  snprintf(priv_key_file, sizeof(priv_key_file) - 1, "%s/%s",
	   get_irssi_dir(), SILC_CLIENT_PRIVATE_KEY_NAME);
  snprintf(pub_key_file, sizeof(pub_key_file) - 1, "%s/%s",
	   get_irssi_dir(), SILC_CLIENT_PUBLIC_KEY_NAME);

  if (silc_create_key_pair(rec->pkcs, rec->bits, pub_key_file, priv_key_file,
		       NULL, (rec->passphrase == NULL ? "" : rec->passphrase),
		       NULL, NULL, FALSE) == TRUE)
    printformat_module("fe-common/silc", NULL, NULL,
		       MSGLEVEL_CRAP, SILCTXT_CONFIG_CREATE);
  else
    printformat_module("fe-common/silc", NULL, NULL,
		       MSGLEVEL_CRAP, SILCTXT_CONFIG_CREATE_FAIL);

  g_free(rec->passphrase);
  g_free(rec->pkcs);
  g_free(rec);
}

void change_private_key_passphrase(const char *answer, CREATE_KEY_REC *rec)
{
  signal_stop();

  if (rec->old == NULL) {
    rec->old = g_strdup((answer == NULL ? "" : answer));
    keyboard_entry_redirect((SIGNAL_FUNC) change_private_key_passphrase,
		            format_get_text("fe-common/silc", NULL, NULL,
				            NULL, SILCTXT_CONFIG_PASS_ASK2),
			    ENTRY_REDIRECT_FLAG_HIDDEN, rec);
    return;
  }
  
  if ((rec->passphrase == NULL) && (answer) && (*answer != '\0')) {
    rec->passphrase = g_strdup(answer);
    keyboard_entry_redirect((SIGNAL_FUNC) change_private_key_passphrase,
		            format_get_text("fe-common/silc", NULL, NULL,
				            NULL, SILCTXT_CONFIG_PASS_ASK3),
			    ENTRY_REDIRECT_FLAG_HIDDEN, rec);
    return;
  }

  if ((answer) && (*answer != '\0') && (rec->passphrase != NULL)) {
    if (strcmp(answer, rec->passphrase)) {
      printformat_module("fe-common/silc", NULL, NULL,
		         MSGLEVEL_CRAP, SILCTXT_CONFIG_PASSMISMATCH);
      g_free(rec->old);
      g_free(rec->file);
      g_free(rec->pkcs);
      g_free(rec->passphrase);
      g_free(rec);
      return;
    }
  }

  if (silc_change_private_key_passphrase(rec->file, rec->old,
				     (rec->passphrase == NULL ? 
				      "" : rec->passphrase)) == TRUE)
    printformat_module("fe-common/silc", NULL, NULL,
		       MSGLEVEL_CRAP, SILCTXT_CONFIG_PASSCHANGE);
  else
    printformat_module("fe-common/silc", NULL, NULL,
		       MSGLEVEL_CRAP, SILCTXT_CONFIG_PASSCHANGE_FAIL);
  g_free(rec->old);
  g_free(rec->file);
  g_free(rec->passphrase);
  g_free(rec->pkcs);
  g_free(rec);

}
#endif
