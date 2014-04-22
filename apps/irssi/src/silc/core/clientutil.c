/*

  client.c

  Author: Pekka Riikonen <priikone@silcnet.org>

  Copyright (C) 1997 - 2006, 2008 Pekka Riikonen

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
  SilcBool ret;

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

  if (silc_pkcs_private_key_get_len(irssi_privkey) < 4096) {
    fprintf(stdout,
            "warning: Your private key %s length is under 4096 bits. It is "
	    "recommended to use at least 4096 bits. Consider generating a "
	    "new key pair.\n", prv);
    printf("Press <Enter> to continue...\n");
    getchar();
  }

  return ret;
}

static SilcBool silc_keyboard_prompt_pending;

typedef struct {
  SilcAsyncOperation async_context;
  SILC_KEYBOARD_PROMPT_PROC user_prompt_proc;
  void *user_context;
  SilcBool aborted;
  SilcBool *immediate_completion;
} *SilcKeyboardEntryRedirectContext;

static void silc_keyboard_entry_redirect_abort(SilcAsyncOperation op,
					       void *context)
{
  SilcKeyboardEntryRedirectContext ctx = context;

  /*
   * Flag ourselves as aborted so the irssi callback doesn't do any real
   * work here.
   */
  ctx->aborted = TRUE;

  /*
   * Call the user routine to notify it that we are aborting, so that it may
   * clean up anything that needs cleaning up, e.g. references.  The user
   * may not reference the SilcAsyncOperation beyond this abort call.  The
   * recommended procedure is for the user prompt routine to null out its
   * reference to the SilcAsyncOperation context.  The underlying context
   * structure will be released when the actual wrappered callback fires,
   * though the wrappered callback will not call into user code now that
   * the operation has been aborted.
   */
  ctx->user_prompt_proc(NULL, ctx->user_context, KeyboardCompletionAborted);
}

static void silc_keyboard_entry_redirect_completion(const char *line,
						    void *context)
{
  SilcKeyboardEntryRedirectContext ctx = context;

  /*
   * If we are aborted, then don't call the user routine.  Note that we
   * already notified the user that they were aborted when the abort
   * call was made in the first place, so the user should not have any
   * dangling references at this point.
   *
   * Otherwise, call the user routine.
   */
  if (!ctx->aborted) {
    ctx->user_prompt_proc(line, ctx->user_context,
			  KeyboardCompletionSuccess);
  }

  /*
   * If there's a flag to set on completion, such that we can detect when the
   * operation finished immediately instead of being processed as a callback,
   * then set that now.
   */
  if (ctx->immediate_completion)
    *ctx->immediate_completion = TRUE;

  /*
   * Clean up our internal context structures.  Note that we are considered
   * responsible for handling the SilcAsyncOperation release in this model,
   * unless we were aborted, in which case the abort request has released it.
   */
  if (!ctx->aborted)
    silc_async_free(ctx->async_context);

  silc_free(ctx);

  /*
   * Mark us as not having a keyboard prompt pending.
   */
  silc_keyboard_prompt_pending = FALSE;
}

/* Prompt for user input. */
SilcBool silc_keyboard_entry_redirect(SILC_KEYBOARD_PROMPT_PROC prompt_func,
				      const char *entry,
				      int flags,
				      void *data,
				      SilcAsyncOperation *async)
{
  SilcKeyboardEntryRedirectContext ctx;
  SilcBool completed_now;

  /*
   * Check if we already have a keyboard prompt pending.  This sucks, but
   * irssi stores the keyboard prompt data in a global, and if we request
   * a prompt while there is already a prompt in progress, the old prompt
   * data is leaked.  If irssi gets its act together, this can (and should)
   * go away.
   */
  if (silc_keyboard_prompt_pending) {
    prompt_func(NULL, data, KeyboardCompletionFailed);
    return FALSE;
  }

  /*
   * Allocate our context blocks.
   */
  ctx = (SilcKeyboardEntryRedirectContext)silc_calloc(1, sizeof(*ctx));
  if (!ctx) {
    prompt_func(NULL, data, KeyboardCompletionFailed);
    return FALSE;
  }

  ctx->async_context = silc_async_alloc(silc_keyboard_entry_redirect_abort,
					NULL, ctx);
  if (!ctx->async_context) {
    silc_free(ctx);
    prompt_func(NULL, data, KeyboardCompletionFailed);
    return FALSE;
  }

  /*
   * Initially, we don't consider ourselves as having finished.
   */
  completed_now = FALSE;

  /*
   * Since irssi can't handle overlapping keyboard prompt requests, block
   * future requests until we are finished.  N.B. This should really be
   * handled inside of irssi, but this requires a breaking change to how
   * keyboard callbacks are processed from an API perspective.  A problem
   * exists where another user could call a keyboard redirect request
   * external to silc while we have one pending, and cause ours to get
   * lost, in which case we will get stuck denying future prompt requests.
   *
   * Fortunately, nobody else seems to use keyboard prompt requests, at least
   * not that I can tell.
   */
  silc_keyboard_prompt_pending = TRUE;

  /*
   * Set up the call to the irssi keyboard entry redirection facility.
   */

  ctx->user_prompt_proc     = prompt_func;
  ctx->user_context         = data;
  ctx->aborted              = FALSE;
  ctx->immediate_completion = &completed_now;

  keyboard_entry_redirect((SIGNAL_FUNC)silc_keyboard_entry_redirect_completion,
			  entry, 0, ctx);

  ctx->immediate_completion = NULL;

  /*
   * If we completed immediately, then there is nothing to return as the async
   * context has already been released.  In this case we have completed with a
   * success status, but there is no SilcAsyncOperation context to return.
   */
  if (completed_now) {
    *async = NULL;
    return TRUE;
  }

  /*
   * Otherwise, we must return an async operation context to the caller, and
   * we must unset the immediate_completion flag as we don't want to be
   * notified anymore since we're returning out.  Note that this is not safe
   * if keyboard_entry_redirect can call from a different thread, but we are
   * assuming that it doesn't as there's already many other things that seem
   * to make this assumption.
   */
  *async = ctx->async_context;

  /*
   * All done.  Irssi will invoke the callback on this thread at a later point
   * in time.
   */
  return TRUE;
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
